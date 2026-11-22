package services

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// What lighttpd 1.4.53 answers to requests it won't serve (src/request.c, response.c,
// connections.c, http_kv.c, read in the source). Malformed requests and odd methods must
// get the router's answers, not Go's: net/http answers a request it can't parse by itself, with a
// text/plain "400 Bad Request" and no Server header, which nmap and others recognize as Go.

// lighttpdMethods are the methods lighttpd knows (http_methods in http_kv.c); any other gets 501.
var lighttpdMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true, "CONNECT": true,
	"OPTIONS": true, "TRACE": true, "ACL": true, "BASELINE-CONTROL": true, "BIND": true,
	"CHECKIN": true, "CHECKOUT": true, "COPY": true, "LABEL": true, "LINK": true, "LOCK": true,
	"MERGE": true, "MKACTIVITY": true, "MKCALENDAR": true, "MKCOL": true, "MKREDIRECTREF": true,
	"MKWORKSPACE": true, "MOVE": true, "ORDERPATCH": true, "PATCH": true, "PROPFIND": true,
	"PROPPATCH": true, "REBIND": true, "REPORT": true, "SEARCH": true, "UNBIND": true,
	"UNCHECKOUT": true, "UNLINK": true, "UNLOCK": true, "UPDATE": true, "UPDATEREDIRECTREF": true,
	"VERSION-CONTROL": true,
}

// lighttpdRejects returns lighttpd's answer to a request line it refuses while parsing it
// (http_request_parse_reqline, which checks the method, then the protocol, then the target), or ""
// if it accepts the line. proto is the HTTP version of the answer: HTTP/1.0 as long as lighttpd
// hasn't read the request's own version, so for the first three cases.
func lighttpdRejects(line string) (status, proto string) {
	method, rest, ok := strings.Cut(line, " ")
	target, version, ok2 := strings.Cut(rest, " ")
	if !ok || !ok2 || method == "" || target == "" || strings.Contains(version, " ") {
		return "400 Bad Request", "HTTP/1.0" // "incomplete request line" / "overlong request line"
	}
	if !lighttpdMethods[method] {
		return "501 Not Implemented", "HTTP/1.0"
	}
	major, minor, ok := http.ParseHTTPVersion(version)
	switch {
	case !ok:
		return "400 Bad Request", "HTTP/1.0" // "unknown protocol", e.g. RTSP/1.0
	case major != 1 || minor > 1:
		return "505 HTTP Version Not Supported", "HTTP/1.0"
	}
	proto = "HTTP/1." + strconv.Itoa(minor)

	switch {
	case strings.HasPrefix(target, "/"):
	case hasPrefixFold(target, "http://") && strings.Contains(target[len("http://"):], "/"):
	case hasPrefixFold(target, "https://") && strings.Contains(target[len("https://"):], "/"):
		// an absolute URI with a path: lighttpd takes the host from it and serves the path
	case method == "CONNECT" && (target[0] == ':' || target[0] >= '0' && target[0] <= '9'):
		// an IP:port is parsed (and then refused with 405), a host name is not
	case method == "OPTIONS" && target == "*":
	default:
		return "400 Bad Request", proto // "request-URI parse error" (strict parsing, the default)
	}
	return "", proto
}

// hasPrefixFold is strings.HasPrefix ignoring case (lighttpd compares schemes with strncasecmp).
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// writeLighttpdError writes lighttpd's answer to a request it refused while parsing it: its error
// page, in its header order, with "Connection: close" (request.c turns keep-alive off then).
func writeLighttpdError(w io.Writer, proto, status string) {
	page := lighttpdErrorPage(status)
	fmt.Fprintf(w, "%s %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n"+
		"Date: %s\r\nServer: lighttpd/1.4.53\r\n\r\n%s",
		proto, status, len(page), time.Now().UTC().Format(http.TimeFormat), page)
}

// answerAndClose answers from the handler with writeLighttpdError and closes the connection. Written by
// hand (Hijack): net/http would write the status line with its own text and version.
func answerAndClose(w http.ResponseWriter, proto, status string) {
	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	writeLighttpdError(buf, proto, status)
	buf.Flush()
}

// goErrorHeaders follow the status line in every answer net/http writes by itself to a request it
// can't parse (server.go): "HTTP/1.1 400 Bad Request" + these + the status again as plain text.
const goErrorHeaders = "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"

// httpConn is one TCP connection of the web server. It keeps what the handler needs across the
// requests of a keep-alive connection, and replaces the answers net/http gives by itself (Write).
type httpConn struct {
	net.Conn
	sessionID string // keep-alive requests on one connection share one session_id
	requests  int    // requests so far (only the handler uses it: one request at a time, no mutex)

	// rejected logs a request net/http refused before the handler saw it (set by RunHTTP)
	rejected func(c *httpConn, line string)

	// The start of the current request, up to its first \n (at most 1024 bytes). Limitation: with
	// pipelining (the next request sent before the answer, in the same read) the next request's line
	// isn't seen; if net/http then refuses that request, the answer is HTTP/1.0 400 and the event has
	// no line. Clients that wait for each answer (nearly all) are fine.
	mu       sync.Mutex // Read may run in net/http's background read while the handler resets line
	line     []byte
	lineDone bool
}

// Read reads like the real connection, and keeps the first line of each request: if net/http
// refuses the request, it's all we have to answer like lighttpd and to log.
func (c *httpConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	if !c.lineDone {
		data := p[:n]
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data, c.lineDone = data[:i+1], true
		}
		c.line = append(c.line, data[:min(len(data), 1024-len(c.line))]...)
	}
	c.mu.Unlock()
	return n, err
}

// takeLine returns the first line of the current request (without its line end) and starts over
// for the next one. Called by the handler for each request, and when net/http refuses one.
func (c *httpConn) takeLine() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	line := strings.TrimRight(string(c.line), "\r\n")
	c.line, c.lineDone = c.line[:0], false
	return line
}

// Write writes like the real connection, except an answer net/http gives by itself (it writes it in
// one piece, straight to the connection): lighttpd's answer to that request goes out instead.
func (c *httpConn) Write(p []byte) (int, error) {
	rest, ok := bytes.CutPrefix(p, []byte("HTTP/1.1 "))
	end := bytes.Index(rest, []byte("\r\n"))
	if !ok || end < 3 || !bytes.HasPrefix(rest[end:], []byte(goErrorHeaders)) {
		return c.Conn.Write(p)
	}
	code := string(rest[:3])

	line := c.takeLine()
	status, proto := lighttpdRejects(line)
	switch {
	case code == "431": // headers too large: lighttpd answers before it parses anything (see http.go)
		status, proto = "431 ", "HTTP/1.0"
	case status != "": // lighttpd already refuses the request line
	case code == "501": // a Transfer-Encoding Go doesn't support
		status = "501 Not Implemented"
	default: // the line is fine, the rest isn't: e.g. HTTP/1.1 without Host, a header line without ':'
		status = "400 Bad Request"
	}
	c.rejected(c, line)
	writeLighttpdError(c.Conn, proto, status)
	return len(p), nil // to net/http it looks like its own answer went out
}

// httpListener wraps every connection it accepts in an httpConn.
type httpListener struct {
	net.Listener
	rejected func(c *httpConn, line string)
}

func (l httpListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &httpConn{Conn: conn, sessionID: newSessionID(), rejected: l.rejected}, nil
}

// lineWithoutPasswords takes the password fields out of the query string of a request line, the way
// http_path loses them: the password goes only in credentials, never in raw_data.
func lineWithoutPasswords(line string) string {
	start := strings.IndexByte(line, '?')
	if start < 0 {
		return line
	}
	end := strings.IndexByte(line[start:], ' ')
	if end < 0 {
		end = len(line) - start
	}
	return line[:start+1] + withoutPasswords(line[start+1:start+end]) + line[start+end:]
}
