package services

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"honeypot-agent/internal/shipper"
	"honeypot-agent/internal/vfs"
)

// formValue returns the first NON-EMPTY field among the names, in the order given.
func TestFormValue(t *testing.T) {
	form := url.Values{"log": {"admin"}, "pass": {""}, "pwd": {"secret"}}
	tests := []struct {
		names []string
		want  string
	}{
		{[]string{"username", "log", "user"}, "admin"},  // the first name is missing
		{[]string{"password", "pass", "pwd"}, "secret"}, // "pass" is empty -> skipped
		{[]string{"email"}, ""},
		{nil, ""},
	}
	for _, tt := range tests {
		if got := formValue(form, tt.names...); got != tt.want {
			t.Errorf("formValue(%v) = %q, want %q", tt.names, got, tt.want)
		}
	}
}

// The password fields are cut out of the body (it goes only in credentials), the rest stays as sent.
func TestWithoutPasswords(t *testing.T) {
	tests := []struct{ body, want string }{
		{"username=admin&password=admin", "username=admin"},
		{"user=a&pass=b&pwd=c&lang=en", "user=a&lang=en"},
		{"pass%77ord=x&log=root", "log=root"}, // escaped name, decoded like url.ParseQuery does
		{"password=x", ""},
		{"a=1&b=%3Cscript%3E", "a=1&b=%3Cscript%3E"}, // nothing to cut: unchanged, not re-encoded
	}
	for _, tt := range tests {
		if got := withoutPasswords(tt.body); got != tt.want {
			t.Errorf("withoutPasswords(%q) = %q, want %q", tt.body, got, tt.want)
		}
	}
}

// startHTTP runs the real RunHTTP on a free local port. stop shuts it down like SIGTERM and checks
// that RunHTTP returns nil; after that every handler has finished, so the shipper's output is complete.
func startHTTP(t *testing.T, s *shipper.Shipper) (addr string, stop func()) {
	t.Helper()
	// RunHTTP opens its own listener -> find a free port first
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = free.Addr().String()
	free.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() { result <- RunHTTP(ctx, addr, "http-test", s) }()

	// wait until the server is listening
	for start := time.Now(); ; time.Sleep(20 * time.Millisecond) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		select {
		case err := <-result:
			t.Fatalf("RunHTTP stopped: %v", err)
		default:
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("RunHTTP is not listening")
		}
	}

	return addr, func() {
		t.Helper()
		cancel() // like SIGTERM: RunHTTP must return nil
		select {
		case err := <-result:
			if err != nil {
				t.Fatalf("on shutdown RunHTTP should return nil, it returned %v", err)
			}
		case <-time.After(shutdownWait + time.Second):
			t.Fatal("RunHTTP did not stop")
		}
	}
}

// Keep-alive like lighttpd (values shortened here): after max-keep-alive-requests the next answer
// says "Connection: close" and ends the connection, and an idle keep-alive connection is closed
// after max-keep-alive-idle. Otherwise one request now and then would hold a connection forever.
func TestHTTPKeepAliveLikeLighttpd(t *testing.T) {
	oldIdle, oldMax := httpKeepAliveIdle, httpMaxKeepAliveRequests
	httpKeepAliveIdle, httpMaxKeepAliveRequests = 500*time.Millisecond, 2
	t.Cleanup(func() { httpKeepAliveIdle, httpMaxKeepAliveRequests = oldIdle, oldMax })
	addr, stop := startHTTP(t, shipper.NewShipper(io.Discard, "", ""))
	defer stop()

	get := func(conn net.Conn, r *bufio.Reader) *http.Response {
		t.Helper()
		fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: gateway\r\n\r\n")
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	// 3 requests on one connection: the answer one past the limit of 2 closes it (lighttpd's ">")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	for i := 1; i <= 3; i++ {
		if resp := get(conn, r); resp.Close != (i == 3) {
			t.Errorf("answer %d: Connection: close = %v (expected only on the 3rd)", i, resp.Close)
		}
	}
	if _, err := r.ReadByte(); err != io.EOF {
		t.Errorf("after the 3rd answer the connection is still open (%v)", err)
	}

	// an idle keep-alive connection is closed after 500ms
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	idle.SetDeadline(time.Now().Add(10 * time.Second))
	r = bufio.NewReader(idle)
	get(idle, r)
	start := time.Now()
	_, err = r.ReadByte() // nothing more is sent: wait until the server hangs up
	if took := time.Since(start); err != io.EOF || took > time.Second {
		t.Errorf("idle keep-alive connection: %v after %v (expected closed after 500ms)", err, took)
	}
}

// The real RunHTTP on a local port: a scanner's GET, a login form and Basic Auth, then shutdown.
// Checks the persona (lighttpd, "Gateway Router"), the status codes and the logged events.
func TestHTTP(t *testing.T) {
	var out bytes.Buffer
	addr, stop := startHTTP(t, shipper.NewShipper(&out, "", ""))

	// own Transport = own keep-alive connection: requests 1-3 reuse one TCP connection
	client := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	do := func(req *http.Request) (*http.Response, string) {
		t.Helper()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body)
	}

	start := time.Now() // every answer takes at least routerDelay: checked after the 9 requests

	// 1. a scanner looking for a path that doesn't exist -> lighttpd's own 404 page
	req, _ := http.NewRequest("GET", "http://"+addr+"/cgi-bin/luci?x=1", nil)
	req.Header.Set("User-Agent", "zgrab/0.x")
	resp, body := do(req)
	if resp.StatusCode != 404 || resp.Header.Get("Server") != "lighttpd/1.4.53" ||
		resp.Header.Get("Content-Type") != "text/html" || resp.Header.Get("WWW-Authenticate") != "" ||
		!strings.Contains(body, "<title>404 Not Found</title>") || len(body) != 341 {
		t.Errorf("GET unknown path: %d, Server %q, Content-Type %q, %d bytes: %q", resp.StatusCode,
			resp.Header.Get("Server"), resp.Header.Get("Content-Type"), len(body), body)
	}

	// 2. the login form (its target is the CGI /var/www/login.cgi)
	req, _ = http.NewRequest("POST", "http://"+addr+"/login.cgi", strings.NewReader("username=admin&password=7ujMko0admin&lang=en"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, body = do(req)
	if resp.StatusCode != 401 || !strings.Contains(body, "Invalid username or password") ||
		resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("form login: %d, WWW-Authenticate %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// 3. Basic Auth -> only now we answer with WWW-Authenticate (and lighttpd's 401 page)
	req, _ = http.NewRequest("GET", "http://"+addr+"/", nil)
	req.SetBasicAuth("root", "xc3511")
	resp, body = do(req)
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != `Basic realm="Gateway"` ||
		!strings.Contains(body, "<h1>401 Unauthorized</h1>") {
		t.Errorf("Basic Auth: %d, WWW-Authenticate %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// 4-8. another client = another TCP connection = another session
	client = &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	req, _ = http.NewRequest("GET", "http://"+addr+"/", nil)
	if resp, body = do(req); resp.StatusCode != 200 || !strings.Contains(body, `action="/login.cgi"`) {
		t.Errorf("GET /: %d", resp.StatusCode)
	}
	if page, _ := vfs.WebFile("/"); body != page {
		t.Error("GET / is not /var/www/index.html from the fake filesystem (cat would show something else)")
	}
	// the password in the URL (IoT exploits): a login_attempt, even on a path that doesn't exist
	req, _ = http.NewRequest("GET", "http://"+addr+"/goform/login?user=admin&pwd=s3cr3t&lang=en", nil)
	if resp, _ = do(req); resp.StatusCode != 404 {
		t.Errorf("GET /goform/login: %d (expected 404)", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", "http://"+addr+"/index.html", nil)
	if resp, body = do(req); resp.StatusCode != 200 || !strings.Contains(body, "Gateway Router") {
		t.Errorf("GET /index.html: %d", resp.StatusCode)
	}
	// login.cgi is a program: without a password it shows the form, never its own (binary) file
	req, _ = http.NewRequest("GET", "http://"+addr+"/login.cgi", nil)
	if resp, body = do(req); resp.StatusCode != 200 || !strings.Contains(body, "Gateway Router") {
		t.Errorf("GET /login.cgi: %d %q", resp.StatusCode, body)
	}
	// only files that exist in /var/www: not the old /login, and ".." can't leave the web root
	for _, p := range []string{"/login", "/../../etc/passwd"} {
		req, _ = http.NewRequest("GET", "http://"+addr+p, nil)
		if resp, _ = do(req); resp.StatusCode != 404 {
			t.Errorf("GET %s: %d (expected 404)", p, resp.StatusCode)
		}
	}
	// the slow answers are what caps an HTTP flood (see RunHTTP): all kinds of requests, not only logins
	if took := time.Since(start); took < 9*routerDelay {
		t.Errorf("9 requests took %v: every answer should take at least %v", took, routerDelay)
	}

	stop()
	events := parseEvents(t, out.String())
	if len(events) != 9 {
		t.Fatalf("%d events (expected 9): %+v", len(events), events)
	}
	for _, e := range events {
		if e.Protocol != "HTTP" || e.TargetPort != 80 || e.SourceIP != "127.0.0.1" {
			t.Errorf("%s: %s/%d from %s", e.EventType, e.Protocol, e.TargetPort, e.SourceIP)
		}
	}

	// one session_id per TCP connection (the Python SessionStore groups by it)
	first := events[0].SessionID
	if len(first) != 16 || events[1].SessionID != first || events[2].SessionID != first {
		t.Errorf("same connection, session_ids %q %q %q (expected one, 16 hex)", first, events[1].SessionID, events[2].SessionID)
	}
	if id := events[3].SessionID; len(id) != 16 || id == first {
		t.Errorf("new connection, session_id %q (expected a new one, not %q)", id, first)
	}
	for _, e := range events[4:] {
		if e.SessionID != events[3].SessionID {
			t.Errorf("same (second) connection, session_id %q (expected %q)", e.SessionID, events[3].SessionID)
		}
	}

	if e := events[0]; e.EventType != "http_request" || e.Credentials != nil ||
		e.PayloadDetails.HTTPMethod != "GET" || e.PayloadDetails.HTTPPath != "/cgi-bin/luci?x=1" ||
		e.PayloadDetails.HTTPUserAgent != "zgrab/0.x" {
		t.Errorf("GET event: %+v %+v", e, e.PayloadDetails)
	}
	if e := events[1]; e.EventType != "login_attempt" || e.PayloadDetails.HTTPMethod != "POST" ||
		e.Credentials.Username != "admin" || e.Credentials.Password != "7ujMko0admin" || e.Credentials.Success {
		t.Errorf("form login event: %+v %+v", e, e.Credentials)
	}
	// the password only in credentials, never in raw_data
	if raw := events[1].PayloadDetails.RawData; raw != "username=admin&lang=en" {
		t.Errorf("form login raw_data = %q (expected the body without the password)", raw)
	}
	// even a weak password never "works" over HTTP
	if e := events[2]; e.EventType != "login_attempt" ||
		e.Credentials.Username != "root" || e.Credentials.Password != "xc3511" || e.Credentials.Success {
		t.Errorf("Basic Auth event: %+v %+v", e, e.Credentials)
	}
	// the password from the URL: in credentials, cut out of http_path (the rest stays as sent)
	if e := events[4]; e.EventType != "login_attempt" || e.Credentials.Username != "admin" ||
		e.Credentials.Password != "s3cr3t" || e.PayloadDetails.HTTPPath != "/goform/login?user=admin&lang=en" {
		t.Errorf("URL login event: %+v %+v %+v", e, e.Credentials, e.PayloadDetails)
	}
	if e := events[5]; e.EventType != "http_request" || e.PayloadDetails.HTTPPath != "/index.html" {
		t.Errorf("GET /index.html event: %+v %+v", e, e.PayloadDetails)
	}
}

// Like lighttpd (max-request-field-size 8192): a request line + headers of 8192 bytes is served,
// 8193 gets lighttpd's own 431, byte for byte. Far over the limit Go stops reading and refuses it
// itself: lighttpd's 431 again (httpConn.Write), and an event with only the first line, not 20KB.
func TestHTTPHeaderLimit(t *testing.T) {
	var out bytes.Buffer
	addr, stop := startHTTP(t, shipper.NewShipper(&out, "", ""))

	// send sends exact bytes and reads the answer until the server closes the connection.
	// The header block is 60 bytes + the User-Agent.
	send := func(userAgent string) string {
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: h\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", userAgent)
		answer, _ := io.ReadAll(conn) // a reset after Go's own 431 is fine: the events are what matter
		return string(answer)
	}

	if answer := send(strings.Repeat("a", 8192-60)); !strings.HasPrefix(answer, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("8192 bytes of headers: %.60q (expected 200, lighttpd allows exactly 8192)", answer)
	}

	answer := send(strings.Repeat("b", 8193-60))
	head, page, _ := strings.Cut(answer, "\r\n\r\n")
	date, _ := time.Parse(http.TimeFormat, strings.TrimPrefix(strings.Split(head, "\r\n")[4], "Date: "))
	if !strings.HasPrefix(head, "HTTP/1.0 431 \r\nContent-Type: text/html\r\nContent-Length: 323\r\nConnection: close\r\nDate: ") ||
		!strings.HasSuffix(head, "\r\nServer: lighttpd/1.4.53") || time.Since(date) > time.Minute ||
		page != lighttpdErrorPage("431 ") || len(page) != 323 {
		t.Errorf("8193 bytes of headers, not lighttpd's 431:\n%s", answer)
	}

	huge := send(strings.Repeat("c", 20000)) // over MaxHeaderBytes + Go's 4KB: refused by Go itself
	if !strings.HasPrefix(huge, "HTTP/1.0 431 \r\nContent-Type: text/html\r\nContent-Length: 323\r\n") {
		t.Errorf("20000 bytes of headers: %.60q (expected lighttpd's 431)", huge)
	}

	stop()
	events := parseEvents(t, out.String())
	if len(events) != 3 || len(events[0].PayloadDetails.HTTPUserAgent) != 8192-60 ||
		len(events[1].PayloadDetails.HTTPUserAgent) != 8193-60 || events[2].PayloadDetails.RawData != "GET / HTTP/1.1" {
		t.Fatalf("%d events (expected the 8192 and 8193 requests, then only the first line of the huge one): %+v",
			len(events), events)
	}
}

// Requests lighttpd refuses or doesn't serve (src/request.c, response.c in 1.4.53) get lighttpd's
// answers, never net/http's own text/plain errors: malformed requests, odd methods, odd versions.
// The expected status lines are written here from the source, not taken from lighttpdRejects.
func TestHTTPRefusesLikeLighttpd(t *testing.T) {
	var out bytes.Buffer
	addr, stop := startHTTP(t, shipper.NewShipper(&out, "", ""))
	send := func(request string) string { // exact bytes; read until the server closes
		t.Helper()
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, request)
		answer, _ := io.ReadAll(conn)
		time.Sleep(150 * time.Millisecond) // limit.go: 10 new connections per second per IP
		return string(answer)
	}

	const end = "Connection: close\r\n\r\n" // the keep-alive cases end the connection with this
	tests := []struct{ request, status, page string }{
		// refused while parsing (net/http refuses these itself): HTTP/1.0 until the version is read
		{"HELP\r\n\r\n", "HTTP/1.0 400 Bad Request", "400 Bad Request"},
		{"\r\n\r\n", "HTTP/1.0 400 Bad Request", "400 Bad Request"},
		{"OPTIONS / RTSP/1.0\r\n\r\n", "HTTP/1.0 400 Bad Request", "400 Bad Request"},
		{"GET / HTTP/2.0\r\nHost: g\r\n\r\n", "HTTP/1.0 505 HTTP Version Not Supported", "505 HTTP Version Not Supported"},
		{"GET / HTTP/1.1\r\n\r\n", "HTTP/1.1 400 Bad Request", "400 Bad Request"}, // HTTP/1.1 without Host
		{"GET / HTTP/1.1\r\nHost: g\r\nBad Header\r\n\r\n", "HTTP/1.1 400 Bad Request", "400 Bad Request"},
		// refused while parsing (net/http accepts them, the handler refuses)
		{"FOO / HTTP/1.1\r\nHost: g\r\n\r\n", "HTTP/1.0 501 Not Implemented", "501 Not Implemented"},
		{"GET / HTTP/1.2\r\nHost: g\r\n\r\n", "HTTP/1.0 505 HTTP Version Not Supported", "505 HTTP Version Not Supported"},
		{"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n", "HTTP/1.1 400 Bad Request", "400 Bad Request"},
		{"GET * HTTP/1.1\r\nHost: g\r\n\r\n", "HTTP/1.1 400 Bad Request", "400 Bad Request"},
		// parsed, then not served
		{"CONNECT 203.0.113.5:443 HTTP/1.1\r\nHost: 203.0.113.5:443\r\n" + end, "HTTP/1.1 405 Method Not Allowed", "405 Method Not Allowed"},
		{"DELETE /index.html HTTP/1.1\r\nHost: g\r\n" + end, "HTTP/1.1 403 Forbidden", "403 Forbidden"},
		{"PUT /x.php HTTP/1.1\r\nHost: g\r\nContent-Length: 0\r\n" + end, "HTTP/1.1 404 Not Found", "404 Not Found"},
		{"OPTIONS * HTTP/1.1\r\nHost: g\r\n" + end, "HTTP/1.1 200 OK", ""},
		{"OPTIONS /index.html HTTP/1.1\r\nHost: g\r\n" + end, "HTTP/1.1 200 OK", ""},
		{"GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\n" + end, "HTTP/1.1 200 OK", "file"},
	}
	for _, tt := range tests {
		answer := send(tt.request)
		head, body, _ := strings.Cut(answer, "\r\n\r\n")
		if !strings.HasPrefix(head, tt.status+"\r\n") || !strings.Contains(head+"\r\n", "\r\nServer: lighttpd/1.4.53\r\n") ||
			strings.Contains(head, "text/plain") {
			t.Errorf("%q:\n got %q\nwant %q + Server: lighttpd", tt.request, head, tt.status)
			continue
		}
		switch tt.page {
		case "": // OPTIONS: lighttpd's list of methods, no body
			if !strings.Contains(head, "\r\nAllow: OPTIONS, GET, HEAD, POST") || body != "" {
				t.Errorf("%q: %q", tt.request, answer)
			}
		case "file":
			if body != vfs.LoginPage(false) {
				t.Errorf("%q: body %.80q", tt.request, body)
			}
		default:
			if body != lighttpdErrorPage(tt.page) {
				t.Errorf("%q: body %.80q", tt.request, body)
			}
		}
	}

	// keep-alive: a good request, its answer, then a malformed one on the same connection: the
	// malformed one's own line is used (not pipelined: see the limitation in httpConn)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	io.WriteString(conn, "GET /index.html HTTP/1.1\r\nHost: g\r\n\r\n")
	if resp, err := http.ReadResponse(r, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("first request: %v %v", resp, err)
	} else {
		io.Copy(io.Discard, resp.Body)
	}
	io.WriteString(conn, "GET /x HTTP/1.1\r\nBad Header\r\n\r\n")
	if answer, _ := io.ReadAll(r); !strings.HasPrefix(string(answer), "HTTP/1.1 400 Bad Request\r\n") {
		t.Errorf("keep-alive, then a malformed request: %.80q", answer)
	}

	// every request is logged: the ones net/http refused only with their first line
	stop()
	var rejected []string
	for _, e := range parseEvents(t, out.String()) {
		if e.PayloadDetails != nil && e.PayloadDetails.HTTPMethod == "" {
			rejected = append(rejected, e.PayloadDetails.RawData)
		}
	}
	want := []string{"HELP", "", "OPTIONS / RTSP/1.0", "GET / HTTP/2.0", "GET / HTTP/1.1", "GET / HTTP/1.1", "GET /x HTTP/1.1"}
	if !slices.Equal(rejected, want) {
		t.Errorf("requests refused by net/http, logged: %q\n                                    want %q", rejected, want)
	}
}

// lighttpd's verdict on a request line, in its order (method, protocol, target), from request.c.
func TestLighttpdRejects(t *testing.T) {
	tests := []struct{ line, status, proto string }{
		{"GET / HTTP/1.1", "", "HTTP/1.1"},
		{"HEAD /x HTTP/1.0", "", "HTTP/1.0"},
		{"PROPFIND / HTTP/1.1", "", "HTTP/1.1"},               // WebDAV: known to lighttpd (http_kv.c)
		{"GET /", "400 Bad Request", "HTTP/1.0"},              // incomplete request line
		{"GET  / HTTP/1.1", "400 Bad Request", "HTTP/1.0"},    // two spaces: overlong
		{"GET / HTTP/1.1 x", "400 Bad Request", "HTTP/1.0"},   // overlong
		{"", "400 Bad Request", "HTTP/1.0"},                   // a blank line first
		{"get / HTTP/1.1", "501 Not Implemented", "HTTP/1.0"}, // methods are case-sensitive
		{"FOO / RTSP/1.0", "501 Not Implemented", "HTTP/1.0"}, // the method is checked first
		{"OPTIONS / RTSP/1.0", "400 Bad Request", "HTTP/1.0"}, // unknown protocol
		{"GET / HTTP/1.2", "505 HTTP Version Not Supported", "HTTP/1.0"},
		{"GET / HTTP/0.9", "505 HTTP Version Not Supported", "HTTP/1.0"},
		{"GET http://example.com/a HTTP/1.1", "", "HTTP/1.1"},              // absolute URI with a path
		{"GET HTTPS://example.com/ HTTP/1.1", "", "HTTP/1.1"},              // scheme in any case
		{"GET http://example.com HTTP/1.1", "400 Bad Request", "HTTP/1.1"}, // no path
		{"CONNECT 203.0.113.5:443 HTTP/1.1", "", "HTTP/1.1"},               // then 405, in the handler
		{"CONNECT example.com:443 HTTP/1.0", "400 Bad Request", "HTTP/1.0"},
		{"OPTIONS * HTTP/1.1", "", "HTTP/1.1"},
		{"GET * HTTP/1.1", "400 Bad Request", "HTTP/1.1"},
	}
	for _, tt := range tests {
		if status, proto := lighttpdRejects(tt.line); status != tt.status || proto != tt.proto {
			t.Errorf("lighttpdRejects(%q) = %q, %q; want %q, %q", tt.line, status, proto, tt.status, tt.proto)
		}
	}
}

// A refused request's line is logged without its password, like http_path.
func TestLineWithoutPasswords(t *testing.T) {
	tests := []struct{ line, want string }{
		{"GET /login.cgi?user=admin&pwd=s3cr3t HTTP/9.9", "GET /login.cgi?user=admin HTTP/9.9"},
		{"GET /x?password=1", "GET /x?"},
		{"HELP", "HELP"},
	}
	for _, tt := range tests {
		if got := lineWithoutPasswords(tt.line); got != tt.want {
			t.Errorf("lineWithoutPasswords(%q) = %q, want %q", tt.line, got, tt.want)
		}
	}
}
