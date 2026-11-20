package services

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
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

// The real RunHTTP on a local port: a scanner's GET, a login form and Basic Auth, then shutdown.
// Checks the persona (lighttpd, "Gateway Router"), the status codes and the logged events.
func TestHTTP(t *testing.T) {
	// RunHTTP opens its own listener -> find a free port first
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := free.Addr().String()
	free.Close()

	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

	start := time.Now() // every answer takes at least httpDelay: checked after the 9 requests

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
	if took := time.Since(start); took < 9*httpDelay {
		t.Errorf("9 requests took %v: every answer should take at least %v", took, httpDelay)
	}

	cancel() // like SIGTERM: RunHTTP must return nil
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("on shutdown RunHTTP should return nil, it returned %v", err)
		}
	case <-time.After(shutdownWait + time.Second):
		t.Fatal("RunHTTP did not stop")
	}

	// RunHTTP has returned = every request handler has finished, so out is complete
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
