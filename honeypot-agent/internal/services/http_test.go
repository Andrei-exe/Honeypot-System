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

	client := &http.Client{Timeout: 5 * time.Second}
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

	// 1. a scanner looking around
	req, _ := http.NewRequest("GET", "http://"+addr+"/cgi-bin/luci?x=1", nil)
	req.Header.Set("User-Agent", "zgrab/0.x")
	resp, body := do(req)
	if resp.StatusCode != 200 || resp.Header.Get("Server") != "lighttpd/1.4.55" ||
		!strings.Contains(body, "Gateway Router") || resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("GET: %d, Server %q, WWW-Authenticate %q", resp.StatusCode, resp.Header.Get("Server"), resp.Header.Get("WWW-Authenticate"))
	}

	// 2. the login form
	req, _ = http.NewRequest("POST", "http://"+addr+"/login", strings.NewReader("username=admin&password=admin"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, body = do(req)
	if resp.StatusCode != 401 || !strings.Contains(body, "Invalid username or password") ||
		resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("form login: %d, WWW-Authenticate %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}

	// 3. Basic Auth -> only now we answer with WWW-Authenticate
	req, _ = http.NewRequest("GET", "http://"+addr+"/", nil)
	req.SetBasicAuth("root", "xc3511")
	resp, _ = do(req)
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != `Basic realm="Gateway"` {
		t.Errorf("Basic Auth: %d, WWW-Authenticate %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
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
	if len(events) != 3 {
		t.Fatalf("%d events (expected 3): %+v", len(events), events)
	}
	for _, e := range events {
		if e.Protocol != "HTTP" || e.TargetPort != 80 || e.SourceIP != "127.0.0.1" {
			t.Errorf("%s: %s/%d from %s", e.EventType, e.Protocol, e.TargetPort, e.SourceIP)
		}
	}

	if e := events[0]; e.EventType != "http_request" || e.Credentials != nil ||
		e.PayloadDetails.HTTPMethod != "GET" || e.PayloadDetails.HTTPPath != "/cgi-bin/luci?x=1" ||
		e.PayloadDetails.HTTPUserAgent != "zgrab/0.x" {
		t.Errorf("GET event: %+v %+v", e, e.PayloadDetails)
	}
	if e := events[1]; e.EventType != "login_attempt" || e.PayloadDetails.HTTPMethod != "POST" ||
		e.Credentials.Username != "admin" || e.Credentials.Password != "admin" || e.Credentials.Success {
		t.Errorf("form login event: %+v %+v", e, e.Credentials)
	}
	// even a weak password never "works" over HTTP
	if e := events[2]; e.EventType != "login_attempt" ||
		e.Credentials.Username != "root" || e.Credentials.Password != "xc3511" || e.Credentials.Success {
		t.Errorf("Basic Auth event: %+v %+v", e, e.Credentials)
	}
}
