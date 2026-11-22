package services

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"honeypot-agent/internal/shipper"
)

// A handler that panics (a bug some attacker input triggers) ends only its own session: serve keeps
// accepting, the panic is logged once (not once per session: an attacker could repeat it), and
// shutdown still works. Without the recover, this test binary itself would crash.
func TestServeSurvivesPanic(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := raw.Addr().String()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	handle := func(c net.Conn) { // closes the connection itself only when it doesn't panic
		buf := make([]byte, 4)
		n, _ := c.Read(buf)
		if string(buf[:n]) == "boom" {
			var m map[string]int
			m["x"] = 1 // a real bug: writing to a nil map panics
		}
		c.Write([]byte("ok"))
		c.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- serve(ctx, limitConnections(raw, "TEST"), handle) }()

	send := func(msg string) string {
		t.Helper()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte(msg))
		answer, err := io.ReadAll(c)
		if err != nil {
			t.Errorf("%s: %v (the session should be closed right away)", msg, err)
		}
		return string(answer)
	}
	for range 3 {
		if got := send("boom"); got != "" {
			t.Errorf("the panicking session answered %q (expected it closed)", got)
		}
	}
	if got := send("ping"); got != "ok" {
		t.Errorf("after 3 panics, a normal session got %q (expected ok)", got)
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("on shutdown serve should return nil, it returned %v", err)
		}
	case <-time.After(shutdownWait + time.Second):
		t.Fatal("serve did not stop")
	}
	log.SetOutput(os.Stderr) // from here on nothing writes into logs
	if n := strings.Count(logs.String(), "panic in a session"); n != 1 {
		t.Errorf("%d panic messages for 3 panics (expected 1, at most one per %v):\n%s", n, limitLogEvery, logs.String())
	}
	if !strings.Contains(logs.String(), "assignment to entry in nil map") || !strings.Contains(logs.String(), "serve_test.go") {
		t.Errorf("the message should have the panic and where it happened (the stack):\n%s", logs.String())
	}
}

// On shutdown, serve closes the open sessions: every one ends with session_end, serve returns
// nil quickly, and new connections are no longer accepted.
func TestShutdownEndsOpenSessions(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := raw.Addr().String()

	var out bytes.Buffer // JSONL written by the shipper (no URL = stdout copy only)
	s := shipper.NewShipper(&out, "", "")

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- serve(ctx, limitConnections(raw, "TEST"), func(c net.Conn) { handleTelnet(c, "test", s) })
	}()

	// 3 attackers sitting at the login prompt
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString(' ')
			if err != nil {
				t.Fatalf("client %d did not get the login prompt: %v", i, err)
			}
			if strings.Contains(line, "login:") {
				break
			}
		}
	}

	start := time.Now()
	cancel() // what SIGTERM does in main
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("on shutdown serve should return nil, it returned %v", err)
		}
	case <-time.After(shutdownWait + time.Second):
		t.Fatal("serve did not stop")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("shutdown took %v (the sessions should be closed right away)", d)
	}

	// serve has returned = every handler has finished, so out is complete
	jsonl := out.String()
	if n := strings.Count(jsonl, `"session_start"`); n != 3 {
		t.Errorf("session_start: %d (expected 3)", n)
	}
	if n := strings.Count(jsonl, `"session_end"`); n != 3 {
		t.Errorf("session_end: %d (expected 3) - the sessions were not ended on shutdown", n)
	}

	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Error("connections are still accepted after shutdown")
	}
}
