package services

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"honeypot-agent/internal/shipper"
)

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
