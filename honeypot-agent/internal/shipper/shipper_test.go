package shipper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"honeypot-agent/internal/models"
)

// fakeReceiver is a test HTTP server that pretends to be the Python receiver.
// status(n) is the response code for the n-th request (1, 2, 3...).
type fakeReceiver struct {
	mu       sync.Mutex
	requests int
	events   []models.HoneypotEvent
	auth     string
	status   func(n int) int
}

func (f *fakeReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	f.auth = r.Header.Get("Authorization")

	code := f.status(f.requests)
	if code == http.StatusOK {
		var batch []models.HoneypotEvent
		json.NewDecoder(r.Body).Decode(&batch)
		f.events = append(f.events, batch...)
	}
	w.WriteHeader(code)
}

func (f *fakeReceiver) counts() (requests, events int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests, len(f.events)
}

func event(i int) models.HoneypotEvent {
	return models.HoneypotEvent{EventType: "command_exec", NodeID: fmt.Sprint("test-", i), SourceIP: "1.2.3.4"}
}

// waitFor waits until cond() is true, but no longer than max.
func waitFor(max time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}

// All events arrive, in order, with the token in the header.
func TestDeliversAllEventsInOrder(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(int) int { return http.StatusOK }}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "secret")
	for i := 0; i < 120; i++ { // 2 full batches of 50 go right away, the last 20 on the next tick
		s.EmitEvent(event(i))
	}

	if !waitFor(5*time.Second, func() bool { _, n := rcv.counts(); return n == 120 }) {
		_, n := rcv.counts()
		t.Fatalf("%d of 120 events arrived", n)
	}
	for i, e := range rcv.events {
		if e.NodeID != fmt.Sprint("test-", i) {
			t.Fatalf("wrong order at position %d: %s", i, e.NodeID)
		}
	}
	if rcv.auth != "Bearer secret" {
		t.Errorf("header Authorization = %q", rcv.auth)
	}
}

// If the receiver answers with an error (5xx), the shipper retries and loses nothing.
func TestRetriesAfterServerError(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(n int) int {
		if n == 1 {
			return http.StatusInternalServerError // the first request "crashes"
		}
		return http.StatusOK
	}}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "")
	for i := 0; i < 10; i++ {
		s.EmitEvent(event(i))
	}

	if !waitFor(12*time.Second, func() bool { _, n := rcv.counts(); return n == 10 }) {
		req, n := rcv.counts()
		t.Fatalf("after the retry %d of 10 events arrived (%d requests)", n, req)
	}
}

// On 4xx (e.g. wrong token) the same batch is NOT resent forever.
func TestGivesUpOnClientError(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(int) int { return http.StatusUnauthorized }}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "wrong-token")
	for i := 0; i < 10; i++ {
		s.EmitEvent(event(i))
	}

	waitFor(4*time.Second, func() bool { req, _ := rcv.counts(); return req >= 1 })
	time.Sleep(3 * time.Second) // one more tick: a retry would show up as a second request
	if req, _ := rcv.counts(); req != 1 {
		t.Fatalf("sent the same rejected batch %d times (should be once)", req)
	}
}

// Close sends right away what is still waiting (without it, the last events would wait for the
// next 2s tick, and on docker stop they would be lost).
func TestCloseSendsPendingEvents(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(int) int { return http.StatusOK }}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "")
	for i := 0; i < 10; i++ { // fewer than batchSize: normally they would wait for the tick
		s.EmitEvent(event(i))
	}
	start := time.Now()
	s.Close(3 * time.Second)

	if _, n := rcv.counts(); n != 10 {
		t.Fatalf("after Close %d of 10 events arrived", n)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Close took %v (should send right away)", d)
	}
}

// If the receiver is down, Close gives up at the deadline instead of hanging.
func TestCloseGivesUpAtDeadline(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(int) int { return http.StatusServiceUnavailable }}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "")
	s.EmitEvent(event(1))
	start := time.Now()
	s.Close(time.Second)

	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Close took %v with the receiver down (the limit was 1s)", d)
	}
	if req, _ := rcv.counts(); req < 1 {
		t.Fatal("Close did not even try to send")
	}
}

// On shutdown a rejected batch (4xx) is not retried until the deadline: same answer every time.
func TestCloseDoesNotRetryRejected(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(int) int { return http.StatusUnauthorized }}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "wrong-token")
	s.EmitEvent(event(1))
	start := time.Now()
	s.Close(3 * time.Second)

	if d := time.Since(start); d > time.Second {
		t.Errorf("Close took %v (a rejected batch should be dropped at once)", d)
	}
	if req, _ := rcv.counts(); req != 1 {
		t.Errorf("sent the rejected batch %d times (should be once)", req)
	}
}

// Shell characters stay readable in JSONL (by default json.Encoder writes < > & as unicode escapes).
func TestJSONLKeepsShellCharacters(t *testing.T) {
	var out bytes.Buffer
	s := NewShipper(&out, "", "")
	e := event(1)
	e.PayloadDetails = &models.PayloadDetails{Command: "cat /proc/cpuinfo > /tmp/x && echo <ok>"}
	s.EmitEvent(e)

	if !strings.Contains(out.String(), `"command":"cat /proc/cpuinfo > /tmp/x && echo <ok>"`) {
		t.Fatalf("command escaped in JSONL: %s", out.String())
	}
}

// Without a URL there is no sender goroutine: Close returns at once and doesn't panic.
func TestCloseWithoutURL(t *testing.T) {
	s := NewShipper(io.Discard, "", "")
	s.EmitEvent(event(1))
	s.Close(time.Second)
}

// Without a URL, everything goes to JSONL only.
func TestWithoutURLOnlyWritesJSONL(t *testing.T) {
	var out bytes.Buffer
	s := NewShipper(&out, "", "")
	s.EmitEvent(event(1))
	s.EmitEvent(event(2))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"node_id":"test-1"`) {
		t.Fatalf("wrong JSONL: %q", out.String())
	}
}
