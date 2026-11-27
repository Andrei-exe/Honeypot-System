package shipper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"honeypot-agent/internal/models"
)

// fakeReceiver is a test HTTP server that pretends to be the Python receiver.
// status(n) is the response code for the n-th request (1, 2, 3...).
type fakeReceiver struct {
	mu        sync.Mutex
	requests  int
	events    []models.HoneypotEvent
	sizes     []int      // events in each accepted POST
	tried     [][]string // event IDs of every POST, accepted or not
	auth      string
	status    func(n int) int
	slowFirst time.Duration // the first request takes this long to answer (events pile up meanwhile)
}

func (f *fakeReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	f.auth = r.Header.Get("Authorization")

	var batch []models.HoneypotEvent
	json.NewDecoder(r.Body).Decode(&batch)
	var ids []string
	for _, e := range batch {
		ids = append(ids, e.EventID)
	}
	f.tried = append(f.tried, ids)

	code := f.status(f.requests)
	if code == http.StatusOK {
		f.events = append(f.events, batch...)
		f.sizes = append(f.sizes, len(batch))
	}
	if f.requests == 1 {
		time.Sleep(f.slowFirst)
	}
	w.WriteHeader(code)
}

func (f *fakeReceiver) counts() (requests, events int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests, len(f.events)
}

// checkReceived checks that the receiver got exactly the events first, first+1, ... first+n-1, in
// order, and returns how many were in each accepted POST.
func checkReceived(t *testing.T, f *fakeReceiver, first, n int) []int {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) != n {
		t.Fatalf("%d events arrived (expected %d)", len(f.events), n)
	}
	for i, e := range f.events {
		if want := fmt.Sprint("test-", first+i); e.NodeID != want {
			t.Fatalf("position %d: %s (expected %s)", i, e.NodeID, want)
		}
	}
	return f.sizes
}

// checkPOSTSizes: no POST over 200 events (receiver.py refuses a body over 32MB, see maxPerPOST).
// 200 is written here, not taken from maxPerPOST, so a changed constant fails the test too.
func checkPOSTSizes(t *testing.T, sizes []int) {
	t.Helper()
	for _, n := range sizes {
		if n > 200 {
			t.Errorf("a POST with %d events (at most 200): %v", n, sizes)
		}
	}
}

// After the receiver was down, the backlog goes in several POSTs of at most 200 events, in order,
// nothing lost (one POST with all of it could go over the receiver's limit and lose everything).
func TestBacklogGoesInParts(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(n int) int {
		if n == 1 {
			return http.StatusServiceUnavailable // down: the events wait in RAM
		}
		return http.StatusOK
	}}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "")
	for i := 0; i < 450; i++ {
		s.EmitEvent(event(i))
	}
	waitFor(2*time.Second, func() bool { req, _ := rcv.counts(); return req >= 1 }) // the first POST failed
	s.Close(5 * time.Second)                                                        // the backlog goes now

	sizes := checkReceived(t, rcv, 0, 450)
	checkPOSTSizes(t, sizes)
	if len(sizes) < 3 {
		t.Errorf("450 events in %d POSTs: %v", len(sizes), sizes)
	}
}

// Under load, what is already waiting in the queue goes in the same POST: fewer, bigger POSTs
// (each one costs the receiver a request), still at most 200 events and in order.
func TestBiggerPOSTsUnderLoad(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(int) int { return http.StatusOK }, slowFirst: 300 * time.Millisecond}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "")
	for i := 0; i < 450; i++ { // the first 50 go, the other 400 wait for the slow answer
		s.EmitEvent(event(i))
	}
	if !waitFor(5*time.Second, func() bool { _, n := rcv.counts(); return n == 450 }) {
		_, n := rcv.counts()
		t.Fatalf("%d of 450 events arrived", n)
	}
	sizes := checkReceived(t, rcv, 0, 450)
	checkPOSTSizes(t, sizes)
	if slices.Max(sizes) <= 50 {
		t.Errorf("no POST took more than the 50 of a normal batch: %v", sizes)
	}
}

// A part the receiver refuses (4xx, e.g. 413 Request Entity Too Large) is dropped alone: the parts
// after it still go.
func TestRejectedPartDoesNotDropTheRest(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(n int) int {
		switch n {
		case 1:
			return http.StatusServiceUnavailable // down: a backlog builds up
		case 2:
			return http.StatusRequestEntityTooLarge // its first part is refused
		}
		return http.StatusOK
	}}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "")
	for i := 0; i < 450; i++ {
		s.EmitEvent(event(i))
	}
	waitFor(2*time.Second, func() bool { req, _ := rcv.counts(); return req >= 1 })
	s.Close(5 * time.Second)

	checkReceived(t, rcv, 200, 250) // events 0-199 were the refused part, 200-449 arrived
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
	for i := 0; i < 120; i++ { // the first 50 start a send; what already waits in the queue goes too
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

// Every event gets its own event_id (16 hex, the format receiver.py accepts), given once: a batch
// resent after a failure and the JSONL copy carry the same IDs, so the threat-engine can drop the
// second copy (a POST over 5s is resent even if the receiver already stored it).
func TestEventIDs(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(n int) int {
		if n == 1 {
			return http.StatusServiceUnavailable // the first try fails: the same batch goes again
		}
		return http.StatusOK
	}}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	var out bytes.Buffer
	s := NewShipper(&out, srv.URL, "")
	for i := 0; i < 10; i++ {
		s.EmitEvent(event(i)) // the same struct values a service could send: the ID comes from EmitEvent
	}
	// fewer than batchSize: the first try comes at the 2s tick
	if !waitFor(4*time.Second, func() bool { req, _ := rcv.counts(); return req >= 1 }) {
		t.Fatal("no first try")
	}
	s.Close(5 * time.Second) // the resend

	checkReceived(t, rcv, 0, 10)
	var delivered []string
	seen := map[string]bool{}
	for _, e := range rcv.events {
		if len(e.EventID) != 16 || strings.Trim(e.EventID, "0123456789abcdef") != "" {
			t.Errorf("event_id %q: expected 16 hex characters", e.EventID)
		}
		if seen[e.EventID] {
			t.Errorf("event_id %q given twice", e.EventID)
		}
		seen[e.EventID] = true
		delivered = append(delivered, e.EventID)
	}

	if len(rcv.tried) < 2 || !slices.Equal(rcv.tried[0], delivered) {
		t.Errorf("the resend has other IDs:\nfirst try %v\ndelivered %v", rcv.tried, delivered)
	}
	var copied []string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var e models.HoneypotEvent
		json.Unmarshal([]byte(line), &e)
		copied = append(copied, e.EventID)
	}
	if !slices.Equal(copied, delivered) {
		t.Errorf("the JSONL copy has other IDs:\nJSONL     %v\ndelivered %v", copied, delivered)
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
