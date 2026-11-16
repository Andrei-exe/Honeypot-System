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

// fakeReceiver = un server HTTP de test care se preface ca e receptorul de Python.
// status(n) zice ce raspunde la a n-a cerere (1, 2, 3...).
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

// waitFor asteapta pana cand cond() e adevarat, dar nu mai mult de max.
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

// Toate evenimentele ajung, in ordine, cu token-ul in header.
func TestDeliversAllEventsInOrder(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(int) int { return http.StatusOK }}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "secret")
	for i := 0; i < 120; i++ { // 2 grupuri pline de 50 pleaca imediat, restul de 20 la urmatorul tick
		s.EmitEvent(event(i))
	}

	if !waitFor(5*time.Second, func() bool { _, n := rcv.counts(); return n == 120 }) {
		_, n := rcv.counts()
		t.Fatalf("au ajuns %d evenimente din 120", n)
	}
	for i, e := range rcv.events {
		if e.NodeID != fmt.Sprint("test-", i) {
			t.Fatalf("ordine gresita la pozitia %d: %s", i, e.NodeID)
		}
	}
	if rcv.auth != "Bearer secret" {
		t.Errorf("header Authorization = %q", rcv.auth)
	}
}

// Daca Python-ul raspunde cu eroare (5xx), shipper-ul reincearca si nu pierde nimic.
func TestRetriesAfterServerError(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(n int) int {
		if n == 1 {
			return http.StatusInternalServerError // prima data "crapa"
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
		t.Fatalf("dupa reincercare au ajuns %d evenimente din 10 (%d cereri)", n, req)
	}
}

// La 4xx (ex: token gresit) NU retrimitem acelasi grup la infinit.
func TestGivesUpOnClientError(t *testing.T) {
	t.Parallel()
	rcv := &fakeReceiver{status: func(int) int { return http.StatusUnauthorized }}
	srv := httptest.NewServer(rcv)
	defer srv.Close()

	s := NewShipper(io.Discard, srv.URL, "parola-gresita")
	for i := 0; i < 10; i++ {
		s.EmitEvent(event(i))
	}

	waitFor(4*time.Second, func() bool { req, _ := rcv.counts(); return req >= 1 })
	time.Sleep(3 * time.Second) // inca un tick: daca ar reincerca, am vedea a doua cerere
	if req, _ := rcv.counts(); req != 1 {
		t.Fatalf("a trimis de %d ori acelasi grup refuzat (trebuia o singura data)", req)
	}
}

// Fara URL: totul merge doar in JSONL, ca inainte.
func TestWithoutURLOnlyWritesJSONL(t *testing.T) {
	var out bytes.Buffer
	s := NewShipper(&out, "", "")
	s.EmitEvent(event(1))
	s.EmitEvent(event(2))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"node_id":"test-1"`) {
		t.Fatalf("JSONL gresit: %q", out.String())
	}
}
