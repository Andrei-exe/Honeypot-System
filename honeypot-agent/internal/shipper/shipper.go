package shipper

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"honeypot-agent/internal/models"
)

const (
	queueSize  = 1000            // events that can wait in the channel
	batchSize  = 50              // send as soon as this many have gathered...
	flushEvery = 2 * time.Second // ...or every 2 seconds, with whatever is there
	retryAfter = 5 * time.Second // wait this long after a failed send
	maxPending = 5000            // cap kept in RAM while the receiver is down

	// maxPerPOST caps one POST. An event is at most ~96KB of JSON (12KB of HTTP headers + 4KB of body,
	// every byte escaped to 6), so a POST stays under ~19MB: below receiver.py's 32MB limit (over it,
	// a 413 would drop the whole POST), cheap to marshal, and quick for the receiver to process (a
	// POST that takes over 5s is resent, and the receiver would store it twice).
	maxPerPOST = 200
)

// errRejected means the receiver answered 4xx: the request itself is wrong (token, format, path),
// so resending the same batch would get the same answer.
var errRejected = errors.New("rejected by the threat-engine")

// Shipper writes every event as JSONL and, if a URL is set, POSTs it to the threat-engine
// in batches. Services only call EmitEvent; one background goroutine (run) does the network work.
type Shipper struct {
	mu  sync.Mutex
	enc *json.Encoder // backup copy: JSONL on stdout (works even without the receiver)

	url     string
	token   string
	client  *http.Client
	queue   chan models.HoneypotEvent // buffer between the services and the sender goroutine
	dropped atomic.Int64              // events that never reached the receiver (only in JSONL)

	quit chan time.Time // Close sends here the deadline for the last send
	done chan struct{}  // closed by run when it has finished
}

// NewShipper writes JSONL to out; url is where batches are POSTed ("" = nowhere).
func NewShipper(out io.Writer, url, token string) *Shipper {
	s := &Shipper{enc: json.NewEncoder(out)}
	s.enc.SetEscapeHTML(false) // keep < > & as they are (by default they become unicode escapes), shell commands stay readable
	if url == "" {
		log.Println("shipper: SHIPPER_URL is not set -> events go to stdout only")
		return s
	}

	s.url = url
	s.token = token
	s.client = &http.Client{Timeout: 5 * time.Second}
	s.queue = make(chan models.HoneypotEvent, queueSize)
	s.quit = make(chan time.Time)
	s.done = make(chan struct{})
	go s.run() // sender goroutine, separate from the services
	log.Println("shipper: sending events to", url)
	return s
}

// EmitEvent is called by the services and never waits on the network:
// it writes the JSONL line, queues the event and returns immediately.
func (s *Shipper) EmitEvent(e models.HoneypotEvent) {
	// the ID is given here, once: every resend of the event and its JSONL copy carry the same one
	e.EventID = newEventID()

	func() {
		s.mu.Lock()
		defer s.mu.Unlock() // even if Encode panicked: a session's recovered panic must not leave it locked
		s.enc.Encode(e)
	}()

	if s.queue == nil {
		return // no URL: JSONL only
	}

	select {
	case s.queue <- e:
		// queued
	default:
		// queue full (receiver down for a long time) -> don't block the service, just count it
		s.dropped.Add(1)
	}
}

// newEventID returns 8 random bytes as 16 hex characters (like the session IDs).
func newEventID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Close sends the events still waiting and stops the sender goroutine, giving up after timeout.
// Call it only after the services have stopped, so their last events (session_end) are queued.
// The queue is never closed: a late EmitEvent can't panic, its event only stays in JSONL.
func (s *Shipper) Close(timeout time.Duration) {
	if s.queue == nil {
		return // no URL: there is nothing to send
	}
	s.quit <- time.Now().Add(timeout)
	<-s.done
}

// run loops in its own goroutine until Close: it collects queued events and sends them in batches.
func (s *Shipper) run() {
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()

	var batch []models.HoneypotEvent
	var retryAt time.Time // after a failure, don't try again before this
	down := false         // so the same error isn't logged on every attempt

	for {
		select {
		case deadline := <-s.quit:
			s.flush(batch, deadline)
			close(s.done)
			return

		case e := <-s.queue:
			batch = s.add(batch, e)
			if len(batch) < batchSize {
				continue // wait, more may come
			}

		case <-ticker.C:
			if n := s.dropped.Swap(0); n > 0 {
				log.Printf("shipper: %d events did not reach the threat-engine (they are only in JSONL)", n)
			}
		}

		if len(batch) == 0 || time.Now().Before(retryAt) {
			continue
		}

		// what is already waiting in the queue goes now too: under load, fewer and bigger POSTs
		batch = s.takeQueued(batch)
		rest, sent, err := s.sendInParts(context.Background(), batch)
		batch = rest
		if err != nil {
			if !down {
				log.Printf("shipper: cannot send (%v) - keeping the events, retrying every %v", err, retryAfter)
				down = true
			}
			retryAt = time.Now().Add(retryAfter)
			continue
		}
		if down && sent > 0 { // not after a 4xx: those events were dropped, not sent
			log.Printf("shipper: working again, sent %d events", sent)
		}
		down = false // it answered, so it is not down
	}
}

// add appends e to batch. Over maxPending the oldest event is dropped (it's still in JSONL).
func (s *Shipper) add(batch []models.HoneypotEvent, e models.HoneypotEvent) []models.HoneypotEvent {
	batch = append(batch, e)
	if len(batch) > maxPending {
		batch[0] = models.HoneypotEvent{} // so its strings can be freed (the array still holds them)
		batch = batch[1:]
		s.dropped.Add(1)
	}
	return batch
}

// takeQueued adds to batch the events already waiting in the queue, without waiting for more.
func (s *Shipper) takeQueued(batch []models.HoneypotEvent) []models.HoneypotEvent {
	for {
		select {
		case e := <-s.queue:
			batch = s.add(batch, e)
		default: // the queue is empty
			return batch
		}
	}
}

// sendInParts sends batch in POSTs of at most maxPerPOST events, oldest first. A part the receiver
// rejects (4xx) is dropped and logged, and the next parts still go. On a network error or 5xx it
// stops and returns the events not sent yet (rest), to retry later. sent = events the receiver took.
func (s *Shipper) sendInParts(ctx context.Context, batch []models.HoneypotEvent) (rest []models.HoneypotEvent, sent int, err error) {
	for len(batch) > 0 {
		n := min(len(batch), maxPerPOST)
		err = s.send(ctx, batch[:n])
		switch {
		case errors.Is(err, errRejected):
			log.Printf("shipper: %d events %v - dropped, they are only in JSONL", n, err)
		case err != nil:
			return batch, sent, err
		default:
			sent += n
		}
		clear(batch[:n]) // like in add: the array would keep the done events' strings alive
		batch = batch[n:]
	}
	return nil, sent, nil
}

// flush is the last send, on shutdown: the batch plus everything still in the queue, in parts,
// retried every half second until it works or the deadline passes.
func (s *Shipper) flush(batch []models.HoneypotEvent, deadline time.Time) {
	batch = s.takeQueued(batch) // the services have stopped, so nothing new comes in
	if len(batch) == 0 {
		return
	}

	// the request itself is cut off at the deadline too
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	total := 0
	for {
		rest, sent, err := s.sendInParts(ctx, batch)
		total += sent
		if err == nil {
			if total > 0 {
				log.Printf("shipper: shutdown: sent the last %d events", total)
			}
			return
		}
		batch = rest
		if time.Until(deadline) < 500*time.Millisecond {
			log.Printf("shipper: shutdown: %d events did not reach the threat-engine (%v) - they are only in JSONL", len(batch), err)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// send POSTs a batch as a JSON array; ctx can cut the request short.
// Errors: errRejected (4xx, don't resend) or anything else (network down, 5xx: retry later).
func (s *Shipper) send(ctx context.Context, batch []models.HoneypotEvent) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err // receiver is down or didn't answer within 5 seconds
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024)) // drain the body so the connection can be reused

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Errorf("%w (%s)", errRejected, resp.Status)
	}
	return fmt.Errorf("the server answered %s", resp.Status) // 5xx -> their problem, retry
}
