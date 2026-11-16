package shipper

import (
	"bytes"
	"encoding/json"
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
)

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
}

// NewShipper writes JSONL to out; url is where batches are POSTed ("" = nowhere).
func NewShipper(out io.Writer, url, token string) *Shipper {
	s := &Shipper{enc: json.NewEncoder(out)}
	if url == "" {
		log.Println("shipper: SHIPPER_URL nu e setat -> evenimentele merg doar pe stdout")
		return s
	}

	s.url = url
	s.token = token
	s.client = &http.Client{Timeout: 5 * time.Second}
	s.queue = make(chan models.HoneypotEvent, queueSize)
	go s.run() // sender goroutine, separate from the services
	log.Println("shipper: trimit evenimentele la", url)
	return s
}

// EmitEvent is called by the services and never waits on the network:
// it writes the JSONL line, queues the event and returns immediately.
func (s *Shipper) EmitEvent(e models.HoneypotEvent) {
	s.mu.Lock()
	s.enc.Encode(e)
	s.mu.Unlock()

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

// run loops forever in its own goroutine: it collects queued events and sends them in batches.
func (s *Shipper) run() {
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()

	var batch []models.HoneypotEvent
	var retryAt time.Time // after a failure, don't try again before this
	down := false         // so the same error isn't logged on every attempt

	for {
		select {
		case e := <-s.queue:
			batch = append(batch, e)
			if len(batch) > maxPending {
				batch = batch[1:] // drop the oldest (it's still in JSONL)
				s.dropped.Add(1)
			}
			if len(batch) < batchSize {
				continue // wait, more may come
			}

		case <-ticker.C:
			if n := s.dropped.Swap(0); n > 0 {
				log.Printf("shipper: %d evenimente n-au ajuns la Python (sunt doar in JSONL)", n)
			}
		}

		if len(batch) == 0 || time.Now().Before(retryAt) {
			continue
		}

		if err := s.send(batch); err != nil {
			if !down {
				log.Printf("shipper: nu pot trimite (%v) - pastrez evenimentele si reincerc la fiecare %v", err, retryAfter)
				down = true
			}
			retryAt = time.Now().Add(retryAfter)
			continue
		}
		if down {
			log.Printf("shipper: merge din nou, am trimis %d evenimente", len(batch))
			down = false
		}
		batch = nil
	}
}

// send POSTs a batch as a JSON array.
// It returns an error only when retrying makes sense (network down, 5xx).
func (s *Shipper) send(batch []models.HoneypotEvent) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
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
		// 4xx = the request itself is wrong (token, format, path).
		// Resending would get the same answer -> drop this batch.
		log.Printf("shipper: serverul a refuzat %d evenimente: %s", len(batch), resp.Status)
		return nil
	}
	return fmt.Errorf("serverul a raspuns %s", resp.Status) // 5xx -> their problem, retry
}
