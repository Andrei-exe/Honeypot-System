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
	queueSize  = 1000            // cate evenimente pot astepta in channel
	batchSize  = 50              // trimitem imediat ce se strang atatea...
	flushEvery = 2 * time.Second // ...sau la fiecare 2 secunde, cate s-au strans
	retryAfter = 5 * time.Second // dupa un esec, asteptam atat pana reincercam
	maxPending = 5000            // daca Python-ul e picat mult timp, nu tinem in RAM mai mult de atat
)

type Shipper struct {
	mu  sync.Mutex
	enc *json.Encoder // copia de rezerva: JSONL pe stdout (merge mereu, si fara Python)

	url     string
	token   string
	client  *http.Client
	queue   chan models.HoneypotEvent // "coada" dintre servicii si goroutine-ul care trimite
	dropped atomic.Int64              // evenimente care n-au ajuns la Python (sunt doar in JSONL)
}

// NewShipper: out = unde scriem JSONL-ul (stdout); url = unde trimitem prin HTTP ("" = nicaieri).
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
	go s.run() // goroutine-ul care trimite, separat de servicii
	log.Println("shipper: trimit evenimentele la", url)
	return s
}

// EmitEvent e chemat de servicii. NU asteapta niciodata dupa retea:
// scrie JSONL-ul si pune evenimentul in coada, apoi se intoarce imediat.
func (s *Shipper) EmitEvent(e models.HoneypotEvent) {
	s.mu.Lock()
	s.enc.Encode(e)
	s.mu.Unlock()

	if s.queue == nil {
		return // fara URL: doar JSONL
	}

	select {
	case s.queue <- e:
		// a intrat in coada
	default:
		// coada e plina (Python-ul e picat de mult) -> nu blocam serviciul, il numaram si mergem mai departe
		s.dropped.Add(1)
	}
}

// run ruleaza la infinit in goroutine-ul lui: strange evenimente din coada si le trimite in grupuri.
func (s *Shipper) run() {
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()

	var batch []models.HoneypotEvent
	var retryAt time.Time // dupa un esec, nu mai incercam pana atunci
	down := false         // ca sa nu scriem aceeasi eroare la fiecare incercare

	for {
		select {
		case e := <-s.queue:
			batch = append(batch, e)
			if len(batch) > maxPending {
				batch = batch[1:] // il aruncam pe cel mai vechi (e oricum in JSONL)
				s.dropped.Add(1)
			}
			if len(batch) < batchSize {
				continue // mai asteptam, poate mai vin
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

// send trimite un grup de evenimente ca array JSON.
// Intoarce eroare DOAR daca merita reincercat (retea picata, 5xx).
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
		return err // Python-ul e picat sau nu raspunde in 5 secunde
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024)) // citim raspunsul ca sa se poata refolosi conexiunea

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// 4xx = "nu-mi place ce mi-ai trimis" (token gresit, format gresit, cale gresita).
		// Daca retrimitem acelasi lucru, primim acelasi raspuns -> renuntam la grupul asta.
		log.Printf("shipper: serverul a refuzat %d evenimente: %s", len(batch), resp.Status)
		return nil
	}
	return fmt.Errorf("serverul a raspuns %s", resp.Status) // 5xx -> problema la ei, reincercam
}
