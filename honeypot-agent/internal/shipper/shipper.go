package shipper

import (
	"encoding/json"
	"io"
	"sync"

	"honeypot-agent/internal/models"
)

type Shipper struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewShipper(out io.Writer) *Shipper {
	return &Shipper{enc: json.NewEncoder(out)}
}

func (s *Shipper) EmitEvent(e models.HoneypotEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enc.Encode(e)
}
