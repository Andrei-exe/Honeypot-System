package main

import (
	"os"
	"time"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
)

func main() {
	s := shipper.NewShipper(os.Stdout)
	s.EmitEvent(models.HoneypotEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		NodeID:    "hp-01",
		EventType: "login_attempt",
		SourceIP:  "203.0.113.5",
		Protocol:  "SSH",
		SessionID: "test-1",
		Credentials: &models.Credentials{
			Username: "root",
			Password: "123456",
			Success:  false,
		},
	})
}
