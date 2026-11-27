package models

import "time"

// HoneypotEvent is one event sent to the threat-engine (one JSONL line).
// Any field change must also go into shared/event-schema.json.
type HoneypotEvent struct {
	// EventID is unique per event, set by shipper.EmitEvent: a batch sent twice (retry) has the
	// same IDs, so the threat-engine stores it once.
	EventID        string          `json:"event_id,omitempty"`
	Timestamp      string          `json:"timestamp"`
	NodeID         string          `json:"node_id"`
	EventType      string          `json:"event_type"`
	SourceIP       string          `json:"source_ip"`
	SourcePort     int             `json:"source_port"`
	TargetPort     int             `json:"target_port"` // the "persona" port (22/23/80/21), not the one we listen on
	Protocol       string          `json:"protocol"`
	SessionID      string          `json:"session_id,omitempty"`
	Credentials    *Credentials    `json:"credentials,omitempty"`
	PayloadDetails *PayloadDetails `json:"payload_details,omitempty"`
}

// Credentials is set only on login_attempt events.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Success  bool   `json:"success"`
}

// PayloadDetails holds what the attacker sent: commands, URLs, HTTP request data.
type PayloadDetails struct {
	Command       string `json:"command,omitempty"`
	ExtractedURL  string `json:"extracted_url,omitempty"`
	HTTPMethod    string `json:"http_method,omitempty"`
	HTTPPath      string `json:"http_path,omitempty"`
	HTTPUserAgent string `json:"http_user_agent,omitempty"`
	RawData       string `json:"raw_data,omitempty"`
}

// timestampLayout is RFC3339 with milliseconds.
const timestampLayout = "2006-01-02T15:04:05.000Z07:00"

// Now returns the current UTC time as an event timestamp.
// All event timestamps must come from here.
func Now() string {
	return time.Now().UTC().Format(timestampLayout)
}
