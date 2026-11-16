package models

import "time"

type HoneypotEvent struct {
	Timestamp      string          `json:"timestamp"`
	NodeID         string          `json:"node_id"`
	EventType      string          `json:"event_type"`
	SourceIP       string          `json:"source_ip"`
	SourcePort     int             `json:"source_port"`
	TargetPort     int             `json:"target_port"`
	Protocol       string          `json:"protocol"`
	SessionID      string          `json:"session_id,omitempty"`
	Credentials    *Credentials    `json:"credentials,omitempty"`
	PayloadDetails *PayloadDetails `json:"payload_details,omitempty"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Success  bool   `json:"success"`
}

type PayloadDetails struct {
	Command       string `json:"command,omitempty"`
	ExtractedURL  string `json:"extracted_url,omitempty"`
	HTTPMethod    string `json:"http_method,omitempty"`
	HTTPPath      string `json:"http_path,omitempty"`
	HTTPUserAgent string `json:"http_user_agent,omitempty"`
	RawData       string `json:"raw_data,omitempty"`
}

// timestampLayout = RFC3339 cu milisecunde
const timestampLayout = "2006-01-02T15:04:05.000Z07:00"

func Now() string {
	return time.Now().UTC().Format(timestampLayout)
}
