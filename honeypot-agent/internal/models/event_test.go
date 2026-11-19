package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Timestamps: RFC3339, UTC ("Z") and always exactly 3 decimals, so Python can parse them and
// they sort correctly even as plain text.
func TestNowFormat(t *testing.T) {
	ts := Now()
	if len(ts) != len("2006-01-02T15:04:05.000Z") || !strings.HasSuffix(ts, "Z") {
		t.Fatalf("timestamp %q: expected UTC with milliseconds, like 2006-01-02T15:04:05.000Z", ts)
	}
	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t.Fatalf("timestamp %q is not RFC3339: %v", ts, err)
	}
	if d := time.Since(parsed); d < 0 || d > time.Minute {
		t.Errorf("timestamp %q is not the current time", ts)
	}
}

// The JSON the threat-engine receives: optional fields are left out (omitempty), but a failed
// login with an EMPTY password keeps "password": "" and "success": false (both mean something).
func TestEventJSON(t *testing.T) {
	start := HoneypotEvent{
		Timestamp: "2026-11-19T10:00:00.000Z", NodeID: "ssh-01", EventType: "session_start",
		SourceIP: "203.0.113.7", SourcePort: 40000, TargetPort: 22, Protocol: "SSH", SessionID: "abc",
	}
	got, _ := json.Marshal(start)
	want := `{"timestamp":"2026-11-19T10:00:00.000Z","node_id":"ssh-01","event_type":"session_start",` +
		`"source_ip":"203.0.113.7","source_port":40000,"target_port":22,"protocol":"SSH","session_id":"abc"}`
	if string(got) != want {
		t.Errorf("session_start:\n got %s\nwant %s", got, want)
	}

	login := start
	login.EventType = "login_attempt"
	login.Credentials = &Credentials{Username: "admin", Password: "", Success: false}
	got, _ = json.Marshal(login)
	if !strings.Contains(string(got), `"credentials":{"username":"admin","password":"","success":false}`) {
		t.Errorf("login_attempt with an empty password: %s", got)
	}
}
