package services

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"honeypot-agent/internal/models"
)

// Helpers shared by the service tests (only compiled by `go test`, like every _test.go file).

// serveOne listens on a free local port and runs handle for exactly one connection.
// done is closed when handle has returned, so by then every event of the session is written.
func serveOne(t *testing.T, handle func(net.Conn)) (addr string, done <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0") // :0 = any free port
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		handle(conn)
	}()
	return listener.Addr().String(), finished
}

// waitDone waits until a handler started with serveOne has returned.
func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not return")
	}
}

// readUntil reads until the text received so far ends with marker (e.g. a prompt) and returns it.
// The caller sets a deadline on the connection, so a missing marker fails instead of hanging.
func readUntil(t *testing.T, r *bufio.Reader, marker string) string {
	t.Helper()
	var got []byte
	for !bytes.HasSuffix(got, []byte(marker)) {
		b, err := r.ReadByte()
		if err != nil {
			t.Fatalf("waiting for %q, got only %q: %v", marker, got, err)
		}
		got = append(got, b)
	}
	return string(got)
}

// parseEvents turns the shipper's JSONL into events and checks every line against
// shared/event-schema.json: a field or value the Python side doesn't know fails the test.
func parseEvents(t *testing.T, jsonl string) []models.HoneypotEvent {
	t.Helper()
	schema := loadSchema(t)

	var events []models.HoneypotEvent
	for _, line := range strings.Split(jsonl, "\n") {
		if line == "" {
			continue
		}
		var raw map[string]any // as a map, to see the exact JSON keys
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatalf("not valid JSON: %q: %v", line, err)
		}
		checkSchema(t, schema, raw)

		var event models.HoneypotEvent
		json.Unmarshal([]byte(line), &event)
		events = append(events, event)
	}
	return events
}

// eventSchema is the part of shared/event-schema.json the tests check.
type eventSchema struct {
	Required   []string `json:"required"`
	Properties map[string]struct {
		Enum       []string       `json:"enum"`       // allowed values (event_type, protocol)
		Properties map[string]any `json:"properties"` // sub-fields (credentials, payload_details)
	} `json:"properties"`
}

func loadSchema(t *testing.T) eventSchema {
	t.Helper()
	// `go test` runs in the package folder: honeypot-agent/internal/services
	data, err := os.ReadFile("../../../shared/event-schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema eventSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func checkSchema(t *testing.T, schema eventSchema, event map[string]any) {
	t.Helper()
	for _, name := range schema.Required {
		if _, ok := event[name]; !ok {
			t.Errorf("required field %q is missing: %v", name, event)
		}
	}
	for name, value := range event {
		field, ok := schema.Properties[name]
		if !ok {
			t.Errorf("field %q is not in event-schema.json", name)
			continue
		}
		if text, isText := value.(string); isText && len(field.Enum) > 0 && !slices.Contains(field.Enum, text) {
			t.Errorf("%s = %q is not allowed by event-schema.json (allowed: %v)", name, text, field.Enum)
		}
		if object, isObject := value.(map[string]any); isObject {
			for sub := range object {
				if _, ok := field.Properties[sub]; !ok {
					t.Errorf("field %s.%s is not in event-schema.json", name, sub)
				}
			}
		}
	}
}

// checkSession checks what every session must look like: session_start first, session_end last,
// and all events with the same session_id, protocol, persona port and the client's IP.
func checkSession(t *testing.T, events []models.HoneypotEvent, protocol string, targetPort int) {
	t.Helper()
	if len(events) < 2 {
		t.Fatalf("only %d events: %+v", len(events), events)
	}
	if events[0].EventType != "session_start" {
		t.Errorf("first event: %q (expected session_start)", events[0].EventType)
	}
	if last := events[len(events)-1]; last.EventType != "session_end" {
		t.Errorf("last event: %q (expected session_end)", last.EventType)
	}
	for _, e := range events {
		if e.SessionID == "" || e.SessionID != events[0].SessionID {
			t.Errorf("%s: session_id %q (expected %q)", e.EventType, e.SessionID, events[0].SessionID)
		}
		if e.Protocol != protocol || e.TargetPort != targetPort {
			t.Errorf("%s: %s/%d (expected %s/%d)", e.EventType, e.Protocol, e.TargetPort, protocol, targetPort)
		}
		if e.SourceIP != "127.0.0.1" || e.SourcePort == 0 {
			t.Errorf("%s: source %s:%d (expected 127.0.0.1 and the client's port)", e.EventType, e.SourceIP, e.SourcePort)
		}
	}
}

// ofType returns the events with the given event_type, in order.
func ofType(events []models.HoneypotEvent, eventType string) []models.HoneypotEvent {
	var result []models.HoneypotEvent
	for _, e := range events {
		if e.EventType == eventType {
			result = append(result, e)
		}
	}
	return result
}
