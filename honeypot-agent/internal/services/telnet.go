package services

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
	"honeypot-agent/internal/vfs"
)

// Telnet protocol bytes (RFC 854). Every Telnet command starts with IAC (255).
const (
	telnetIAC     = 255 // "Interpret As Command"
	telnetDONT    = 254
	telnetDO      = 253
	telnetWONT    = 252
	telnetWILL    = 251
	telnetSB      = 250 // subnegotiation begin
	telnetSE      = 240 // subnegotiation end
	telnetOptEcho = 1   // ECHO option
)

const (
	telnetIdleTimeout   = 60 * time.Second
	telnetMaxLine       = 1024
	telnetMaxLoginTries = 3
	telnetMaxCommands   = 50
)

// RunTelnet serves a fake BusyBox telnetd on address until ctx is cancelled.
// Returns nil after a clean shutdown, or an error if it fails (usually the port is in use).
func RunTelnet(ctx context.Context, address string, nodeID string, shipper *shipper.Shipper) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	listener = limitConnections(listener, "TELNET")
	defer listener.Close()

	log.Println("TELNET node running")
	return serve(ctx, listener, func(conn net.Conn) { handleTelnet(conn, nodeID, shipper) })
}

// handleTelnet runs one Telnet session: login prompt, then the fake shell.
func handleTelnet(conn net.Conn, nodeID string, shipper *shipper.Shipper) {
	defer conn.Close()

	ip, portText, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		ip = conn.RemoteAddr().String()
	}
	port, _ := strconv.Atoi(portText)

	sessionID := newSessionID()

	// newEvent fills in the fields shared by every event of this session
	newEvent := func(eventType string) models.HoneypotEvent {
		return models.HoneypotEvent{
			Timestamp:  models.Now(),
			NodeID:     nodeID,
			EventType:  eventType,
			SourceIP:   ip,
			SourcePort: port,
			TargetPort: 23,
			Protocol:   "TELNET",
			SessionID:  sessionID,
		}
	}

	shipper.EmitEvent(newEvent("session_start"))
	// wrapped in func() so the timestamp is taken at the end, not now
	defer func() { shipper.EmitEvent(newEvent("session_end")) }()

	reader := &telnetReader{conn: conn, r: bufio.NewReader(conn)}

	// ---------- Phase 1: login ----------
	fmt.Fprint(conn, "\r\nGateway Linux 4.14\r\n\r\n")
	loggedIn := false
	for try := 1; try <= telnetMaxLoginTries; try++ {
		fmt.Fprint(conn, "gateway login: ")
		user, err := reader.readLine()
		if err != nil {
			return
		}

		// WILL ECHO = the client stops echoing what it types -> hidden password
		conn.Write([]byte{telnetIAC, telnetWILL, telnetOptEcho})
		fmt.Fprint(conn, "Password: ")
		pass, err := reader.readLine()
		conn.Write([]byte{telnetIAC, telnetWONT, telnetOptEcho})
		fmt.Fprint(conn, "\r\n")
		if err != nil {
			return
		}

		success := weakCredentials[user+":"+pass]

		event := newEvent("login_attempt")
		event.Credentials = &models.Credentials{
			Username: user,
			Password: pass,
			Success:  success,
		}
		shipper.EmitEvent(event)

		if success {
			loggedIn = true
			break
		}
		time.Sleep(time.Second) // real logins also delay after a failure
		fmt.Fprint(conn, "Login incorrect\r\n")
	}
	if !loggedIn {
		return
	}

	// ---------- Phase 2: fake shell ----------
	sh := vfs.NewShell() // one shell per connection (its own cwd and files)
	fmt.Fprint(conn, toCRLF(vfs.Banner))
	for i := 0; i < telnetMaxCommands; i++ {
		fmt.Fprint(conn, sh.Prompt())
		line, err := reader.readLine()
		if err != nil {
			return
		}

		output, exit := runShellLine(sh, line, newEvent, shipper)
		fmt.Fprint(conn, toCRLF(output))
		if exit {
			return
		}
	}
}

// toCRLF converts the shell's \n line endings to the \r\n that Telnet expects.
func toCRLF(text string) string {
	return strings.ReplaceAll(text, "\n", "\r\n")
}

// telnetReader reads lines from a Telnet client and drops Telnet commands (IAC ...).
// It's a struct, not a plain function, because it must remember lastCR between lines.
type telnetReader struct {
	conn net.Conn
	r    *bufio.Reader

	// Enter is "\r\n" or "\r\0", and the two bytes may arrive in separate packets.
	// lastCR = the previous line ended with \r, so a \n or \0 right after it is dropped.
	lastCR bool
}

// readLine reads one line, without the trailing Enter.
func (t *telnetReader) readLine() (string, error) {
	var line []byte
	for {
		// kick the attacker after 60s of silence (or if they stop reading our output)
		t.conn.SetDeadline(time.Now().Add(telnetIdleTimeout))

		b, err := t.r.ReadByte()
		if err != nil {
			return "", err
		}

		if t.lastCR {
			t.lastCR = false
			if b == '\n' || b == 0 {
				continue // second half of the previous Enter
			}
		}

		switch {
		case b == telnetIAC:
			if err := skipTelnetCommand(t.r); err != nil {
				return "", err
			}
		case b == '\r':
			t.lastCR = true
			return string(line), nil
		case b == '\n':
			return string(line), nil // some clients (e.g. nc on Linux) send only \n
		case b == 8 || b == 127: // backspace / delete
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		case b == 0:
			// ignore NUL
		default:
			if len(line) < telnetMaxLine { // bytes past the limit are dropped
				line = append(line, b)
			}
		}
	}
}

// skipTelnetCommand skips one Telnet command (the IAC byte was already read).
func skipTelnetCommand(reader *bufio.Reader) error {
	cmd, err := reader.ReadByte()
	if err != nil {
		return err
	}

	switch cmd {
	case telnetWILL, telnetWONT, telnetDO, telnetDONT:
		_, err = reader.ReadByte() // option byte
		return err
	case telnetSB:
		// subnegotiation: skip everything up to IAC SE
		for {
			b, err := reader.ReadByte()
			if err != nil {
				return err
			}
			if b == telnetIAC {
				next, err := reader.ReadByte()
				if err != nil {
					return err
				}
				if next == telnetSE {
					return nil
				}
			}
		}
	}
	return nil
}
