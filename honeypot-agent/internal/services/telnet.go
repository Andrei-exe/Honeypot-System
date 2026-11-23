package services

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
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
	telnetOptSGA  = 3   // SUPPRESS-GO-AHEAD: the client sends each key as it is typed
	telnetOptNAWS = 31  // window size
)

// telnetGreeting is what BusyBox 1.30.1 telnetd sends on a new connection, byte for byte (scanners
// such as Shodan store exactly these bytes). First iacs_to_send (telnetd.c): DO ECHO, DO NAWS,
// WILL ECHO, WILL SGA = "I echo, send me every key". Then /etc/issue.net, printed through the pty by
// print_login_issue (libbb/login.c): puts("\r") and every \n written as \n\r, and the pty's ONLCR
// turns each \n into \r\n -> the doubled \r, and a lone \r before "gateway login: ".
const telnetGreeting = "\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03" + "\r\r\nGateway Linux 4.14\r\n\r"

const (
	telnetMaxLine       = 1024
	telnetMaxLoginTries = 3
	telnetMaxEmptyNames = 10 // BusyBox login gives up after 10 empty user names (EMPTY_USERNAME_COUNT)

	// telnetFailDelay is BusyBox login's wait after a wrong password: bb_do_delay(LOGIN_FAIL_DELAY),
	// LOGIN_FAIL_DELAY = 3 in include/libbb.h, at least 3s of wall-clock time.
	telnetFailDelay = 3 * time.Second
)

// Variables only so the tests can shorten them.
var (
	// telnetIdleTimeout: a whole line must arrive within it (not each byte: one byte every 59s
	// would otherwise hold a connection, and its slot in limit.go, forever).
	telnetIdleTimeout = 60 * time.Second

	// telnetLoginTimeout is BusyBox login's TIMEOUT: all the tries together, from the first prompt
	// (alarm(TIMEOUT) in login.c, cancelled only by a successful login).
	telnetLoginTimeout = 60 * time.Second
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

	// echo: like the pty of a real telnetd (it said WILL ECHO), what the client types comes back
	reader := &telnetReader{conn: conn, r: bufio.NewReader(conn), echo: true}

	// ---------- Phase 1: login ----------
	fmt.Fprint(conn, telnetGreeting)
	reader.limit = time.Now().Add(telnetLoginTimeout)
	timedOut := func(err error) { // BusyBox login's alarm_handler, when its 60s run out
		if errors.Is(err, os.ErrDeadlineExceeded) {
			conn.SetWriteDeadline(time.Now().Add(time.Second)) // the old deadline (writes too) has passed
			// printf("\r\nLogin timed out after %u seconds\r\n"): the pty adds a \r before each \n
			fmt.Fprint(conn, "\r\r\nLogin timed out after 60 seconds\r\r\n")
		}
	}
	loggedIn := false
	var user string
	for try := 1; try <= telnetMaxLoginTries; try++ {
		var err error
		user, err = readUsername(conn, reader)
		if err != nil {
			timedOut(err)
			return
		}
		if user == "" {
			return // the 10th empty name: BusyBox login exits
		}

		// The password is hidden like bb_ask_noecho does it: no Telnet option changes (the client
		// already leaves the echo to us), only no echo while it is typed, then a newline.
		fmt.Fprint(conn, "Password: ")
		reader.echo = false
		pass, err := reader.readLine()
		reader.echo = true
		if err != nil {
			timedOut(err)
			return
		}
		fmt.Fprint(conn, "\r\n") // bb_putchar('\n'), through the pty

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
		time.Sleep(telnetFailDelay)
		fmt.Fprint(conn, "Login incorrect\r\n")
	}
	if !loggedIn {
		return
	}
	reader.limit = time.Time{} // alarm(0): from now on only the per-line timeout

	// ---------- Phase 2: fake shell ----------
	// no banner: Buildroot builds BusyBox's shell "quiet" (FEATURE_SH_EXTRA_QUIET), the prompt comes right away
	sh := vfs.NewLoginShell(user) // one shell per connection (its own cwd and files)
	var pace pacer                // commands sent all at once are answered one by one (common.go)
	for i := 0; i < maxSessionCommands; i++ {
		fmt.Fprint(conn, sh.Prompt())
		line, err := reader.readLine()
		if err != nil {
			return
		}

		pace.wait()
		var screen strings.Builder // output and errors both go to the pty
		_, exit := runShellLine(sh, line, &screen, &screen, newEvent, shipper)
		fmt.Fprint(conn, toCRLF(screen.String()))
		if exit {
			return
		}
	}
	commandLimitReached("TELNET", ip)
}

// readUsername asks "gateway login: " like BusyBox login: an empty line only asks again (no
// "Password:", not a login attempt), 10 times at most, and the name ends at the first space.
// Returns "" and no error after the 10th empty name.
func readUsername(conn net.Conn, reader *telnetReader) (string, error) {
	for range telnetMaxEmptyNames {
		fmt.Fprint(conn, "gateway login: ")
		line, err := reader.readLine()
		if err != nil {
			return "", err
		}
		if words := strings.Fields(line); len(words) > 0 {
			return words[0], nil
		}
	}
	return "", nil
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

	limit time.Time // the line must also arrive before this (the login's 60s); zero = no limit

	// echo sends back what the client types, as the pty of a real telnetd does (it said WILL ECHO,
	// so the client shows nothing by itself). Off while the password is typed (bb_ask_noecho).
	echo bool
}

// echoBack writes text back to the client if echo is on (a failed write shows up at the next read).
func (t *telnetReader) echoBack(text string) {
	if t.echo {
		io.WriteString(t.conn, text)
	}
}

// readLine reads one line, without the trailing Enter. The whole line must arrive within
// telnetIdleTimeout (and before limit): sending one byte now and then doesn't extend it.
func (t *telnetReader) readLine() (string, error) {
	deadline := time.Now().Add(telnetIdleTimeout)
	if !t.limit.IsZero() && t.limit.Before(deadline) {
		deadline = t.limit
	}
	t.conn.SetDeadline(deadline) // writes too: an attacker who stops reading our output is cut off as well

	var line []byte
	for {
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
		case b == '\r' || b == '\n': // Enter; some clients (e.g. nc on Linux) send only \n
			t.lastCR = b == '\r'
			t.echoBack("\r\n")
			return string(line), nil
		case b == 8 || b == 127: // backspace / delete
			if len(line) > 0 {
				line = line[:len(line)-1]
				t.echoBack("\b \b") // back, blank, back: the character disappears from the screen
			}
		case b == 0:
			// ignore NUL
		default:
			if len(line) < telnetMaxLine { // bytes past the limit are dropped
				line = append(line, b)
				if b >= ' ' { // control characters are kept but not shown (simplification)
					t.echoBack(string([]byte{b})) // the byte itself; string(b) would be the rune b (2 bytes over 127)
				}
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
