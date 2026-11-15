package services

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
)

// Bytes speciali din protocolul Telnet (RFC 854).
// Orice comanda Telnet incepe cu IAC (255), urmat de comanda si eventual o optiune.
const (
	telnetIAC     = 255 // "Interpret As Command"
	telnetDONT    = 254
	telnetDO      = 253
	telnetWONT    = 252
	telnetWILL    = 251
	telnetSB      = 250 // inceput subnegociere
	telnetSE      = 240 // sfarsit subnegociere
	telnetOptEcho = 1   // optiunea ECHO
)

const (
	telnetIdleTimeout   = 60 * time.Second
	telnetMaxLine       = 1024
	telnetMaxLoginTries = 3
	telnetMaxCommands   = 50
	telnetPrompt        = "root@gateway:~# "
)

// Combinatii user:parola cu care "intra" atacatorul, ca sa-i vedem comenzile.
var weakCredentials = map[string]bool{
	"root:root":      true,
	"root:admin":     true,
	"root:123456":    true,
	"root:12345":     true,
	"admin:admin":    true,
	"admin:password": true,
	"user:user":      true,
}

var telnetURLRegex = regexp.MustCompile(`(?:https?|ftp|tftp)://[^\s'";|&<>()]+`)

func RunTelnet(address string, nodeID string, shipper *shipper.Shipper) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Println("TELNET node running")
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Println("telnet accept error:", err)
			continue
		}
		// fiecare atacator primeste goroutine-ul lui
		go handleTelnet(conn, nodeID, shipper)
	}
}

func handleTelnet(conn net.Conn, nodeID string, shipper *shipper.Shipper) {
	defer conn.Close()

	ip, portText, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		ip = conn.RemoteAddr().String()
	}
	port, _ := strconv.Atoi(portText)

	sessionID := newSessionID()

	// construieste campurile comune, la fel ca in http.go
	newEvent := func(eventType string) models.HoneypotEvent {
		return models.HoneypotEvent{
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
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
	// func() ca timestamp-ul sa fie calculat la final, nu acum
	defer func() { shipper.EmitEvent(newEvent("session_end")) }()

	reader := bufio.NewReader(conn)

	// ---------- Faza 1: login ----------
	fmt.Fprint(conn, "\r\nGateway Linux 4.14\r\n\r\n")
	loggedIn := false
	for try := 1; try <= telnetMaxLoginTries; try++ {
		fmt.Fprint(conn, "gateway login: ")
		user, err := readTelnetLine(conn, reader)
		if err != nil {
			return
		}

		// "WILL ECHO" = clientul nu mai afiseaza ce tasteaza -> parola ascunsa
		conn.Write([]byte{telnetIAC, telnetWILL, telnetOptEcho})
		fmt.Fprint(conn, "Password: ")
		pass, err := readTelnetLine(conn, reader)
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
		time.Sleep(time.Second) // login-urile reale au si ele un mic delay
		fmt.Fprint(conn, "Login incorrect\r\n")
	}
	if !loggedIn {
		return
	}

	// ---------- Faza 2: shell fals ----------
	fmt.Fprint(conn, "\r\nBusyBox v1.30.1 built-in shell (ash)\r\n\r\n")
	for i := 0; i < telnetMaxCommands; i++ {
		fmt.Fprint(conn, telnetPrompt)
		line, err := readTelnetLine(conn, reader)
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		event := newEvent("command_exec")
		event.PayloadDetails = &models.PayloadDetails{
			Command:      line,
			ExtractedURL: telnetURLRegex.FindString(line),
		}
		shipper.EmitEvent(event)

		output, exit := fakeShellOutput(line)
		fmt.Fprint(conn, output)
		if exit {
			return
		}
	}
}

// readTelnetLine citeste o linie de la client si arunca comenzile Telnet (IAC ...).
func readTelnetLine(conn net.Conn, reader *bufio.Reader) (string, error) {
	var line []byte
	for {
		// daca atacatorul tace 60s (sau nu citeste ce-i trimitem), il dam afara
		conn.SetDeadline(time.Now().Add(telnetIdleTimeout))

		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}

		switch {
		case b == telnetIAC:
			if err := skipTelnetCommand(reader); err != nil {
				return "", err
			}
		case b == '\r' || b == '\n':
			// Enter in Telnet = "\r\n" sau "\r\0"; inghitim si al doilea byte
			if b == '\r' && reader.Buffered() > 0 {
				next, _ := reader.Peek(1)
				if next[0] == '\n' || next[0] == 0 {
					reader.ReadByte()
				}
			}
			return string(line), nil
		case b == 8 || b == 127: // backspace / delete
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		case b == 0:
			// ignoram NUL
		default:
			if len(line) < telnetMaxLine {
				line = append(line, b)
			}
		}
	}
}

// skipTelnetCommand sare peste o comanda Telnet (IAC-ul a fost deja citit).
func skipTelnetCommand(reader *bufio.Reader) error {
	cmd, err := reader.ReadByte()
	if err != nil {
		return err
	}

	switch cmd {
	case telnetWILL, telnetWONT, telnetDO, telnetDONT:
		_, err = reader.ReadByte() // byte-ul de optiune
		return err
	case telnetSB:
		// subnegociere: sarim tot pana la IAC SE
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

// fakeShellOutput intoarce ce "afiseaza" shell-ul si daca sesiunea trebuie inchisa.
func fakeShellOutput(line string) (string, bool) {
	fields := strings.Fields(line)
	cmd := fields[0]

	switch cmd {
	case "exit", "logout", "quit":
		return "", true
	case "whoami":
		return "root\r\n", false
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)\r\n", false
	case "uname":
		return "Linux gateway 4.14.180 #1 SMP armv7l GNU/Linux\r\n", false
	case "pwd":
		return "/root\r\n", false
	case "ls":
		return "bin  dev  etc  lib  proc  sbin  tmp  usr  var\r\n", false
	case "enable", "system", "shell", "sh", "cd":
		return "", false
	case "busybox", "/bin/busybox":
		if len(fields) > 1 {
			return fields[1] + ": applet not found\r\n", false
		}
		return "BusyBox v1.30.1 multi-call binary.\r\n", false
	case "wget", "curl", "tftp":
		return cmd + ": can't connect to remote host: Connection timed out\r\n", false
	default:
		return fmt.Sprintf("-sh: %s: not found\r\n", cmd), false
	}
}

func newSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
