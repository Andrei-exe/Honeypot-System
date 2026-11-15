package services

import (
	"bufio"
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
)

func RunTelnet(address string, nodeID string, shipper *shipper.Shipper) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	// limite de conexiuni + pauza la erori de accept (vezi limit.go)
	listener = limitConnections(listener, "TELNET")
	defer listener.Close()

	log.Println("TELNET node running")
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err // limitListener reincearca singur erorile trecatoare; aici ajung doar cele fatale
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

	// cititorul tine minte intre citiri daca ultimul Enter s-a terminat cu \r (vezi telnetReader)
	reader := &telnetReader{conn: conn, r: bufio.NewReader(conn)}

	// ---------- Faza 1: login ----------
	fmt.Fprint(conn, "\r\nGateway Linux 4.14\r\n\r\n")
	loggedIn := false
	for try := 1; try <= telnetMaxLoginTries; try++ {
		fmt.Fprint(conn, "gateway login: ")
		user, err := reader.readLine()
		if err != nil {
			return
		}

		// "WILL ECHO" = clientul nu mai afiseaza ce tasteaza -> parola ascunsa
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
		time.Sleep(time.Second) // login-urile reale au si ele un mic delay
		fmt.Fprint(conn, "Login incorrect\r\n")
	}
	if !loggedIn {
		return
	}

	// ---------- Faza 2: shell fals ----------
	// fiecare conexiune primeste shell-ul ei (cu directorul curent si fisierele ei)
	sh := vfs.NewShell()
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

// toCRLF: shell-ul scrie randurile cu \n, dar Telnet vrea \r\n la capat de rand.
func toCRLF(text string) string {
	return strings.ReplaceAll(text, "\n", "\r\n")
}

// telnetReader citeste linii de la clientul Telnet si arunca comenzile Telnet (IAC ...).
// E un struct (si nu o simpla functie) pentru ca trebuie sa tina minte ceva INTRE linii: lastCR.
type telnetReader struct {
	conn net.Conn
	r    *bufio.Reader

	// Enter in Telnet = "\r\n" sau "\r\0". De obicei vin impreuna, dar pot veni si in pachete separate:
	// "\r" acum, "\n" abia la citirea urmatoare. lastCR = "linia trecuta s-a terminat cu \r",
	// deci un \n sau \0 care vine imediat dupa e tot din Enter-ul ala si il aruncam.
	lastCR bool
}

// readLine citeste o linie (fara Enter la final).
func (t *telnetReader) readLine() (string, error) {
	var line []byte
	for {
		// daca atacatorul tace 60s (sau nu citeste ce-i trimitem), il dam afara
		t.conn.SetDeadline(time.Now().Add(telnetIdleTimeout))

		b, err := t.r.ReadByte()
		if err != nil {
			return "", err
		}

		if t.lastCR {
			t.lastCR = false
			if b == '\n' || b == 0 {
				continue // a doua jumatate din Enter-ul de data trecuta
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
			return string(line), nil // unii clienti (ex: nc pe Linux) trimit doar \n
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
