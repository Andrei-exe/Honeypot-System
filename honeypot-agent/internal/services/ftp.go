package services

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
)

const (
	ftpMaxLine       = 1024
	ftpMaxCommands   = 50
	ftpMaxLoginTries = 3
)

// ftpIdleTimeout is vsftpd's idle_session_timeout (300s); after it vsftpd says "421 Timeout."
// and hangs up. A variable only so the test can shorten it.
var ftpIdleTimeout = 300 * time.Second

// RunFTP serves a fake vsftpd on address until ctx is cancelled.
// Returns nil after a clean shutdown, or an error if it fails (usually the port is in use).
func RunFTP(ctx context.Context, address string, nodeID string, shipper *shipper.Shipper) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	listener = limitConnections(listener, "FTP")
	defer listener.Close()

	log.Println("FTP node running")
	return serve(ctx, listener, func(conn net.Conn) { handleFTP(conn, nodeID, shipper) })
}

// handleFTP runs one FTP session: login, then commands.
// It never opens a data connection, so nothing is ever transferred.
func handleFTP(conn net.Conn, nodeID string, shipper *shipper.Shipper) {
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
			TargetPort: 21,
			Protocol:   "FTP",
			SessionID:  sessionID,
		}
	}

	reply := func(text string) {
		fmt.Fprint(conn, text+"\r\n")
	}

	shipper.EmitEvent(newEvent("session_start"))
	defer func() { shipper.EmitEvent(newEvent("session_end")) }()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, ftpMaxLine), ftpMaxLine)

	user := ""
	loggedIn := false
	failed := 0
	cwd := "/"

	reply("220 (vsFTPd 3.0.3)")

	for i := 0; i < ftpMaxCommands; i++ {
		conn.SetDeadline(time.Now().Add(ftpIdleTimeout))
		if !scanner.Scan() {
			if errors.Is(scanner.Err(), os.ErrDeadlineExceeded) {
				conn.SetWriteDeadline(time.Now().Add(time.Second)) // the old deadline has passed
				reply("421 Timeout.")                              // like vsftpd (ftpcmdio.c)
			}
			return
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(cmd)

		switch cmd {
		case "USER":
			user = arg
			reply("331 Please specify the password.")

		case "PASS":
			if user == "" {
				reply("503 Login with USER first.")
				continue
			}

			success := ftpLoginOK(user, arg)

			event := newEvent("login_attempt")
			event.Credentials = &models.Credentials{
				Username: user,
				Password: arg,
				Success:  success,
			}
			shipper.EmitEvent(event)

			if success {
				loggedIn = true
				reply("230 Login successful.")
				continue
			}

			failed++
			time.Sleep(time.Second)
			reply("530 Login incorrect.")
			if failed >= ftpMaxLoginTries {
				return
			}

		case "QUIT":
			reply("221 Goodbye.")
			return

		default:
			// every other command is logged; before login only OPTS works (like vsftpd)
			event := newEvent("command_exec")
			event.PayloadDetails = &models.PayloadDetails{
				Command:      line,
				ExtractedURL: urlRegex.FindString(line),
			}
			shipper.EmitEvent(event)

			if !loggedIn && cmd != "OPTS" {
				reply("530 Please login with USER and PASS.")
				continue
			}
			reply(ftpAnswer(cmd, arg, &cwd))
		}
	}
}

// ftpLoginOK accepts "anonymous" with any password, plus the shared weakCredentials.
func ftpLoginOK(user, pass string) bool {
	if strings.ToLower(user) == "anonymous" {
		return true
	}
	return weakCredentials[user+":"+pass]
}

// ftpAnswer returns the vsftpd reply to a command sent after login. CWD updates *cwd.
func ftpAnswer(cmd, arg string, cwd *string) string {
	switch cmd {
	case "SYST":
		return "215 UNIX Type: L8"

	case "PWD", "XPWD":
		return `257 "` + *cwd + `" is the current directory`

	case "CWD":
		if !strings.HasPrefix(arg, "/") {
			arg = *cwd + "/" + arg
		}
		*cwd = path.Clean(arg)
		return "250 Directory successfully changed."

	case "TYPE":
		return "200 Switching to Binary mode."

	case "NOOP":
		return "200 NOOP ok."

	case "OPTS":
		return "200 Always in UTF8 mode."

	// Data connections are never opened (internal Docker IP + FTP bounce risk).
	case "PASV", "EPSV":
		return "550 Permission denied."
	case "PORT", "EPRT":
		return "200 PORT command successful. Consider using PASV."
	case "LIST", "NLST", "RETR", "STOR":
		return "425 Failed to establish connection."

	case "DELE", "MKD", "RMD":
		return "550 Permission denied."
	}
	return "500 Unknown command."
}
