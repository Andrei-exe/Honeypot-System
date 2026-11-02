package services

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
)

const (
	ftpIdleTimeout   = 60 * time.Second
	ftpMaxLine       = 1024
	ftpMaxCommands   = 50
	ftpMaxLoginTries = 3
)

var ftpCredentials = map[string]bool{
	"root:root":      true,
	"root:admin":     true,
	"root:123456":    true,
	"admin:admin":    true,
	"admin:password": true,
	"user:user":      true,
}

var ftpURLRegex = regexp.MustCompile(`(?:https?|ftp|tftp)://[^\s'";|&<>()]+`)

func RunFTP(address string, nodeID string, shipper *shipper.Shipper) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Println("FTP node running")
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Println("ftp accept error:", err)
			continue
		}
		go handleFTP(conn, nodeID, shipper)
	}
}

func handleFTP(conn net.Conn, nodeID string, shipper *shipper.Shipper) {
	defer conn.Close()

	ip, portText, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		ip = conn.RemoteAddr().String()
	}
	port, _ := strconv.Atoi(portText)
	sessionID := ftpSessionID()

	newEvent := func(eventType string) models.HoneypotEvent {
		return models.HoneypotEvent{
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
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
			event := newEvent("command_exec")
			event.PayloadDetails = &models.PayloadDetails{
				Command:      line,
				ExtractedURL: ftpURLRegex.FindString(line),
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

func ftpLoginOK(user, pass string) bool {
	if strings.ToLower(user) == "anonymous" {
		return true
	}
	return ftpCredentials[user+":"+pass]
}

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

func ftpSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
