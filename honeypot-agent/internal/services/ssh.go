package services

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
	"honeypot-agent/internal/vfs"
)

const (
	sshIdleTimeout = 60 * time.Second
	sshMaxCommands = 50
	sshMaxAuth     = 6 // password attempts allowed per connection

	// BusyBox routers run Dropbear, not OpenSSH -> same persona as Telnet.
	sshServerVersion = "SSH-2.0-dropbear_2019.78"

	// Kept on disk so the key (and its fingerprint) doesn't change on restart.
	sshHostKeyFile = "ssh_host_ed25519_key"
)

// RunSSH serves a fake Dropbear SSH server on address. Returns only on a fatal error.
func RunSSH(address string, nodeID string, shipper *shipper.Shipper) error {
	hostKey, err := loadOrCreateHostKey(sshHostKeyFile)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	// limits matter even more for SSH: every handshake costs CPU (crypto)
	listener = limitConnections(listener, "SSH")
	defer listener.Close()

	log.Println("SSH node running")
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err // transient errors are already retried inside limitListener
		}
		go handleSSH(conn, hostKey, nodeID, shipper) // one goroutine per attacker
	}
}

// handleSSH runs one SSH connection: handshake + login, then a single session channel.
func handleSSH(conn net.Conn, hostKey ssh.Signer, nodeID string, shipper *shipper.Shipper) {
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
			TargetPort: 22,
			Protocol:   "SSH",
			SessionID:  sessionID,
		}
	}

	shipper.EmitEvent(newEvent("session_start"))
	defer func() { shipper.EmitEvent(newEvent("session_end")) }()

	// ---------- Phase 1: handshake + login ----------
	// The library does the crypto; we only decide which passwords work.
	config := &ssh.ServerConfig{
		ServerVersion: sshServerVersion,
		MaxAuthTries:  sshMaxAuth,
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			// keep the attacker connected while they keep trying passwords
			conn.SetDeadline(time.Now().Add(sshIdleTimeout))

			user := meta.User()
			pass := string(password)
			success := weakCredentials[user+":"+pass]

			event := newEvent("login_attempt")
			event.Credentials = &models.Credentials{
				Username: user,
				Password: pass,
				Success:  success,
			}
			shipper.EmitEvent(event)

			if success {
				return nil, nil // nil error = login accepted
			}
			time.Sleep(time.Second) // real servers also delay after a wrong password
			return nil, errors.New("password rejected")
		},
		// Dropbear offers exactly "publickey" and "password" (no keyboard-interactive).
		// We offer publickey too but reject every key, so clients fall back to password.
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			conn.SetDeadline(time.Now().Add(sshIdleTimeout))
			return nil, errors.New("public key rejected")
		},
	}
	config.AddHostKey(hostKey)

	// drop the connection if the handshake isn't done within 60s
	conn.SetDeadline(time.Now().Add(sshIdleTimeout))

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return // handshake failed or all passwords were wrong
	}
	defer sshConn.Close()

	// global requests (e.g. port forwarding) -> all rejected
	go ssh.DiscardRequests(reqs)

	// ---------- Phase 2: session channel ----------
	// A client can open several channels on one connection; we serve only the first "session".
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		handleSSHSession(conn, channel, requests, newEvent, shipper)
		return
	}
}

// handleSSHSession waits for the client to ask for an interactive shell or a single command (exec).
func handleSSHSession(conn net.Conn, channel ssh.Channel, requests <-chan *ssh.Request,
	newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) {

	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "pty-req", "env", "window-change":
			// accept terminal setup; the details don't matter to us
			req.Reply(true, nil)

		case "exec":
			// ssh root@host "uname -a" -> one command, no prompt
			var payload struct{ Command string }
			ssh.Unmarshal(req.Payload, &payload)
			req.Reply(true, nil)
			go ssh.DiscardRequests(requests)

			// no terminal: output goes straight to the channel with plain \n
			output, _ := runShellLine(vfs.NewShell(), payload.Command, newEvent, shipper)
			fmt.Fprint(channel, output)
			sendExitStatus(channel)
			return

		case "shell":
			// ssh root@host -> interactive prompt
			req.Reply(true, nil)
			go ssh.DiscardRequests(requests)

			runSSHShell(conn, channel, newEvent, shipper)
			sendExitStatus(channel)
			return

		default:
			// sftp, x11 and the like -> rejected
			req.Reply(false, nil)
		}
	}
}

// runSSHShell is the fake shell loop, almost the same as Phase 2 in telnet.go.
func runSSHShell(conn net.Conn, channel ssh.Channel,
	newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) {

	sh := vfs.NewShell() // one shell per connection (its own cwd and files)

	// term.Terminal handles echo, backspace and arrow keys (with a pty the client doesn't
	// echo what it types, the server must send it back). It also turns \n into \r\n.
	terminal := term.NewTerminal(channel, sh.Prompt())
	fmt.Fprint(terminal, vfs.Banner)

	for i := 0; i < sshMaxCommands; i++ {
		conn.SetDeadline(time.Now().Add(sshIdleTimeout))

		terminal.SetPrompt(sh.Prompt()) // the prompt changes after cd
		line, err := terminal.ReadLine()
		if err != nil {
			return
		}

		output, exit := runShellLine(sh, line, newEvent, shipper)
		fmt.Fprint(terminal, output)
		if exit {
			return
		}
	}
}

// sendExitStatus tells the client the command finished with exit code 0, like a real server.
func sendExitStatus(channel ssh.Channel) {
	status := struct{ Status uint32 }{0}
	channel.SendRequest("exit-status", false, ssh.Marshal(&status))
}

// loadOrCreateHostKey reads the host key from disk, or generates and saves it the first time.
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, err
	}
	log.Println("generated new SSH host key:", path)
	return ssh.NewSignerFromKey(privateKey)
}
