package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
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

	// Dropbear's limits (MAX_USERNAME_LEN, DROPBEAR_MAX_PASSWORD_LEN, MAX_CMD_LEN): longer is refused.
	// They also keep events small: an SSH packet could carry ~256KB into one event.
	dropbearMaxLogin  = 100 // username or password, in bytes
	dropbearMaxCmdLen = 9000

	// BusyBox routers run Dropbear, not OpenSSH -> same persona as Telnet.
	sshServerVersion = "SSH-2.0-dropbear_2019.78"

	// Kept on disk so the key (and its fingerprint) doesn't change on restart. ECDSA, not ed25519:
	// Dropbear only got ed25519 in 2020.79, so a 2019.78 with an ed25519 key can't exist.
	sshHostKeyFile = "ssh_host_ecdsa_key"
)

// dropbearAlgorithms are the algorithms Dropbear 2019.78 offers when Buildroot 2019.05.3 builds it
// with its defaults (no legacy crypto, no zlib), in Dropbear's order (common-algo.c). Scanners
// fingerprint these lists (HASSH); x/crypto's defaults have algorithms Dropbear never had (mlkem,
// chacha20, gcm, etm). Can't be imitated: x/crypto always adds kex-strict-s-v00@openssh.com,
// and it can't send Dropbear's kexguess2@matt.ucc.asn.au.
var dropbearAlgorithms = ssh.Config{
	KeyExchanges: []string{"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp521", "ecdh-sha2-nistp384", "ecdh-sha2-nistp256",
		"diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"},
	Ciphers: []string{"aes128-ctr", "aes256-ctr"},
	MACs:    []string{"hmac-sha1", "hmac-sha2-256"},
}

// RunSSH serves a fake Dropbear SSH server on address until ctx is cancelled.
// Returns nil after a clean shutdown, or an error if it fails (usually the port is in use).
func RunSSH(ctx context.Context, address string, nodeID string, shipper *shipper.Shipper) error {
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
	return serve(ctx, listener, func(conn net.Conn) { handleSSH(conn, hostKey, nodeID, shipper) })
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
		Config:        dropbearAlgorithms, // a copy: every connection gets its own
		ServerVersion: sshServerVersion,
		MaxAuthTries:  sshMaxAuth,
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			// keep the attacker connected while they keep trying passwords
			conn.SetDeadline(time.Now().Add(sshIdleTimeout))

			user := meta.User()
			pass := string(password)
			if len(user) > dropbearMaxLogin || len(pass) > dropbearMaxLogin {
				time.Sleep(time.Second) // Dropbear doesn't check it: a plain failure, not logged
				return nil, errors.New("too long")
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
			if len(payload.Command) > dropbearMaxCmdLen {
				req.Reply(false, nil) // like Dropbear: fails, nothing runs; the client may try again
				continue
			}
			req.Reply(true, nil)
			go ssh.DiscardRequests(requests)

			// no terminal: output goes straight to the channel with plain \n
			output, code, _ := runShellLine(vfs.NewShell(), payload.Command, newEvent, shipper)
			fmt.Fprint(channel, output)
			sendExitStatus(channel, code) // e.g. 127 for a command that doesn't exist
			return

		case "shell":
			// ssh root@host -> interactive prompt
			req.Reply(true, nil)
			go ssh.DiscardRequests(requests)

			sendExitStatus(channel, runSSHShell(conn, channel, newEvent, shipper))
			return

		default:
			// sftp, x11 and the like -> rejected
			req.Reply(false, nil)
		}
	}
}

// runSSHShell is the fake shell loop, almost the same as Phase 2 in telnet.go.
// Returns the exit code of the last command, which a real shell also exits with.
func runSSHShell(conn net.Conn, channel ssh.Channel,
	newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) int {

	sh := vfs.NewShell() // one shell per connection (its own cwd and files)

	// term.Terminal handles echo, backspace and arrow keys (with a pty the client doesn't
	// echo what it types, the server must send it back). It also turns \n into \r\n.
	terminal := term.NewTerminal(channel, sh.Prompt()) // no banner, like telnet.go

	code := 0
	for i := 0; i < sshMaxCommands; i++ {
		conn.SetDeadline(time.Now().Add(sshIdleTimeout))

		terminal.SetPrompt(sh.Prompt()) // the prompt changes after cd
		line, err := terminal.ReadLine()
		if err != nil {
			return code
		}

		output, c, exit := runShellLine(sh, line, newEvent, shipper)
		fmt.Fprint(terminal, output)
		if exit {
			return code // "exit" itself doesn't count: the shell exits with the previous command's code
		}
		if strings.TrimSpace(line) != "" {
			code = c
		}
	}
	return code
}

// sendExitStatus tells the client the exit code of the command or shell, like a real server.
func sendExitStatus(channel ssh.Channel, code int) {
	status := struct{ Status uint32 }{uint32(code)}
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

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // ecdsa-sha2-nistp256, Dropbear's default
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
