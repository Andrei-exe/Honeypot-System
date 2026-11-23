package services

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	mrand "math/rand/v2" // rand is crypto/rand here (the host key)
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

	// Dropbear's MAX_AUTH_TRIES (Buildroot's S50dropbear passes no -T): wrong passwords per connection.
	// Rejected public keys don't count (svr-authpubkey.c).
	sshMaxAuth = 10

	// After a wrong password Dropbear answers in 300ms +-50 (send_msg_userauth_failure): this + up to 100ms.
	sshFailDelay = 250 * time.Millisecond

	// Dropbear's limits (MAX_USERNAME_LEN, DROPBEAR_MAX_PASSWORD_LEN, MAX_CMD_LEN): longer is refused.
	// They also keep events small: an SSH packet could carry ~256KB into one event.
	dropbearMaxLogin   = 100 // username or password, in bytes
	dropbearMaxCmdLen  = 9000
	dropbearMaxTermLen = 200 // MAX_TERM_LEN: the terminal type in a pty request

	sshMaxLine = 1024 // a line of a session without a pty; the rest of it is dropped (like Telnet)

	// BusyBox routers run Dropbear, not OpenSSH -> same persona as Telnet.
	sshServerVersion = "SSH-2.0-dropbear_2019.78"

	// Kept on disk so the key (and its fingerprint) doesn't change on restart. ECDSA, not ed25519:
	// Dropbear only got ed25519 in 2020.79, so a 2019.78 with an ed25519 key can't exist.
	sshHostKeyFile = "ssh_host_ecdsa_key"
)

// sshAuthTimeout is Dropbear's AUTH_TIMEOUT (sysoptions.h): from the connection to a successful login,
// whatever the client does meanwhile (rejected public keys don't count as tries, so without it a
// client offering one key a minute would hold the connection forever). A variable only for the tests.
var sshAuthTimeout = 300 * time.Second

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
	showHostKey(hostKey)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	// limits matter even more for SSH: every handshake costs CPU (crypto)
	listener = limitConnections(listener, "SSH")
	defer listener.Close()

	publicIP := sshPublicIP()
	log.Println("SSH node running")
	return serve(ctx, listener, func(conn net.Conn) { handleSSH(conn, hostKey, nodeID, publicIP, shipper) })
}

// sshPublicIP is PUBLIC_IP from the environment: the router's address on the internet, which Dropbear
// shows in SSH_CONNECTION. The agent can't see it itself (Docker translates the address), and showing the
// container's own address would give us away: "" = SSH_CONNECTION and SSH_CLIENT are left out.
func sshPublicIP() string {
	ip := os.Getenv("PUBLIC_IP")
	if ip != "" && net.ParseIP(ip) == nil {
		log.Printf("PUBLIC_IP %q is not an IP address: SSH sessions get no SSH_CONNECTION", ip)
		return ""
	}
	return ip
}

// handleSSH runs one SSH connection: handshake + login, then a single session channel.
// publicIP: see sshPublicIP.
func handleSSH(conn net.Conn, hostKey ssh.Signer, nodeID, publicIP string, shipper *shipper.Shipper) {
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

	// Until the login: 60s of silence at most, and all of it within Dropbear's AUTH_TIMEOUT
	// ("Timeout before auth": the connection is just closed, like at the 10th wrong password).
	authEnd := time.Now().Add(sshAuthTimeout)
	keepAuthAlive := func() {
		deadline := time.Now().Add(sshIdleTimeout)
		if authEnd.Before(deadline) {
			deadline = authEnd
		}
		conn.SetDeadline(deadline)
	}

	// wrongPassword answers a failed password like Dropbear: after ~300ms, and at the 10th one it just
	// closes the connection (dropbear_exit: no disconnect message, the last failure isn't even sent).
	// x/crypto's own limit would send OpenSSH's "too many authentication failures" instead.
	failures := 0
	wrongPassword := func() error {
		time.Sleep(sshFailDelay + mrand.N(sshFailDelay*2/5))
		if failures++; failures >= sshMaxAuth {
			conn.Close()
		}
		return errors.New("password rejected")
	}

	// ---------- Phase 1: handshake + login ----------
	// The library does the crypto; we only decide which passwords work.
	config := &ssh.ServerConfig{
		Config:        dropbearAlgorithms, // a copy: every connection gets its own
		ServerVersion: sshServerVersion,
		MaxAuthTries:  -1, // no limit in x/crypto: wrongPassword counts, like Dropbear
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			keepAuthAlive() // the attacker is still trying passwords

			user := meta.User()
			pass := string(password)
			if len(user) > dropbearMaxLogin || len(pass) > dropbearMaxLogin {
				return nil, wrongPassword() // Dropbear doesn't check it: a plain failure, not logged
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
			return nil, wrongPassword()
		},
		// Dropbear offers exactly "publickey" and "password" (no keyboard-interactive).
		// We offer publickey too but reject every key, so clients fall back to password.
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			keepAuthAlive()
			return nil, errors.New("public key rejected")
		},
	}
	config.AddHostKey(hostKey)

	keepAuthAlive() // the handshake itself must be done within 60s too

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return // handshake failed or all passwords were wrong
	}
	defer sshConn.Close()

	// global requests (e.g. port forwarding) -> all rejected
	go ssh.DiscardRequests(reqs)

	// what Dropbear adds to the shell's environment (make_connection_string): who connected, and to where
	vars := map[string]string{}
	if publicIP != "" {
		vars["SSH_CLIENT"] = fmt.Sprintf("%s %d 22", ip, port)
		vars["SSH_CONNECTION"] = fmt.Sprintf("%s %d %s 22", ip, port, publicIP)
	}

	// ---------- Phase 2: session channel ----------
	// A client can open several channels on one connection; we serve only the first "session".
	// After it, like Dropbear, the connection stays open until the CLIENT closes it (a server that
	// hangs up first makes OpenSSH print "Connection to X closed by remote host."). The loop ends
	// when the client goes away, or after sshIdleTimeout for one that never does.
	served := false
	for newChannel := range chans {
		if served || newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		served = true
		handleSSHSession(conn, channel, requests, sshConn.User(), vars, newEvent, shipper)
		conn.SetDeadline(time.Now().Add(sshIdleTimeout))
	}
}

// handleSSHSession waits for the client to ask for a shell or a single command (exec), then runs it
// the way Dropbear would (svr-chansession.c): with a pty if the client asked for one (pty-req), else
// with plain pipes, where the errors go apart as SSH extended data. user and vars: the environment.
func handleSSHSession(conn net.Conn, channel ssh.Channel, requests <-chan *ssh.Request, user string,
	vars map[string]string, newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) {

	defer channel.Close()

	pty := false // the client asked for a terminal
	for req := range requests {
		switch req.Type {
		case "pty-req":
			if pty {
				conn.Close() // Dropbear: dropbear_exit("Multiple pty requests"), the whole connection ends
				return
			}
			var request struct {
				Term                         string
				Columns, Rows, Width, Height uint32
				Modes                        string
			}
			if ssh.Unmarshal(req.Payload, &request) != nil {
				conn.Close() // Dropbear reads past the packet's end: dropbear_exit, the whole connection ends
				return
			}
			if len(request.Term) > dropbearMaxTermLen {
				req.Reply(false, nil) // sessionpty: DROPBEAR_FAILURE
				continue
			}
			pty = true
			vars["TERM"], vars["SSH_TTY"] = request.Term, "/dev/pts/0" // the first pty of the router
			req.Reply(true, nil)

		case "window-change", "x11-req", "auth-agent-req@openssh.com":
			// what Dropbear accepts (chansessionrequest; Buildroot builds it with X11 and agent
			// forwarding). Nothing is ever forwarded: we never open a channel toward the client.
			req.Reply(true, nil)

		case "exec":
			// ssh root@host "uname -a": Dropbear runs sh -c "uname -a", no prompt
			var payload struct{ Command string }
			ssh.Unmarshal(req.Payload, &payload)
			if len(payload.Command) > dropbearMaxCmdLen {
				req.Reply(false, nil) // like Dropbear: fails, nothing runs; the client may try again
				continue
			}
			req.Reply(true, nil)
			go ssh.DiscardRequests(requests)

			sh := vfs.NewSSHShell(user, vars, pty, true)
			code := 0
			if pty { // ssh -t: one stream, and the pty turns \n into \r\n
				var screen strings.Builder
				code, _ = runShellLine(sh, payload.Command, &screen, &screen, newEvent, shipper)
				fmt.Fprint(channel, toCRLF(screen.String()))
			} else {
				code, _ = runShellLine(sh, payload.Command, channel, channel.Stderr(), newEvent, shipper)
			}
			endCommand(channel, code) // e.g. 127 for a command that doesn't exist
			return

		case "shell":
			// ssh root@host: the login shell "-sh"
			req.Reply(true, nil)
			go ssh.DiscardRequests(requests)

			sh := vfs.NewSSHShell(user, vars, pty, false) // one shell per connection (its own cwd and files)
			if pty {
				endCommand(channel, runSSHTerminal(conn, channel, sh, newEvent, shipper))
			} else {
				endCommand(channel, runSSHPlain(conn, channel, sh, newEvent, shipper))
			}
			return

		default:
			// env (Dropbear has no handler for it), sftp and the like -> rejected
			req.Reply(false, nil)
		}
	}
}

// runSSHTerminal is the login shell on a pty: prompt and echo, almost the same as Phase 2 in telnet.go.
// Returns the exit code of the last command, which a real shell also exits with.
func runSSHTerminal(conn net.Conn, channel ssh.Channel, sh *vfs.Shell,
	newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) int {

	// term.Terminal handles echo, backspace and arrow keys (with a pty the client doesn't
	// echo what it types, the server must send it back). It also turns \n into \r\n.
	terminal := term.NewTerminal(channel, sh.Prompt()) // no banner, like telnet.go

	code := 0
	var pace pacer // commands sent all at once are answered one by one (common.go)
	for i := 0; i < maxSessionCommands; i++ {
		conn.SetDeadline(time.Now().Add(sshIdleTimeout))

		terminal.SetPrompt(sh.Prompt()) // the prompt changes after cd
		line, err := terminal.ReadLine()
		if err != nil {
			return code
		}

		pace.wait()
		exit := false
		code, exit = runShellLine(sh, line, terminal, terminal, newEvent, shipper)
		if exit {
			return code
		}
	}
	commandLimitReached("SSH", remoteIP(conn))
	return code
}

// runSSHPlain is the login shell without a pty (ssh -T, scripts, bots that skip pty-req): ash reads its
// lines from its input, no prompt, no echo, plain \n, the errors apart. It ends at EOF (the client closed
// its side) with the last command's code, at exit, or at the first error that ends a line (code 2).
func runSSHPlain(conn net.Conn, channel ssh.Channel, sh *vfs.Shell,
	newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) int {

	reader := bufio.NewReader(channel)
	code := 0
	var pace pacer
	for i := 0; i < maxSessionCommands; i++ {
		conn.SetDeadline(time.Now().Add(sshIdleTimeout)) // the whole line within it, like Telnet
		line, err := readPlainLine(reader)
		if err != nil {
			return code
		}

		pace.wait()
		exit := false
		code, exit = runShellLine(sh, line, channel, channel.Stderr(), newEvent, shipper)
		if exit {
			return code
		}
	}
	commandLimitReached("SSH", remoteIP(conn))
	return code
}

// readPlainLine reads one line of a session without a pty, without its \n; bytes past sshMaxLine are
// dropped. A last line without \n still counts: ash runs it at EOF.
func readPlainLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		b, err := r.ReadByte()
		switch {
		case err != nil && len(line) > 0:
			return string(line), nil // the next call gets the error
		case err != nil:
			return "", err
		case b == '\n':
			return string(line), nil
		case len(line) < sshMaxLine:
			line = append(line, b)
		}
	}
}

// endCommand ends the command or shell in Dropbear's order (check_close in common-channel.c): EOF,
// then the exit status; the channel's CLOSE follows from the caller's defer.
func endCommand(channel ssh.Channel, code int) {
	channel.CloseWrite()
	status := struct{ Status uint32 }{uint32(code)}
	channel.SendRequest("exit-status", false, ssh.Marshal(&status))
}

// showHostKey puts the served key's public part in the shell's /etc/dropbear/dropbear_ecdsa_host_key,
// so its fingerprint is the one clients see. Only the public part: the file's private number is made up.
func showHostKey(hostKey ssh.Signer) {
	if public := hostKey.PublicKey(); public.Type() == ssh.KeyAlgoECDSA256 { // the file's type
		vfs.SetHostKey(public.Marshal())
	}
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
