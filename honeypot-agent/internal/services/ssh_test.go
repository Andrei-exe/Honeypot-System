package services

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"honeypot-agent/internal/shipper"
	"honeypot-agent/internal/vfs"
)

// newTestKey makes a throwaway ECDSA key in memory (RunSSH would write the host key to disk).
func newTestKey(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// sshDial logs in as root with password, the way a bot does. It also returns the login methods
// the server offered (the list it sends back after the client's first, empty "none" attempt).
func sshDial(addr, password string) (client *ssh.Client, offered []string, err error) {
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		// called before every login attempt; AllowedMethods = what the server offers.
		// Returning nil, nil means "carry on normally with Auth".
		AuthCallback: func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			if offered == nil {
				offered = slices.Clone(ctx.AllowedMethods)
			}
			return nil, nil
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test only: the server key is a throwaway one
		Timeout:         5 * time.Second,
	}
	client, err = ssh.Dial("tcp", addr, config)
	return client, offered, err
}

// checkOfferedMethods: exactly what Dropbear offers, publickey + password. keyboard-interactive
// (OpenSSH has it, Dropbear doesn't) would give the persona away.
func checkOfferedMethods(t *testing.T, offered []string) {
	t.Helper()
	sorted := slices.Sorted(slices.Values(offered)) // the order is chosen by x/crypto, not by us
	if !slices.Equal(sorted, []string{"password", "publickey"}) {
		t.Errorf("offered login methods: %v (expected publickey and password, like Dropbear)", offered)
	}
}

// readServerKexInit does what a scanner does: it sends a version line, then reads the server's
// first binary packet (KEXINIT, not encrypted yet) and returns its 10 algorithm lists as sent.
func readServerKexInit(t *testing.T, addr string) []string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "SSH-2.0-scanner\r\n")
	r := bufio.NewReader(conn)
	readUntil(t, r, "\r\n") // the server's version line

	// packet = length (4 bytes) | padding length (1) | payload | padding
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, length)
	if _, err := io.ReadFull(r, packet); err != nil {
		t.Fatal(err)
	}
	payload := packet[1 : len(packet)-int(packet[0])]
	if payload[0] != 20 { // SSH_MSG_KEXINIT
		t.Fatalf("first message type %d, expected KEXINIT (20)", payload[0])
	}

	// after the type byte and a 16-byte random cookie: 10 name-lists, each length (4) + text
	p := payload[17:]
	var lists []string
	for range 10 {
		n := binary.BigEndian.Uint32(p)
		lists = append(lists, string(p[4:4+n]))
		p = p[4+n:]
	}
	return lists
}

// The algorithm lists must be Dropbear 2019.78's (as Buildroot 2019.05.3 builds it), in its order:
// that's what scanners fingerprint. Only kex-strict-s-v00 is extra (x/crypto always adds it).
func TestSSHAlgorithmsLikeDropbear(t *testing.T) {
	s := shipper.NewShipper(io.Discard, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

	lists := readServerKexInit(t, addr)
	want := []string{
		// key exchange: Dropbear's list (without its kexguess2@matt.ucc.asn.au) + x/crypto's kex-strict
		"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384," +
			"ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1," +
			"kex-strict-s-v00@openssh.com",
		"ecdsa-sha2-nistp256",                            // host key: no ed25519 (Dropbear 2020.79+)
		"aes128-ctr,aes256-ctr", "aes128-ctr,aes256-ctr", // ciphers, both directions
		"hmac-sha1,hmac-sha2-256", "hmac-sha1,hmac-sha2-256", // MACs
		"none", "none", // compression (Buildroot's "small" Dropbear has no zlib)
		"", "", // languages
	}
	for i := range want {
		if lists[i] != want[i] {
			t.Errorf("list %d:\n got: %s\nwant: %s", i, lists[i], want[i])
		}
	}
	waitDone(t, done)
}

// ssh root@host "command" ends with the command's real exit code (127 = not found), like Dropbear.
// One connection per command: the server serves one session per connection.
func TestSSHExitCodes(t *testing.T) {
	tests := []struct {
		command string
		want    int
	}{
		{"uname -m", 0},
		{"nosuchcmd", 127},
		{"curl http://203.0.113.7/x.sh", 127}, // BusyBox has no curl
		{"cat /missing", 1},
		{"false && echo never", 1},
	}
	for _, tt := range tests {
		s := shipper.NewShipper(io.Discard, "", "")
		hostKey := newTestKey(t)
		addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

		client, _, err := sshDial(addr, "root")
		if err != nil {
			t.Fatal(err)
		}
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		code := 0
		var exitErr *ssh.ExitError // what Run returns when the exit status isn't 0
		if err := session.Run(tt.command); errors.As(err, &exitErr) {
			code = exitErr.ExitStatus()
		} else if err != nil {
			t.Errorf("%s: %v", tt.command, err)
		}
		if code != tt.want {
			t.Errorf("%q: exit code %d, want %d", tt.command, code, tt.want)
		}
		client.Close()
		waitDone(t, done)
	}
}

// Like Dropbear (MAX_CMD_LEN 9000): a longer exec command is refused (nothing runs, nothing is
// logged) and the client may try again on the same channel; exactly 9000 bytes still runs.
func TestSSHLongCommand(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

	client, _, err := sshDial(addr, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Run("echo " + strings.Repeat("a", dropbearMaxCmdLen-4)); err == nil {
		t.Error("a 9001-byte command was accepted")
	}
	command := "echo " + strings.Repeat("b", dropbearMaxCmdLen-5) // exactly 9000 bytes
	output, err := session.Output(command)
	if err != nil || string(output) != command[5:]+"\n" {
		t.Errorf("9000-byte command after the refused one: %d bytes, %v", len(output), err)
	}
	client.Close()
	waitDone(t, done)

	commands := ofType(parseEvents(t, out.String()), "command_exec")
	if len(commands) != 1 || commands[0].PayloadDetails.Command != command {
		t.Errorf("%d command_exec events (expected only the 9000-byte one)", len(commands))
	}
}

// Like Dropbear: a username or password over 100 bytes is refused without being checked, and not
// logged (one login could put ~256KB into an event). 100 bytes is still a normal, logged attempt.
func TestSSHLongLogin(t *testing.T) {
	long := strings.Repeat("x", dropbearMaxLogin)
	tests := []struct {
		user, password string
		logged         bool
	}{
		{"root", long, true},
		{"root", long + "x", false},
		{long + "x", "root", false}, // the right password, but never checked
	}
	for _, tt := range tests {
		var out bytes.Buffer
		s := shipper.NewShipper(&out, "", "")
		hostKey := newTestKey(t)
		addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

		config := &ssh.ClientConfig{
			User:            tt.user,
			Auth:            []ssh.AuthMethod{ssh.Password(tt.password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test only: the server key is a throwaway one
			Timeout:         5 * time.Second,
		}
		if client, err := ssh.Dial("tcp", addr, config); err == nil {
			client.Close()
			t.Errorf("user of %d bytes, password of %d: accepted", len(tt.user), len(tt.password))
		}
		waitDone(t, done)

		logins := ofType(parseEvents(t, out.String()), "login_attempt")
		if tt.logged && (len(logins) != 1 || logins[0].Credentials.Password != tt.password) ||
			!tt.logged && len(logins) != 0 {
			t.Errorf("user of %d bytes, password of %d: %d login_attempt events (logged: %v)",
				len(tt.user), len(tt.password), len(logins), tt.logged)
		}
	}
}

// After a command, like Dropbear, the server keeps the connection until the client closes it (a
// server that hangs up first makes OpenSSH print "Connection to X closed by remote host.").
func TestSSHWaitsForClientToClose(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

	client, _, err := sshDial(addr, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if output, err := session.Output("uname -m"); err != nil || string(output) != "armv7l\n" {
		t.Fatalf("exec: %q, %v", output, err)
	}
	select {
	case <-done:
		t.Fatal("the server closed the connection after the command, before the client did")
	case <-time.After(300 * time.Millisecond):
	}
	client.Close() // now the server's side ends too
	waitDone(t, done)
	checkSession(t, parseEvents(t, out.String()), "SSH", 22)
}

// Like Dropbear: 10 wrong passwords per connection (rejected public keys don't count), each answered
// after ~300ms; at the 10th the server just closes, without x/crypto's (OpenSSH's) disconnect message.
func TestSSHMaxAuthTries(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

	var keys []ssh.Signer // more keys than the limit: if they counted, no password would be tried
	for range 12 {
		keys = append(keys, newTestKey(t))
	}
	tries := 0
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(keys...),
			ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
				tries++
				return fmt.Sprintf("wrong%d", tries), nil
			}), 50),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test only: the server key is a throwaway one
		Timeout:         10 * time.Second,
	}
	start := time.Now()
	client, err := ssh.Dial("tcp", addr, config)
	took := time.Since(start)
	if err == nil {
		client.Close()
		t.Fatal("wrong passwords were accepted")
	}
	if strings.Contains(err.Error(), "disconnect") {
		t.Errorf("the server sent a disconnect message (Dropbear just closes): %v", err)
	}
	waitDone(t, done)

	// Dropbear's numbers, not our constants (a changed constant must fail here)
	logins := ofType(parseEvents(t, out.String()), "login_attempt")
	if tries != 10 || len(logins) != 10 {
		t.Errorf("%d passwords tried, %d login_attempt events (expected 10, Dropbear's MAX_AUTH_TRIES)", tries, len(logins))
	}
	if took < 10*250*time.Millisecond || took > 10*350*time.Millisecond+time.Second {
		t.Errorf("10 wrong passwords took %v (expected 10 x 300ms +-50)", took)
	}
}

// The channel requests Dropbear 2019.78 accepts as Buildroot builds it (chansessionrequest), and env,
// which it has no handler for.
func TestSSHRequestsLikeDropbear(t *testing.T) {
	s := shipper.NewShipper(io.Discard, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

	client, _, err := sshDial(addr, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	pty := func(term string) []byte { // what ssh -t sends: TERM, columns, rows, pixels, terminal modes
		return ssh.Marshal(struct {
			Term                         string
			Columns, Rows, Width, Height uint32
			Modes                        string
		}{term, 80, 24, 0, 0, "\x00"})
	}
	for _, tt := range []struct {
		request string
		payload []byte
		want    bool
	}{
		{"env", nil, false},
		{"pty-req", pty(strings.Repeat("x", 201)), false}, // Dropbear's MAX_TERM_LEN is 200
		{"pty-req", pty("xterm"), true},
		{"window-change", nil, true},
		{"x11-req", nil, true},                    // ssh -X: accepted, nothing is ever forwarded
		{"auth-agent-req@openssh.com", nil, true}, // ssh -A: the same
		{"break", nil, false},
	} {
		if ok, err := session.SendRequest(tt.request, true, tt.payload); err != nil || ok != tt.want {
			t.Errorf("%s: accepted %v, %v (expected %v)", tt.request, ok, err, tt.want)
		}
	}
	// a command on the pty: one stream with \r\n, TERM from the request; sh -c isn't interactive ($- empty)
	if output, err := session.Output("echo $TERM $SSH_TTY $-"); err != nil || string(output) != "xterm /dev/pts/0\r\n" {
		t.Errorf("exec after the requests: %q, %v", output, err)
	}
	client.Close()
	waitDone(t, done)
}

// The host key is created once and then read back: same key = same fingerprint after a restart.
func TestHostKeyIsKeptOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), sshHostKeyFile)
	first, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKey().Type() != "ecdsa-sha2-nistp256" {
		t.Errorf("host key type %s, expected ecdsa-sha2-nistp256", first.PublicKey().Type())
	}
	if !bytes.Equal(first.PublicKey().Marshal(), again.PublicKey().Marshal()) {
		t.Error("the second start made a new key: the fingerprint would change")
	}
}

// Wrong password: refused, logged, and the session still ends with session_end.
func TestSSHWrongPassword(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

	client, offered, err := sshDial(addr, "wrong")
	if err == nil {
		client.Close()
		t.Fatal("a wrong password was accepted")
	}
	checkOfferedMethods(t, offered)
	waitDone(t, done)

	events := parseEvents(t, out.String())
	checkSession(t, events, "SSH", 22)
	logins := ofType(events, "login_attempt")
	if len(logins) != 1 || logins[0].Credentials.Username != "root" ||
		logins[0].Credentials.Password != "wrong" || logins[0].Credentials.Success {
		t.Errorf("login_attempt events: %+v", logins)
	}
}

// Like Dropbear's AUTH_TIMEOUT (1s here): the login must be done in time from the connection,
// whatever the client does meanwhile. Rejected public keys don't count as tries, so a client
// offering a new key every 200ms would otherwise keep the connection forever.
func TestSSHAuthTimeout(t *testing.T) {
	old := sshAuthTimeout
	sshAuthTimeout = time.Second
	t.Cleanup(func() { sshAuthTimeout = old })

	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

	slowKeys := ssh.RetryableAuthMethod(ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		time.Sleep(200 * time.Millisecond)
		return []ssh.Signer{newTestKey(t)}, nil // a new key every time
	}), 50) // 10s of keys, if nothing cut it
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	start := time.Now()
	_, _, _, err = ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User: "root", Auth: []ssh.AuthMethod{slowKeys}, HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err == nil {
		t.Fatal("logged in with a public key")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("offering keys kept the connection for %v (expected closed after 1s)", took)
	}
	waitDone(t, done)
	events := parseEvents(t, out.String())
	checkSession(t, events, "SSH", 22)
	if logins := ofType(events, "login_attempt"); len(logins) != 0 {
		t.Errorf("public keys were logged as login attempts: %+v", logins)
	}
}

// In the interactive shell too, commands sent all at once are answered one by one, 200-300ms
// apart (pacer), and none is lost.
func TestSSHShellCommandsArePaced(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

	client, _, err := sshDial(addr, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	fmt.Fprint(stdin, strings.Repeat("echo x\n", 5)+"exit\n")     // 6 lines in one write (no pty: \n)
	io.ReadAll(stdout)                                            // until the shell exits
	if took := time.Since(start); took < 5*200*time.Millisecond { // the first runs at once, then 5 waits
		t.Errorf("6 commands sent at once took %v (expected at least 1s)", took)
	}
	client.Close()
	waitDone(t, done)
	if n := len(ofType(parseEvents(t, out.String()), "command_exec")); n != 6 {
		t.Errorf("%d command_exec events (expected 6)", n)
	}
}

// sshRun opens a session on a new connection to the honeypot (PUBLIC_IP 198.51.100.7), lets setup start it,
// and returns what came on stdout and stderr and the exit status. The client's port goes in for "PORT".
func sshRun(t *testing.T, setup func(*ssh.Session, io.WriteCloser) error) (stdout, stderr string, code int, port string) {
	t.Helper()
	s := shipper.NewShipper(io.Discard, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "198.51.100.7", s) })
	client, _, err := sshDial(addr, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	session.Stdout, session.Stderr = &out, &errs
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := setup(session, stdin); err != nil {
		t.Fatal(err)
	}
	err = session.Wait()
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitStatus()
	} else if err != nil {
		t.Fatal(err)
	}
	_, port, _ = net.SplitHostPort(client.LocalAddr().String())
	client.Close()
	waitDone(t, done)
	return out.String(), errs.String(), code, port
}

// No pty (ssh -T, bots that skip pty-req): Dropbear's login shell "-sh" reads its input, without prompt
// or echo; the errors come apart (extended data). It ends at EOF with the last command's code, at exit,
// or by itself at an error that ends a line (ash isn't interactive). Measured on the real ash.
func TestSSHShellWithoutPTY(t *testing.T) {
	for _, tt := range []struct {
		input          string
		eof            bool // the client closes its side after the input
		stdout, stderr string
		code           int
	}{
		{"echo $0 $- $LINENO $SSH_CONNECTION\nnosuch\n\ncd /nope\necho y\nfalse", true, // no \n at the end
			"-sh s 1 127.0.0.1 PORT 198.51.100.7 22\ny\n",
			"-sh: nosuch: not found\n-sh: cd: line 4: can't cd to /nope: No such file or directory\n", 1},
		{"echo a\necho ${x?unset}\necho never\n", false, "a\n", "-sh: x: unset\n", 2},
		{"echo a; exit 3\necho never\n", false, "a\n", "", 3},
		{"echo $TERM$SSH_TTY. $PS1 $SSH_CLIENT; history", true, ". \\u@\\h:\\w\\$ 127.0.0.1 PORT 22\n", "", 0},
		// a command on several lines waits for them; one not finished at EOF is a syntax error (code 2)
		{"for i in 1 2\ndo\necho $i\ndone\necho $LINENO\n", true, "1\n2\n5\n", "", 0},
		{"echo a\nfor i in 1; do\n", true, "a\n", "-sh: syntax error: unexpected end of file\n", 2},
	} {
		stdout, stderr, code, port := sshRun(t, func(session *ssh.Session, stdin io.WriteCloser) error {
			if err := session.Shell(); err != nil {
				return err
			}
			fmt.Fprint(stdin, tt.input)
			if tt.eof {
				stdin.Close()
			}
			return nil
		})
		if want := strings.ReplaceAll(tt.stdout, "PORT", port); stdout != want || stderr != tt.stderr || code != tt.code {
			t.Errorf("%q\n got: %q %q, exit %d\nwant: %q %q, exit %d", tt.input, stdout, stderr, code, want, tt.stderr, tt.code)
		}
	}
}

// With a pty (ssh, ssh -t): the interactive login shell, prompt and echo, one stream with \r\n,
// TERM from the request and SSH_TTY; exit N ends it with N.
func TestSSHShellWithPTY(t *testing.T) {
	stdout, stderr, code, _ := sshRun(t, func(session *ssh.Session, stdin io.WriteCloser) error {
		if err := session.RequestPty("vt100", 24, 80, ssh.TerminalModes{}); err != nil {
			return err
		}
		if err := session.Shell(); err != nil {
			return err
		}
		fmt.Fprint(stdin, "echo $TERM $SSH_TTY $-\rnosuch\rfor i in 1 2\rdo echo n$i; done\rexit 4\r")
		return nil
	})
	// a command not finished waits for its next line with $PS2 ("> ")
	for _, want := range []string{"root@gateway:~# ", "vt100 /dev/pts/0 smi\r\n", "-sh: nosuch: not found\r\n",
		"for i in 1 2\r\n> do echo n$i; done\r\nn1\r\nn2\r\nroot@gateway:~# "} {
		if !strings.Contains(stdout, want) {
			t.Errorf("no %q in %q", want, stdout)
		}
	}
	if stderr != "" || code != 4 {
		t.Errorf("stderr %q, exit %d (expected none, 4)", stderr, code)
	}
}

// exec without a pty (ssh host CMD): sh -c CMD, without /etc/profile; the errors apart, with "line N:".
// The host key file in the shell starts with the public key the client was really served (its
// fingerprint matches), and ends with a private number that is not the server's.
func TestSSHHostKeyFileMatchesServedKey(t *testing.T) {
	t.Cleanup(func() { vfs.SetHostKey(nil) })
	hostKey := newTestKey(t)
	showHostKey(hostKey)

	s := shipper.NewShipper(io.Discard, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })
	var seen []byte
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.Password("root")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key.Marshal() // what ssh-keyscan and the fingerprint come from
			return nil
		},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	file, err := session.Output("cat /etc/dropbear/dropbear_ecdsa_host_key")
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	waitDone(t, done)

	if len(seen) == 0 || !bytes.HasPrefix(file, seen) {
		t.Errorf("the key file starts with %x\n           served key %x", file[:min(len(file), len(seen))], seen)
	}
	if len(file) < len(seen)+4+31 || len(file) > len(seen)+4+33 { // + the private number: an mpint of 31-33 bytes
		t.Errorf("key file of %d bytes", len(file))
	}

	// a key of another type never goes in the ECDSA file: it keeps its made-up ECDSA key
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := ssh.NewSignerFromKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	vfs.SetHostKey(nil)
	before, _, _ := vfs.NewShell().Run("cat /etc/dropbear/dropbear_ecdsa_host_key")
	showHostKey(edSigner)
	if after, _, _ := vfs.NewShell().Run("cat /etc/dropbear/dropbear_ecdsa_host_key"); after != before {
		t.Errorf("an ed25519 key went into the ECDSA key file: %x", after)
	}
}

func TestSSHExecWithoutPTY(t *testing.T) {
	stdout, stderr, code, _ := sshRun(t, func(session *ssh.Session, _ io.WriteCloser) error {
		return session.Start("echo $0 $-; nosuch; cd /nope; echo $PS1; exit 5")
	})
	if stdout != "sh\n\\w \\$\n" || code != 5 ||
		stderr != "sh: nosuch: not found\nsh: cd: line 1: can't cd to /nope: No such file or directory\n" {
		t.Errorf("got %q %q, exit %d", stdout, stderr, code)
	}
}

// Right password: Dropbear banner, port forwarding refused (we must never be a proxy),
// and an exec command (ssh root@host "...") runs in the fake shell.
func TestSSHSession(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", "", s) })

	client, offered, err := sshDial(addr, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	checkOfferedMethods(t, offered)

	if v := string(client.ServerVersion()); v != "SSH-2.0-dropbear_2019.78" {
		t.Errorf("server version: %q", v)
	}

	// ssh -L / -D (local forwarding, SOCKS proxy) = "direct-tcpip" channel -> refused
	if c, err := client.Dial("tcp", "203.0.113.7:80"); err == nil {
		c.Close()
		t.Error("local port forwarding was accepted")
	}
	// ssh -R (remote forwarding) = "tcpip-forward" global request -> refused
	if l, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
		l.Close()
		t.Error("remote port forwarding was accepted")
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("uname -m; cat /etc/hostname") // err != nil if the exit status isn't 0
	if err != nil || string(output) != "armv7l\ngateway\n" {
		t.Errorf("exec: %q, %v", output, err)
	}
	client.Close()
	waitDone(t, done)

	events := parseEvents(t, out.String())
	checkSession(t, events, "SSH", 22)

	logins := ofType(events, "login_attempt")
	if len(logins) != 1 || logins[0].Credentials.Password != "root" || !logins[0].Credentials.Success {
		t.Errorf("login_attempt events: %+v", logins)
	}
	commands := ofType(events, "command_exec")
	if len(commands) != 1 || commands[0].PayloadDetails.Command != "uname -m; cat /etc/hostname" {
		t.Errorf("command_exec events: %+v", commands)
	}
}
