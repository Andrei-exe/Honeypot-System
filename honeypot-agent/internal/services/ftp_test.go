package services

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"honeypot-agent/internal/shipper"
)

// ftpAnswer: vsftpd's exact replies, the cwd changes, and the safety rule (no data connection:
// PASV refused, PORT "accepted" but LIST/RETR/STOR always fail).
func TestFTPAnswer(t *testing.T) {
	tests := []struct {
		cmd, arg string
		cwd      string // directory before the command
		want     string
		wantCwd  string // directory after the command
	}{
		{"SYST", "", "/", "215 UNIX Type: L8", "/"},
		{"PWD", "", "/etc", `257 "/etc" is the current directory`, "/etc"},
		{"CWD", "pub", "/", "250 Directory successfully changed.", "/pub"},
		{"CWD", "/var/../etc", "/pub", "250 Directory successfully changed.", "/etc"},
		{"CWD", "..", "/", "250 Directory successfully changed.", "/"},
		{"TYPE", "I", "/", "200 Switching to Binary mode.", "/"},
		{"NOOP", "", "/", "200 NOOP ok.", "/"},
		{"PASV", "", "/", "550 Permission denied.", "/"},
		{"EPSV", "", "/", "550 Permission denied.", "/"},
		{"PORT", "203,0,113,7,4,1", "/", "200 PORT command successful. Consider using PASV.", "/"},
		{"LIST", "", "/", "425 Failed to establish connection.", "/"},
		{"RETR", "secret.txt", "/", "425 Failed to establish connection.", "/"},
		{"STOR", "bot", "/", "425 Failed to establish connection.", "/"},
		{"DELE", "x", "/", "550 Permission denied.", "/"},
		{"SITE", "EXEC id", "/", "500 Unknown command.", "/"},
	}

	for _, tt := range tests {
		cwd := tt.cwd
		got := ftpAnswer(tt.cmd, tt.arg, &cwd)
		if got != tt.want || cwd != tt.wantCwd {
			t.Errorf("%s %s (cwd %s): got %q, cwd %s\n                    want %q, cwd %s",
				tt.cmd, tt.arg, tt.cwd, got, cwd, tt.want, tt.wantCwd)
		}
	}
}

// anonymous logs in with any password (like vsftpd with anonymous_enable), everyone else
// only with the shared weakCredentials.
func TestFTPLoginOK(t *testing.T) {
	tests := []struct {
		user, pass string
		want       bool
	}{
		{"anonymous", "", true},
		{"Anonymous", "bot@example.com", true},
		{"root", "root", true},
		{"admin", "", true}, // empty password is in weakCredentials
		{"root", "wrong", false},
		{"ftp", "ftp", false},
	}
	for _, tt := range tests {
		if got := ftpLoginOK(tt.user, tt.pass); got != tt.want {
			t.Errorf("ftpLoginOK(%q, %q) = %v, want %v", tt.user, tt.pass, got, tt.want)
		}
	}
}

// A whole FTP session: commands before login are refused (but logged), anonymous login works,
// and even with PORT pointing at a listener of ours, LIST/RETR never open the data connection
// (FTP bounce: otherwise attackers could make us connect anywhere).
func TestFTPSession(t *testing.T) {
	// the would-be victim of an FTP bounce: nothing may ever connect here
	victim, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer victim.Close()
	connected := make(chan bool, 1)
	go func() {
		if c, err := victim.Accept(); err == nil {
			c.Close()
			connected <- true
		}
	}()
	port := victim.Addr().(*net.TCPAddr).Port

	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleFTP(c, "ftp-test", s) })

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)

	if banner := readUntil(t, r, "\r\n"); banner != "220 (vsFTPd 3.0.3)\r\n" {
		t.Errorf("banner: %q", banner)
	}

	portCommand := fmt.Sprintf("PORT 127,0,0,1,%d,%d", port/256, port%256) // FTP writes the port as 2 bytes
	steps := []struct{ send, want string }{
		{"SYST", "530 Please login with USER and PASS."},
		{"USER anonymous", "331 Please specify the password."},
		{"PASS bot@example.com", "230 Login successful."},
		{"PASV", "550 Permission denied."},
		{portCommand, "200 PORT command successful. Consider using PASV."},
		{"LIST", "425 Failed to establish connection."},
		{"RETR /etc/passwd", "425 Failed to establish connection."},
		{"QUIT", "221 Goodbye."},
	}
	for _, step := range steps {
		fmt.Fprint(conn, step.send+"\r\n")
		if got := readUntil(t, r, "\r\n"); got != step.want+"\r\n" {
			t.Errorf("%s: got %q, want %q", step.send, got, step.want)
		}
	}
	waitDone(t, done)

	select {
	case <-connected:
		t.Error("the FTP server connected to the PORT address (FTP bounce)")
	case <-time.After(200 * time.Millisecond):
	}

	events := parseEvents(t, out.String())
	checkSession(t, events, "FTP", 21)

	logins := ofType(events, "login_attempt")
	if len(logins) != 1 || logins[0].Credentials.Username != "anonymous" ||
		logins[0].Credentials.Password != "bot@example.com" || !logins[0].Credentials.Success {
		t.Errorf("login_attempt events: %+v", logins)
	}

	// USER, PASS and QUIT are not commands; SYST before login is logged too
	var commands []string
	for _, e := range ofType(events, "command_exec") {
		commands = append(commands, e.PayloadDetails.Command)
	}
	want := []string{"SYST", "PASV", portCommand, "LIST", "RETR /etc/passwd"}
	if !slices.Equal(commands, want) {
		t.Errorf("command_exec: %q\n           want %q", commands, want)
	}
}
