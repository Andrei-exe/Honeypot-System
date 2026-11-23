package vfs

import "testing"

// The colors BusyBox ls gives each kind of file (ls.c, checked on the real one through script, a tty).
func blue(name string) string    { return "\x1b[1;34m" + name + "\x1b[m" } // directory
func cyan(name string) string    { return "\x1b[1;36m" + name + "\x1b[m" } // link
func green(name string) string   { return "\x1b[1;32m" + name + "\x1b[m" } // program
func magenta(name string) string { return "\x1b[1;35m" + name + "\x1b[m" } // device
func plain(name string) string   { return "\x1b[0;0m" + name + "\x1b[m" }  // file

// ls looks at where its output goes, like BusyBox's (isatty): on a terminal (Telnet, SSH with a pty)
// its names are in colored columns; into a |, a file, a $(...), or an SSH session without a pty, one
// per line and plain. --color, -C / -x / -1 / -l and LS_COLORS change that like on the real one.
func TestLsTerminal(t *testing.T) {
	fixedClock(t)
	const etc = "dropbear group hostapd.conf hostname hosts issue.net lighttpd os-release passwd ppp profile resolv.conf shadow shells vsftpd.conf"
	tests := []struct{ line, want string }{
		// on the terminal: colors by kind, the columns as wide as the names on the screen
		{"ls /var/www", plain("index.html") + "  " + green("login.cgi") + "\n"},
		{"ls -d /tmp /dev/null /bin/sh", cyan("/bin/sh") + "    " + magenta("/dev/null") + "  " + blue("/tmp") + "\n"}, // sorted
		{"ls -l /bin/sh", "lrwxrwxrwx    1 root     root             7 Jun  4  2020 " + cyan("/bin/sh") + " -> " + green("busybox") + "\n"},
		{"ls -l /etc/os-release", "lrwxrwxrwx    1 root     root            21 Jun  4  2020 " + cyan("/etc/os-release") + " -> " + plain("../usr/lib/os-release") + "\n"},
		{"ls --color=never /var", "log    run    spool  tmp    www\n"},
		{"LS_COLORS=none; ls -d /tmp", blue("/tmp") + "\n"},        // not exported: ls doesn't see it
		{"export LS_COLORS=none; ls -d /tmp", "/tmp\n"},            // exported: no colors
		{"export LS_COLORS=; ls -d /tmp", "/tmp\n"},                // set but empty: no colors either
		{"export LS_COLORS=di=1; ls -d /tmp", blue("/tmp") + "\n"}, // anything else: the built-in colors

		// not a terminal: one name per line, plain
		{"ls /var | cat", "log\nrun\nspool\ntmp\nwww\n"},
		{"echo $(ls /var)", "log run spool tmp www\n"},
		{"ls /var > /tmp/l; cat /tmp/l", "log\nrun\nspool\ntmp\nwww\n"},
		{"{ ls -d /tmp; } | cat; (ls -d /tmp) > /tmp/o; cat /tmp/o", "/tmp\n/tmp\n"},
		{"ls -d /tmp >&2", blue("/tmp") + "\n"},                          // the errors' descriptor is the terminal too
		{"ls -d /tmp | cat; ls -d /tmp", "/tmp\n" + blue("/tmp") + "\n"}, // after the pipe, the terminal again
		{"ls -C /var | cat", "log    run    spool  tmp    www\n"},
		{"ls --color=al -d /tmp | cat", blue("/tmp") + "\n"}, // "always", even into a pipe
		{"ls --color=auto -d /tmp | cat", "/tmp\n"},
		{"ls -x /etc | cat; ls -C /etc | cat", // across, then down: 5 columns of 14
			"dropbear      group         hostapd.conf  hostname      hosts\n" +
				"issue.net     lighttpd      os-release    passwd        ppp\n" +
				"profile       resolv.conf   shadow        shells        vsftpd.conf\n" +
				"dropbear      hostname      lighttpd      ppp           shadow\n" +
				"group         hosts         os-release    profile       shells\n" +
				"hostapd.conf  issue.net     passwd        resolv.conf   vsftpd.conf\n"},
		{"for f in $(ls /etc); do echo -n $f' '; done", etc + " "},
		{"ls /var | grep -c .; ls /var | grep -x run", "5\nrun\n"}, // a line per name, as scripts count and match them

		// of -C -x -1 -l, the later wins: -lC = columns, -1l = long
		{"ls -lC --color=never /var", "log    run    spool  tmp    www\n"},
		{"ls -1l --color=never /var/run", "total 8\n-rw-r--r--    1 root     root             4 Nov 18 09:15 dropbear.pid\n" +
			"-rw-r--r--    1 root     root             4 Nov 18 09:15 lighttpd.pid\n"},
	}
	for _, tt := range tests {
		if got, _, _ := NewShell().Run(tt.line); got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}

	// SSH: the terminal is the pty's, exec or not
	for _, tt := range []struct {
		pty, exec bool
		want      string
	}{
		{false, false, "log\nrun\nspool\ntmp\nwww\n"},
		{false, true, "log\nrun\nspool\ntmp\nwww\n"}, // ssh host ls
		{true, true, blue("log") + "    " + blue("run") + "    " + blue("spool") + "  " + blue("tmp") + "    " + blue("www") + "\n"}, // ssh -t host ls
	} {
		if got, _, _ := NewSSHShell("root", nil, tt.pty, tt.exec).Run("ls /var"); got != tt.want {
			t.Errorf("SSH pty %v exec %v: %q, want %q", tt.pty, tt.exec, got, tt.want)
		}
	}

	if got := paint("x", ""); got != "\x1b[1;31mx\x1b[m" { // a link to nothing: stat failed
		t.Errorf("a broken link's color: %q", got)
	}
}
