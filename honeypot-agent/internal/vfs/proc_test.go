package vfs

import (
	"strconv"
	"strings"
	"testing"
)

// /proc has a folder for each process ps shows, in a 4.14 kernel's formats (fs/proc/array.c, base.c);
// /proc/self is the command running. The shell's side (links, cd, ls, writes, running exe) is compared
// with the real BusyBox 1.30.1 ash.
func TestProc(t *testing.T) {
	fixedClock(t)
	const init1 = "Name:\tinit\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t1\nNgid:\t0\nPid:\t1\nPPid:\t0\nTracerPid:\t0\n" +
		"Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t32\nGroups:\t \nNStgid:\t1\nNSpid:\t1\nNSpgid:\t1\nNSsid:\t1\n" +
		"VmPeak:\t    1516 kB\nVmSize:\t    1516 kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t     840 kB\n" +
		"VmRSS:\t     840 kB\nRssAnon:\t     208 kB\nRssFile:\t     632 kB\nRssShmem:\t       0 kB\nVmData:\t     712 kB\n" +
		"VmStk:\t     132 kB\nVmExe:\t     264 kB\nVmLib:\t     328 kB\nVmPTE:\t       8 kB\nVmPMD:\t       0 kB\n" +
		"VmSwap:\t       0 kB\nThreads:\t1\nSigQ:\t0/972\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n" +
		"SigBlk:\t0000000000000000\nSigIgn:\t0000000000000000\nSigCgt:\t0000000000000000\nCapInh:\t0000000000000000\n" +
		"CapPrm:\t0000003fffffffff\nCapEff:\t0000003fffffffff\nCapBnd:\t0000003fffffffff\nCapAmb:\t0000000000000000\n" +
		"NoNewPrivs:\t0\nSpeculation_Store_Bypass:\tunknown\nCpus_allowed:\t1\nCpus_allowed_list:\t0\n" +
		"voluntary_ctxt_switches:\t792\nnonvoluntary_ctxt_switches:\t37\n"
	tests := []struct{ line, want string }{
		// the folders, as ls shows them (digits sort first); self is a link to the command looking
		{"ls /proc", "1        341      362      517      loadavg  self     version\n" +
			"289      349      377      530      meminfo  sys\n" +
			"291      356      402      cpuinfo  mounts   uptime\n"},
		{"ls /proc/1 | wc -l; ls /proc/self | wc -l", "35\n35\n"}, // ls follows a named link to a folder...
		{"ls -l /proc/self /proc/1/exe /proc/341/exe /proc/517/cwd /proc/1/root",
			"lrwxrwxrwx    1 root     root             0 Nov 18 09:15 /proc/1/exe -> /bin/busybox\n" +
				"lrwxrwxrwx    1 root     root             0 Nov 18 09:15 /proc/1/root -> /\n" +
				"lrwxrwxrwx    1 root     root             0 Nov 18 09:15 /proc/341/exe -> /usr/sbin/dropbear\n" +
				"lrwxrwxrwx    1 root     root             0 Nov 18 09:15 /proc/517/cwd -> /root\n" +
				"lrwxrwxrwx    1 root     root             0 Nov 18 09:15 /proc/self -> 530\n"}, // ...but -l shows the link
		{"ls -ld /proc/self/ /proc/1", // a slash at the end goes through the link; 2 + 6 folders, the links not counted
			"dr-xr-xr-x    8 root     root             0 Nov 18 09:15 /proc/1\n" +
				"dr-xr-xr-x    8 root     root             0 Nov 18 09:15 /proc/self/\n"},
		{"ls -l /proc/1 | grep -E ' (fd|environ|mem|clear_refs|timerslack_ns|comm)$'",
			"--w-------    1 root     root             0 Nov 18 09:15 clear_refs\n" +
				"-rw-r--r--    1 root     root             0 Nov 18 09:15 comm\n" +
				"-r--------    1 root     root             0 Nov 18 09:15 environ\n" +
				"dr-x------    2 root     root             0 Nov 18 09:15 fd\n" +
				"-rw-------    1 root     root             0 Nov 18 09:15 mem\n" +
				"-rw-rw-rw-    1 root     root             0 Nov 18 09:15 timerslack_ns\n"},
		{"cd /proc/self; pwd; cd fd; pwd; cd ..; ls -d cmdline", "/proc/self\n/proc/self/fd\ncmdline\n"}, // cd -L, like ash
		{"cat /proc/1/root/etc/hostname /proc/self/root/proc/self/comm", "gateway\ncat\n"},               // links on the way

		// cmdline: the arguments, each ended by a NUL; comm: the program's file name
		{"cat /proc/341/cmdline", "/usr/sbin/dropbear\x00-F\x00-P\x00/var/run/dropbear.pid\x00-p\x0022\x00"},
		{"cat /proc/self/cmdline | tr '\\0' ' '; echo", "cat /proc/self/cmdline \n"}, // self = the command reading it
		{"/bin/busybox cat /proc/self/comm /proc/517/comm /proc/1/comm", "busybox\nsh\ninit\n"},
		{"cat /proc/self/stat | cut -d' ' -f1-8", "530 (cat) R 517 530 517 34816 530\n"}, // on the terminal, its own group
		{"cat /proc/517/stat | cut -d' ' -f1-9,22-24", "517 (sh) S 356 517 517 34816 530 4194560 17730000 1331200 228\n"},
		{"for p in /proc/[0-9]*; do grep -q dropbear $p/cmdline && echo ${p#/proc/}; done", "341\n"}, // a killer's loop
		{"echo /proc/5*; read c < /proc/self/comm; echo $c", "/proc/517\nsh\n"},                      // between commands: only the shell
		{"echo /proc/self/cm*; cd /proc/self; ls -l | grep -c ^l", "/proc/self/cmdline\n3\n"},        // in the link: exe cwd root
		{"ls --color=always /proc/self | grep -c '1;34m'", "6\n"},                                    // its folders in blue: task fd map_files fdinfo ns net
		{"grep Groups /proc/self/status /proc/1/status", "/proc/self/status:Groups:\t0 10 \n/proc/1/status:Groups:\t \n"},
		{"cat /proc/1/status", init1},
		{"cat /proc/349/statm /proc/349/oom_score /proc/1/oom_score /proc/1/oom_adj /proc/1/coredump_filter",
			"527 309 232 44 0 365 0\n9\n0\n0\n00000033\n"},
		{"cat /proc/341/wchan /proc/self/wchan; echo", "poll_schedule_timeout0\n"}, // no newline; 0 = running
		{"cat /proc/1/environ; echo; cat /proc/289/environ", "HOME=/\x00TERM=linux\x00\n" +
			"HOME=/\x00TERM=linux\x00PATH=/sbin:/usr/sbin:/bin:/usr/bin\x00SHELL=/bin/sh\x00USER=root\x00"},
		{"export X=1; cat /proc/self/environ | tr '\\0' '\\n' | grep -c ^X=1$", "1\n"}, // what the command got
		{"head -2 /proc/1/limits", "Limit                     Soft Limit           Hard Limit           Units     \n" +
			"Max cpu time              unlimited            unlimited            seconds   \n"},
		{"grep nice /proc/1/limits", "Max nice priority         0                    0                    \n"}, // no unit
		{"cmp() { [ \"$(cat $1)\" = \"$(cat $2)\" ] && echo same; }; cmp /proc/mounts /proc/1/mounts", "same\n"},
		{"cat /proc/1/maps /proc/1/auxv | wc -c", "0\n"}, // not simulated: empty

		// writes: the files with a write handler take one (nothing changes), the others refuse (EINVAL)
		{"echo 5 > /proc/1/stat; echo 5 > /proc/1/cmdline", "sh: write error: Invalid argument\nsh: write error: Invalid argument\n"},
		{"echo -500 > /proc/self/oom_score_adj; echo $?; echo x > /proc/1/comm; echo $?", "0\n0\n"},
		{"echo x > /proc/1/mem", "sh: write error: Input/output error\n"},
		{"echo > /proc/1/new; echo > /proc/self", "-sh: can't create /proc/1/new: nonexistent directory\n" +
			"-sh: can't create /proc/self: Is a directory\n"},

		// exe runs busybox under the name "exe", which no applet has
		{"/proc/1/exe; echo $?", "exe: applet not found\n127\n"},
		{"(unset PATH; /bin/ls -d /tmp; echo $?)", "/tmp\n0\n"}, // a path needs no $PATH

		{"ps", "  PID USER       VSZ STAT COMMAND\n" +
			"    1 root      1516 S    /sbin/init\n" +
			"  289 root      1032 S    /sbin/syslogd -n\n" +
			"  291 root      1032 S    /sbin/klogd -n\n" +
			"  341 root      1124 S    /usr/sbin/dropbear -F -P /var/run/dropbear.pid -p 22\n" +
			"  349 root      2108 S    /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf\n" +
			"  356 root      1032 S    /usr/sbin/telnetd -F -l /bin/login\n" +
			"  362 root      1840 S    /usr/sbin/hostapd -B /etc/hostapd.conf\n" +
			"  377 root      1216 S    /usr/sbin/pppd call isp\n" +
			"  402 root      1208 S    /usr/sbin/vsftpd\n" +
			"  517 root      1300 S    -sh\n" +
			"  530 root      1296 R    ps\n"},
	}
	for _, tt := range tests {
		if got, _, _ := noColors().Run(tt.line); got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}

	// SSH without a pty: no terminal, no job control (the command stays in the shell's group)
	if got, _, _ := NewSSHShell("root", nil, false, false).Run("cut -d' ' -f1-8 /proc/self/stat"); got != "530 (cut) R 517 517 517 0 -1\n" {
		t.Errorf("SSH without a pty: %q", got)
	}

	// FTP sees the same folders, and follows /proc/self
	if names := ReadDir("/proc"); len(names) != 18 || names[0] != "1" {
		t.Errorf("FTP's /proc: %q", names)
	}
	if f, ok := Stat("/proc/self"); !ok || f.Mode != "dr-xr-xr-x" {
		t.Errorf("FTP's /proc/self: %+v %v", f, ok)
	}
}

// Every process agrees with ps and with itself: VSZ = VmSize = stat's vsize, the command line, and the
// addresses of the arguments and environment in stat fit their lengths. /proc/loadavg counts them.
func TestProcMatchesPs(t *testing.T) {
	sh := NewShell()
	ps, _, _ := sh.Run("ps")
	sh.argv = []string{"ps"} // as if ps were reading: 530 is the command running
	lines := strings.Split(strings.TrimSuffix(ps, "\n"), "\n")[1:]
	if len(lines) != len(processes) || !strings.Contains(fakeFiles["/proc/mounts"], "proc /proc") {
		t.Fatalf("ps shows %d processes, /proc has %d", len(lines), len(processes))
	}
	if load, _ := sh.readFile("/proc/loadavg"); !strings.HasSuffix(load, " 1/"+strconv.Itoa(len(processes))+" 530\n") {
		t.Errorf("/proc/loadavg: %q", load)
	}
	for i, p := range processes {
		dir := "/proc/" + strconv.Itoa(p.pid) + "/"
		ps := strings.Fields(lines[i])
		status, _ := sh.readFile(dir + "status")
		stat, _ := sh.readFile(dir + "stat")
		cmdline, _ := sh.readFile(dir + "cmdline")
		environ, _ := sh.readFile(dir + "environ")
		f := strings.Fields(stat)
		vsize, _ := strconv.Atoi(f[22])

		if !strings.Contains(status, "\nVmSize:\t"+strings.Repeat(" ", 8-len(ps[2]))+ps[2]+" kB\n") || vsize != p.vsz*1024 ||
			strconv.Itoa(p.vsz) != ps[2] {
			t.Errorf("%d: VSZ %s, status %q, stat %d", p.pid, ps[2], status, vsize)
		}
		if strings.Join(ps[4:], " ") != strings.ReplaceAll(strings.TrimSuffix(cmdline, "\x00"), "\x00", " ") {
			t.Errorf("%d: ps %q, cmdline %q", p.pid, ps[4:], cmdline)
		}
		if f[0] != strconv.Itoa(p.pid) || f[3] != strconv.Itoa(p.ppid) || len(f) != 52 {
			t.Errorf("%d: stat %q", p.pid, stat)
		}
		n := func(i int) int { v, _ := strconv.Atoi(f[i]); return v }
		if n(48)-n(47) != len(cmdline) || n(48) != n(49) || n(50)-n(49) != len(environ) {
			t.Errorf("%d: arg %d-%d, env %d-%d for %q, %q", p.pid, n(47), n(48), n(49), n(50), cmdline, environ)
		}
	}
}
