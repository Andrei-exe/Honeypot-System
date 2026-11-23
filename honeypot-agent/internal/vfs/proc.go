package vfs

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

// The processes' folders in /proc (/proc/1, /proc/341, /proc/self...), the same processes ps shows, with
// their files in a 4.14 kernel's format (fs/proc/base.c, array.c, task_mmu.c). Scripts look for rivals
// there ("for p in /proc/[0-9]*; do grep -q xmrig $p/cmdline ..."), people check what runs.

// process is one process of the router: dropbear, telnetd and vsftpd, syslogd writing /var/log/messages,
// Wi-Fi (hostapd) and the PPPoE link to the provider (pppd). Every program here exists in the files.
// 517 is the attacker's shell, 530 the command running now (ps when ps runs: it is ps's own line), so
// their files are made from the session (procFile).
type process struct {
	pid, ppid    int
	argv         []string // its command line (ps shows it with spaces)
	exe          string   // the program it runs (/proc/PID/exe): the applets are busybox
	vsz, rss     int      // kB: the memory it maps (VSZ in ps) and the RAM it uses
	exeKB, libKB int      // kB of code: its program's and its libraries' (uClibc: 328)
	start        int      // when it started: hundredths of a second after boot (517, 530: the session)
	utime, stime int      // the CPU it has used, in hundredths
	wchan        string   // the kernel function it sleeps in
}

var processes = []process{
	{1, 0, []string{"/sbin/init"}, "/bin/busybox", 1516, 840, 264, 328, 112, 18, 95, "do_wait"},
	{289, 1, []string{"/sbin/syslogd", "-n"}, "/bin/busybox", 1032, 604, 264, 328, 298, 9, 27, "skb_wait_for_more_packets"},
	{291, 1, []string{"/sbin/klogd", "-n"}, "/bin/busybox", 1032, 560, 264, 328, 301, 1, 6, "do_syslog"},
	{341, 1, []string{"/usr/sbin/dropbear", "-F", "-P", "/var/run/dropbear.pid", "-p", "22"}, "/usr/sbin/dropbear", 1124, 720, 184, 328, 381, 4, 11, "poll_schedule_timeout"},
	{349, 1, []string{"/usr/sbin/lighttpd", "-f", "/etc/lighttpd/lighttpd.conf"}, "/usr/sbin/lighttpd", 2108, 1236, 176, 392, 389, 22, 41, "poll_schedule_timeout"},
	{356, 1, []string{"/usr/sbin/telnetd", "-F", "-l", "/bin/login"}, "/bin/busybox", 1032, 548, 264, 328, 394, 2, 5, "poll_schedule_timeout"},
	{362, 1, []string{"/usr/sbin/hostapd", "-B", "/etc/hostapd.conf"}, "/usr/sbin/hostapd", 1840, 1112, 556, 380, 412, 31, 88, "poll_schedule_timeout"},
	{377, 1, []string{"/usr/sbin/pppd", "call", "isp"}, "/usr/sbin/pppd", 1216, 788, 260, 348, 437, 6, 19, "poll_schedule_timeout"},
	{402, 1, []string{"/usr/sbin/vsftpd"}, "/usr/sbin/vsftpd", 1208, 716, 112, 328, 455, 1, 3, "inet_csk_accept"},
	{517, 356, []string{"-sh"}, "/bin/busybox", 1300, 912, 264, 328, 0, 1, 2, "do_wait"},
	{530, 517, []string{"ps"}, "/bin/busybox", 1296, 664, 264, 328, 0, 0, 0, ""},
}

// fakePS is ps's output: BusyBox's columns (procps/ps.c), one line per process.
var fakePS = func() string {
	out := "  PID USER       VSZ STAT COMMAND\n"
	for _, p := range processes {
		state := "S"
		if p.pid == 530 {
			state = "R"
		}
		out += fmt.Sprintf("%5d %-8s %5d %-4s %s\n", p.pid, "root", p.vsz, state, strings.Join(p.argv, " "))
	}
	return out
}()

// procEntries is what each /proc/PID holds on a 4.14 kernel built for a small router (tgid_base_stuff,
// without the parts of CONFIG_SECURITY, CGROUPS, USER_NS, AUDITSYSCALL...), with each one's mode.
// cmdline, comm, environ, stat, statm, status, limits, mounts, wchan and the oom_* are computed
// (procFile); the others read empty and their folders are empty (simplification).
var procEntries = []struct{ name, mode string }{
	{"task", "dr-xr-xr-x"}, {"fd", "dr-x------"}, {"map_files", "dr-x------"}, {"fdinfo", "dr-x------"},
	{"ns", "dr-x--x--x"}, {"net", "dr-xr-xr-x"}, {"environ", "-r--------"}, {"auxv", "-r--------"},
	{"status", "-r--r--r--"}, {"personality", "-r--------"}, {"limits", "-r--r--r--"}, {"sched", "-rw-r--r--"},
	{"comm", "-rw-r--r--"}, {"syscall", "-r--------"}, {"cmdline", "-r--r--r--"}, {"stat", "-r--r--r--"},
	{"statm", "-r--r--r--"}, {"maps", "-r--r--r--"}, {"mem", "-rw-------"}, {"cwd", "lrwxrwxrwx"},
	{"root", "lrwxrwxrwx"}, {"exe", "lrwxrwxrwx"}, {"mounts", "-r--r--r--"}, {"mountinfo", "-r--r--r--"},
	{"mountstats", "-r--------"}, {"clear_refs", "--w-------"}, {"smaps", "-r--r--r--"},
	{"smaps_rollup", "-r--r--r--"}, {"pagemap", "-r--------"}, {"wchan", "-r--r--r--"},
	{"oom_score", "-r--r--r--"}, {"oom_adj", "-rw-r--r--"}, {"oom_score_adj", "-rw-r--r--"},
	{"coredump_filter", "-rw-r--r--"}, {"timerslack_ns", "-rw-rw-rw-"},
}

// init adds the processes' folders to the built-in files (Go runs it once, after the package's variables
// are set). Their files are "" here: procFile makes the content when one is read.
func init() {
	for _, p := range processes {
		dir := "/proc/" + strconv.Itoa(p.pid)
		fakeDirs[dir] = true
		for _, e := range procEntries {
			name := dir + "/" + e.name
			specialModes[name] = e.mode
			switch e.mode[0] {
			case 'd':
				fakeDirs[name] = true
			case 'l':
				fakeLinks[name] = "/" // cwd and root: the daemons run in /
			default:
				fakeFiles[name] = ""
			}
		}
		fakeLinks[dir+"/exe"] = p.exe
	}
	fakeLinks["/proc/517/cwd"] = "/root" // where login started the shell (simplification: cd doesn't change it)
	fakeLinks["/proc/530/cwd"] = "/root"
	fakeLinks["/proc/self"] = "530" // the process looking: the command running now
}

// procSelf: 530 exists only while a command runs. Between commands the one looking at /proc is the shell
// itself (echo -1000 > /proc/self/oom_score_adj), so /proc/self (= /proc/530 here) is 517; and the shell
// expanding /proc/[0-9]* (a killer's loop) doesn't see 530 (list), like on a real system.
func (s *Shell) procSelf(p string) string {
	if s.argv == nil && under(p, "/proc/530") {
		return "/proc/517" + p[len("/proc/530"):]
	}
	return p
}

// noSession is who looks at /proc without a shell (FTP): procFile only reads it.
var noSession Shell

// Numbers of the kernel that every process shows.
const (
	userHZ   = 100      // the clock ticks of /proc/PID/stat (USER_HZ)
	maxProcs = 972      // RLIMIT_NPROC and RLIMIT_SIGPENDING: max_threads / 2, from the 124520 kB of RAM
	ptsTTY   = 136 << 8 // /dev/pts/0, the session's terminal (new_encode_dev(MKDEV(136, 0)))
)

// procFile is the content of a computed file in /proc/PID (p is a clean path, links followed). s is the
// session: 517 and 530 are its shell and its command (s.argv). false: not one of these files.
func procFile(p string, s *Shell) (string, bool) {
	rest, ok := strings.CutPrefix(p, "/proc/")
	if !ok {
		return "", false
	}
	pid, name, _ := strings.Cut(rest, "/")
	if name == "" || strings.Contains(name, "/") || specialModes[p] == "" {
		return "", false // the folder itself, or one inside it
	}
	var pr process
	for _, q := range processes {
		if strconv.Itoa(q.pid) == pid {
			pr, ok = q, true
		}
	}
	if !ok {
		return "", false
	}

	// the session's own: when it started, its command, its terminal (an SSH session without a pty has none)
	// the environment: init's is what the kernel gave it; init adds these for what it starts (init.c)
	tty, tpgid, pgrp, sid, env := 0, -1, pr.pid, pr.pid, "HOME=/\x00TERM=linux\x00"
	if pr.pid != 1 {
		env += "PATH=/sbin:/usr/sbin:/bin:/usr/bin\x00SHELL=/bin/sh\x00USER=root\x00"
	}
	if pr.pid == 517 || pr.pid == 530 {
		started := s.started
		if started.IsZero() { // FTP's look at the files: no shell
			started = now()
		}
		pr.start = int(started.Sub(bootTime) / (time.Second / userHZ))
		sid, env = 517, s.environ("\x00")
		if s.terminal {
			tty, tpgid = ptsTTY, 530 // the command running is the terminal's foreground job
		}
		if pr.pid == 530 {
			pr.start = int(now().Sub(bootTime) / (time.Second / userHZ))
			if len(s.argv) > 0 {
				pr.argv = s.argv
			}
			if !s.terminal {
				pgrp = 517 // no job control: the command stays in the shell's group
			}
		}
	}
	// the program's file name ("-sh" ran /bin/sh). The kernel keeps 15 bytes of it: no applet's is longer
	comm := path.Base(pr.argv[0])
	if pr.pid == 517 {
		comm = "sh"
	}

	anon := pr.rss / 4 / 4 * 4                 // kB: the RAM that is its own; the rest is files (its code)
	data := pr.vsz - pr.exeKB - pr.libKB - 212 // what isn't code, nor the 132 kB stack, nor the libraries' data
	switch name {
	case "cmdline":
		return strings.Join(pr.argv, "\x00") + "\x00", true
	case "comm":
		return comm + "\n", true
	case "environ":
		return env, true
	case "status":
		return pr.status(comm, pgrp, sid, anon, data), true
	case "stat":
		return pr.stat(comm, pgrp, sid, tty, tpgid, env), true
	case "statm": // in pages: size resident shared text lib data dt
		return fmt.Sprintf("%d %d %d %d 0 %d 0\n", pr.vsz/4, pr.rss/4, (pr.rss-anon)/4, pr.exeKB/4, (data+132)/4), true
	case "limits":
		return procLimits, true
	case "mounts":
		return fakeFiles["/proc/mounts"], true
	case "wchan": // no newline; "0" for one that runs
		if pr.wchan == "" {
			return "0", true
		}
		return pr.wchan, true
	case "oom_score": // oom_badness: its pages (+ its 4 page tables), 3% less for root, per 1000 of the RAM
		if pr.pid == 1 {
			return "0\n", true // init can't be killed
		}
		pages := pr.rss/4 + 4
		return strconv.Itoa((pages-pages*3/100)*1000/(memKB("MemTotal")/4)) + "\n", true
	case "oom_adj", "oom_score_adj":
		return "0\n", true
	case "coredump_filter":
		return "00000033\n", true
	case "timerslack_ns":
		return "50000\n", true
	case "personality":
		return "00000000\n", true
	}
	return "", false
}

// status is /proc/PID/status (proc_pid_status): no Seccomp line (no CONFIG_SECCOMP), no hugepages.
func (pr process) status(comm string, pgrp, sid, anon, data int) string {
	state, groups := "S (sleeping)", ""
	if pr.pid == 530 {
		state = "R (running)"
	}
	if pr.pid == 517 || pr.pid == 530 {
		groups = "0 10" // login's initgroups: root's group and wheel (/etc/group)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Name:\t%s\nUmask:\t0022\nState:\t%s\nTgid:\t%d\nNgid:\t0\nPid:\t%d\nPPid:\t%d\nTracerPid:\t0\n",
		strings.ReplaceAll(comm, "\\", "\\\\"), state, pr.pid, pr.pid, pr.ppid)
	fmt.Fprintf(&b, "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t32\nGroups:\t%s \n", groups)
	fmt.Fprintf(&b, "NStgid:\t%d\nNSpid:\t%d\nNSpgid:\t%d\nNSsid:\t%d\n", pr.pid, pr.pid, pgrp, sid)
	for _, m := range []struct {
		name string
		kb   int
	}{
		{"VmPeak", pr.vsz}, {"VmSize", pr.vsz}, {"VmLck", 0}, {"VmPin", 0}, {"VmHWM", pr.rss}, {"VmRSS", pr.rss},
		{"RssAnon", anon}, {"RssFile", pr.rss - anon}, {"RssShmem", 0}, {"VmData", data}, {"VmStk", 132},
		{"VmExe", pr.exeKB}, {"VmLib", pr.libKB}, {"VmPTE", 8}, {"VmPMD", 0}, {"VmSwap", 0},
	} {
		fmt.Fprintf(&b, "%s:\t%8d kB\n", m.name, m.kb)
	}
	const none = "0000000000000000"
	fmt.Fprintf(&b, "Threads:\t1\nSigQ:\t0/%d\nSigPnd:\t%s\nShdPnd:\t%s\nSigBlk:\t%s\nSigIgn:\t%s\nSigCgt:\t%s\n",
		maxProcs, none, none, none, none, none)
	fmt.Fprintf(&b, "CapInh:\t%s\nCapPrm:\t0000003fffffffff\nCapEff:\t0000003fffffffff\nCapBnd:\t0000003fffffffff\nCapAmb:\t%s\n", none, none)
	fmt.Fprintf(&b, "NoNewPrivs:\t0\nSpeculation_Store_Bypass:\tunknown\nCpus_allowed:\t1\nCpus_allowed_list:\t0\n")
	fmt.Fprintf(&b, "voluntary_ctxt_switches:\t%d\nnonvoluntary_ctxt_switches:\t%d\n", (pr.utime+pr.stime)*7+pr.pid%13, (pr.utime+pr.stime)/3)
	return b.String()
}

// stat is /proc/PID/stat (do_task_stat): 52 numbers after the name, the addresses of a 32-bit ARM
// program (its code at 0x10000, its stack under 0xbf000000), what root may see.
func (pr process) stat(comm string, pgrp, sid, tty, tpgid int, env string) string {
	state, flags, wchan := "S", 4194560, 1 // PF_RANDOMIZE | PF_SUPERPRIV
	if pr.pid == 530 {
		state, flags, wchan = "R", 4194304, 0
	}
	cmdline := len(strings.Join(pr.argv, " ")) + 1
	startCode := 0x10000
	endCode := startCode + pr.exeKB*1024 - 492
	startData := (endCode+0xffff)/0x10000*0x10000 + endCode%0x1000
	endData := startData + 2148
	startStack := (3196100000 + pr.pid*14000) &^ 15
	argStart := startStack + 448
	return fmt.Sprintf("%d (%s) %s %d %d %d %d %d %d %d 0 %d 0 %d %d 0 0 20 0 1 0 %d %d %d 4294967295 %d %d %d 0 0 0 0 0 0 %d 0 0 17 0 0 0 0 0 0 %d %d %d %d %d %d %d 0\n",
		pr.pid, comm, state, pr.ppid, pgrp, sid, tty, tpgid, flags,
		pr.rss/2+pr.pid%50, pr.rss/200, // minor and major page faults
		pr.utime, pr.stime, pr.start, pr.vsz*1024, pr.rss/4,
		startCode, endCode, startStack, wchan,
		startData, endData, (endData+0xfff)/0x1000*0x1000+0x3000, // brk: the heap starts after the data
		argStart, argStart+cmdline, argStart+cmdline, argStart+cmdline+len(env))
}

// procLimits is /proc/PID/limits (proc_pid_limits): the kernel's defaults, which nothing here changes.
var procLimits = func() string {
	limits := []struct{ name, soft, hard, unit string }{
		{"Max cpu time", "unlimited", "unlimited", "seconds"},
		{"Max file size", "unlimited", "unlimited", "bytes"},
		{"Max data size", "unlimited", "unlimited", "bytes"},
		{"Max stack size", "8388608", "unlimited", "bytes"},
		{"Max core file size", "0", "unlimited", "bytes"},
		{"Max resident set", "unlimited", "unlimited", "bytes"},
		{"Max processes", strconv.Itoa(maxProcs), strconv.Itoa(maxProcs), "processes"},
		{"Max open files", "1024", "4096", "files"},
		{"Max locked memory", "65536", "65536", "bytes"},
		{"Max address space", "unlimited", "unlimited", "bytes"},
		{"Max file locks", "unlimited", "unlimited", "locks"},
		{"Max pending signals", strconv.Itoa(maxProcs), strconv.Itoa(maxProcs), "signals"},
		{"Max msgqueue size", "819200", "819200", "bytes"},
		{"Max nice priority", "0", "0", ""},
		{"Max realtime priority", "0", "0", ""},
		{"Max realtime timeout", "unlimited", "unlimited", "us"},
	}
	out := fmt.Sprintf("%-25s %-20s %-20s %-10s\n", "Limit", "Soft Limit", "Hard Limit", "Units")
	for _, l := range limits {
		out += fmt.Sprintf("%-25s %-20s %-20s ", l.name, l.soft, l.hard)
		if l.unit != "" {
			out += fmt.Sprintf("%-10s", l.unit)
		}
		out += "\n"
	}
	return out
}()

// writePID is a write to a file in /proc/PID: the writable ones take it (simplification: nothing
// changes, "echo -1000 > /proc/self/oom_score_adj" reads back 0), mem says EIO, the others have no
// write at all (EINVAL).
func writePID(p string) error {
	switch {
	case path.Base(p) == "mem":
		return errIO
	case strings.Contains(specialModes[p][1:], "w"):
		return nil
	}
	return errInvalid
}
