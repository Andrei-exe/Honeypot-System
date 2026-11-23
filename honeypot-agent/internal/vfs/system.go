package vfs

import (
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"
	"time"
)

// The commands bots run to size up a machine before installing a cryptominer: free, nproc, df,
// uptime, crontab. Their output is BusyBox 1.30.1's (procps/free.c, coreutils/df.c, procps/uptime.c,
// coreutils/nproc.c, miscutils/crontab.c) with Buildroot 2019.05.3's config (DESKTOP, LONG_OPTS,
// FEATURE_HUMAN_READABLE, FEATURE_SKIP_ROOTFS on; FEATURE_DF_FANCY, FEATURE_UPTIME_UTMP_SUPPORT off).
// The numbers come from memInfo, /proc/cpuinfo and /proc/mounts, so everything agrees.

// crontabDir is where crontab keeps one file per user (Buildroot: FEATURE_CROND_DIR + "/crontabs").
const crontabDir = "/var/spool/cron/crontabs"

// load is the load average over 1, 5 and 15 minutes, in hundredths: an idle router.
// Simplification: it never changes.
var load = [3]int{8, 3, 1}

// dynamicFiles are the /proc files whose content changes with time: computed when they are read.
var dynamicFiles = map[string]func() string{
	"/proc/uptime":  procUptime,
	"/proc/loadavg": func() string { return loadText(" ") + " 1/11 530\n" }, // + running/total processes (ps), last PID
}

// usage is BusyBox's answer to wrong arguments (bb_show_usage in libbb/appletlib.c), exit code 1.
func usage(applet, text string) (string, int, bool) {
	return busyboxBanner + " multi-call binary.\n\nUsage: " + applet + text + "\n", 1, false
}

// usageAfter is usage after getopt's complaint about a wrong option (see getopt in text.go).
func usageAfter(complaint, applet, text string) (string, int, bool) {
	out, code, exit := usage(applet, text)
	return complaint + out, code, exit
}

// free [-b/k/m/g]: like the kernel's sysinfo + /proc/meminfo, the way BusyBox 1.30 adds them up
// (buff/cache = Buffers + Cached, used = total - free - buff/cache). Only the first argument counts.
func free(args []string) (string, int, bool) {
	shift := 10 // the unit is 2^shift bytes: kB by default and with -k
	if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		option := byte(0)
		if len(args[0]) > 1 {
			option = args[0][1]
		}
		switch option {
		case 'b':
			shift = 0
		case 'k':
		case 'm':
			shift = 20
		case 'g':
			shift = 30
		default: // e.g. -h, which BusyBox's free doesn't have
			return usage("free", " [-b/k/m/g]\n\nDisplay the amount of free and used system memory")
		}
	}
	scale := func(kb int) uint64 { return (uint64(kb) * 1024) >> shift }

	total, freeKB := memKB("MemTotal"), memKB("MemFree")
	cache := memKB("Buffers") + memKB("Cached")
	swap, swapFree := memKB("SwapTotal"), memKB("SwapFree")
	return fmt.Sprintf("       %12s%12s%12s%12s%12s%12s\n", "total", "used", "free", "shared", "buff/cache", "available") +
		fmt.Sprintf("Mem:   %12d %11d %11d %11d %11d %11d\n", scale(total), scale(total-freeKB-cache),
			scale(freeKB), scale(memKB("Shmem")), scale(cache), scale(memKB("MemAvailable"))) +
		fmt.Sprintf("Swap:   %11d %11d %11d\n", scale(swap), scale(swap-swapFree), scale(swapFree)), 0, false
}

// nproc prints the number of CPUs: the processors in /proc/cpuinfo (--all and --ignore=N change
// nothing with one CPU: BusyBox never prints less than 1).
func nproc() string {
	return strconv.Itoa(max(strings.Count(fakeFiles["/proc/cpuinfo"], "processor\t:"), 1)) + "\n"
}

// uptime: " 10:30:00 up 2 days,  1:15,  load average: 0.08, 0.03, 0.01" (no "users": Buildroot's
// config has no FEATURE_UPTIME_UTMP_SUPPORT); -s prints when the router booted.
func uptime(args []string) string {
	t := now().UTC() // the router has no time zone set: UTC
	up := int(now().Sub(bootTime) / time.Second)
	for _, a := range args {
		if a == "-s" {
			return t.Add(-time.Duration(up)*time.Second).Format("2006-01-02 15:04:05") + "\n"
		}
	}

	out := " " + t.Format("15:04:05") + " up "
	if days := up / 86400; days != 0 {
		plural := "s"
		if days == 1 {
			plural = ""
		}
		out += fmt.Sprintf("%d day%s, ", days, plural)
	}
	minutes := up / 60
	hours := minutes / 60 % 24
	if minutes %= 60; hours != 0 {
		out += fmt.Sprintf("%2d:%02d", hours, minutes)
	} else {
		out += fmt.Sprintf("%d min", minutes)
	}
	return out + ",  load average: " + loadText(", ") + "\n"
}

// loadText is the load average as "0.08<sep>0.03<sep>0.01".
func loadText(sep string) string {
	parts := make([]string, len(load))
	for i, l := range load {
		parts[i] = fmt.Sprintf("%d.%02d", l/100, l%100)
	}
	return strings.Join(parts, sep)
}

// procUptime is /proc/uptime: seconds since boot and seconds the CPU was idle (98% of them).
func procUptime() string {
	hundredths := func(d time.Duration) string {
		return fmt.Sprintf("%d.%02d", d/time.Second, d%time.Second/(10*time.Millisecond))
	}
	up := now().Sub(bootTime)
	return hundredths(up) + " " + hundredths(up/100*98) + "\n"
}

// mount is one line of /proc/mounts, with the size df shows.
type mount struct {
	device, dir, fsType string
	sizeKB              int // 0 = no blocks (rootfs, proc, sysfs): df leaves it out
}

// mounts reads /proc/mounts. A tmpfs is as big as its size= option, else half the RAM (the kernel's default).
func mounts() []mount {
	var list []mount
	for _, line := range strings.Split(strings.TrimSpace(fakeFiles["/proc/mounts"]), "\n") {
		f := strings.Fields(line) // device, dir, type, options, 0, 0
		m := mount{device: f[0], dir: f[1], fsType: f[2]}
		if m.fsType == "tmpfs" {
			m.sizeKB = memKB("MemTotal") / 2
			for _, option := range strings.Split(f[3], ",") {
				if size, ok := strings.CutPrefix(option, "size="); ok && strings.HasSuffix(size, "k") {
					m.sizeKB, _ = strconv.Atoi(strings.TrimSuffix(size, "k"))
				}
			}
		}
		list = append(list, m)
	}
	return list
}

// mountOf returns the filesystem p is on: the mount with the longest directory containing p.
func mountOf(p string) mount {
	var best mount
	for _, m := range mounts() {
		if (m.dir == "/" || under(p, m.dir)) && len(m.dir) >= len(best.dir) {
			best = m
		}
	}
	return best
}

// usedKB is how much of a tmpfs the attacker's files fill: a tmpfs stores a file in whole 4KB pages.
func (s *Shell) usedKB(m mount) int {
	if m.sizeKB == 0 {
		return 0
	}
	kb := 0
	for p, content := range s.files {
		if mountOf(p).dir == m.dir {
			kb += (len(content) + 4095) / 4096 * 4
		}
	}
	return min(kb, m.sizeKB)
}

// df [-hmkT] [PATH]...: the filesystems with blocks (here the two tmpfs; rootfs is left out like
// FEATURE_SKIP_ROOTFS does), or the one each PATH is on. Other options (-P, -a, -i) are ignored.
func (s *Shell) df(args []string) (string, int, bool) {
	human, mega, showType := false, false, false
	var targets []string
	for _, a := range args {
		if a == "-" || !strings.HasPrefix(a, "-") {
			targets = append(targets, a)
			continue
		}
		for _, c := range a[1:] {
			switch c {
			case 'h':
				human = true
			case 'm':
				mega = true
			case 'k':
				mega = false // -k and -m: the last one wins
			case 'T':
				showType = true
			}
		}
	}
	unit, unitHeader := 1024, "1K-blocks" // unit: bytes per block shown; 0 = human readable
	if mega {
		unit, unitHeader = 1024*1024, "1M-blocks"
	}
	if human {
		unit, unitHeader = 0, "     Size"
	}

	typeHeader := ""
	if showType {
		typeHeader = "Type       "
	}
	out := fmt.Sprintf("Filesystem           %s%-15sUsed Available Use%% Mounted on\n", typeHeader, unitHeader)
	code := 0

	var rows []mount
	if len(targets) == 0 {
		for _, m := range mounts() {
			if m.sizeKB > 0 {
				rows = append(rows, m)
			}
		}
	}
	for _, t := range targets {
		p := resolve(s.cwd, t)
		if _, ok := s.readFile(p); !ok && !s.isDir(p) {
			out += "df: " + t + ": can't find mount point\n"
			code = 1
			continue
		}
		if m := mountOf(p); m.device != "rootfs" { // "df /etc" is on rootfs: only the header
			rows = append(rows, m)
		}
	}

	// when the session's quota can't take another page, the disk is full: nothing is available
	full := sessionQuota-s.quotaUsed() < 4096
	for _, m := range rows {
		used, avail := s.usedKB(m), m.sizeKB-s.usedKB(m)
		if full {
			avail = 0
		}
		percent := 0 // df.c: used / (used + available) in 4KB blocks, rounded; 0 if both are 0
		if total := (used + avail) / 4; total > 0 {
			percent = (used/4*100 + total/2) / total
		}
		out += fmt.Sprintf("%-20s", m.device)
		if len(m.device) > 20 {
			out += "\n" + strings.Repeat(" ", 20)
		}
		if showType {
			out += fmt.Sprintf(" %-10s", m.fsType)
		}
		out += fmt.Sprintf(" %9s %9s %9s %3d%% %s\n",
			dfSize(m.sizeKB, unit), dfSize(used, unit), dfSize(avail, unit), percent, m.dir)
	}
	return out, code, false
}

// dfSize is a size the way df prints it (make_human_readable_str in libbb/human_readable.c):
// in blocks of unit bytes, rounded, or with unit 0 (-h) with one decimal and a suffix: 60.8M.
func dfSize(kb, unit int) string {
	bytes := uint64(kb) * 1024
	if bytes == 0 {
		return "0"
	}
	if unit != 0 {
		return strconv.FormatUint((bytes+uint64(unit)/2)/uint64(unit), 10)
	}
	suffix, tenths := 0, uint64(0)
	for bytes >= 1024 {
		suffix++
		tenths = ((bytes%1024)*10 + 512) / 1024
		bytes /= 1024
	}
	if tenths >= 10 { // e.g. 1023.96K -> 1024.0K
		bytes++
		tenths = 0
	}
	return fmt.Sprintf("%d.%d%c", bytes, tenths, "KMGTPEZY"[suffix-1])
}

// userExists reports whether /etc/passwd has the user (crontab -u checks it).
func (s *Shell) userExists(name string) bool {
	passwd, _ := s.readFile("/etc/passwd")
	for _, line := range strings.Split(passwd, "\n") {
		if user, _, _ := strings.Cut(line, ":"); name != "" && user == name {
			return true
		}
	}
	return false
}

// crontab like BusyBox's: -l lists, -r deletes, FILE or "-" (what comes through |) replaces.
// Cryptominers use it to come back after a reboot: "(crontab -l; echo '* * * * * /tmp/x') | crontab -".
// Nothing ever runs the jobs (nothing runs here at all), but the file stays for the session, so
// "crontab -l" shows the bot what it installed.
func (s *Shell) crontab(args []string, input string) (string, int, bool) {
	const help = " [-c DIR] [-u USER] [-ler]|[FILE]\n\n" +
		"\t-c\tCrontab directory\n\t-u\tUser\n\t-l\tList crontab\n\t-e\tEdit crontab\n" +
		"\t-r\tDelete crontab\n\tFILE\tReplace crontab by FILE ('-': stdin)"
	user, dir := "root", crontabDir
	modes := "" // the -l, -e, -r given (-d is -r)
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-" || !strings.HasPrefix(a, "-") {
			files = append(files, a)
			continue
		}
		for j := 1; j < len(a); j++ {
			switch c := a[j]; c {
			case 'u', 'c': // the value is the rest of the word (-uroot) or the next word
				value := a[j+1:]
				if value == "" {
					if i+1 == len(args) {
						return usage("crontab", help)
					}
					i++
					value = args[i]
				}
				if c == 'u' {
					user = value
				} else {
					dir = value
				}
				j = len(a)
			case 'l', 'e', 'r', 'd':
				if c == 'd' {
					c = 'r'
				}
				if !strings.ContainsRune(modes, rune(c)) {
					modes += string(c)
				}
			default:
				return usage("crontab", help)
			}
		}
	}
	// the checks in BusyBox's order
	if len(files) > 1 {
		return usage("crontab", help)
	}
	if !s.userExists(user) {
		return "crontab: unknown user " + user + "\n", 1, false
	}
	if len(modes) > 1 || (modes == "" && len(files) == 0) {
		return usage("crontab", help)
	}
	content := input // "crontab -": the new crontab is what came through |
	if modes == "" && files[0] != "-" {
		var ok bool
		if content, ok = s.readFile(resolve(s.cwd, files[0])); !ok {
			return "crontab: can't open '" + files[0] + "': No such file or directory\n", 1, false
		}
	}
	dirPath := resolve(s.cwd, dir)
	if !s.isDir(dirPath) {
		return "crontab: can't change directory to '" + dir + "': No such file or directory\n", 1, false
	}
	file := path.Join(dirPath, user)

	out := ""
	switch modes {
	case "l":
		if text, ok := s.readFile(file); ok {
			return text, 0, false
		}
		return "crontab: can't open '" + user + "': No such file or directory\n", 1, false
	case "r":
		delete(s.files, file)
		delete(s.mtimes, file)
	case "e": // BusyBox runs vi on a copy, and this router has no vi: the crontab is written back as it was
		content, _ = s.readFile(file)
		out = "crontab: can't execute 'vi': No such file or directory\n"
		fallthrough
	default:
		// on a full disk BusyBox still installs what it could write, and still exits 0 (crontab.c)
		failed, err := s.writeFile(file, content, false)
		if err != nil {
			out += "crontab: can't create " + dir + "/" + user + ".new\n" // its temporary file
		} else if failed != nil {
			out += writeError("crontab", failed)
		}
	}
	s.writeFile(path.Join(dirPath, "cron.update"), user+"\n", true) // the note for crond to reread (unchecked)
	return out, 0, false
}

// kernelSetting is one file in /proc/sys (what sysctl reads and writes): its value at boot, its mode
// (root is held to it too: a read-only one can't be written, vm/drop_caches can't be read) and what its
// kernel handler takes: any text (proc_dostring) or an integer from min to max (proc_dointvec_minmax).
type kernelSetting struct {
	value    string // as read, without "\n"
	mode     string // as ls -l shows it: settingRW, settingRO or settingWO
	text     bool
	min, max int64
}

const (
	settingRW = "-rw-r--r--"
	settingRO = "-r--r--r--"
	settingWO = "--w-------"
)

// kernelSettings are the /proc/sys files bots touch, as on a 4.14 kernel on a 128MB 32-bit ARM router:
// its identity (the same as uname's) and what cryptominers tune. No vm/nr_hugepages: cheap ARM
// routers have no hugetlbfs (and /proc/meminfo has no HugePages lines either).
var kernelSettings = map[string]kernelSetting{
	"/proc/sys/kernel/hostname":           {value: "gateway", mode: settingRW, text: true},
	"/proc/sys/kernel/domainname":         {value: "(none)", mode: settingRW, text: true},
	"/proc/sys/kernel/ostype":             {value: "Linux", mode: settingRO, text: true},
	"/proc/sys/kernel/osrelease":          {value: kernelRelease, mode: settingRO, text: true},
	"/proc/sys/kernel/version":            {value: kernelVersion, mode: settingRO, text: true},
	"/proc/sys/kernel/pid_max":            {value: "32768", mode: settingRW, min: 301, max: 32768}, // 32-bit: PID_MAX_LIMIT
	"/proc/sys/kernel/randomize_va_space": {value: "2", mode: settingRW, min: math.MinInt32, max: math.MaxInt32},
	"/proc/sys/vm/overcommit_memory":      {value: "0", mode: settingRW, min: 0, max: 2},
	"/proc/sys/vm/swappiness":             {value: "60", mode: settingRW, min: 0, max: 100},
	"/proc/sys/vm/drop_caches":            {mode: settingWO, min: 1, max: 4},
	"/proc/sys/net/ipv4/ip_forward":       {value: "1", mode: settingRW, min: math.MinInt32, max: math.MaxInt32}, // a router forwards
}

// read is the setting's file as read at boot ("" for the write-only one, see unreadable).
func (k kernelSetting) read() string {
	if k.mode == settingWO {
		return ""
	}
	return k.value + "\n"
}

// unreadable: a write-only setting (vm/drop_caches), which not even root can open for reading.
func unreadable(p string) bool {
	return kernelSettings[p].mode == settingWO
}

// set is what writing text to the setting leaves in its file, ok = false is the kernel's EINVAL. Text: the
// first line, cut to 64 bytes. An integer: decimal, 0x hex or 0 octal (simple_strtoul with base 0), then
// a space, tab, newline or nothing ("128abc" is refused, "128 abc" is 128).
func (k kernelSetting) set(text string) (string, bool) {
	if k.text {
		line, _, _ := strings.Cut(text, "\n")
		return line[:min(len(line), 64)] + "\n", true
	}
	text = strings.TrimLeft(text, " \t\n\v\f\r")
	digits, negative := strings.CutPrefix(text, "-")
	if end := strings.IndexAny(digits, " \t\n"); end >= 0 {
		digits = digits[:end]
	}
	base := 10
	switch {
	case strings.HasPrefix(digits, "0x") || strings.HasPrefix(digits, "0X"):
		base, digits = 16, digits[2:]
	case len(digits) > 1 && digits[0] == '0':
		base, digits = 8, digits[1:]
	}
	n, err := strconv.ParseUint(digits, base, 32) // only digits (no sign, no "_"); over 32 bits = refused
	if err != nil {
		return "", false
	}
	value := int64(n)
	if negative {
		value = -value
	}
	if value < k.min || value > k.max {
		return "", false
	}
	return strconv.FormatInt(value, 10) + "\n", true
}

const sysctlUsage = " -p [-enq] [FILE...] / [-enqaw] [KEY[=VALUE]]...\n\nShow/set kernel parameters\n\n" +
	"\t-p\tSet values from FILEs (default /etc/sysctl.conf)\n\t-e\tDon't warn about unknown keys\n" +
	"\t-n\tDon't show key names\n\t-q      Quiet\n\t-a\tShow all values\n\t-w\tSet values"

// sysctlRun is one run of sysctl: its options, output and exit code.
type sysctlRun struct {
	s                  *Shell
	names, warn, quiet bool // print "key = " (no -n), report unknown keys (no -e), print what was set (no -q)
	out                strings.Builder
	code               int
}

// sysctl shows and sets the kernel settings, like BusyBox's procps/sysctl.c: "vm.swappiness" is the file
// /proc/sys/vm/swappiness. Miners run "sysctl -w vm.nr_hugepages=128" (this kernel has no such key).
func (s *Shell) sysctl(args []string) (string, int, bool) {
	opts, rest, complaint := getopt("sysctl", args, "neAapwq", nil)
	if complaint != "" {
		return usageAfter(complaint, "sysctl", sysctlUsage)
	}
	r := &sysctlRun{s: s, names: opts['n'] == nil, warn: opts['e'] == nil, quiet: opts['q'] != nil}
	switch {
	case opts['p'] != nil: // -p [FILE]...: the "key = value" lines of each file
		if len(rest) == 0 {
			rest = []string{"/etc/sysctl.conf"}
		}
		for _, f := range rest {
			if !r.file(f) {
				break
			}
		}
		r.code = 0 // errors in a file don't change the exit code
	case opts['a'] != nil || opts['A'] != nil:
		r.tree("/proc/sys")
	default:
		for _, a := range rest {
			key, value, hasValue := strings.Cut(a, "=")
			key = s.sysctlPath(key)
			if dir := path.Join("/proc/sys", key); s.isDir(dir) && !hasValue && opts['w'] == nil {
				r.tree(dir) // "sysctl vm": every setting in it
				continue
			}
			if hasValue {
				key += "=" + value
			}
			if !r.act(key, opts['w'] != nil) {
				break
			}
		}
	}
	return r.out.String(), r.code, false
}

// sysctlPath turns a key into a path under /proc/sys, like sysctl_dots_to_slashes: a dot becomes a
// slash where the part before it exists, trying from the end ("net.ipv4.ip_forward" -> "net/ipv4/ip_forward").
func (s *Shell) sysctlPath(key string) string {
	b := []byte(key + ".") // the extra dot tries the whole key too
	end, lastGood := len(key), -1
	for changed := true; changed; {
		changed = false
		for i := end; i > lastGood && i > 0; i-- {
			if b[i] != '.' {
				continue
			}
			p := path.Join("/proc/sys", string(b[:i]))
			if _, isFile := s.readFile(p); isFile || s.isDir(p) {
				b[i], lastGood, changed = '/', i, true
				break
			}
		}
	}
	return string(b[:end])
}

// act reads one setting, or sets it ("key=value", or -w). It returns false when sysctl would die (a
// value the kernel refused): the keys after it aren't touched.
func (r *sysctlRun) act(setting string, write bool) bool {
	name := strings.ReplaceAll(setting, "/", ".")
	key, value, hasValue := strings.Cut(setting, "=")
	p := path.Join("/proc/sys", key)
	if !write && !hasValue {
		if unreadable(p) {
			return true // EACCES: skipped without a word, exit code 0
		}
		text, ok := r.s.readFile(p)
		if !ok {
			r.unknown(name)
			return true
		}
		for _, line := range strings.SplitAfter(text, "\n") {
			if line != "" && r.names {
				r.out.WriteString(name + " = ")
			}
			r.out.WriteString(line)
		}
		return true
	}
	switch {
	case !hasValue:
		r.s.warn("sysctl: error: '" + name + "' must be of the form name=value\n")
		r.code = 1
		return true
	case key == "" || value == "":
		r.s.warn("sysctl: error: malformed setting '" + name + "'\n")
		r.code = 1
		return true
	}
	name = strings.ReplaceAll(key, "/", ".")
	failed, err := r.s.writeFile(p, value, false)
	switch {
	case err == errNoAccess:
		return true // a read-only key: skipped without a word, exit code 0
	case err == errNoDir:
		r.unknown(name)
		return true
	case err != nil:
		r.s.warn("sysctl: error setting key '" + name + "': " + err.Error() + "\n")
		r.code = 1
		return true
	case failed != nil:
		r.s.warn("sysctl: write error: " + failed.Error() + "\n")
		r.code = 1
		return false
	}
	if !r.quiet {
		if r.names {
			r.out.WriteString(name + " = ")
		}
		r.out.WriteString(value + "\n")
	}
	return true
}

// unknown reports a key that isn't in /proc/sys.
func (r *sysctlRun) unknown(name string) {
	if r.warn {
		r.s.warn("sysctl: error: '" + name + "' is an unknown key\n")
	}
	r.code = 1
}

// tree reads every setting under dir (alphabetically; the kernel lists them in its own order).
func (r *sysctlRun) tree(dir string) {
	for _, name := range r.s.list(dir) {
		p := path.Join(dir, name)
		if r.s.isDir(p) {
			r.tree(p)
		} else {
			r.act(strings.TrimPrefix(p, "/proc/sys/"), false)
		}
	}
}

// file sets the "key = value" lines of a file (sysctl -p); # and ; start a comment.
func (r *sysctlRun) file(name string) bool {
	text, ok := r.s.readFile(resolve(r.s.cwd, name))
	if !ok {
		r.s.warn("sysctl: " + name + ": No such file or directory\n")
		return true
	}
	for n, line := range splitLines(text) {
		line = strings.TrimLeft(line, " \t")
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			r.s.warn(fmt.Sprintf("sysctl: bad line %d: 1 tokens found, 2 needed\n", n+1))
			continue
		}
		if !r.act(r.s.sysctlPath(strings.TrimSpace(key))+"="+strings.TrimSpace(value), true) {
			return false
		}
	}
	return true
}
