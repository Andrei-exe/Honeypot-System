package vfs

import (
	"fmt"
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
		full, err := s.writeFile(file, content, false)
		if err != nil {
			out += "crontab: can't create " + dir + "/" + user + ".new\n" // its temporary file
		} else if full {
			out += writeError("crontab")
		}
	}
	s.writeFile(path.Join(dirPath, "cron.update"), user+"\n", true) // the note for crond to reread (unchecked)
	return out, 0, false
}
