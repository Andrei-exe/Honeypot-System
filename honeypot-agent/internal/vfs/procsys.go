package vfs

import (
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"
)

// /proc/sys, the kernel settings, and sysctl, which reads and writes them (BusyBox 1.30.1's
// procps/sysctl.c; the checks of a Linux 4.14 kernel).

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
