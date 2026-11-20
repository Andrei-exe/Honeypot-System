package vfs

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// maxSize caps an attacker-created file and the output of one command. Without it,
// "cat a a > b; cat b b > a; ..." would double the file on every command until RAM runs out.
const maxSize = 16 * 1024

// elfHeader is the start of a 32-bit ARM ELF binary. Mirai-style bots "cat /bin/echo" and read
// these bytes to learn the architecture (0x28 = ARM), then download the matching binary.
const elfHeader = "\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00"

// firmwareTime is when the firmware was built (the date in /proc/version). ls -l shows it for
// every built-in file, except those on the in-memory filesystems (see mtime in ls.go).
var firmwareTime = time.Date(2020, time.June, 4, 12, 0, 0, 0, time.UTC)

// bootTime is when the "router" booted = when the agent started. /tmp, /var, /dev, /proc
// and the boot log in /var/log/messages date from then.
var bootTime = time.Now().UTC()

// now is the current time; the tests replace it to get a fixed ls -l output.
var now = time.Now

// fakeDirs exist from the start (read-only, shared by all sessions). Bots often cd into
// /tmp, /var/run, /mnt or /dev/shm to drop their binary, so all of these must exist.
var fakeDirs = map[string]bool{
	"/": true, "/bin": true, "/dev": true, "/dev/shm": true, "/etc": true,
	"/lib": true, "/mnt": true, "/proc": true, "/root": true, "/sbin": true,
	"/sys": true, "/tmp": true, "/usr": true, "/usr/bin": true, "/usr/sbin": true,
	"/var": true, "/var/log": true, "/var/run": true, "/var/tmp": true,
}

// applets are the BusyBox commands, installed as symlinks to /bin/busybox like on a real router.
// Only commands the fake shell answers: a listed command that says "not found" would give us
// away (TestAppletsAreImplemented checks it).
var applets = []struct {
	dir    string
	target string // /bin/busybox, relative to dir (the way BusyBox installs its links)
	names  []string
}{
	{"/bin", "busybox", []string{"ash", "cat", "chmod", "cp", "echo", "false", "grep", "hostname",
		"kill", "login", "ls", "mkdir", "mv", "ps", "pwd", "rm", "sh", "sleep", "touch", "true", "uname"}},
	{"/sbin", "../bin/busybox", []string{"init", "klogd", "syslogd"}},
	{"/usr/bin", "../../bin/busybox", []string{"ftpget", "id", "killall", "tftp", "wget", "whoami"}},
	{"/usr/sbin", "../../bin/busybox", []string{"telnetd"}},
}

// fakeLinks are the symbolic links: path -> target, written the way ls -l shows it.
var fakeLinks = makeLinks()

func makeLinks() map[string]string {
	links := map[string]string{
		// the C library (uClibc-ng, common on cheap routers): short names -> the versioned file
		"/lib/ld-uClibc.so.0": "ld-uClibc-1.0.31.so",
		"/lib/libc.so.0":      "libuClibc-1.0.31.so",
	}
	for _, a := range applets {
		for _, name := range a.names {
			links[a.dir+"/"+name] = a.target
		}
	}
	return links
}

// binarySizes are the sizes ls -l shows for the programs. Their content is only the ELF header
// (what bots read), but a real busybox is a few hundred KB.
var binarySizes = map[string]int{
	"/bin/busybox":             278412,
	"/usr/sbin/dropbear":       196104,
	"/usr/sbin/vsftpd":         121352,
	"/lib/ld-uClibc-1.0.31.so": 28324,
	"/lib/libuClibc-1.0.31.so": 334688,
	"/lib/libgcc_s.so.1":       58640,
}

// fakeFiles exist from the start: path -> content (read-only, shared by all sessions).
var fakeFiles = map[string]string{
	// every command in /bin, /sbin, /usr/bin and /usr/sbin is a link to busybox (see applets)
	"/bin/busybox": elfHeader,

	// the services ps shows that are separate programs, and the libraries they use
	"/usr/sbin/dropbear":       elfHeader,
	"/usr/sbin/vsftpd":         elfHeader,
	"/lib/ld-uClibc-1.0.31.so": elfHeader,
	"/lib/libuClibc-1.0.31.so": elfHeader,
	"/lib/libgcc_s.so.1":       elfHeader,

	"/dev/null": "",

	"/var/run/dropbear.pid": "341\n", // ps: dropbear -P /var/run/dropbear.pid, PID 341
	"/var/log/messages":     bootLog(),

	"/etc/hostname":    "gateway\n",
	"/etc/hosts":       "127.0.0.1 localhost\n192.168.1.1 gateway\n",
	"/etc/resolv.conf": "nameserver 192.168.1.1\n",
	// admin, support and user have uid 0 (common on IoT), so whoami says root for any login.
	// Every user in weakCredentials must be here and in /etc/shadow.
	"/etc/passwd": "root:x:0:0:root:/root:/bin/ash\n" +
		"daemon:*:1:1:daemon:/var:/bin/false\n" +
		"admin:x:0:0:admin:/root:/bin/ash\n" +
		"support:x:0:0:support:/root:/bin/ash\n" +
		"user:x:0:0:user:/root:/bin/ash\n" +
		"nobody:*:65534:65534:nobody:/var:/bin/false\n",
	"/etc/shadow": "root:$1$Fz8sK2lQ$wE0bq3Yt1aRk9mVh7uXcN.:18417:0:99999:7:::\n" +
		"daemon:*:0:0:99999:7:::\n" +
		"admin:$1$Qw3rT9pZ$Lm2vX8cB1nK7dF4hJ6sA0.:18417:0:99999:7:::\n" +
		"support:$1$Hy6uJ1kL$Pq9wE3rT5yU7iO2aS4dF6.:18417:0:99999:7:::\n" +
		"user:$1$Zx8cV2bN$Mk1lO3pI5uY7tR9eW0qA2.:18417:0:99999:7:::\n" +
		"nobody:*:0:0:99999:7:::\n",

	"/proc/version": "Linux version 4.14.180 (builder@buildhost) (gcc version 8.4.0) #1 SMP Thu Jun 4 12:00:00 UTC 2020\n",
	"/proc/meminfo": meminfo(),
	"/proc/cpuinfo": "processor\t: 0\n" +
		"model name\t: ARMv7 Processor rev 5 (v7l)\n" +
		"BogoMIPS\t: 48.00\n" +
		"Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm\n" +
		"CPU implementer\t: 0x41\n" +
		"CPU architecture: 7\n" +
		"CPU variant\t: 0x0\n" +
		"CPU part\t: 0xc07\n" +
		"CPU revision\t: 5\n\n" +
		"Hardware\t: Generic DT based system\n" +
		"Revision\t: 0000\n" +
		"Serial\t\t: 0000000000000000\n",
	// Mirai reads /proc/mounts to find writable (rw) directories
	"/proc/mounts": "rootfs / rootfs rw 0 0\n" +
		"proc /proc proc rw,nosuid,nodev,noexec,noatime 0 0\n" +
		"sysfs /sys sysfs rw,nosuid,nodev,noexec,noatime 0 0\n" +
		"tmpfs /tmp tmpfs rw,nosuid,nodev,noatime 0 0\n" +
		"tmpfs /dev tmpfs rw,nosuid,relatime,size=512k,mode=755 0 0\n",
}

// meminfo is /proc/meminfo of a 4.14 kernel with 128MB and no swap, in the kernel's format.
// The numbers agree (Active = Active(anon) + Active(file), Slab = SReclaimable + SUnreclaim,
// CommitLimit = MemTotal / 2), so a future "free" can be computed from them.
func meminfo() string {
	fields := []struct {
		name string
		kb   int
	}{
		{"MemTotal", 124520}, {"MemFree", 38412}, {"MemAvailable", 61208},
		{"Buffers", 3216}, {"Cached", 24284}, {"SwapCached", 0},
		{"Active", 20412}, {"Inactive", 17228},
		{"Active(anon)", 10232}, {"Inactive(anon)", 220},
		{"Active(file)", 10180}, {"Inactive(file)", 17008},
		{"Unevictable", 0}, {"Mlocked", 0}, {"SwapTotal", 0}, {"SwapFree", 0},
		{"Dirty", 0}, {"Writeback", 0}, {"AnonPages", 10140}, {"Mapped", 7860}, {"Shmem", 312},
		{"Slab", 17640}, {"SReclaimable", 4268}, {"SUnreclaim", 13372},
		{"KernelStack", 640}, {"PageTables", 432}, {"NFS_Unstable", 0}, {"Bounce", 0},
		{"WritebackTmp", 0}, {"CommitLimit", 62260}, {"Committed_AS", 19044},
		{"VmallocTotal", 901120}, {"VmallocUsed", 0}, {"VmallocChunk", 0},
	}
	var out strings.Builder
	for _, f := range fields {
		fmt.Fprintf(&out, "%-16s%8d kB\n", f.name+":", f.kb)
	}
	return out.String()
}

// bootLog is /var/log/messages: what BusyBox syslogd wrote while the router booted. The kernel
// lines agree with /proc/version, /proc/cpuinfo and /proc/meminfo, dropbear's PID with ps.
func bootLog() string {
	lines := []struct {
		second int // after boot
		text   string
	}{
		{0, "syslog.info syslogd started: BusyBox v1.30.1"},
		{0, "kern.notice kernel: [    0.000000] Linux version 4.14.180 (builder@buildhost) (gcc version 8.4.0) #1 SMP Thu Jun 4 12:00:00 UTC 2020"},
		{0, "kern.info kernel: [    0.000000] CPU: ARMv7 Processor [410fc075] revision 5 (ARMv7), cr=10c5387d"},
		{0, "kern.info kernel: [    0.000000] Memory: 123496K/131072K available (5120K kernel code, 380K rwdata, 1344K rodata, 1024K init, 260K bss, 7576K reserved, 0K cma-reserved)"},
		{0, "kern.info kernel: [    3.512214] eth0: link up (1000Mbps/Full duplex)"},
		{2, "authpriv.info dropbear[341]: Not backgrounding"},
	}
	var out strings.Builder
	for _, l := range lines {
		t := bootTime.Add(time.Duration(l.second) * time.Second)
		out.WriteString(t.Format("Jan _2 15:04:05") + " gateway " + l.text + "\n")
	}
	return out.String()
}

// resolve turns a path typed by the attacker (relative, with .., with ~) into a clean absolute path.
// E.g. cwd "/tmp" + "../etc/passwd" -> "/etc/passwd"
func resolve(cwd, p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = "/root" + p[1:]
	}
	if !strings.HasPrefix(p, "/") {
		p = cwd + "/" + p
	}
	return path.Clean(p)
}

// under reports whether p is dir itself or something inside it.
func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// readFile checks the session's files first, then the built-in ones (following a symlink),
// so "echo x > /etc/passwd" overwrites it only for this attacker.
func (s *Shell) readFile(p string) (string, bool) {
	if content, ok := s.files[p]; ok {
		return content, true
	}
	if target, ok := fakeLinks[p]; ok {
		p = resolve(path.Dir(p), target) // /usr/bin/wget -> ../../bin/busybox -> /bin/busybox
	}
	content, ok := fakeFiles[p]
	return content, ok
}

// isDir reports whether p is a built-in or a session-created directory.
func (s *Shell) isDir(p string) bool {
	return fakeDirs[p] || s.dirs[p]
}

// list returns the names inside dir (hidden ones too), sorted alphabetically like ls.
func (s *Shell) list(dir string) []string {
	seen := map[string]bool{}
	add := func(p string) {
		if p != "/" && path.Dir(p) == dir {
			seen[path.Base(p)] = true
		}
	}
	for p := range fakeFiles {
		add(p)
	}
	for p := range fakeLinks {
		add(p)
	}
	for p := range fakeDirs {
		add(p)
	}
	for p := range s.files {
		add(p)
	}
	for p := range s.dirs {
		add(p)
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// writeFile writes (or appends, for >>) to a session file.
// Returns the error message, or "" on success.
func (s *Shell) writeFile(name, content string, appendTo bool) string {
	p := resolve(s.cwd, name)
	switch {
	case p == "/dev/null":
		return "" // anything written here disappears, like on a real system
	case s.isDir(p):
		return "-sh: can't create " + name + ": Is a directory\n"
	case !s.isDir(path.Dir(p)):
		return "-sh: can't create " + name + ": nonexistent directory\n"
	}

	if appendTo {
		old, _ := s.readFile(p)
		content = old + content
	}
	if len(content) > maxSize {
		content = content[:maxSize]
	}
	s.files[p] = content
	s.mtimes[p] = now().UTC()
	return ""
}
