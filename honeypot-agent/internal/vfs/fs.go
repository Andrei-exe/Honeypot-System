package vfs

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// maxSize caps an attacker-created file and the output of one command. Without it,
// "cat a a > b; cat b b > a; ..." would double the file on every command until RAM runs out.
const maxSize = 16 * 1024

// sessionQuota is the "disk" of one session: its files live in the agent's RAM, and maxSize alone
// doesn't stop "cat b >f1; cat b >f2; ...". Over it, writes fail like on a full disk (ENOSPC).
// 400 shells (200 SSH + 200 Telnet) x 256KB = 100MB at most.
const sessionQuota = 256 * 1024

// Why a file can't be written: the kernel's texts (strerror), capitalized as the user sees them.
// Each command puts them in its own message ("touch: x: ...", "cp: can't create 'x': ...").
var (
	errIsDir    = errors.New("Is a directory")
	errNoDir    = errors.New("No such file or directory")
	errNoSpace  = errors.New("No space left on device")
	errBadFD    = errors.New("Bad file descriptor") // writing to a descriptor closed with >&-
	errNoAccess = errors.New("Permission denied")   // a read-only /proc/sys setting, a new file in /sys
	errInvalid  = errors.New("Invalid argument")    // a value a /proc/sys setting doesn't take
	errIO       = errors.New("Input/output error")  // writing to a /proc file that takes no writes
)

// diskCost is what a file or directory takes from sessionQuota: its content in whole 4KB pages (like
// tmpfs, and like df counts it) + its path + 256 bytes (like an inode), so even empty files run out.
func diskCost(p, content string) int {
	return (len(content)+4095)/4096*4096 + len(p) + 256
}

// quotaUsed is how much of sessionQuota the session's files and directories take.
func (s *Shell) quotaUsed() int {
	used := 0
	for p, content := range s.files {
		used += diskCost(p, content)
	}
	for p := range s.dirs {
		used += diskCost(p, "")
	}
	return used
}

// room is how many bytes of content p can hold before the quota is full (p's current content is
// replaced, so its space counts as free). Negative: not even an empty p fits.
func (s *Shell) room(p string) int {
	left := sessionQuota - s.quotaUsed()
	if content, ok := s.files[p]; ok {
		left += diskCost(p, content)
	} else if s.dirs[p] {
		left += diskCost(p, "")
	}
	return left - diskCost(p, "")
}

// writeError is what a command prints when writing its output fails (the disk is full, or the output
// was closed). echo is ash's builtin, so it reports as the shell: "sh" (applet_name, the login "-"
// stripped); applets copying data (cat, cp, crontab: libbb/copyfd.c) use their own name. Other
// applets would say "standard output" (simplified).
func writeError(command string, reason error) string {
	if command == "echo" {
		command = "sh"
	}
	return path.Base(command) + ": write error: " + reason.Error() + "\n"
}

// elfHeader is the start of a 32-bit ARM ELF binary. Mirai-style bots "cat /bin/echo" and read
// these bytes to learn the architecture (0x28 = ARM), then download the matching binary.
const elfHeader = "\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00"

// The firmware's identity: built with Buildroot 2019.05.3 (the release that has exactly our
// BusyBox, Dropbear, uClibc-ng, vsftpd and lighttpd) on Jun 4 2020. /proc/version, uname -a,
// the boot log and busybox must agree; the kernel's date pads the day like date does: "Jun  4".
const (
	kernelRelease = "4.14.180"
	kernelVersion = "#1 SMP Thu Jun  4 12:00:00 UTC 2020"
	linuxVersion  = "Linux version " + kernelRelease + " (builder@buildhost) (gcc version 8.3.0 (Buildroot 2019.05.3)) " + kernelVersion
	busyboxBanner = "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC)"
)

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
	"/": true, "/bin": true, "/dev": true, "/dev/shm": true, "/etc": true, "/etc/dropbear": true,
	"/etc/lighttpd": true, "/usr/lib/lighttpd": true, "/var/www": true,
	"/lib": true, "/mnt": true, "/proc": true, "/root": true, "/sbin": true,
	"/sys": true, "/tmp": true, "/usr": true, "/usr/bin": true, "/usr/lib": true, "/usr/sbin": true,
	"/var": true, "/var/log": true, "/var/run": true, "/var/tmp": true,
	"/var/spool": true, "/var/spool/cron": true, crontabDir: true, // crontab's (Buildroot: FEATURE_CROND_DIR)
	"/etc/ppp": true, "/etc/ppp/peers": true, "/usr/lib/pppd": true, "/usr/lib/pppd/2.4.7": true,
	// the kernel settings (kernelSettings in system.go); the directories a 4.14 ARM kernel has, some empty here
	"/proc/sys": true, "/proc/sys/debug": true, "/proc/sys/dev": true, "/proc/sys/fs": true, "/proc/sys/kernel": true,
	"/proc/sys/net": true, "/proc/sys/net/ipv4": true, "/proc/sys/user": true, "/proc/sys/vm": true,
}

// Honeytokens: secrets that exist only in the files below (the Wi-Fi password, the provider's
// PPPoE account). Reading the files is logged anyway (command_exec). If one of these strings ever
// comes back in a login attempt, whoever sent it had read the file. They must never be in
// weakCredentials: the Wi-Fi password is not root's password on a real router either.
const (
	wifiPassphrase = "w7Kq2mVx9pLz"
	pppoeUser      = "2210417553"
	pppoePassword  = "Rp4tHx92kQ"
)

// applets are the BusyBox commands, installed as symlinks to /bin/busybox like on a real router.
// Only commands the fake shell answers: a listed command that says "not found" would give us
// away (TestAppletsAreImplemented checks it).
var applets = []struct {
	dir    string
	target string // /bin/busybox, relative to dir (the way BusyBox installs its links)
	names  []string
}{
	{"/bin", "busybox", []string{"ash", "cat", "chmod", "cp", "date", "df", "echo", "egrep", "false", "fgrep",
		"grep", "hostname", "kill", "login", "ls", "mkdir", "mv", "ps", "pwd", "rm", "sed", "sh", "sleep",
		"touch", "true", "uname"}},
	{"/sbin", "../bin/busybox", []string{"init", "klogd", "sysctl", "syslogd"}},
	{"/usr/bin", "../../bin/busybox", []string{"[", "[[", "awk", "crontab", "cut", "env", "free", "ftpget",
		"head", "id", "killall", "nohup", "nproc", "printf", "seq", "sort", "tail", "test", "tftp", "tr", "uniq",
		"uptime", "w", "wc", "wget", "which", "who", "whoami"}},
	{"/usr/sbin", "../../bin/busybox", []string{"telnetd"}},
}

// fakeLinks are the symbolic links: path -> target, written the way ls -l shows it.
var fakeLinks = makeLinks()

func makeLinks() map[string]string {
	links := map[string]string{
		// the C library (uClibc-ng, common on cheap routers): short names -> the versioned file
		"/lib/ld-uClibc.so.0": "ld-uClibc-1.0.31.so",
		"/lib/libc.so.0":      "libuClibc-1.0.31.so",
		"/etc/os-release":     "../usr/lib/os-release", // Buildroot makes exactly this link
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

	"/usr/sbin/lighttpd":                  203512,
	"/var/www/login.cgi":                  13764,
	"/usr/lib/lighttpd/mod_access.so":     5328,
	"/usr/lib/lighttpd/mod_cgi.so":        22968,
	"/usr/lib/lighttpd/mod_dirlisting.so": 21456,
	"/usr/lib/lighttpd/mod_indexfile.so":  4912,
	"/usr/lib/lighttpd/mod_staticfile.so": 9632,

	"/usr/sbin/hostapd":               598764,
	"/usr/sbin/pppd":                  301228,
	"/usr/lib/pppd/2.4.7/rp-pppoe.so": 22584,
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

	// the web server (ps: lighttpd -f /etc/lighttpd/lighttpd.conf), its modules and its site
	"/usr/sbin/lighttpd":                  elfHeader,
	"/usr/lib/lighttpd/mod_access.so":     elfHeader, // the 2 modules in lighttpd.conf...
	"/usr/lib/lighttpd/mod_cgi.so":        elfHeader,
	"/usr/lib/lighttpd/mod_dirlisting.so": elfHeader, // ...and the 3 lighttpd always loads
	"/usr/lib/lighttpd/mod_indexfile.so":  elfHeader,
	"/usr/lib/lighttpd/mod_staticfile.so": elfHeader,
	"/etc/lighttpd/lighttpd.conf":         lighttpdConf,
	"/var/www/index.html":                 LoginPage(false),
	"/var/www/login.cgi":                  elfHeader, // the form's target: a compiled CGI, like on real routers

	// Wi-Fi (ps: hostapd -B /etc/hostapd.conf) and the provider link (ps: pppd call isp): their
	// configs hold the honeytokens. A vendor's default SSID ends with part of the MAC address.
	"/usr/sbin/hostapd": elfHeader,
	"/etc/hostapd.conf": "interface=wlan0\ndriver=nl80211\nssid=Gateway-4F2A\nhw_mode=g\nchannel=6\n" +
		"ieee80211n=1\nwmm_enabled=1\nauth_algs=1\nwpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n" +
		"wpa_passphrase=" + wifiPassphrase + "\n",
	"/usr/sbin/pppd":                  elfHeader,
	"/usr/lib/pppd/2.4.7/rp-pppoe.so": elfHeader, // PPPoE = PPP over the WAN port (eth0)
	"/etc/ppp/peers/isp": "plugin rp-pppoe.so eth0\nuser \"" + pppoeUser + "\"\nnoauth\ndefaultroute\n" +
		"persist\nmaxfail 0\nholdoff 10\nmtu 1492\nmru 1492\n",
	"/etc/ppp/chap-secrets": "# Secrets for authentication using CHAP\n# client\tserver\tsecret\t\t\tIP addresses\n" +
		"\"" + pppoeUser + "\"\t*\t\"" + pppoePassword + "\"\t*\n",

	"/dev/null": "",

	"/var/run/dropbear.pid": "341\n", // ps: dropbear -P /var/run/dropbear.pid, PID 341
	"/var/run/lighttpd.pid": "349\n", // lighttpd.conf: server.pid-file
	"/var/log/messages":     bootLog(),

	// what Buildroot writes in os-release (its Makefile, target-finalize)
	"/usr/lib/os-release": "NAME=Buildroot\nVERSION=2019.05.3\nID=buildroot\nVERSION_ID=2019.05.3\n" +
		"PRETTY_NAME=\"Buildroot 2019.05.3\"\n",
	// the vendor's profile: the PS1 here is why the prompt is root@gateway:~# (Buildroot's own is "# ")
	"/etc/profile":   "export PATH=/bin:/sbin:/usr/bin:/usr/sbin\n" + `export PS1='\u@\h:\w\$ '` + "\n",
	"/etc/issue.net": "Gateway Linux 4.14\n", // telnetd shows it before "gateway login:"

	// Buildroot's own /etc/group (system/skeleton); admin, support and user are in group 0
	"/etc/group": "root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:\ntty:x:5:\ndisk:x:6:\nlp:x:7:\n" +
		"mail:x:8:\nkmem:x:9:\nwheel:x:10:root\ncdrom:x:11:\ndialout:x:18:\nfloppy:x:19:\nvideo:x:28:\n" +
		"audio:x:29:\ntape:x:32:\nwww-data:x:33:\noperator:x:37:\nutmp:x:43:\nplugdev:x:46:\nstaff:x:50:\n" +
		"lock:x:54:\nnetdev:x:82:\nusers:x:100:\nnogroup:x:65534:\n",
	// Buildroot's finalize hooks write it: busybox.mk adds /bin/ash, skeleton-init-common.mk /bin/sh
	// (Dropbear refuses a login whose shell isn't listed here)
	"/etc/shells": "/bin/ash\n/bin/sh\n",
	// Dropbear's host key (the SSH server's type: ECDSA)
	"/etc/dropbear/dropbear_ecdsa_host_key": dropbearHostKey(),

	"/etc/hostname":    "gateway\n",
	"/etc/hosts":       "127.0.0.1 localhost\n192.168.1.1 gateway\n",
	"/etc/resolv.conf": "nameserver 192.168.1.1\n",
	// admin, support and user have uid 0 (common on IoT), so whoami says root for any login.
	// Every user in weakCredentials must be here and in /etc/shadow. The shell is /bin/sh, like root's
	// in Buildroot's skeleton: login starts it as "-sh", the name in ps, $0 and the shell's errors.
	"/etc/passwd": "root:x:0:0:root:/root:/bin/sh\n" +
		"daemon:*:1:1:daemon:/var:/bin/false\n" +
		"admin:x:0:0:admin:/root:/bin/sh\n" +
		"support:x:0:0:support:/root:/bin/sh\n" +
		"user:x:0:0:user:/root:/bin/sh\n" +
		"nobody:*:65534:65534:nobody:/var:/bin/false\n",
	"/etc/shadow": "root:$1$Fz8sK2lQ$wE0bq3Yt1aRk9mVh7uXcN.:18417:0:99999:7:::\n" +
		"daemon:*:0:0:99999:7:::\n" +
		"admin:$1$Qw3rT9pZ$Lm2vX8cB1nK7dF4hJ6sA0.:18417:0:99999:7:::\n" +
		"support:$1$Hy6uJ1kL$Pq9wE3rT5yU7iO2aS4dF6.:18417:0:99999:7:::\n" +
		"user:$1$Zx8cV2bN$Mk1lO3pI5uY7tR9eW0qA2.:18417:0:99999:7:::\n" +
		"nobody:*:0:0:99999:7:::\n",

	"/proc/version": linuxVersion + "\n",
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

// memInfo is the memory of a 4.14 kernel with 128MB and no swap. The numbers agree
// (Active = Active(anon) + Active(file), Slab = SReclaimable + SUnreclaim, CommitLimit = MemTotal / 2);
// /proc/meminfo, free and df (the size of a tmpfs) are all computed from them.
var memInfo = []struct {
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

// memKB returns one memInfo value in kB ("MemTotal" -> 124520).
func memKB(name string) int {
	for _, f := range memInfo {
		if f.name == name {
			return f.kb
		}
	}
	return 0 // a typo in our own code: free's exact output in the tests would show it
}

// meminfo is /proc/meminfo, in the kernel's format.
func meminfo() string {
	var out strings.Builder
	for _, f := range memInfo {
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
		{0, "kern.notice kernel: [    0.000000] " + linuxVersion},
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

// dropbearHostKey is a key file in Dropbear's format: type, curve, public point, private number
// (141 bytes, like a real ECDSA P-256 one). The numbers are made up from a hash of a fixed text:
// the real SSH host key is never put where an attacker can read it.
func dropbearHostKey() string {
	var key []byte
	field := func(b []byte) { // Dropbear writes each part as length (4 bytes) + bytes
		key = binary.BigEndian.AppendUint32(key, uint32(len(b)))
		key = append(key, b...)
	}
	x := sha256.Sum256([]byte("gateway dropbear x"))
	y := sha256.Sum256(x[:])
	d := sha256.Sum256(y[:])
	field([]byte("ecdsa-sha2-nistp256"))
	field([]byte("nistp256"))
	field(append(append([]byte{4}, x[:]...), y[:]...)) // the point: 04 | X | Y
	field(append([]byte{0}, d[:]...))                  // the private number
	return string(key)
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

// readFile checks the session's files first, then the built-in ones,
// so "echo x > /etc/passwd" overwrites it only for this attacker.
func (s *Shell) readFile(p string) (string, bool) {
	if content, ok := s.files[p]; ok {
		return content, true
	}
	return readBuiltin(p)
}

// readBuiltin reads a built-in file, following a symlink.
func readBuiltin(p string) (string, bool) {
	if target, ok := fakeLinks[p]; ok {
		p = resolve(path.Dir(p), target) // /usr/bin/wget -> ../../bin/busybox -> /bin/busybox
	}
	if gen, ok := dynamicFiles[p]; ok {
		return gen(), true // /proc/uptime: computed now
	}
	if k, ok := kernelSettings[p]; ok {
		return k.read(), true
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
	for p := range dynamicFiles {
		add(p)
	}
	for p := range kernelSettings {
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

// writeFile writes (or appends, for >>) to a session file. err says why the file can't be opened or
// created (nil if it was). failed = it was opened, but writing failed and the caller prints its own write
// error: the disk filled up (errNoSpace: only the whole pages that fit were written, where a real write
// stops with ENOSPC), or the kernel refused what was written to /proc (see writeProc).
func (s *Shell) writeFile(name, content string, appendTo bool) (failed, err error) {
	p := resolve(s.cwd, name)
	switch {
	case p == "/dev/null":
		return nil, nil // anything written here disappears, like on a real system
	case s.isDir(p):
		return nil, errIsDir
	case !s.isDir(path.Dir(p)):
		return nil, errNoDir
	case under(p, "/proc"):
		return s.writeProc(p, content)
	case under(p, "/sys"):
		return nil, errNoAccess // sysfs makes no new files (and none of its own are simulated)
	}
	room := s.room(p)
	if room < 0 {
		return nil, errNoSpace // not even an empty file fits (like running out of inodes)
	}

	if appendTo {
		old, _ := s.readFile(p)
		content = old + content
	}
	if len(content) > maxSize {
		content = content[:maxSize]
	}
	if fits := room / 4096 * 4096; len(content) > fits {
		content, failed = content[:fits], errNoSpace
	}
	// a copy: a cut string still holds all of the original's memory (even cut to ""), which the
	// quota wouldn't see (measured: 2x the quota in RAM, from the empty files of a cat that didn't fit)
	s.files[p] = strings.Clone(content)
	s.mtimes[p] = now().UTC()
	return failed, nil
}

// writeProc writes to /proc like the kernel: nothing new can be created there (ENOENT, which ash
// calls "nonexistent directory"), a /proc/sys setting takes only what its handler accepts, the other
// files take no writes (EIO). Each write is checked by itself, like one write(); opening ("") changes nothing.
func (s *Shell) writeProc(p, content string) (failed, err error) {
	k, isSetting := kernelSettings[p]
	_, exists := readBuiltin(p)
	switch {
	case !exists:
		return nil, errNoDir
	case isSetting && k.mode == settingRO:
		return nil, errNoAccess // even for root (proc_sys_permission)
	case content == "":
		return nil, nil
	case !isSetting:
		return errIO, nil
	}
	value, ok := k.set(content)
	if !ok {
		return errInvalid, nil
	}
	if k.mode != settingWO {
		s.files[p] = value // read back from here (readFile looks at the session's files first)
	}
	return nil, nil
}
