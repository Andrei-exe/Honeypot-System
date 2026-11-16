package vfs

import (
	"path"
	"sort"
	"strings"
)

// maxSize caps an attacker-created file and the output of one command. Without it,
// "cat a a > b; cat b b > a; ..." would double the file on every command until RAM runs out.
const maxSize = 16 * 1024

// elfHeader is the start of a 32-bit ARM ELF binary. Mirai-style bots "cat /bin/echo" and read
// these bytes to learn the architecture (0x28 = ARM), then download the matching binary.
const elfHeader = "\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00"

// fakeDirs exist from the start (read-only, shared by all sessions). Bots often cd into
// /tmp, /var/run, /mnt or /dev/shm to drop their binary, so all of these must exist.
var fakeDirs = map[string]bool{
	"/": true, "/bin": true, "/dev": true, "/dev/shm": true, "/etc": true,
	"/lib": true, "/mnt": true, "/proc": true, "/root": true, "/sbin": true,
	"/sys": true, "/tmp": true, "/usr": true, "/usr/bin": true, "/usr/sbin": true,
	"/var": true, "/var/log": true, "/var/run": true, "/var/tmp": true,
}

// fakeFiles exist from the start: path -> content (read-only, shared by all sessions).
var fakeFiles = map[string]string{
	// on routers every command in /bin is the same program (busybox)
	"/bin/busybox": elfHeader,
	"/bin/ash":     elfHeader,
	"/bin/sh":      elfHeader,
	"/bin/cat":     elfHeader,
	"/bin/echo":    elfHeader,
	"/bin/ls":      elfHeader,
	"/bin/ps":      elfHeader,
	"/bin/wget":    elfHeader,
	"/sbin/init":   elfHeader,

	// "our" services, matching what ps shows
	"/usr/sbin/dropbear": elfHeader,
	"/usr/sbin/telnetd":  elfHeader,
	"/usr/sbin/vsftpd":   elfHeader,

	"/dev/null": "",

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
	"/proc/meminfo": "MemTotal:         124520 kB\nMemFree:           38412 kB\nMemAvailable:      61208 kB\n",
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

// readFile checks the session's files first, then the built-in ones,
// so "echo x > /etc/passwd" overwrites it only for this attacker.
func (s *Shell) readFile(p string) (string, bool) {
	if content, ok := s.files[p]; ok {
		return content, true
	}
	content, ok := fakeFiles[p]
	return content, ok
}

// isDir reports whether p is a built-in or a session-created directory.
func (s *Shell) isDir(p string) bool {
	return fakeDirs[p] || s.dirs[p]
}

// list returns the names inside dir, sorted alphabetically like ls.
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
	return ""
}
