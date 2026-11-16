package vfs

import (
	"path"
	"sort"
	"strings"
)

// maxSize = cat text tinem intr-un fisier creat de atacator si cat afisam dintr-o data.
// Fara limita, "cat a a > b; cat b b > a; ..." ar dubla fisierul la fiecare comanda -> RAM plin.
const maxSize = 16 * 1024

// elfHeader = inceputul unui program compilat pentru ARM pe 32 de biti.
// Botii de tip Mirai dau "cat /bin/echo" si se uita la bytes-ii astia ca sa afle
// arhitectura (0x28 = ARM), apoi descarca binarul potrivit pentru ea.
const elfHeader = "\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00\x00\x00"

// Directoarele care exista din start. Botii fac des cd in /tmp, /var/run, /mnt, /dev/shm
// ca sa-si puna acolo binarul -> toate trebuie sa existe.
var fakeDirs = map[string]bool{
	"/": true, "/bin": true, "/dev": true, "/dev/shm": true, "/etc": true,
	"/lib": true, "/mnt": true, "/proc": true, "/root": true, "/sbin": true,
	"/sys": true, "/tmp": true, "/usr": true, "/usr/bin": true, "/usr/sbin": true,
	"/var": true, "/var/log": true, "/var/run": true, "/var/tmp": true,
}

// Fisierele care exista din start: cale -> continut.
var fakeFiles = map[string]string{
	// pe routere, toate comenzile din /bin sunt de fapt acelasi program (busybox)
	"/bin/busybox": elfHeader,
	"/bin/ash":     elfHeader,
	"/bin/sh":      elfHeader,
	"/bin/cat":     elfHeader,
	"/bin/echo":    elfHeader,
	"/bin/ls":      elfHeader,
	"/bin/ps":      elfHeader,
	"/bin/wget":    elfHeader,
	"/sbin/init":   elfHeader,

	// serviciile "noastre", ca sa se potriveasca cu ce arata ps
	"/usr/sbin/dropbear": elfHeader,
	"/usr/sbin/telnetd":  elfHeader,
	"/usr/sbin/vsftpd":   elfHeader,

	"/dev/null": "",

	"/etc/hostname":    "gateway\n",
	"/etc/hosts":       "127.0.0.1 localhost\n192.168.1.1 gateway\n",
	"/etc/resolv.conf": "nameserver 192.168.1.1\n",
	// admin, support si user au uid 0 (adica sunt tot root) - des intalnit pe dispozitive IoT.
	// Asa "whoami" = root e realist pentru oricine intra: whoami cauta PRIMUL nume cu uid-ul tau.
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
	// Mirai citeste /proc/mounts ca sa gaseasca directoare in care poate scrie (rw)
	"/proc/mounts": "rootfs / rootfs rw 0 0\n" +
		"proc /proc proc rw,nosuid,nodev,noexec,noatime 0 0\n" +
		"sysfs /sys sysfs rw,nosuid,nodev,noexec,noatime 0 0\n" +
		"tmpfs /tmp tmpfs rw,nosuid,nodev,noatime 0 0\n" +
		"tmpfs /dev tmpfs rw,nosuid,relatime,size=512k,mode=755 0 0\n",
}

// resolve face dintr-o cale scrisa de atacator (relativa, cu .., cu ~) o cale absoluta curata.
// Ex: cwd "/tmp" + "../etc/passwd" -> "/etc/passwd"
func resolve(cwd, p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = "/root" + p[1:]
	}
	if !strings.HasPrefix(p, "/") {
		p = cwd + "/" + p
	}
	return path.Clean(p)
}

// readFile cauta intai in fisierele create de atacator, apoi in cele din start.
// Asa, "echo x > /etc/passwd" il "suprascrie" doar pentru atacatorul asta.
func (s *Shell) readFile(p string) (string, bool) {
	if content, ok := s.files[p]; ok {
		return content, true
	}
	content, ok := fakeFiles[p]
	return content, ok
}

func (s *Shell) isDir(p string) bool {
	return fakeDirs[p] || s.dirs[p]
}

// list intoarce ce e in directorul dir (numele simple), sortat alfabetic ca la ls.
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

// writeFile scrie (sau adauga la final, la >>) intr-un fisier al sesiunii.
// Intoarce mesajul de eroare, sau "" daca a mers.
func (s *Shell) writeFile(name, content string, appendTo bool) string {
	p := resolve(s.cwd, name)
	switch {
	case p == "/dev/null":
		return "" // tot ce intra aici dispare, ca pe un sistem real
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
