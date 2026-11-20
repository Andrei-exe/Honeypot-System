package vfs

import (
	"path"
	"sort"
	"strconv"
	"strings"
)

// fakePS is the output of ps. It matches the persona: a router running dropbear, telnetd and vsftpd,
// with syslogd writing /var/log/messages. Every program here exists in the fake filesystem.
const fakePS = `  PID USER       VSZ STAT COMMAND
    1 root      1516 S    /sbin/init
  289 root      1032 S    /sbin/syslogd -n
  291 root      1032 S    /sbin/klogd -n
  341 root      1124 S    /usr/sbin/dropbear -F -P /var/run/dropbear.pid -p 22
  349 root      2108 S    /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf
  356 root      1032 S    /usr/sbin/telnetd -F -l /bin/login
  402 root      1208 S    /usr/sbin/vsftpd
  517 root      1300 S    -sh
  530 root      1296 R    ps
`

// command runs one command. Returns the output, the exit code
// (0 = ok, 127 = command not found, other = error) and whether the session should end.
func (s *Shell) command(args []string, input string) (string, int, bool) {
	name := args[0]
	// "/bin/cat" or "/usr/bin/wget" = "cat" / "wget": busybox itself or one of its applet links
	if strings.Contains(name, "/") {
		if p := resolve(s.cwd, name); p == "/bin/busybox" || path.Base(fakeLinks[p]) == "busybox" {
			name = path.Base(p)
		}
	}
	args = args[1:] // from here on, args holds only the arguments

	switch name {
	case "exit", "logout", "quit":
		return "", 0, true

	case "busybox":
		// "busybox wget ..." = "wget ..." (on routers every command is a busybox applet)
		if len(args) == 0 {
			return busyboxHelp(), 0, false
		}
		out, code, exit := s.command(args, input)
		if code == 127 {
			// Mirai sends "/bin/busybox ECCHI" and expects exactly this reply
			return args[0] + ": applet not found\n", 127, false
		}
		return out, code, exit

	case "whoami":
		return "root\n", 0, false
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)\n", 0, false
	case "hostname":
		return "gateway\n", 0, false
	case "uname":
		return uname(args), 0, false
	case "pwd":
		return s.cwd + "\n", 0, false
	case "ps":
		return fakePS, 0, false
	case "echo":
		return echo(args), 0, false

	case "cd":
		return s.cd(args)
	case "ls":
		return s.ls(args)
	case "cat":
		return s.cat(args, input)
	case "grep":
		return s.grep(args, input)
	case "touch":
		return s.touch(args)
	case "mkdir":
		return s.mkdir(args)
	case "rm":
		return s.rm(args)
	case "cp":
		return s.cp(args)

	case "wget", "tftp", "ftpget":
		// nothing is downloaded: pretend the network is down (the URL is already logged).
		// No curl: BusyBox has none, so "curl" is "not found" below, like on a real router.
		return name + ": can't connect to remote host: Connection timed out\n", 1, false

	case "sh", "ash", "chmod", "mv", "kill", "killall", "export", "ulimit", "sleep", "true", "syslogd", "klogd":
		// commands that print nothing on success on a real system (the daemons go to the background)
		return "", 0, false
	case "login":
		return "", 0, false // simplification: a real one would ask "gateway login:" again
	case "false":
		return "", 1, false
	case "init":
		return "init: must be run as PID 1\n", 1, false
	case "telnetd":
		return "telnetd: bind: Address already in use\n", 1, false // it is already running (ps)
	}

	// Everything else is "not found", like on a real BusyBox: also curl and Mirai's probes for a
	// vendor CLI (enable, system, shell, linuxshell), which Mirai sends without reading the answer.

	// a program in PATH that isn't an applet (dropbear, vsftpd, lighttpd) "runs" silently too
	if !strings.Contains(name, "/") {
		for _, dir := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin"} {
			if _, ok := fakeFiles[dir+"/"+name]; ok {
				return "", 0, false
			}
		}
	}

	// ./bot or /tmp/x: if the file exists it "runs" silently (like malware started in the background)
	if strings.Contains(name, "/") {
		if _, ok := s.readFile(resolve(s.cwd, name)); ok {
			return "", 0, false
		}
	}
	return "-sh: " + name + ": not found\n", 127, false
}

// busyboxHelp is what "busybox" alone prints: BusyBox 1.30.1's text (libbb/appletlib.c, with
// Buildroot's config) and the applets, wrapped like BusyBox does for an 80-column terminal.
func busyboxHelp() string {
	var names []string
	for _, a := range applets {
		names = append(names, a.names...)
	}
	sort.Strings(names)

	var out strings.Builder
	out.WriteString(busyboxBanner + " multi-call binary.\n" +
		"BusyBox is copyrighted by many authors between 1998-2015.\n" +
		"Licensed under GPLv2. See source distribution for detailed\n" +
		"copyright notices.\n\n" +
		"Usage: busybox [function [arguments]...]\n" +
		"   or: busybox --list[-full]\n" +
		"   or: busybox --install [-s] [DIR]\n" +
		"   or: function [arguments]...\n\n" +
		"\tBusyBox is a multi-call binary that combines many common Unix\n" +
		"\tutilities into a single executable.  Most people will create a\n" +
		"\tlink to busybox for each function they wish to use and BusyBox\n" +
		"\twill act like whatever it was invoked as.\n\n" +
		"Currently defined functions:\n")
	col := 0
	for _, name := range names {
		if col >= 79-(len(name)+2) { // the line would get too long: wrap
			out.WriteString(",\n")
			col = 0
		}
		if col == 0 {
			out.WriteString("\t")
			col = 6 // BusyBox counts the tab as 6
		} else {
			out.WriteString(", ")
		}
		out.WriteString(name)
		col += len(name) + 2
	}
	return out.String() + "\n"
}

// uname answers the flags bots usually ask for; -a agrees with /proc/version.
func uname(args []string) string {
	if len(args) == 0 {
		return "Linux\n"
	}
	switch args[0] {
	case "-a":
		return "Linux gateway " + kernelRelease + " " + kernelVersion + " armv7l GNU/Linux\n"
	case "-m":
		return "armv7l\n" // bots ask this to pick which binary to download
	case "-r":
		return kernelRelease + "\n"
	case "-v":
		return kernelVersion + "\n"
	case "-n":
		return "gateway\n"
	case "-o":
		return "GNU/Linux\n"
	}
	return "Linux\n"
}

// echo [-n] [-e] text. -n = no trailing newline, -e = interpret \n, \t, \xHH.
func echo(args []string) string {
	newline := true
	escapes := false
	for len(args) > 0 && isEchoFlag(args[0]) {
		if strings.Contains(args[0], "n") {
			newline = false
		}
		if strings.Contains(args[0], "e") {
			escapes = true
		}
		args = args[1:]
	}

	text := strings.Join(args, " ")
	if escapes {
		text = unescape(text)
	}
	if newline {
		text += "\n"
	}
	return text
}

// isEchoFlag: "-n", "-e", "-ne", "-en", "-E" -> yes; "-x" or "-" -> no (printed as text).
func isEchoFlag(a string) bool {
	return len(a) > 1 && a[0] == '-' && strings.Trim(a[1:], "neE") == ""
}

// unescape turns \n, \t, \r, \\ and \xHH into the real characters. Bots often send
// "echo -e '\x6b\x61\x6d\x69'" and check for "kami" to tell if the shell is real.
func unescape(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			out.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		case 'r':
			out.WriteByte('\r')
		case '\\':
			out.WriteByte('\\')
		case 'x':
			// \x6b -> two hex digits after x -> one byte
			if i+2 < len(s) {
				if b, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					out.WriteByte(byte(b))
					i += 2
					continue
				}
			}
			out.WriteString(`\x`)
		default:
			out.WriteByte('\\')
			out.WriteByte(s[i])
		}
	}
	return out.String()
}

func (s *Shell) cd(args []string) (string, int, bool) {
	if len(args) == 0 {
		s.cwd = "/root" // cd with no argument = home
		return "", 0, false
	}
	dir := resolve(s.cwd, args[0])
	if !s.isDir(dir) {
		return "-sh: cd: can't cd to " + args[0] + ": No such file or directory\n", 1, false
	}
	s.cwd = dir
	return "", 0, false
}

func (s *Shell) cat(args []string, input string) (string, int, bool) {
	if len(args) == 0 {
		return input, 0, false // "... | cat" passes its input through
	}

	var out strings.Builder
	code := 0
	for _, a := range args {
		p := resolve(s.cwd, a)
		content, ok := s.readFile(p)
		switch {
		case ok:
			out.WriteString(content)
		case s.isDir(p):
			out.WriteString("cat: read error: Is a directory\n")
			code = 1
		default:
			out.WriteString("cat: can't open '" + a + "': No such file or directory\n")
			code = 1
		}
		if out.Len() > maxSize {
			break // so "cat x x x x ..." can't fill the RAM
		}
	}
	return out.String(), code, false
}

// grep TEXT [file] keeps only the lines containing TEXT (no regex, options are ignored).
func (s *Shell) grep(args []string, input string) (string, int, bool) {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		args = args[1:]
	}
	if len(args) == 0 {
		return "Usage: grep [-HhnlLoqvsriwFE] PATTERN [FILE]...\n", 2, false
	}

	text := input // without a file, grep works on what comes through |
	if len(args) > 1 {
		text, _, _ = s.cat(args[1:], "")
	}

	var out strings.Builder
	for _, row := range strings.SplitAfter(text, "\n") {
		if row != "" && strings.Contains(row, args[0]) {
			out.WriteString(row)
		}
	}
	if out.Len() == 0 {
		return "", 1, false // no match = exit code 1 (matters for && and ||)
	}
	return out.String(), 0, false
}

func (s *Shell) touch(args []string) (string, int, bool) {
	for _, a := range args {
		p := resolve(s.cwd, a)
		if _, ok := s.readFile(p); ok || s.isDir(p) {
			s.mtimes[p] = now().UTC() // already exists: touch only changes its date
			continue
		}
		if msg := s.writeFile(a, "", false); msg != "" {
			return "touch: " + a + ": No such file or directory\n", 1, false
		}
	}
	return "", 0, false
}

func (s *Shell) mkdir(args []string) (string, int, bool) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue // -p
		}
		p := resolve(s.cwd, a)
		if !s.isDir(path.Dir(p)) {
			return "mkdir: can't create directory '" + a + "': No such file or directory\n", 1, false
		}
		s.dirs[p] = true
		s.mtimes[p] = now().UTC()
	}
	return "", 0, false
}

// rm only deletes what the attacker created; built-in files stay (simplification).
func (s *Shell) rm(args []string) (string, int, bool) {
	for _, a := range args {
		p := resolve(s.cwd, a)
		delete(s.files, p)
		delete(s.dirs, p)
		delete(s.mtimes, p)
	}
	return "", 0, false
}

// cp src dst. Mirai runs "cp /bin/echo x" to get an executable file it can overwrite.
func (s *Shell) cp(args []string) (string, int, bool) {
	var paths []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			paths = append(paths, a)
		}
	}
	if len(paths) < 2 {
		return "cp: missing file operand\n", 1, false
	}

	src, dst := paths[0], paths[len(paths)-1]
	content, ok := s.readFile(resolve(s.cwd, src))
	if !ok {
		return "cp: can't stat '" + src + "': No such file or directory\n", 1, false
	}
	if s.isDir(resolve(s.cwd, dst)) {
		dst = dst + "/" + path.Base(src) // cp x /tmp -> /tmp/x
	}
	if msg := s.writeFile(dst, content, false); msg != "" {
		return msg, 1, false
	}
	return "", 0, false
}
