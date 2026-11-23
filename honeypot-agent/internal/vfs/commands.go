package vfs

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// command runs one command (not one of the shell's own, see dispatch). Returns the output, the exit
// code (0 = ok, 127 = command not found, other = error) and whether the session should end.
// "/bin/cat" or "/usr/bin/wget" = "cat" / "wget" (busybox itself or one of its applet links); a name
// without "/" must be a builtin or in a directory of $PATH.
func (s *Shell) command(args []string, input string) (string, int, bool) {
	name := s.appletName(args[0])
	if name == "" { // "" (or an empty $X in quotes): ash tries to run it and the kernel refuses
		return s.errorf("", ": Permission denied"), 127, false
	}
	if !strings.Contains(args[0], "/") && !builtins[name] && !s.inPath(name) { // "/bin/ls" needs no $PATH
		return s.errorf("", name+": not found"), 127, false
	}
	if strings.Contains(args[0], "/") && !strings.Contains(name, "/") && name != "busybox" && !appletNames[name] {
		return name + ": applet not found\n", 127, false // busybox under a name no applet has (/proc/1/exe)
	}
	return s.applet(name, args[1:], input)
}

// appletNames are the commands busybox itself runs ("busybox wget"), those in applets.
var appletNames = func() map[string]bool {
	names := map[string]bool{}
	for _, a := range applets {
		for _, n := range a.names {
			names[n] = true
		}
	}
	return names
}()

// applet runs a command by name; args holds only its arguments.
func (s *Shell) applet(name string, args []string, input string) (string, int, bool) {
	switch name {
	case "busybox":
		// "busybox wget ..." = "wget ..." (on routers every command is a busybox applet)
		if len(args) == 0 {
			return busyboxHelp(), 0, false
		}
		if !appletNames[args[0]] {
			// Mirai sends "/bin/busybox ECCHI" and expects exactly this reply
			return args[0] + ": applet not found\n", 127, false
		}
		return s.applet(args[0], args[1:], input)

	case "whoami":
		return "root\n", 0, false
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)\n", 0, false
	case "hostname":
		return s.hostnameApplet(args)
	case "uname":
		return s.uname(args)
	case "sysctl":
		return s.sysctl(args)
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
	case "grep", "egrep", "fgrep":
		return s.grep(name, args, input)
	case "touch":
		return s.touch(args)
	case "mkdir":
		return s.mkdir(args)
	case "sync": // cryptominers: "sync; echo 3 > /proc/sys/vm/drop_caches"
		if len(args) > 0 { // Buildroot's BusyBox has no FEATURE_SYNC_FANCY: no options, no files
			s.warn("sync: ignoring all arguments\n")
		}
		return "", 0, false
	case "rm":
		return s.rm(args)
	case "cp":
		return s.cp(args)

	// what cryptominers check before installing (system.go)
	case "free":
		return free(args)
	case "nproc":
		return nproc(), 0, false
	case "uptime":
		return uptime(args), 0, false
	case "df":
		return s.df(args)
	case "crontab":
		return s.crontab(args, input)

	// nothing is ever downloaded (network.go); the URL is already logged. No curl: BusyBox has
	// none, so "curl" is "not found" below, like on a real router.
	case "wget":
		return s.wget(args)
	case "tftp":
		return s.tftp(args)
	case "ftpget":
		return s.ftpget(args)

	// the text tools bots pipe /proc and /etc through (text.go, sed.go, awk.go)
	case "wc":
		return s.wc(args, input)
	case "head", "tail":
		return s.headTail(name, args, input)
	case "cut":
		return s.cutApplet(args, input)
	case "tr":
		return s.tr(args, input)
	case "sort":
		return s.sortApplet(args, input)
	case "uniq":
		return s.uniq(args, input)
	case "seq":
		return seq(args)
	case "sed":
		return s.sed(args, input)
	case "awk":
		return s.awk(args, input)

	// looking around (utils.go)
	case "printf":
		return s.printf(args)
	case "test", "[", "[[":
		return s.test(name, args)
	case "which":
		return s.which(args)
	case "type":
		return s.typeBuiltin(args)
	case "read":
		return s.read(args, input)
	case "history":
		return s.historyBuiltin()
	case "help":
		return helpText, 0, false
	case "date":
		return date(args)
	case "sleep":
		out, code, exit := sleep(args)
		for _, a := range args {
			if n, _ := strconv.ParseFloat(strings.TrimRight(a, "smhd"), 64); code == 0 && n > 0 {
				s.stopJob() // a job sleeping: it goes on later, for us never
			}
		}
		return out, code, exit
	case "w":
		return wHeader, 0, false
	case "who":
		return "", 0, false

	case "sh", "ash", "chmod", "mv", "kill", "killall", "ulimit", "true", "syslogd", "klogd": // (kill: the applet)
		// commands that print nothing on success on a real system (the daemons go to the background;
		// "sh" alone would start a new shell, see sh in builtins.go)
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
		if s.inPath(name) {
			return "", 0, false
		}
		return s.errorf("", name+": not found"), 127, false
	}

	// ./bot or /tmp/x (a shell script never gets here: dispatch runs it, see script)
	p := resolve(s.cwd, name)
	content, ok := s.readFile(p)
	switch {
	case s.isDir(p):
		return s.errorf("", name+": Permission denied"), 126, false
	case !ok:
		return s.errorf("", name+": not found"), 127, false
	case s.files[p] == elfHeader:
		// the attacker's copy of busybox (cp /bin/busybox x, cp /bin/echo x): it runs as the applet it
		// is named after (the built-in programs, dropbear..., have the same header but run silently)
		if base := path.Base(name); appletNames[base] {
			return s.applet(base, args, input)
		}
		return path.Base(name) + ": applet not found\n", 127, false
	case strings.HasPrefix(content, "#!"):
		return s.errorf("", name+": not found"), 127, false // its interpreter (#!/bin/bash) doesn't exist
	}
	s.stopJob()         // in a job ("./xmrig &"): it runs for ever
	return "", 0, false // a program the attacker wrote: it "runs" silently (malware goes to the background)
}

// script reports whether running this file means running it as a shell script: text (ash runs a file
// the kernel can't execute itself) or "#!/bin/sh".
func (s *Shell) script(name string) bool {
	content, ok := s.readFile(resolve(s.cwd, name))
	if !ok || strings.HasPrefix(content, "\x7fELF") {
		return false
	}
	interpreter, _, _ := strings.Cut(strings.TrimPrefix(content, "#!"), "\n")
	if fields := strings.Fields(interpreter); strings.HasPrefix(content, "#!") {
		return len(fields) > 0 && (s.appletName(fields[0]) == "sh" || s.appletName(fields[0]) == "ash")
	}
	return true
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

const unameUsage = " [-amnrspvio]\n\nPrint system information\n\n\t-a\tPrint all\n\t-m\tThe machine (hardware) type\n" +
	"\t-n\tHostname\n\t-r\tKernel release\n\t-s\tKernel name (default)\n\t-p\tProcessor type\n" +
	"\t-v\tKernel version\n\t-i\tThe hardware platform\n\t-o\tOS name"

// unameLong are uname's long options (Buildroot: LONG_OPTS).
var unameLong = map[string]byte{"all": 'a', "kernel-name": 's', "nodename": 'n', "kernel-release": 'r',
	"release": 'r', "kernel-version": 'v', "machine": 'm', "processor": 'p', "hardware-platform": 'i',
	"operating-system": 'o'}

// uname prints the fields asked for, always in the order s n r v m p i o (coreutils/uname.c);
// -a agrees with /proc/version. Bots ask for -m to pick which binary to download.
func (s *Shell) uname(args []string) (string, int, bool) {
	opts, rest, complaint := getopt("uname", args, "snrvmpioa", unameLong)
	if complaint != "" || len(rest) > 0 {
		return usageAfter(complaint, "uname", unameUsage)
	}
	unknown := "unknown" // -p and -i: what the kernel doesn't say
	if opts['a'] != nil {
		unknown = "" // -a leaves them out
	}
	fields := []struct {
		letter byte
		value  string
	}{{'s', "Linux"}, {'n', s.hostname()}, {'r', kernelRelease}, {'v', kernelVersion}, {'m', "armv7l"},
		{'p', unknown}, {'i', unknown}, {'o', "GNU/Linux"}}
	var out []string
	for _, f := range fields {
		if (opts[f.letter] != nil || opts['a'] != nil) && f.value != "" {
			out = append(out, f.value)
		}
	}
	if len(opts) == 0 {
		out = []string{"Linux"} // no option = -s
	}
	return strings.Join(out, " ") + "\n", 0, false
}

// hostname is the router's name now: "gateway", unless the attacker changed it (hostname NAME,
// /proc/sys/kernel/hostname). The prompt keeps the old one: ash reads it once, like $HOSTNAME.
func (s *Shell) hostname() string {
	name, _ := s.readFile("/proc/sys/kernel/hostname")
	return strings.TrimSuffix(name, "\n")
}

const hostnameUsage = " [OPTIONS] [HOSTNAME | -F FILE]\n\nGet or set hostname or DNS domain name\n\n" +
	"\t-s\tShort\n\t-i\tAddresses for the hostname\n\t-d\tDNS domain name\n\t-f\tFully qualified domain name\n" +
	"\t-F FILE\tUse FILE's content as hostname"

// hostnameApplet prints or sets the name (networking/hostname.c). -d, -f and -i look the name up in
// /etc/hosts, where "gateway" is 192.168.1.1.
func (s *Shell) hostnameApplet(args []string) (string, int, bool) {
	opts, rest, complaint := getopt("hostname", args, "dfisF:v", nil)
	if complaint != "" {
		return usageAfter(complaint, "hostname", hostnameUsage)
	}
	name := s.hostname()
	short, _, _ := strings.Cut(name, ".")
	switch {
	case opts['d'] != nil || opts['f'] != nil || opts['i'] != nil:
		ip, canonical := s.lookupHost(name)
		if ip == "" {
			return "hostname: " + name + ": Unknown host\n", 1, false
		}
		first, domain, _ := strings.Cut(canonical, ".")
		switch {
		case opts['f'] != nil:
			return canonical + "\n", 0, false
		case opts['s'] != nil:
			return first + "\n", 0, false
		case opts['d'] != nil:
			if domain == "" {
				return "", 0, false
			}
			return domain + "\n", 0, false
		}
		return ip + "\n", 0, false
	case opts['s'] != nil:
		return short + "\n", 0, false
	case opts['F'] != nil: // the first word of each line that isn't a comment; the last one stays
		file := opts['F'][len(opts['F'])-1]
		text, ok := s.readFile(resolve(s.cwd, file))
		if !ok {
			return "hostname: can't open '" + file + "': No such file or directory\n", 1, false
		}
		for _, line := range splitLines(text) {
			if f := strings.Fields(line); len(f) > 0 && f[0][0] != '#' {
				if out, code, exit := s.setHostname(f[0]); code != 0 {
					return out, code, exit
				}
			}
		}
		return "", 0, false
	case len(rest) > 0:
		return s.setHostname(rest[0])
	}
	return name + "\n", 0, false
}

// setHostname is sethostname(): at most 64 bytes, like the kernel.
func (s *Shell) setHostname(name string) (string, int, bool) {
	if len(name) > 64 {
		return "hostname: sethostname: Invalid argument\n", 1, false
	}
	s.writeFile("/proc/sys/kernel/hostname", name, false)
	return "", 0, false
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
		var stop bool
		if text, stop = unescape(text); stop {
			return text // \c: nothing more, not even the newline
		}
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

// unescape = the escapes of echo -e and printf %b (the same code in BusyBox): \a \b \e \f \n \r
// \t \v \\, \xHH, \NNN and \0NNN; stop = a \c (the text ends there). Bots often send
// "echo -e '\x6b\x61\x6d\x69'" and check for "kami".
func unescape(s string) (text string, stop bool) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			out.WriteByte(s[i])
			continue
		}
		i++
		if j := strings.IndexByte(`abefnrtv\`, s[i]); j >= 0 {
			out.WriteByte("\a\b\x1b\f\n\r\t\v\\"[j])
			continue
		}
		switch s[i] {
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
		case 'c':
			return out.String(), true
		case '0', '1', '2', '3', '4', '5', '6', '7': // \NNN, and \0NNN (the leading 0 is skipped)
			if s[i] == '0' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' {
				i++
			}
			v, n := octalEscape(s[i:])
			out.WriteByte(v)
			i += n - 1
		default:
			out.WriteByte('\\')
			out.WriteByte(s[i])
		}
	}
	return out.String(), false
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
		case unreadable(p):
			out.WriteString("cat: can't open '" + a + "': Permission denied\n")
			code = 1
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

func (s *Shell) touch(args []string) (string, int, bool) {
	for _, a := range args {
		p := resolve(s.cwd, a)
		if _, ok := s.readFile(p); ok || s.isDir(p) {
			s.mtimes[p] = now().UTC() // already exists: touch only changes its date
			continue
		}
		if _, err := s.writeFile(a, "", false); err != nil {
			return "touch: " + a + ": " + err.Error() + "\n", 1, false
		}
	}
	return "", 0, false
}

const mkdirUsage = " [OPTIONS] DIRECTORY...\n\nCreate DIRECTORY\n\n\t-m MODE\tMode\n\t-p\tNo error if exists; make parent directories as needed"

// symbolicMode is what bb_parse_mode takes besides an octal number: u+x, go=rx, a-w,o+t...
var symbolicMode = regexp.MustCompile(`^[ugoa]*[-+=]([rwxXst]*|[ugo])([-+=]([rwxXst]*|[ugo]))*(,[ugoa]*[-+=]([rwxXst]*|[ugo])([-+=]([rwxXst]*|[ugo]))*)*$`)

// mkdir [-p] [-v] [-m MODE] DIRECTORY... like BusyBox's (coreutils/mkdir.c, libbb/make_directory.c):
// one that exists is an error unless -p, -p makes the parents, -v tells each one made; an error doesn't
// stop the others (exit code 1 at the end). The mode is checked, not kept (simplification).
func (s *Shell) mkdir(args []string) (string, int, bool) {
	opts, dirs, complaint := getopt("mkdir", args, "m:pv", map[string]byte{"mode": 'm', "parents": 'p', "verbose": 'v'})
	if complaint != "" {
		return usageAfter(complaint, "mkdir", mkdirUsage)
	}
	for _, m := range opts['m'] {
		if octal, err := strconv.ParseUint(m, 8, 32); (err != nil || octal > 07777) && !symbolicMode.MatchString(m) {
			return "mkdir: invalid mode '" + m + "'\n", 1, false
		}
	}
	if len(dirs) == 0 {
		return usage("mkdir", mkdirUsage)
	}
	_, parents := opts['p']
	_, verbose := opts['v']
	var out strings.Builder
	code := 0
	for _, dir := range dirs {
		if dir == "/" || dir == "." {
			continue // nothing to make
		}
		// with -p, each part in turn ("a/", "a/b/", "a/b/c"), like make_directory: the parts that exist are fine
		for end := 0; ; {
			last := true
			if parents {
				if i := strings.IndexByte(dir[end:], '/'); i >= 0 {
					end += i
					for end < len(dir) && dir[end] == '/' {
						end++
					}
					last = end == len(dir)
				} else {
					end = len(dir)
				}
			} else {
				end = len(dir)
			}
			part := dir[:end]
			reason := s.makeDir(part)
			if reason == "File exists" && parents && s.isDir(resolve(s.cwd, part)) {
				reason = "" // already there
			} else if reason == "" && verbose {
				out.WriteString("created directory: '" + part + "'\n")
			}
			if reason != "" {
				s.warn("mkdir: can't create directory '" + part + "': " + reason + "\n")
				code = 1
				break
			}
			if last {
				break
			}
		}
	}
	return out.String(), code, false
}

// makeDir makes one directory, whose parent must exist. Returns the kernel's reason if it can't ("" = made).
func (s *Shell) makeDir(name string) string {
	p := resolve(s.cwd, name)
	_, isFile := s.readFile(p)
	switch {
	case name == "":
		return "No such file or directory"
	case isFile && strings.HasSuffix(name, "/"): // "file/"
		return "Not a directory"
	case isFile || s.isDir(p):
		return "File exists"
	}
	if dir := path.Dir(p); !s.isDir(dir) {
		for d := dir; d != "/"; d = path.Dir(d) {
			if _, isFile := s.readFile(d); isFile { // a file on the way: /etc/passwd/x
				return "Not a directory"
			}
		}
		return "No such file or directory"
	}
	switch {
	case under(p, "/proc"): // procfs makes no directories
		return "No such file or directory"
	case under(p, "/sys"):
		return "Operation not permitted"
	case s.room(p) < 0:
		return errNoSpace.Error()
	}
	s.dirs[p] = true
	s.mtimes[p] = now().UTC()
	return ""
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
	failed, err := s.writeFile(dst, content, false)
	if err != nil { // libbb/copy_file.c
		return "cp: can't create '" + dst + "': " + err.Error() + "\n", 1, false
	}
	if failed != nil {
		return writeError("cp", failed), 1, false
	}
	return "", 0, false
}
