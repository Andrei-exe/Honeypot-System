package vfs

import (
	"path"
	"strconv"
	"strings"
)

// Ce afiseaza "ps". Se potriveste cu povestea: router cu dropbear (SSH), telnetd si vsftpd.
const fakePS = `  PID USER       VSZ STAT COMMAND
    1 root      1516 S    /sbin/init
  341 root      1124 S    /usr/sbin/dropbear -F -P /var/run/dropbear.pid -p 22
  356 root      1032 S    /usr/sbin/telnetd -F -l /bin/login
  402 root      1208 S    /usr/sbin/vsftpd
  517 root      1300 S    -sh
  530 root      1296 R    ps
`

// command ruleaza o comanda. Intoarce: ce afiseaza, codul de iesire
// (0 = a mers, 127 = comanda nu exista, altceva = eroare) si daca sesiunea se inchide.
func (s *Shell) command(args []string, input string) (string, int, bool) {
	name := args[0]
	// "/bin/cat" = "cat", daca exista in /bin-ul nostru fals
	if _, ok := fakeFiles[name]; ok && path.Dir(name) == "/bin" {
		name = path.Base(name)
	}
	args = args[1:] // de aici, args = doar argumentele

	switch name {
	case "exit", "logout", "quit":
		return "", 0, true

	case "busybox":
		// "busybox wget ..." = "wget ..." (pe routere, toate comenzile sunt "applet-uri" din busybox)
		if len(args) == 0 {
			return "BusyBox v1.30.1 multi-call binary.\n", 0, false
		}
		out, code, exit := s.command(args, input)
		if code == 127 {
			// Mirai trimite "/bin/busybox ECCHI" si asteapta exact raspunsul asta
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

	case "wget", "curl", "tftp", "ftpget":
		// nu descarcam nimic: ii zicem ca "nu merge netul", dar URL-ul e deja logat
		return name + ": can't connect to remote host: Connection timed out\n", 1, false

	case "sh", "ash", "enable", "system", "shell", "linuxshell", "chmod", "mv",
		"kill", "killall", "export", "ulimit", "sleep", "true":
		// comenzi care pe un sistem real nu afiseaza nimic cand merg
		return "", 0, false
	case "false":
		return "", 1, false
	}

	// ./bot sau /tmp/x: daca fisierul exista, "ruleaza" in liniste (ca un malware pornit in fundal)
	if strings.Contains(name, "/") {
		if _, ok := s.readFile(resolve(s.cwd, name)); ok {
			return "", 0, false
		}
	}
	return "-sh: " + name + ": not found\n", 127, false
}

func uname(args []string) string {
	if len(args) == 0 {
		return "Linux\n"
	}
	switch args[0] {
	case "-a":
		return "Linux gateway 4.14.180 #1 SMP armv7l GNU/Linux\n"
	case "-m":
		return "armv7l\n" // botii intreaba asta ca sa stie ce binar sa descarce
	case "-r":
		return "4.14.180\n"
	case "-n":
		return "gateway\n"
	}
	return "Linux\n"
}

// echo [-n] [-e] text. -n = fara rand nou la final, -e = interpreteaza \n, \t, \xHH.
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

// isEchoFlag: "-n", "-e", "-ne", "-en", "-E" -> da; "-x" sau "-" -> nu (se afiseaza ca text)
func isEchoFlag(a string) bool {
	return len(a) > 1 && a[0] == '-' && strings.Trim(a[1:], "neE") == ""
}

// unescape transforma \n, \t, \r, \\ si \xHH in caracterele reale.
// Botii trimit des "echo -e '\x6b\x61\x6d\x69'" si verifica daca primesc "kami" -> asa stiu ca shell-ul e real.
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
			// \x6b -> 2 cifre hexa dupa x -> un byte
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
		s.cwd = "/root" // cd fara nimic = acasa
		return "", 0, false
	}
	dir := resolve(s.cwd, args[0])
	if !s.isDir(dir) {
		return "-sh: cd: can't cd to " + args[0] + ": No such file or directory\n", 1, false
	}
	s.cwd = dir
	return "", 0, false
}

func (s *Shell) ls(args []string) (string, int, bool) {
	target := "."
	for _, a := range args {
		if !strings.HasPrefix(a, "-") { // optiunile (-la, -l) le ignoram
			target = a
		}
	}

	p := resolve(s.cwd, target)
	if !s.isDir(p) {
		if _, ok := s.readFile(p); ok {
			return target + "\n", 0, false // ls pe un fisier = afiseaza numele lui
		}
		return "ls: " + target + ": No such file or directory\n", 1, false
	}

	names := s.list(p)
	if len(names) == 0 {
		return "", 0, false
	}
	return strings.Join(names, "  ") + "\n", 0, false
}

func (s *Shell) cat(args []string, input string) (string, int, bool) {
	if len(args) == 0 {
		return input, 0, false // "... | cat" = da mai departe ce a primit
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
			break // "cat x x x x ..." nu ne umple RAM-ul
		}
	}
	return out.String(), code, false
}

// grep TEXT [fisier] - pastreaza doar randurile care contin TEXT (fara regex, optiunile se ignora).
func (s *Shell) grep(args []string, input string) (string, int, bool) {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		args = args[1:]
	}
	if len(args) == 0 {
		return "Usage: grep [-HhnlLoqvsriwFE] PATTERN [FILE]...\n", 2, false
	}

	text := input // fara fisier, grep lucreaza pe ce vine prin |
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
		return "", 1, false // grep fara rezultat = cod 1 (conteaza la && si ||)
	}
	return out.String(), 0, false
}

func (s *Shell) touch(args []string) (string, int, bool) {
	for _, a := range args {
		p := resolve(s.cwd, a)
		if _, ok := s.readFile(p); ok || s.isDir(p) {
			continue // exista deja
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
	}
	return "", 0, false
}

// rm sterge doar ce a creat atacatorul; fisierele "de sistem" raman (simplificare).
func (s *Shell) rm(args []string) (string, int, bool) {
	for _, a := range args {
		p := resolve(s.cwd, a)
		delete(s.files, p)
		delete(s.dirs, p)
	}
	return "", 0, false
}

// cp sursa destinatie. Mirai face "cp /bin/echo x" ca sa aiba un fisier executabil pe care sa-l rescrie.
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
