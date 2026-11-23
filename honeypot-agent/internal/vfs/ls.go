package vfs

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ls imitates BusyBox 1.30 ls: the same columns, the same -l line, hidden files only with -a / -A.

// terminalWidth is what BusyBox ls lays its columns out for: an 80-column terminal, minus one.
const terminalWidth = 79

// specialModes are the modes that differ from the defaults
// (drwxr-xr-x for directories, -rw-r--r-- for files, -rwxr-xr-x for programs).
var specialModes = map[string]string{
	"/tmp": "drwxrwxrwt", "/var/tmp": "drwxrwxrwt", "/dev/shm": "drwxrwxrwt", // anyone can write, sticky bit
	"/proc": "dr-xr-xr-x", "/sys": "dr-xr-xr-x",
	"/home/ftp": "dr-xr-xr-x", "/usr/share/empty": "drwx------", // vsftpd refuses a writable chroot

	"/etc/shadow": "-rw-------", hostKeyFile: "-rw-------",
	"/etc/ppp/chap-secrets": "-rw-------", // pppd warns when its secrets can be read by everyone
}

// lsFlags are the options we understand; the others are ignored.
type lsFlags struct {
	long      bool // -l: one line per entry, with mode, size and date
	all       bool // -a: hidden files too, plus . and ..
	almostAll bool // -A: hidden files too, without . and ..
	dirItself bool // -d: the directory itself, not what is inside it
	// how the names are laid out without -l: '1' one per line, 'C' in columns, 'x' in columns filled
	// row by row; 0 = not chosen: columns on a terminal, else one per line (ls.c: isatty)
	format byte
	color  bool // each name in its type's color (on a terminal, unless LS_COLORS or --color say no)
}

// lsEntry is one name ls shows and the path it stands for.
type lsEntry struct{ name, path string }

func (s *Shell) ls(args []string) (string, int, bool) {
	f := lsFlags{color: s.tty && s.lsColors()}
	var targets []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--color"): // --color[=WHEN]: always (the default) / never / auto
			when := strings.TrimPrefix(a, "--color")
			when = strings.TrimPrefix(when, "=")
			switch {
			case strings.HasPrefix(when, "n"): // never, no, none
				f.color = false
			case when == "" || prefixOf(when, "always", "yes", "force"):
				f.color = true
			case prefixOf(when, "auto", "tty", "if-tty"):
				f.color = s.tty
			}
		case strings.HasPrefix(a, "--"):
			// the other long options (--full-time...) change nothing here
		case len(a) > 1 && a[0] == '-':
			for _, c := range a[1:] { // -la = -l -a; of -C -x -l -1, the later ones win (ls.c's opt_complementary)
				switch c {
				case 'l': // (the layout doesn't matter then, until a later -C / -x)
					f.long = true
				case 'C', 'x':
					f.long, f.format = false, byte(c)
				case '1':
					f.format = '1'
				case 'a':
					f.all = true
				case 'A':
					f.almostAll = true
				case 'd':
					f.dirItself = true
				}
			}
		default:
			targets = append(targets, a)
		}
	}
	if f.format == 0 {
		f.format = '1'
		if s.tty {
			f.format = 'C'
		}
	}
	if len(targets) == 0 {
		targets = []string{"."}
	}
	sort.Strings(targets)

	// like BusyBox: errors first, then the files that were named, then each directory's content
	var out strings.Builder
	code := 0
	var files []lsEntry
	var dirs []string
	for _, t := range targets {
		p := resolve(s.cwd, t)
		_, isFile := s.readFile(p)
		switch {
		case s.isDir(p) && !f.dirItself && !(f.long && fakeLinks[p] != ""): // -l shows a named link itself (ls.c)
			dirs = append(dirs, t)
		case isFile || s.isDir(p):
			files = append(files, lsEntry{t, p})
		default:
			out.WriteString("ls: " + t + ": No such file or directory\n")
			code = 1
		}
	}

	out.WriteString(s.lsShow(files, f))
	for i, t := range dirs {
		if len(targets) > 1 { // several targets: a "name:" header before each directory
			if i > 0 || len(files) > 0 {
				out.WriteString("\n")
			}
			out.WriteString(t + ":\n")
		}
		entries := s.lsDir(resolve(s.cwd, t), f)
		if f.long { // BusyBox with DESKTOP: the blocks the directory's entries take, in KB
			blocks := 1
			for _, e := range entries {
				blocks += s.blocks(e.path)
			}
			out.WriteString("total " + strconv.Itoa(blocks/2) + "\n")
		}
		out.WriteString(s.lsShow(entries, f))
	}
	return out.String(), code, false
}

// prefixOf: word is the start of one of the names ("--color=alw" = always), like index_in_substrings.
func prefixOf(word string, names ...string) bool {
	for _, n := range names {
		if strings.HasPrefix(n, word) {
			return true
		}
	}
	return false
}

// lsColors: whether LS_COLORS lets ls color its names (unset, or set to something but "none").
func (s *Shell) lsColors() bool {
	v, set := s.vars["LS_COLORS"]
	return !set || !s.exported["LS_COLORS"] || v != "" && v != "none"
}

// blocks is what p takes on its tmpfs, in 512-byte blocks (st_blocks): whole 4KB pages of its content;
// directories, links, devices and /proc files take none.
func (s *Shell) blocks(p string) int {
	mode, _, size, _ := s.stat(p)
	n, err := strconv.Atoi(size)
	if mode[0] != '-' || err != nil || under(p, "/proc") {
		return 0
	}
	return (n + 4095) / 4096 * 8
}

// paint puts a name in the color BusyBox ls gives its mode (ls.c: bold / fgcolor; "" = unknown, red):
// directories blue, links cyan, programs green, devices and sockets magenta, files plain.
func paint(name, mode string) string {
	color := "1;31" // stat failed: a link to nothing
	if mode != "" {
		switch mode[0] {
		case 'd':
			color = "1;34"
		case 'l':
			color = "1;36"
		case 'c', 'b', 's':
			color = "1;35"
		case 'p':
			color = "0;35"
		default:
			color = "0;0"
			if strings.ContainsAny(mode[3:4]+mode[6:7]+mode[9:10], "xst") { // executable by someone
				color = "1;32"
			}
		}
	}
	return "\x1b[" + color + "m" + name + "\x1b[m"
}

// followedMode is the mode of what p is, following its links; "" if they lead nowhere.
func (s *Shell) followedMode(p string) string {
	for i := 0; i < 8 && fakeLinks[p] != ""; i++ {
		p = resolve(path.Dir(p), fakeLinks[p])
	}
	if !s.exists(p) {
		return ""
	}
	mode, _, _, _ := s.stat(p)
	return mode
}

// lsDir returns the entries of a directory that ls shows: hidden ones (.x) only with -a or -A.
func (s *Shell) lsDir(dir string, f lsFlags) []lsEntry {
	var entries []lsEntry
	dir = follow(dir) // "ls /proc/self": what is in /proc/530
	if f.all {
		entries = append(entries, lsEntry{".", dir}, lsEntry{"..", path.Dir(dir)})
	}
	for _, name := range s.list(dir) {
		if strings.HasPrefix(name, ".") && !f.all && !f.almostAll {
			continue
		}
		entries = append(entries, lsEntry{name, path.Join(dir, name)})
	}
	return entries
}

// lsShow prints the entries in the long format (-l), one per line (-1) or in columns.
func (s *Shell) lsShow(entries []lsEntry, f lsFlags) string {
	if len(entries) == 0 {
		return ""
	}
	if f.long {
		var out strings.Builder
		for _, e := range entries {
			out.WriteString(s.longLine(e, f.color))
		}
		return out.String()
	}

	names := make([]string, len(entries))
	shown := make([]string, len(entries)) // the names as printed: in color, maybe
	for i, e := range entries {
		names[i], shown[i] = e.name, e.name
		if f.color {
			mode, _, _, _ := s.stat(e.path)
			shown[i] = paint(e.name, mode)
		}
	}
	if f.format == '1' {
		return strings.Join(shown, "\n") + "\n"
	}
	return columns(names, shown, f.format == 'x')
}

// columns lays names out like BusyBox ls: top to bottom then left to right (across: row by row), every
// column as wide as the longest name plus 2. shown = the names as printed (with their colors, which take
// no room on the screen).
func columns(names, shown []string, across bool) string {
	width := 0
	for _, n := range names {
		width = max(width, len(n)+2)
	}
	cols := max(terminalWidth/width, 1)
	rows := (len(names) + cols - 1) / cols // rounded up

	var out strings.Builder
	for r := 0; r < rows; r++ {
		column := 0 // where on the screen the line is
		for c := 0; c < cols; c++ {
			i := c*rows + r // column by column
			if across {
				i = r*cols + c
			}
			if i >= len(names) {
				break
			}
			out.WriteString(strings.Repeat(" ", c*width-column) + shown[i]) // pad to where column c starts
			column = c*width + len(names[i])
		}
		out.WriteString("\n")
	}
	return out.String()
}

// longLine is one line of ls -l, in BusyBox's format:
// drwxrwxrwt    2 root     root            40 Nov 18 09:15 tmp
// In color, a link's target has the color of what it leads to.
func (s *Shell) longLine(e lsEntry, color bool) string {
	mode, links, size, target := s.stat(e.path)
	name := e.name
	if color {
		name = paint(name, mode)
	}
	if target != "" {
		if color {
			target = paint(target, s.followedMode(e.path))
		}
		name += " -> " + target
	}
	return fmt.Sprintf("%-10s %4d %-8s %-8s %9s %s %s\n", mode, links, "root", "root", size, lsDate(s.mtime(e.path)), name)
}

// stat returns what ls -l shows about p: mode, number of links, size and, for a symlink, its target.
func (s *Shell) stat(p string) (mode string, links int, size string, target string) {
	_, isSessionFile := s.files[p]
	switch {
	case fakeLinks[p] != "": // before isDir, which follows it (/proc/self)
		target = fakeLinks[p]
		mode, links, size = "lrwxrwxrwx", 1, strconv.Itoa(len(target)) // a link's size = its target's length
	case s.isDir(p):
		mode = "drwxr-xr-x"
		names := s.list(p)
		links = 2 // its entry in the parent + its own "."; each subdirectory adds a ".."
		for _, n := range names {
			if sub := path.Join(follow(p), n); s.isDir(sub) && fakeLinks[sub] == "" { // a link to one isn't
				links++
			}
		}
		size = strconv.Itoa(40 + 20*len(names)) // like tmpfs: 20 bytes per entry, . and .. included
	case isSessionFile:
		mode, links, size = "-rw-r--r--", 1, strconv.Itoa(len(s.files[p]))
	case p == "/dev/null":
		mode, links, size = "crw-rw-rw-", 1, "1,   3" // a device shows "major, minor" instead of a size
	default:
		content, _ := readBuiltin(p) // a computed file's size too (/proc's are 0, below)
		mode, links, size = "-rw-r--r--", 1, strconv.Itoa(len(content))
		if strings.HasPrefix(content, "\x7fELF") {
			mode = "-rwxr-xr-x"
		}
		if n, ok := binarySizes[p]; ok {
			size = strconv.Itoa(n)
		}
		if under(p, "/proc") {
			mode = "-r--r--r--"
		}
	}

	m, special := specialModes[p]
	if special { // writing over a file doesn't change its mode
		mode = m
	}
	if under(p, "/proc") {
		size = "0" // files in /proc are generated when read: their size is always 0
		if k, ok := kernelSettings[p]; ok {
			mode = k.mode
		} else if mode[0] == 'd' && !special {
			mode = "dr-xr-xr-x"
		}
	}
	return mode, links, size, target
}

// mtime is the date ls -l shows: when the attacker last changed p, else boot time for the
// in-memory filesystems and the firmware build date for the rest.
func (s *Shell) mtime(p string) time.Time {
	if t, ok := s.mtimes[p]; ok {
		return t
	}
	// in-memory filesystems; /var itself is on the firmware (its www), only log, run and tmp are not
	for _, dir := range []string{"/dev", "/proc", "/sys", "/tmp", "/var/log", "/var/run", "/var/tmp"} {
		if under(p, dir) {
			return bootTime
		}
	}
	return firmwareTime
}

// lsDate is "Nov 18 09:15" for the last six months and "Jun  4  2020" for older dates, like BusyBox.
func lsDate(t time.Time) string {
	age := now().Sub(t)
	if age < 365*24*time.Hour/2 && age > -15*time.Minute {
		return t.UTC().Format("Jan _2 15:04")
	}
	return t.UTC().Format("Jan _2  2006")
}
