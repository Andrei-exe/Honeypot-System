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
	"/etc/shadow": "-rw-------", "/etc/dropbear/dropbear_ecdsa_host_key": "-rw-------",
	"/etc/ppp/chap-secrets": "-rw-------", // pppd warns when its secrets can be read by everyone
}

// lsFlags are the options we understand; the others are ignored.
type lsFlags struct {
	long       bool // -l: one line per entry, with mode, size and date
	all        bool // -a: hidden files too, plus . and ..
	almostAll  bool // -A: hidden files too, without . and ..
	onePerLine bool // -1
	dirItself  bool // -d: the directory itself, not what is inside it
}

// lsEntry is one name ls shows and the path it stands for.
type lsEntry struct{ name, path string }

func (s *Shell) ls(args []string) (string, int, bool) {
	var f lsFlags
	var targets []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--"):
			// long options (--color=auto) change nothing here
		case len(a) > 1 && a[0] == '-':
			for _, c := range a[1:] { // -la = -l -a
				switch c {
				case 'l':
					f.long = true
				case 'a':
					f.all = true
				case 'A':
					f.almostAll = true
				case '1':
					f.onePerLine = true
				case 'd':
					f.dirItself = true
				}
			}
		default:
			targets = append(targets, a)
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
		case s.isDir(p) && !f.dirItself:
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
		out.WriteString(s.lsShow(s.lsDir(resolve(s.cwd, t), f), f))
	}
	return out.String(), code, false
}

// lsDir returns the entries of a directory that ls shows: hidden ones (.x) only with -a or -A.
func (s *Shell) lsDir(dir string, f lsFlags) []lsEntry {
	var entries []lsEntry
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
			out.WriteString(s.longLine(e))
		}
		return out.String()
	}

	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.name
	}
	if f.onePerLine {
		return strings.Join(names, "\n") + "\n"
	}
	return columns(names)
}

// columns lays names out like BusyBox ls on a terminal: top to bottom, then left to right,
// every column as wide as the longest name plus 2.
func columns(names []string) string {
	width := 0
	for _, n := range names {
		width = max(width, len(n)+2)
	}
	cols := max(terminalWidth/width, 1)
	rows := (len(names) + cols - 1) / cols // rounded up

	var out strings.Builder
	for r := 0; r < rows; r++ {
		line := ""
		for c := 0; c < cols; c++ {
			i := c*rows + r // column by column
			if i >= len(names) {
				break
			}
			line += strings.Repeat(" ", c*width-len(line)) + names[i] // pad to where column c starts
		}
		out.WriteString(line + "\n")
	}
	return out.String()
}

// longLine is one line of ls -l, in BusyBox's format:
// drwxrwxrwt    2 root     root            40 Nov 18 09:15 tmp
func (s *Shell) longLine(e lsEntry) string {
	mode, links, size, target := s.stat(e.path)
	name := e.name
	if target != "" {
		name += " -> " + target
	}
	return fmt.Sprintf("%-10s %4d %-8s %-8s %9s %s %s\n", mode, links, "root", "root", size, lsDate(s.mtime(e.path)), name)
}

// stat returns what ls -l shows about p: mode, number of links, size and, for a symlink, its target.
func (s *Shell) stat(p string) (mode string, links int, size string, target string) {
	_, isSessionFile := s.files[p]
	switch {
	case s.isDir(p):
		mode = "drwxr-xr-x"
		names := s.list(p)
		links = 2 // its entry in the parent + its own "."; each subdirectory adds a ".."
		for _, n := range names {
			if s.isDir(path.Join(p, n)) {
				links++
			}
		}
		size = strconv.Itoa(40 + 20*len(names)) // like tmpfs: 20 bytes per entry, . and .. included
	case isSessionFile:
		mode, links, size = "-rw-r--r--", 1, strconv.Itoa(len(s.files[p]))
	case fakeLinks[p] != "":
		target = fakeLinks[p]
		mode, links, size = "lrwxrwxrwx", 1, strconv.Itoa(len(target)) // a link's size = its target's length
	case p == "/dev/null":
		mode, links, size = "crw-rw-rw-", 1, "1,   3" // a device shows "major, minor" instead of a size
	default:
		content := fakeFiles[p]
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

	if m, ok := specialModes[p]; ok { // writing over a file doesn't change its mode
		mode = m
	}
	if under(p, "/proc") {
		size = "0" // files in /proc are generated when read: their size is always 0
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
