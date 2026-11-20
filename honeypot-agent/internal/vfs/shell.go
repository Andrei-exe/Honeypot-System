package vfs

import (
	"strings"
	"time"
)

// Banner is shown right after login (both Telnet and SSH).
const Banner = "\nBusyBox v1.30.1 built-in shell (ash)\n\n"

// Shell is the fake shell of ONE connection. Every attacker gets a new one (NewShell),
// so their current directory and files are invisible to other attackers.
type Shell struct {
	cwd   string            // current directory
	files map[string]string // files created by the attacker (echo > x, touch, cp)
	dirs  map[string]bool   // directories created by the attacker (mkdir)

	mtimes map[string]time.Time // when the attacker created or touched a path (the date in ls -l)
}

// NewShell returns a fresh shell that starts in /root.
func NewShell() *Shell {
	return &Shell{
		cwd:    "/root",
		files:  map[string]string{},
		dirs:   map[string]bool{},
		mtimes: map[string]time.Time{},
	}
}

// Prompt returns "root@gateway:~# " with the current directory (/root is shown as ~).
func (s *Shell) Prompt() string {
	dir := s.cwd
	if dir == "/root" || strings.HasPrefix(dir, "/root/") {
		dir = "~" + dir[len("/root"):]
	}
	return "root@gateway:" + dir + "# "
}

// step is one command in a line, plus how it is linked to the previous one.
type step struct {
	op   string   // ";" = always, "&&" = if the previous succeeded, "||" = if it failed, "|" = gets its output
	args []string // command and arguments, quotes removed
}

// Run executes a whole line, e.g. "cd /tmp && wget http://x/bot; chmod +x bot".
// Returns what appears on screen (lines end in \n) and whether the attacker typed exit.
func (s *Shell) Run(line string) (string, bool) {
	var screen strings.Builder
	code := 0        // exit code of the last command run: 0 = ok
	piped := ""      // output kept for the next command if it is linked with |
	skipped := false // whether the previous command was skipped (because of && or ||)

	steps := parse(line)
	for i, st := range steps {
		if len(st.args) == 0 {
			continue // e.g. ";;" or a trailing "&"
		}
		if (st.op == "&&" && code != 0) || (st.op == "||" && code == 0) || (st.op == "|" && skipped) {
			skipped = true
			continue
		}
		skipped = false

		input := ""
		if st.op == "|" {
			input = piped
		}

		out, c, exit := s.exec(st.args, input)
		code = c
		if exit {
			return screen.String(), true
		}

		// if the next command is linked with |, the output goes to it, not to the screen
		if i+1 < len(steps) && steps[i+1].op == "|" {
			piped = out
		} else if screen.Len() < maxSize {
			screen.WriteString(out)
		}
	}
	return screen.String(), false
}

// parse splits the line into commands on ; && || | (but not inside quotes), and each command
// into words on whitespace. Quotes are removed, like in a real shell.
func parse(line string) []step {
	steps := []step{{op: ";"}}
	var word strings.Builder
	inWord := false
	var quote byte // ' or " while inside quotes, 0 otherwise

	endWord := func() {
		if inWord {
			last := &steps[len(steps)-1]
			last.args = append(last.args, word.String())
			word.Reset()
			inWord = false
		}
	}
	newStep := func(op string) {
		endWord()
		steps = append(steps, step{op: op})
	}

	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0: // inside quotes everything is text, up to the closing quote
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inWord = true // "" is still a word (an empty one)
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
		case c == ';' || c == '\n':
			newStep(";")
		case c == '&' && strings.HasSuffix(word.String(), ">"):
			word.WriteByte(c) // 2>&1 is a redirect, not an operator
		case c == '&' || c == '|':
			if i+1 < len(line) && line[i+1] == c {
				newStep(line[i : i+2]) // && or ||
				i++
			} else if c == '|' {
				newStep("|")
			} else {
				newStep(";") // a single & = "run in background" -> same as ; for us
			}
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	endWord()
	return steps
}

// redirect is where a command's output should go.
type redirect struct {
	file       string // > file: output goes here, not to the screen
	append     bool   // >> file: append instead of overwrite
	hideErrors bool   // 2>/dev/null: don't show errors
}

// parseRedirects removes the redirects from the arguments:
// ["echo", "hi", ">", "a.txt"] -> ["echo", "hi"] + redirect{file: "a.txt"}
func parseRedirects(args []string) ([]string, redirect) {
	var clean []string
	var r redirect
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "1>") {
			a = a[1:] // 1> is the same as >
		}

		switch {
		case a == "2>&1":
			// "errors go where the output goes" - for us they are already together
		case strings.HasPrefix(a, "2>"):
			r.hideErrors = true
			if a == "2>" {
				i++ // "2> file": skip the file name too
			}
		case strings.HasPrefix(a, ">"):
			r.append = strings.HasPrefix(a, ">>")
			r.file = strings.TrimLeft(a, ">")
			if r.file == "" && i+1 < len(args) {
				i++ // "> file", with a space in between
				r.file = args[i]
			}
			if strings.HasPrefix(r.file, "&") {
				r.file = "" // >&2 = "send to stderr" -> still ends up on screen
			}
		default:
			clean = append(clean, a)
		}
	}
	return clean, r
}

// exec runs a single command (no ; && || |), including its redirects.
// Returns the output, the exit code and whether it was exit.
func (s *Shell) exec(args []string, input string) (string, int, bool) {
	args, r := parseRedirects(args)

	out, code, exit := "", 0, false
	if len(args) > 0 { // "> file" alone is valid: it just creates an empty file
		out, code, exit = s.command(args, input)
	}

	// We have no separate stderr, so the rule is simple:
	// if the command failed (code != 0), everything it printed is the error message.
	failed := code != 0
	if failed && r.hideErrors {
		out = "" // 2>/dev/null: the error disappears
	}
	if r.file != "" {
		content := out
		if failed {
			content = "" // the error stays on screen, the file is still created (empty)
		}
		if msg := s.writeFile(r.file, content, r.append); msg != "" {
			return msg, 1, exit
		}
		if !failed {
			out = "" // it went to the file, not to the screen
		}
	}
	return out, code, exit
}
