package vfs

import (
	"strconv"
	"strings"
	"time"
)

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
	op     string   // ";" = always, "&&" = if the previous succeeded, "||" = if it failed, "|" = gets its output
	args   []string // command and arguments, quotes removed
	redirs []redir  // its redirections, in the order written (it matters: ">f 2>&1" is not "2>&1 >f")
	group  int      // the "( )" group it is in (0 = none): in "(a; b) | c", c gets a's and b's output
}

// redir is one redirection, as ash parses it (parseredir in ash.c): "2>/dev/null" = {2, ">", "/dev/null"}.
type redir struct {
	fd     int    // the descriptor it changes: 0 = input, 1 = output, 2 = errors (or another number)
	op     string // ">", ">>", ">&" (copy a descriptor; a file name = both outputs), "&>", "<", "<>", "<&", "<<"
	target string // the word after it: a file, or a descriptor number for >&
}

// Run executes a whole line, e.g. "cd /tmp && wget http://x/bot; chmod +x bot".
// Returns what appears on screen (lines end in \n), the exit code of the last command that ran
// (like $?: 0 = ok, 127 = not found; SSH sends it to the client) and whether the attacker typed exit.
func (s *Shell) Run(line string) (string, int, bool) {
	var screen strings.Builder
	code := 0        // exit code of the last command run: 0 = ok
	piped := ""      // output kept for the next command if it is linked with |
	skipped := false // whether the previous command was skipped (because of && or ||)

	steps, syntaxErr := parse(line)
	if syntaxErr != "" {
		return "-sh: syntax error: " + syntaxErr + "\n", 2, false // nothing on the line runs
	}
	for i, st := range steps {
		if len(st.args) == 0 && len(st.redirs) == 0 {
			continue // e.g. ";;" or a trailing "&"
		}
		if (st.op == "&&" && code != 0) || (st.op == "||" && code == 0) || (st.op == "|" && skipped) {
			skipped = true
			if st.op == "|" {
				piped = "" // nobody reads it now
			}
			continue
		}
		skipped = false

		input := ""
		if st.op == "|" {
			input, piped = piped, ""
		}

		out, errOut, c, exit := s.exec(st.args, st.redirs, input)
		code = c
		if screen.Len() < maxSize {
			screen.WriteString(errOut) // errors go to the screen at once, even from inside a pipe
		}
		if exit {
			return screen.String(), code, true
		}

		// the output goes to the command linked with | after this one (or after its whole group:
		// in "(a; b) | c" both a's and b's), not to the screen
		next := i + 1
		for st.group != 0 && next < len(steps) && steps[next].group == st.group {
			next++
		}
		if next < len(steps) && steps[next].op == "|" {
			if len(piped) < maxSize {
				piped += out
			}
		} else if screen.Len() < maxSize {
			screen.WriteString(out)
		}
	}
	return screen.String(), code, false
}

// parse splits the line into commands on ; && || | (but not inside quotes), each command into words
// on whitespace, and takes out the redirections, glued to the words or not ("echo hi>x"), like ash.
// Quotes are removed, like in a real shell. A redirection without its file is a syntax error: the
// second result is what ash says then ("unexpected newline"), and nothing on the line runs.
func parse(line string) ([]step, string) {
	steps := []step{{op: ";"}}
	var word strings.Builder
	inWord, quoted := false, false // quoted: the word had quotes, so "2">x is not a descriptor number
	var quote byte                 // ' or " while inside quotes, 0 otherwise
	group, open := 0, 0            // the current "( )" group's number and how many "(" are still open
	needTarget := false            // the last redirection still waits for its word
	syntaxErr := ""

	endWord := func() {
		if !inWord {
			return
		}
		last := &steps[len(steps)-1]
		if needTarget {
			last.redirs[len(last.redirs)-1].target = word.String()
			needTarget = false
		} else {
			last.args = append(last.args, word.String())
		}
		word.Reset()
		inWord, quoted = false, false
	}
	// unexpected: what comes instead of a redirection's word, in ash's words (tokname). The line
	// won't run; parsing goes on without that word (so the next word isn't taken for it)
	unexpected := func(what string) {
		if needTarget && syntaxErr == "" {
			syntaxErr = "unexpected " + what
		}
		needTarget = false
	}
	newStep := func(op, token string) {
		endWord()
		unexpected(token)
		st := step{op: op}
		if open > 0 {
			st.group = group
		}
		steps = append(steps, st)
	}
	addRedir := func(fd int, op string) {
		unexpected("redirection")
		last := &steps[len(steps)-1]
		last.redirs = append(last.redirs, redir{fd: fd, op: op})
		needTarget = true
	}

	for i := 0; i < len(line); i++ {
		c := line[i]
		next := byte(0)
		if i+1 < len(line) {
			next = line[i+1]
		}
		switch {
		case quote != 0: // inside quotes everything is text, up to the closing quote
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inWord, quoted = true, true // "" is still a word (an empty one)
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
		case c == '>' || c == '<':
			fd := 1
			if c == '<' {
				fd = 0
			}
			// "2>x": a word of only digits right before is the descriptor; "a2>x" = "a2" + ">x"
			if inWord && !quoted && isFDNumber(word.String()) {
				fd, _ = strconv.Atoi(word.String())
				word.Reset()
				inWord = false
			}
			endWord()
			op := string(c)
			if c == '>' && (next == '>' || next == '&' || next == '|') || c == '<' && (next == '<' || next == '&' || next == '>') {
				op += string(next)
				i++
			}
			if op == ">|" {
				op = ">" // ">|" overwrites even with noclobber, which we never have
			}
			addRedir(fd, op)
		case c == '&' && next == '>': // "&>file" = ">file 2>&1" (ash's bash compatibility, on in Buildroot)
			endWord()
			addRedir(1, "&>")
			i++
		case c == '(' && !inWord:
			// a subshell, "(crontab -l; echo JOB) | crontab -" (how miners add a cron job): its commands
			// run here (no new shell), marked as one group. A "(" inside a word ("$(id)") is just text.
			if open == 0 {
				group++
				steps[len(steps)-1].group = group // the step this "(" starts
			}
			open++
		case c == ')' && open > 0:
			open--
			endWord()
			unexpected(`")"`)
		case c == ';':
			newStep(";", `";"`)
		case c == '\n':
			newStep(";", "newline")
		case c == '&' || c == '|':
			if next == c {
				newStep(line[i:i+2], `"`+line[i:i+2]+`"`) // && or ||
				i++
			} else if c == '|' {
				newStep("|", `"|"`)
			} else {
				newStep(";", `"&"`) // a single & = "run in background" -> same as ; for us
			}
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	endWord()
	unexpected("newline")
	return steps, syntaxErr
}

// isFDNumber: ash takes a word of 1 to 9 digits right before > or < as the descriptor (isdigit_str9).
func isFDNumber(w string) bool {
	if len(w) == 0 || len(w) > 9 {
		return false
	}
	for _, c := range w {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// sink is where a descriptor writes: the command's original output or errors (orig 1 or 2: the screen,
// or for 1 the next command after |), a file (orig 0), or nowhere because it was closed (orig -1, >&-).
type sink struct {
	orig int
	file string // absolute path
}

// exec runs a single command (no ; && || |). Its redirections are applied first, in order, like
// ash does: "> f" creates f even if the command then fails, "2>&1" copies where 1 points *now*.
// Returns what goes to the original output (the screen, or the next command after |) and to the
// original errors (the screen), the exit code and whether it was exit.
func (s *Shell) exec(args []string, redirs []redir, input string) (stdout, stderr string, code int, exit bool) {
	fds := map[int]sink{0: {orig: 2}, 1: {orig: 1}, 2: {orig: 2}} // 0 = the terminal, writable too
	// write sends text to a sink; full / closed = the write failed (the command reports it, see below)
	write := func(to sink, text string) (full, closed bool) {
		switch {
		case text == "":
		case to.orig == 1:
			stdout += text
		case to.orig == 2:
			stderr += text
		case to.orig == -1:
			closed = true
		default:
			full, _ = s.writeFile(to.file, text, true) // the file was opened (created) by its redirection
		}
		return full, closed
	}
	// fail: a redirection that can't be done stops the command; ash's message goes where 2 points now
	fail := func(msg string) (string, string, int, bool) {
		write(fds[2], "-sh: "+msg+"\n")
		return stdout, stderr, 1, false
	}
	// open creates (">", or empties it) or appends to (">>") a file now, before the command runs
	open := func(name string, appendTo bool) (sink, bool) {
		if _, err := s.writeFile(name, "", appendTo); err != nil {
			reason := err.Error()
			if err == errNoDir {
				reason = "nonexistent directory" // ash's own text for ENOENT (errmsg in ash.c)
			}
			write(fds[2], "-sh: can't create "+name+": "+reason+"\n")
			return sink{}, false
		}
		return sink{file: resolve(s.cwd, name)}, true
	}

	for _, r := range redirs {
		switch r.op {
		case ">", ">>", "&>":
			to, ok := open(r.target, r.op == ">>")
			if !ok {
				return stdout, stderr, 1, false
			}
			fds[r.fd] = to
			if r.op == "&>" {
				fds[2] = to
			}
		case ">&":
			if n, err := strconv.Atoi(r.target); err == nil && isFDNumber(r.target) {
				from, ok := fds[n]
				if !ok {
					return fail(r.target + ": Bad file descriptor") // dup2_or_raise: "echo >&99"
				}
				fds[r.fd] = from
				break
			}
			switch {
			case r.target == "-":
				fds[r.fd] = sink{orig: -1} // ">&-" closes it
			case r.fd != 1:
				return fail("redir error") // "2>&file": only ">&file" means "both outputs to the file"
			default:
				to, ok := open(r.target, false)
				if !ok {
					return stdout, stderr, 1, false
				}
				fds[1], fds[2] = to, to
			}
		case "<", "<>":
			p := resolve(s.cwd, r.target)
			content, ok := s.readFile(p)
			switch {
			case ok || s.isDir(p): // a directory opens fine; reading it gives nothing here
			case r.op == "<>": // read and write: created if missing
				if _, ok := open(r.target, true); !ok {
					return stdout, stderr, 1, false
				}
			default:
				return fail("can't open " + r.target + ": no such file") // ash's text for ENOENT
			}
			if r.fd == 0 {
				input = content
			}
		case "<&", "<<": // input from another descriptor, a here-document: not simulated, no effect
		}
	}

	out := ""
	if len(args) > 0 { // "> file" alone is valid: it only creates the file
		out, code, exit = s.command(args, input)
	}
	// We have no separate stderr, so the rule is simple: if the command failed (code != 0),
	// everything it printed is its error message; if it worked, everything is its output.
	if code != 0 {
		write(fds[2], out)
		return stdout, stderr, code, exit
	}
	// the output's write failed: the disk filled up, or the descriptor was closed (>&-)
	if full, closed := write(fds[1], out); full || closed {
		reason := errNoSpace
		if closed {
			reason = errBadFD
		}
		write(fds[2], writeError(args[0], reason))
		code = 1
	}
	return stdout, stderr, code, exit
}
