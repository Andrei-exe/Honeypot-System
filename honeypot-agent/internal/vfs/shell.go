package vfs

import (
	"io"
	"maps"
	"path"
	"strconv"
	"strings"
	"time"
)

// Limits on what one line can make the shell do. A real shell forks for most of this and would run out
// of processes; ours runs inside the agent, so it stops earlier, like a fork that failed.
const (
	maxDepth    = 16        // sh -c / sh FILE / $(...) / eval / . inside each other
	maxCommands = 10000     // commands one line may run, all depths together (fork bombs, eval loops)
	varsQuota   = 64 * 1024 // a session's variables: names + values + 64 each (like sessionQuota for files)
	// the work one line's expansions may do, all together: names looked at by * ? [, characters tried
	// by ${X#p} ${X/p/r}, steps of $((...)). A 9000-byte SSH command full of "/*/*/*" or "${X#*a*a*a...}"
	// would otherwise keep a CPU busy for seconds; past it they give up (left as typed / unchanged)
	maxWork = 2000000
)

// shellPID is the login shell's PID: "-sh" in ps, $$.
const shellPID = "517"

// Shell is the fake shell of ONE connection. Every attacker gets a new one (NewShell),
// so their current directory, files and variables are invisible to other attackers.
type Shell struct {
	cwd   string            // current directory
	files map[string]string // files created by the attacker (echo > x, touch, cp)
	dirs  map[string]bool   // directories created by the attacker (mkdir)

	mtimes map[string]time.Time // when the attacker created or touched a path (the date in ls -l)

	vars     map[string]string // the variables: $HOME, $PATH... and the attacker's own (X=1)
	exported map[string]bool   // those export lists
	readonly map[string]bool   // readonly NAME: can't be changed or unset
	params   []string          // the positional parameters $1 $2... (set --, sh -c CODE NAME ARGS)
	status   int               // the last command's exit code: $?

	// How the shell names itself in its own errors, like ash_vmsg: "-sh: x: not found" (the login shell),
	// "sh: cd: line 1: ..." (sh -c), "x.sh: line 3: ..." (a script).
	arg0        string // $0: "-sh", "sh", a script's name
	commandname string // ash's commandname: the script or "." file, or "eval"; shown after arg0 if different
	interactive bool   // the login shell on a terminal (ash's iflag): its errors have no "line N:"
	fromStdin   bool   // reading its commands from its input (ash's -s): the login shell, "echo cmd | sh"
	inFile      bool   // reading a file (sh FILE, . FILE): "line N:" even in the login shell
	lineno      int    // the line being run: $LINENO and "line N:"
	execCommand bool   // started as sh -c COMMAND (an SSH exec): Run gets the whole command

	depth       int    // how deep in sh -c / $(...) / eval / . we are
	budget      int    // commands the current line may still run (maxCommands at each Run)
	work        int    // expansion work the current line may still do (maxWork at each Run)
	raised      bool   // an error that ends the whole line, like ash's (bad substitution, exit abc...)
	substStatus int    // the exit code of the last $(...): $? after "X=$(cmd)"
	stdin       string // a child shell's input (echo cmd | sh): the first command that reads gets it

	history   []string // the lines typed (the history builtin)
	errText   string   // what the running applet wrote to its errors, apart from its output (warn)
	ownErrors bool     // the running applet split its output and errors itself (see dispatch)
}

// The variables a login shell starts with: what BusyBox login sets (HOME, SHELL, USER, LOGNAME, PATH;
// libbb/setup_environment.c) and /etc/profile (PATH, PS1), exported; then what ash adds itself
// (ash.c: varinit, init). PPID is telnetd's, from ps. Measured on the real BusyBox 1.30.1 ash.
var (
	loginVars = map[string]string{
		"HOME": "/root", "LOGNAME": "root", "PATH": "/bin:/sbin:/usr/bin:/usr/sbin", "PS1": `\u@\h:\w\$ `,
		"PWD": "/root", "SHELL": "/bin/sh", "SHLVL": "1", "USER": "root",
	}
	ashVars = map[string]string{
		"HOSTNAME": "gateway", "IFS": " \t\n", "OPTIND": "1", "PPID": "356", "PS2": "> ", "PS4": "+ ",
	}
)

// NewShell returns a fresh login shell that starts in /root: root's, after a Telnet login.
func NewShell() *Shell {
	return NewLoginShell("root")
}

// NewLoginShell is the shell of a Telnet login as user ($USER, $LOGNAME; every user here has uid 0,
// so whoami still says root). TERM comes from init through telnetd and login, which keep it: vt102,
// what BusyBox's init sets on a serial console (init.c, console_init).
func NewLoginShell(user string) *Shell {
	return newShell(user, map[string]string{"TERM": "vt102"}, true)
}

// NewSSHShell is the shell Dropbear starts for an SSH session (svr-chansession.c, execchild): a clean
// environment plus vars (SSH_CLIENT, SSH_CONNECTION; TERM and SSH_TTY with a pty). exec ("ssh host CMD")
// = sh -c, which Run gives the whole command, without /etc/profile; else the login shell "-sh", which
// is interactive only on a pty (ash's iflag needs a terminal).
func NewSSHShell(user string, vars map[string]string, pty, exec bool) *Shell {
	s := newShell(user, vars, pty && !exec)
	if exec {
		s.arg0, s.execCommand, s.fromStdin = "sh", true, false
		s.vars["PS1"] = `\w \$ ` // ash's own (no /etc/profile): not exported
		delete(s.exported, "PS1")
	}
	return s
}

// newShell is a login shell with the login environment, plus extra (exported).
func newShell(user string, extra map[string]string, interactive bool) *Shell {
	s := &Shell{
		cwd:         "/root",
		files:       map[string]string{},
		dirs:        map[string]bool{},
		mtimes:      map[string]time.Time{},
		vars:        map[string]string{},
		exported:    map[string]bool{},
		readonly:    map[string]bool{},
		arg0:        "-sh",
		interactive: interactive,
		fromStdin:   true,
		work:        maxWork,
	}
	for name, value := range loginVars {
		s.vars[name], s.exported[name] = value, true
	}
	s.vars["USER"], s.vars["LOGNAME"] = user, user
	for name, value := range extra {
		s.vars[name], s.exported[name] = value, true
	}
	maps.Copy(s.vars, ashVars)
	return s
}

// Prompt is $PS1 the way BusyBox draws it: \u user, \h host, \w directory (~ for $HOME), \W its last
// part, \$ "#" for root. With the PS1 from /etc/profile: "root@gateway:~# ".
func (s *Shell) Prompt() string {
	ps1 := s.vars["PS1"]
	var out strings.Builder
	for i := 0; i < len(ps1); i++ {
		if ps1[i] != '\\' || i+1 == len(ps1) {
			out.WriteByte(ps1[i])
			continue
		}
		switch i++; ps1[i] {
		case 'u':
			out.WriteString("root")
		case 'h':
			out.WriteString("gateway")
		case 'w':
			dir := s.cwd
			if home := s.vars["HOME"]; home != "" && home != "/" && under(dir, home) {
				dir = "~" + dir[len(home):]
			}
			out.WriteString(dir)
		case 'W':
			out.WriteString(path.Base(s.cwd))
		case '$':
			out.WriteByte('#')
		case '\\':
			out.WriteByte('\\')
		default:
			out.WriteByte('\\')
			out.WriteByte(ps1[i])
		}
	}
	return out.String()
}

// step is one command in a line, plus how it is linked to the previous one.
type step struct {
	op     string   // ";" = always, "&&" = if the previous succeeded, "||" = if it failed, "|" = gets its output
	args   []string // its words as typed (quotes and $... still in): expanded when it runs
	redirs []redir  // its redirections, in the order written (it matters: ">f 2>&1" is not "2>&1 >f")
	group  int      // the "( )" group it is in (0 = none): in "(a; b) | c", c gets a's and b's output
}

// redir is one redirection, as ash parses it (parseredir in ash.c): "2>/dev/null" = {2, ">", "/dev/null"}.
type redir struct {
	fd     int    // the descriptor it changes: 0 = input, 1 = output, 2 = errors (or another number)
	op     string // ">", ">>", ">&" (copy a descriptor; a file name = both outputs), "&>", "<", "<>", "<&", "<<"
	target string // the word after it (expanded when the command runs): a file, or a descriptor for >&
}

// output is what commands wrote, in order: to 1 (the output) or to 2 (the errors). Kept apart so a
// | or a redirection gets only its own part, and in order so the screen shows them as they came.
type output struct {
	chunks []chunk
	size   int
}

type chunk struct {
	fd   int
	text string
}

// add appends text; past maxSize the rest is dropped, like the screen's limit.
func (o *output) add(fd int, text string) {
	if text == "" || o.size >= maxSize {
		return
	}
	o.chunks = append(o.chunks, chunk{fd, text})
	o.size += len(text)
}

// Run executes a whole line, e.g. "cd /tmp && wget http://x/bot; chmod +x bot".
// Returns what appears on screen (lines end in \n), the exit code of the last command that ran
// (like $?: 0 = ok, 127 = not found; SSH sends it to the client) and whether the attacker typed exit.
func (s *Shell) Run(line string) (string, int, bool) {
	var screen strings.Builder
	code, exit := s.RunTo(line, &screen, &screen)
	return screen.String(), code, exit
}

// RunTo is Run with the output and the errors written apart, in the order they come (an SSH session
// without a pty sends the errors as a stream of their own). A shell that isn't interactive (SSH without
// a pty, exec) ends at the first error that ends a line, like ash's main loop: exit is true then.
func (s *Shell) RunTo(line string, out, errs io.Writer) (code int, exit bool) {
	s.budget, s.work, s.raised = maxCommands, maxWork, false
	var o output
	if s.execCommand {
		exit = s.runLines(line, &o) // sh -c: the whole command, counting its lines
	} else {
		s.lineno++ // the login shell counts the lines it read ($LINENO)
		if s.interactive {
			s.remember(line) // the history is line editing's: only on a terminal
		}
		exit = s.run(line, &o)
	}
	for _, c := range o.chunks {
		if c.fd == 2 {
			io.WriteString(errs, c.text)
		} else {
			io.WriteString(out, c.text)
		}
	}
	return s.status, exit || s.raised && !s.interactive
}

// run executes one line in this shell, writing to o. Returns whether exit ran.
func (s *Shell) run(line string, o *output) bool {
	steps, syntaxErr := parse(line)
	if syntaxErr != "" {
		s.raise(o, "", "syntax error: "+syntaxErr) // nothing on the line runs
		return false
	}
	piped := ""      // output kept for the next command if it is linked with |
	skipped := false // whether the previous command was skipped (because of && or ||)
	var outside state
	groupDone := false // the current ( ) group ran exit or raised an error: the rest of it is skipped
	for i, st := range steps {
		if s.budget <= 0 || s.raised && st.group == 0 {
			break
		}
		if st.group != 0 && (i == 0 || steps[i-1].group != st.group) {
			outside, groupDone = s.save(), false // ( ) is a subshell: its cd and variables don't stay
		}
		exit := false
		switch {
		case len(st.args) == 0 && len(st.redirs) == 0, groupDone && st.group != 0:
			// e.g. ";;" or a trailing "&"
		case (st.op == "&&" && s.status != 0) || (st.op == "||" && s.status == 0) || (st.op == "|" && skipped):
			skipped = true
			if st.op == "|" {
				piped = "" // nobody reads it now
			}
		default:
			skipped = false
			input := ""
			if st.op == "|" {
				input, piped = piped, ""
			} else if s.stdin != "" {
				input, s.stdin = s.stdin, ""
			}
			// the output goes to the command linked with | after this one (or after its whole group:
			// in "(a; b) | c" both a's and b's), not to the screen; errors go to the screen at once
			next := i + 1
			for st.group != 0 && next < len(steps) && steps[next].group == st.group {
				next++
			}
			toPipe := next < len(steps) && steps[next].op == "|"

			var res output
			if st.group == 0 && (st.op == "|" || toPipe) {
				// ash runs each command of a pipeline in a subshell: "echo a | read x" leaves x unset
				saved := s.save()
				s.runCommand(st, input, &res)
				s.restore(saved)
			} else {
				exit = s.runCommand(st, input, &res)
			}
			for _, c := range res.chunks {
				if c.fd == 1 && toPipe {
					if len(piped) < maxSize {
						piped += c.text
					}
				} else {
					o.add(c.fd, c.text)
				}
			}
		}
		if st.group != 0 && (exit || s.raised && s.budget > 0) {
			groupDone, exit, s.raised = true, false, false // they end only the subshell
		}
		if st.group != 0 && (i+1 == len(steps) || steps[i+1].group != st.group) {
			s.restore(outside)
		}
		if exit {
			return true
		}
	}
	return false
}

// runCommand expands one command's words (with the variables and $? of this moment) and runs it.
func (s *Shell) runCommand(st step, input string, o *output) bool {
	if s.budget--; s.budget == 0 {
		s.raise(o, "", "can't fork: Resource temporarily unavailable")
		return false
	}
	s.substStatus = 0
	words := st.args
	var assigns []string // X=1 before the command
	for len(words) > 0 && isAssignment(words[0]) {
		assigns, words = append(assigns, words[0]), words[1:]
	}
	args := s.expandWords(words, o)
	redirs := make([]redir, len(st.redirs))
	for i, r := range st.redirs {
		redirs[i] = r
		redirs[i].target = s.expandText(r.target, o)
	}
	values := make([]string, len(assigns))
	for i, a := range assigns {
		_, raw, _ := strings.Cut(a, "=")
		values[i] = s.expandText(raw, o)
	}
	if s.raised {
		return false
	}
	if len(args) == 0 { // only assignments: they stay (before a command they would be its environment)
		for i, a := range assigns {
			name, _, _ := strings.Cut(a, "=")
			if msg := s.setVar(name, values[i]); msg != "" {
				s.raise(o, "", msg)
				return false
			}
		}
	}
	res, code, exit := s.exec(args, redirs, input)
	if len(args) == 0 && code == 0 {
		code = s.substStatus // "X=$(false)" fails
	}
	s.status = code
	o.chunks = append(o.chunks, res.chunks...)
	return exit
}

// isAssignment: NAME=... as typed (a name not in quotes, then "=").
func isAssignment(raw string) bool {
	name, _, found := strings.Cut(raw, "=")
	return found && validName(name)
}

// validName: a variable name, [A-Za-z_][A-Za-z0-9_]*.
func validName(name string) bool {
	if name == "" || !isNameStart(name[0]) {
		return false
	}
	for i := 1; i < len(name); i++ {
		if !isNameChar(name[i]) {
			return false
		}
	}
	return true
}

// parse splits the line into commands on ; && || | (but not inside quotes), each command into words
// on whitespace, and takes out the redirections, glued to the words or not ("echo hi>x"), like ash.
// Words stay as typed: quotes, backslashes, $(...), ${...}, `...` are taken apart when the command
// runs (expand.go); the operators inside them are text. A syntax error (a redirection without its
// file, an unclosed quote) gives ash's message, and nothing on the line runs.
func parse(line string) ([]step, string) {
	steps := []step{{op: ";"}}
	var word strings.Builder
	inWord := false
	group, open := 0, 0 // the current "( )" group's number and how many "(" are still open
	needTarget := false // the last redirection still waits for its word
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
		inWord = false
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
		// "; echo", "a; | b": no command before the operator (a newline alone is fine: an empty line)
		if last := steps[len(steps)-1]; token != "newline" && len(last.args) == 0 && len(last.redirs) == 0 && syntaxErr == "" {
			syntaxErr = "unexpected " + token
		}
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
		case c == '\\' || c == '\'' || c == '"' || c == '`' || c == '$' && (next == '(' || next == '{' || next == '\''):
			end, err := partEnd(line, i) // kept whole, as typed
			if err != "" && syntaxErr == "" {
				syntaxErr = err
			}
			word.WriteString(line[i:end])
			inWord = true
			i = end - 1
		case c == '#' && !inWord: // a comment, up to the end of the line
			for i+1 < len(line) && line[i+1] != '\n' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
		case c == '>' || c == '<':
			fd := 1
			if c == '<' {
				fd = 0
			}
			// "2>x": a word of only digits right before is the descriptor; "a2>x" = "a2" + ">x"
			// ("2">x is a word: the quotes are still in it)
			if inWord && isFDNumber(word.String()) {
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
			// are marked as one group, run in a copy of the shell (run: save / restore)
			if open == 0 {
				group++
				steps[len(steps)-1].group = group // the step this "(" starts
			}
			open++
		case c == ')' && open > 0:
			open--
			endWord()
			unexpected(`")"`)
		case c == ';' && next == ';': // a case's terminator, and there are no cases
			if syntaxErr == "" {
				syntaxErr = `unexpected ";;"`
			}
			newStep(";", `";;"`)
			i++
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
	// "echo a &&" with nothing after: a real login shell would wait for the rest (PS2 "> "); like sh -c
	if last := steps[len(steps)-1]; len(last.args) == 0 && len(last.redirs) == 0 && syntaxErr == "" &&
		(last.op == "&&" || last.op == "||" || last.op == "|") {
		syntaxErr = "unexpected end of file"
	}
	return steps, syntaxErr
}

// partEnd returns where the escape, quoted string, $(...), $((...)), ${...} or `...` that starts at
// line[i] ends (the index after it), skipping what is nested inside, like ash's parser. If it never
// ends: the end of the line, and ash's syntax error.
func partEnd(line string, i int) (int, string) {
	switch line[i] {
	case '\\':
		return min(i+2, len(line)), ""
	case '\'':
		if j := strings.IndexByte(line[i+1:], '\''); j >= 0 {
			return i + j + 2, ""
		}
		return len(line), "unterminated quoted string"
	case '"':
		for j := i + 1; j < len(line); j++ {
			switch c := line[j]; {
			case c == '\\':
				j++
			case c == '"':
				return j + 1, ""
			case c == '`' || c == '$' && j+1 < len(line) && (line[j+1] == '(' || line[j+1] == '{'):
				end, err := partEnd(line, j)
				if err != "" {
					return end, err
				}
				j = end - 1
			}
		}
		return len(line), "unterminated quoted string"
	case '`':
		for j := i + 1; j < len(line); j++ {
			switch line[j] {
			case '\\':
				j++
			case '`':
				return j + 1, ""
			}
		}
		return len(line), "EOF in backquote substitution"
	}
	if line[i+1] == '\'' { // $'...' (bash's, on in ash): like '...', but \' doesn't end it
		for j := i + 2; j < len(line); j++ {
			switch line[j] {
			case '\\':
				j++
			case '\'':
				return j + 1, ""
			}
		}
		return len(line), "unterminated quoted string"
	}
	// $( $(( ${: count the brackets, skipping what is quoted or nested inside
	opener, closer, err := byte('('), byte(')'), `unexpected end of file (expecting ")")`
	switch {
	case line[i+1] == '{':
		opener, closer, err = '{', '}', "missing '}'"
	case strings.HasPrefix(line[i:], "$(("):
		err = "missing '))'"
	}
	depth := 0
	for j := i + 1; j < len(line); j++ {
		switch c := line[j]; {
		case c == '\\' || c == '\'' || c == '"' || c == '`' || c == '$' && j+1 < len(line) && (line[j+1] == '(' || line[j+1] == '{'):
			end, e := partEnd(line, j)
			if e != "" {
				return end, e
			}
			j = end - 1
		case c == opener:
			depth++
		case c == closer:
			if depth--; depth == 0 {
				return j + 1, ""
			}
		}
	}
	return len(line), err
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

// exec runs a single command (no ; && || |), already expanded. Its redirections are applied first, in
// order, like ash does: "> f" creates f even if the command then fails, "2>&1" copies where 1 points
// *now*. Returns what went to the original output and errors (in order), the exit code and whether it
// was exit.
func (s *Shell) exec(args []string, redirs []redir, input string) (res output, code int, exit bool) {
	fds := map[int]sink{0: {orig: 2}, 1: {orig: 1}, 2: {orig: 2}} // 0 = the terminal, writable too
	// write sends text to a sink; an error = the write failed (the command reports it, see below)
	write := func(to sink, text string) error {
		switch {
		case text == "":
		case to.orig == 1 || to.orig == 2:
			res.add(to.orig, text)
		case to.orig == -1:
			return errBadFD
		default:
			failed, _ := s.writeFile(to.file, text, true) // the file was opened (created) by its redirection
			return failed
		}
		return nil
	}
	// fail: a redirection that can't be done stops the command; ash's message goes where 2 points now
	fail := func(msg string) (output, int, bool) {
		write(fds[2], s.errorf("", msg))
		return res, 1, false
	}
	// open creates (">", or empties it) or appends to (">>") a file now, before the command runs
	open := func(name string, appendTo bool) (sink, bool) {
		if _, err := s.writeFile(name, "", appendTo); err != nil {
			reason := err.Error()
			if err == errNoDir {
				reason = "nonexistent directory" // ash's own text for ENOENT (errmsg in ash.c)
			}
			write(fds[2], s.errorf("", "can't create "+name+": "+reason))
			return sink{}, false
		}
		return sink{file: resolve(s.cwd, name)}, true
	}

	for _, r := range redirs {
		switch r.op {
		case ">", ">>", "&>":
			to, ok := open(r.target, r.op == ">>")
			if !ok {
				return res, 1, false
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
					return res, 1, false
				}
				fds[1], fds[2] = to, to
			}
		case "<", "<>":
			p := resolve(s.cwd, r.target)
			content, ok := s.readFile(p)
			switch {
			case unreadable(p):
				return fail("can't open " + r.target + ": Permission denied")
			case ok || s.isDir(p): // a directory opens fine; reading it gives nothing here
			case r.op == "<>": // read and write: created if missing
				if _, ok := open(r.target, true); !ok {
					return res, 1, false
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

	var out output
	if len(args) > 0 { // "> file" alone is valid: it only creates the file
		code, exit = s.dispatch(args, input, &out)
	}
	failed := false
	for _, c := range out.chunks {
		if c.fd == 2 {
			write(fds[2], c.text)
			continue
		}
		// the output's write failed: the disk filled up, the descriptor was closed (>&-), /proc refused it
		if err := write(fds[1], c.text); err != nil && !failed {
			failed, code = true, 1
			write(fds[2], writeError(args[0], err))
		}
	}
	return res, code, exit
}
