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
	terminal    bool   // the session has a terminal: Telnet, SSH with a pty (exec too: "ssh -t host ls")
	// the running command's output (descriptor 1) goes to that terminal, not into a |, a file or a $(...):
	// what isatty(1) would say. ls lays its names out in colored columns only then
	tty bool

	linesRead int // the lines the login shell has read: the next one's number
	// a command not finished yet ("for i in 1 2" typed alone): its lines so far, waiting for the next
	// one (Prompt shows $PS2), and the number of its first line
	pending     string
	pendingLine int
	depth       int  // how deep in sh -c / $(...) / eval / . we are
	budget      int  // commands the current line may still run (maxCommands at each Run)
	work        int  // expansion work the current line may still do (maxWork at each Run)
	raised      bool // an error that ends the whole line, like ash's (bad substitution, exit abc...)
	substStatus int  // the exit code of the last $(...): $? after "X=$(cmd)"
	// the input the commands share: what came through | or < into a loop or a { } ("seq 3 | while
	// read x"), or into a child shell (echo cmd | sh). read takes a line of it, the text tools all of it
	stdin string

	funcs     map[string]*node      // the functions defined (f() { ...; }): their definitions
	skip      int                   // a break / continue / return / exit on its way up (control.go)
	crashed   bool                  // the exit on its way up is a crash (control.go: crash)
	skipCount int                   // how many loops the break / continue leaves
	loops     int                   // how many loops are running, one inside the other
	nesting   int                   // compound commands and function calls running one inside the other
	funcLine  int                   // the line the running function was defined on (0: none)
	locals    []map[string]localVar // for each function running: what local changed, to put back

	history   []string // the lines typed (the history builtin)
	errText   string   // what the running applet wrote to its errors, apart from its output (warn)
	ownErrors bool     // the running applet split its output and errors itself (see dispatch)

	started time.Time // when the session's shell started (its /proc/517)
	argv    []string  // the command running now, as typed: what /proc/self (530) shows; nil = none

	jobs         []*job // the background jobs (jobs.go), oldest first; a subshell has none
	bgPID        int    // $!: the last job's PID (0: none yet)
	lastPID      int    // the last PID a job got
	inBackground bool   // running a job: a sleep, the attacker's program or the budget stop it (stopJob)
	frozen       bool   // the job stopped there: it runs on "for ever"; every level stops (stopped)
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
	s.terminal = pty
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
		funcs:       map[string]*node{},
		arg0:        "-sh",
		interactive: interactive,
		terminal:    interactive,
		fromStdin:   true,
		work:        maxWork,
		started:     now().UTC(),
		lastPID:     530, // ps's own
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
// part, \$ "#" for root. With the PS1 from /etc/profile: "root@gateway:~# ". While a command isn't
// finished (RunTo got "for i in 1 2"), $PS2 instead: "> ".
func (s *Shell) Prompt() string {
	ps1 := s.vars["PS1"]
	if s.pending != "" {
		ps1 = s.vars["PS2"]
	}
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
// without a pty sends the errors as a stream of their own). The shell ends (exit is true) on exit, on
// return outside a function, and if it isn't interactive (SSH without a pty, exec) at the first error
// that ends a line, like ash's main loop.
func (s *Shell) RunTo(line string, out, errs io.Writer) (code int, exit bool) {
	s.budget, s.work, s.raised, s.skip, s.crashed, s.tty = maxCommands, maxWork, false, 0, false, s.terminal
	var o output
	if s.execCommand {
		s.runCode(line, 1, &o) // sh -c: the whole command
	} else {
		s.linesRead++ // the login shell counts the lines it read ($LINENO)
		if s.interactive {
			s.remember(line) // the history is line editing's: each line typed
		}
		// what the shell reads is the line with its newline, after the lines of a command not finished yet
		code, first := s.pending+line+"\n", s.pendingLine
		if s.pending == "" {
			first = s.linesRead
		}
		more := len(code) <= maxPending // past it: the error ash would give at the end of its input
		_, s.pending, s.pendingLine = s.runInput(code, first, more, &o)
		if s.interactive && s.pending == "" {
			s.reportJobs(&o) // before the next prompt: the jobs that ended
		}
	}
	return s.status, s.finish(&o, out, errs)
}

// maxPending is how long a command may grow while it waits for its next lines (an open quote that never
// closes, a "for" without its "done"): the agent keeps it in RAM.
const maxPending = 64 * 1024

// EndOfInput tells the shell its input ended (an SSH session without a pty, at EOF): a command still
// waiting for its next lines gets the syntax error ash gives at the end of its input. Returns the exit
// code the shell ends with.
func (s *Shell) EndOfInput(out, errs io.Writer) int {
	if s.pending == "" {
		return s.status
	}
	s.budget, s.work, s.raised, s.skip, s.crashed, s.tty = maxCommands, maxWork, false, 0, false, s.terminal
	var o output
	code, first := s.pending, s.pendingLine
	s.pending = ""
	s.runCode(code, first, &o)
	s.finish(&o, out, errs)
	return s.status
}

// finish writes what a line printed, its output and its errors apart, and says whether the shell
// ended: exit, return outside a function, or (not interactive) an error that ends a line.
func (s *Shell) finish(o *output, out, errs io.Writer) (exit bool) {
	for _, c := range o.chunks {
		if c.fd == 2 {
			io.WriteString(errs, c.text)
		} else {
			io.WriteString(out, c.text)
		}
	}
	return s.skip == skipExit || s.skip == skipFunc || s.raised && !s.interactive
}

// simple runs a simple command: expands its words (with the variables and $? of this moment), then runs
// it with its redirections: a function, one of the shell's own commands, or a program.
func (s *Shell) simple(n *node, o *output) {
	s.lineno = s.lineOf(n)
	if s.budget--; s.budget <= 0 {
		if !s.stopJob() { // a job just goes on running, quietly
			s.raise(o, "", "can't fork: Resource temporarily unavailable")
		}
		return
	}
	s.substStatus = 0
	words := n.words
	var assigns []string // X=1 before the command
	for len(words) > 0 && isAssignment(words[0]) {
		assigns, words = append(assigns, words[0]), words[1:]
	}
	args := s.expandWords(words, o)
	redirs := make([]redir, len(n.redirs))
	for i, r := range n.redirs {
		redirs[i] = r
		redirs[i].target = s.expandText(r.target, o)
	}
	values := make([]string, len(assigns))
	for i, a := range assigns {
		_, raw, _ := strings.Cut(a, "=")
		values[i] = s.expandText(raw, o)
	}
	if s.raised {
		return
	}
	if len(args) == 0 { // only assignments: they stay (before a command they would be its environment)
		for i, a := range assigns {
			name, _, _ := strings.Cut(a, "=")
			if msg := s.setVar(name, values[i]); msg != "" {
				s.raise(o, "", msg)
				return
			}
		}
	}
	name, exit := "", false
	if len(args) > 0 {
		name = args[0]
	}
	code := s.redirected(redirs, name, o, func(out *output) int {
		if len(args) == 0 { // "> file" alone is valid: it only creates the file
			return 0
		}
		if f, ok := s.funcs[args[0]]; ok {
			return s.call(f, args, out)
		}
		code, e := s.dispatch(args, s.stdin, out)
		exit = e
		return code
	})
	if len(args) == 0 && code == 0 {
		code = s.substStatus // "X=$(false)" fails
	}
	s.status = code
	if exit {
		s.skip = skipExit
	}
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

// sink is where a descriptor writes: the command's original output or errors (orig 1 or 2: the screen,
// or for 1 the next command after |), a file (orig 0), or nowhere because it was closed (orig -1, >&-).
type sink struct {
	orig int
	file string // absolute path
}

// redirected applies a command's redirections, in order, like ash does: "> f" creates f even if the
// command then fails, "2>&1" copies where 1 points *now*. Then it runs body (the command: a simple one,
// or all of an if / a loop / a { }) and sends what it wrote where the descriptors point: to o (1 and 2
// as they were) or to files. name is the command's, for its "write error". Returns body's exit code
// (1 if a redirection failed: then body doesn't run).
func (s *Shell) redirected(redirs []redir, name string, o *output, body func(out *output) int) int {
	fds := map[int]sink{0: {orig: 2}, 1: {orig: 1}, 2: {orig: 2}} // 0 = the terminal, writable too
	// write sends text to a sink; an error = the write failed (the command reports it, see below)
	write := func(to sink, text string) error {
		switch {
		case text == "":
		case to.orig == 1 || to.orig == 2:
			o.add(to.orig, text)
		case to.orig == -1:
			return errBadFD
		default:
			failed, _ := s.writeFile(to.file, text, true) // the file was opened (created) by its redirection
			return failed
		}
		return nil
	}
	// fail: a redirection that can't be done stops the command; ash's message goes where 2 points now
	fail := func(msg string) int {
		write(fds[2], s.errorf("", msg))
		return 1
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

	input, ownInput := "", false
	for _, r := range redirs {
		switch r.op {
		case ">", ">>", "&>":
			to, ok := open(r.target, r.op == ">>")
			if !ok {
				return 1
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
					return 1
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
					return 1
				}
			default:
				return fail("can't open " + r.target + ": no such file") // ash's text for ENOENT
			}
			if r.fd == 0 {
				input, ownInput = content, true
			}
		case "<&", "<<": // input from another descriptor, a here-document: not simulated, no effect
		}
	}
	if ownInput { // the command (and all it runs: "while read x; do ...; done < f") reads this instead
		saved := s.stdin
		s.stdin = input
		defer func() { s.stdin = saved }()
	}
	if to := fds[1]; to.orig != 1 && to.orig != 2 { // "> file", ">&-": the output is no terminal now
		saved := s.tty
		s.tty = false
		defer func() { s.tty = saved }()
	}

	var out output
	code := body(&out)
	failed := false
	for _, c := range out.chunks {
		if c.fd == 2 {
			write(fds[2], c.text)
			continue
		}
		// the output's write failed: the disk filled up, the descriptor was closed (>&-), /proc refused it
		if err := write(fds[1], c.text); err != nil && !failed {
			failed, code = true, 1
			write(fds[2], writeError(name, err))
		}
	}
	return code
}
