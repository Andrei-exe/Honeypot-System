package vfs

import (
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
)

// The shell's own commands (ash's builtins) that run shell code or change the shell itself, and
// how the shell reports its own errors. Measured against the real BusyBox 1.30.1 ash.

// errorf is one of the shell's own error lines, the way ash_vmsg writes it: "$0: ", then the command's
// name if it isn't $0 (a builtin, "eval", a script or "." file), then "line N: " if the shell isn't
// interactive or is reading a file. E.g. "-sh: cd: can't cd to /x: ...", "sh: cd: line 1: ...".
func (s *Shell) errorf(builtin, msg string) string {
	text := s.arg0 + ": "
	name := builtin
	if name == "" {
		name = s.commandname
	}
	if name != "" {
		if name != s.arg0 {
			text += name + ": "
		}
		if !s.interactive || s.inFile {
			text += "line " + strconv.Itoa(s.lineno) + ": "
		}
	}
	return text + msg + "\n"
}

// raise prints an error that ends the whole line (ash raises it back to the prompt; a subshell or a
// script ends instead), exit code 2: bad substitution, exit abc, export 1a, a syntax error...
func (s *Shell) raise(o *output, builtin, msg string) {
	o.add(2, s.errorf(builtin, msg))
	s.status, s.raised = 2, true
}

// setVar sets a variable. Returns ash's error if it can't: "X: is read only", or "out of memory" when
// the session's variables would pass varsQuota (they live in the agent's RAM).
func (s *Shell) setVar(name, value string) string {
	if s.readonly[name] {
		return name + ": is read only"
	}
	used := len(name) + len(value) + 64
	for n, v := range s.vars {
		if n != name {
			used += len(n) + len(v) + 64
		}
	}
	if used > varsQuota {
		return "out of memory"
	}
	s.vars[name] = strings.Clone(value) // a copy: a cut string keeps all of the original alive
	return ""
}

// state is what a subshell changes without the parent seeing it: ( ), $(...), sh -c, sh FILE.
type state struct {
	cwd                 string
	vars                map[string]string
	exported, readonly  map[string]bool
	params              []string
	arg0, commandname   string
	interactive, inFile bool
	lineno              int
}

func (s *Shell) save() state {
	return state{s.cwd, maps.Clone(s.vars), maps.Clone(s.exported), maps.Clone(s.readonly), s.params,
		s.arg0, s.commandname, s.interactive, s.inFile, s.lineno}
}

func (s *Shell) restore(v state) {
	s.cwd, s.vars, s.exported, s.readonly, s.params = v.cwd, v.vars, v.exported, v.readonly, v.params
	s.arg0, s.commandname, s.interactive, s.inFile, s.lineno = v.arg0, v.commandname, v.interactive, v.inFile, v.lineno
}

// child runs f as a subshell: what it changes in the shell is undone after, and its errors and exit
// end only it. Too deep: the fork "fails", like on a router out of processes.
func (s *Shell) child(o *output, f func()) {
	if s.depth >= maxDepth {
		s.raise(o, "", "can't fork: Resource temporarily unavailable")
		return
	}
	saved := s.save()
	s.depth++
	f()
	s.depth--
	s.restore(saved)
	s.stdin = ""
	if s.budget > 0 {
		s.raised = false
	}
}

// runLines runs code one line at a time, counting the lines for "line N:" and $LINENO. A newline
// inside quotes or $(...) doesn't end a line ('a<newline>b' is one word).
func (s *Shell) runLines(code string, o *output) bool {
	lineno, start := 1, 0
	for i := 0; i <= len(code); i++ {
		switch {
		case i == len(code) || code[i] == '\n':
			s.lineno = lineno
			if s.run(code[start:i], o) {
				return true
			}
			if s.raised || s.budget <= 0 {
				return false
			}
			lineno += strings.Count(code[start:min(i+1, len(code))], "\n")
			start = i + 1
		case code[i] == '#' && (i == 0 || strings.IndexByte(" \t\n;&|(", code[i-1]) >= 0):
			for i+1 < len(code) && code[i+1] != '\n' { // a comment: its quotes are text
				i++
			}
		case strings.IndexByte("\\'\"`", code[i]) >= 0 || code[i] == '$' && i+1 < len(code) && strings.IndexByte("({'", code[i+1]) >= 0:
			end, _ := partEnd(code, i)
			i = end - 1
		}
	}
	return false
}

// appletName: "/bin/sh" or "/usr/bin/wget" = "sh" / "wget" (a link to busybox); other names stay.
func (s *Shell) appletName(name string) string {
	if !strings.Contains(name, "/") {
		return name
	}
	if p := resolve(s.cwd, name); p == "/bin/busybox" || path.Base(fakeLinks[p]) == "busybox" {
		return path.Base(p)
	}
	return name
}

// inPath reports whether a command name is found in a directory of $PATH ("unset PATH; ls" = not found).
func (s *Shell) inPath(name string) bool {
	for _, dir := range strings.Split(s.vars["PATH"], ":") {
		if dir == "" {
			dir = "."
		}
		if _, ok := s.readFile(resolve(s.cwd, dir+"/"+name)); ok {
			return true
		}
	}
	return false
}

// builtins are ash's own commands that we answer: found whatever $PATH says.
var builtins = map[string]bool{
	".": true, ":": true, "cd": true, "echo": true, "eval": true, "exec": true, "exit": true, "export": true,
	"false": true, "kill": true, "pwd": true, "readonly": true, "set": true, "shift": true, "source": true,
	"true": true, "ulimit": true, "unset": true,
	"[": true, "[[": true, "command": true, "help": true, "history": true, "printf": true, "read": true,
	"test": true, "type": true,
}

// dispatch runs one expanded command, writing to o. A regular command's text goes to 1, or to 2 if it
// failed; the shell's own commands (sh, eval, ., exit...) write both, in order.
func (s *Shell) dispatch(args []string, input string, o *output) (int, bool) {
	name := s.appletName(args[0])
	switch name {
	case ":":
		return 0, false
	case "exit":
		return s.exit(args[1:], o)
	case "eval":
		return s.eval(args[1:], o)
	case ".", "source":
		return s.dot(name, args[1:], o)
	case "exec":
		return s.execBuiltin(args[1:], input, o)
	case "export", "readonly":
		return s.export(name, args[1:], o), false
	case "unset":
		return s.unset(args[1:], o), false
	case "set":
		return s.set(args[1:], o), false
	case "shift":
		return s.shift(args[1:], o), false
	case "command":
		return s.commandBuiltin(args[1:], input, o)
	case "env":
		if strings.Contains(args[0], "/") || s.inPath(name) {
			return s.env(args[1:], input, o)
		}
	case "nohup": // runs the command (simplification: no nohup.out when the output is the terminal)
		if strings.Contains(args[0], "/") || s.inPath(name) {
			if len(args) == 1 {
				out, _, _ := usage("nohup", " PROG ARGS\n\nRun PROG immune to hangups, with output to a non-tty")
				o.add(2, out)
				return 127, false
			}
			return s.dispatch(args[1:], input, o)
		}
	case "busybox": // busybox sh -c ... runs the applet directly
		if len(args) > 1 && (args[1] == "sh" || args[1] == "ash") {
			return s.sh(args[2:], input, o), false
		}
	case "sh", "ash":
		if strings.Contains(args[0], "/") || s.inPath(name) {
			return s.sh(args[1:], input, o), false
		}
	}
	if name == args[0] && strings.Contains(name, "/") && s.script(name) { // ./x.sh: a script, run by sh
		return s.sh(args, "", o), false
	}
	s.errText, s.ownErrors = "", false
	out, code, exit := s.command(args, input)
	if s.ownErrors { // it said what its errors were (warn): "wc: /x: ..." apart from the counts
		o.add(2, s.errText)
		o.add(1, out)
		s.errText, s.ownErrors = "", false
		return code, exit
	}
	fd := 1
	if code != 0 {
		fd = 2 // no separate stderr for the simple commands: a failed one's text is its error
	}
	o.add(fd, out)
	return code, exit
}

// sh runs shell code in a child shell: sh -c CODE [NAME [ARGS...]], sh FILE [ARGS...], or what comes
// through | (echo cmd | sh). Its cd and variables don't stay here. A plain "sh" would start a new
// interactive shell: nothing to see (simplification). Options other than -c (-x, -e) are ignored.
func (s *Shell) sh(args []string, input string, o *output) int {
	command := false
	for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		command = command || strings.Contains(args[0], "c")
		args = args[1:]
	}
	code, name, commandname := input, "sh", ""
	switch {
	case command && len(args) == 0:
		o.add(2, "sh: -c requires an argument\n")
		return 2
	case command:
		code, args = args[0], args[1:]
		if len(args) > 0 { // sh -c CODE NAME: NAME is $0 and names the errors
			name, commandname, args = args[0], args[0], args[1:]
		}
	case len(args) > 0:
		p := resolve(s.cwd, args[0])
		if s.isDir(p) {
			return 0 // it opens, and reading it gives nothing
		}
		content, ok := s.readFile(p)
		if !ok {
			o.add(2, "sh: can't open '"+args[0]+"': No such file or directory\n")
			return 2
		}
		code, name, commandname, args = content, args[0], args[0], args[1:]
		input = ""
	}
	if code == "" {
		return 0
	}
	s.child(o, func() {
		s.arg0, s.commandname, s.params = name, commandname, args
		s.interactive, s.inFile = false, !command && commandname != ""
		if command {
			s.stdin = input // sh -c 'cat' reads what came through |
		}
		s.runLines(code, o)
	})
	return s.status
}

// eval runs its arguments, joined, as a line of this shell (errors say "eval: ...").
func (s *Shell) eval(args []string, o *output) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	if s.depth >= maxDepth {
		s.raise(o, "", "can't fork: Resource temporarily unavailable")
		return 2, false
	}
	saved := s.commandname
	s.commandname = "eval"
	s.depth++
	exit := s.run(strings.Join(args, " "), o)
	s.depth--
	s.commandname = saved
	return s.status, exit
}

// dot runs a file in this shell (. FILE, source FILE). A name without "/" is looked for in $PATH only.
func (s *Shell) dot(name string, args []string, o *output) (int, bool) {
	if len(args) == 0 {
		return 2, false
	}
	file := args[0]
	p := resolve(s.cwd, file)
	if !strings.Contains(file, "/") {
		p = ""
		for _, dir := range strings.Split(s.vars["PATH"], ":") {
			if c := resolve(s.cwd, dir+"/"+file); s.exists(c) {
				p = c
				break
			}
		}
		if p == "" {
			s.raise(o, name, file+": not found")
			return 2, false
		}
	}
	content, ok := s.readFile(p)
	if !ok {
		s.raise(o, name, "can't open '"+file+"': No such file or directory")
		return 2, false
	}
	if s.depth >= maxDepth {
		s.raise(o, "", "can't fork: Resource temporarily unavailable")
		return 2, false
	}
	commandname, inFile, lineno := s.commandname, s.inFile, s.lineno
	s.commandname, s.inFile = file, true
	s.depth++
	exit := s.runLines(content, o)
	s.depth--
	s.commandname, s.inFile, s.lineno = commandname, inFile, lineno
	return s.status, exit
}

// exists reports whether p is a file or a directory.
func (s *Shell) exists(p string) bool {
	_, ok := s.readFile(p)
	return ok || s.isDir(p)
}

// exit [N]: the session ends with N (only the low 8 bits, like any process), or with $?.
func (s *Shell) exit(args []string, o *output) (int, bool) {
	if len(args) == 0 {
		return s.status, true
	}
	if !isNumber(args[0]) {
		s.raise(o, "exit", "Illegal number: "+args[0])
		return 2, false
	}
	n, _ := strconv.ParseUint(args[0], 10, 64)
	return int(n & 255), true
}

func isNumber(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// execBuiltin: exec CMD replaces the shell with CMD, so the session ends when CMD does; "exec sh" starts
// a new shell (the session goes on). exec with only redirections would make them stay (not simulated).
func (s *Shell) execBuiltin(args []string, input string, o *output) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	if name := s.appletName(args[0]); (name == "sh" || name == "ash") && len(args) == 1 {
		return 0, false
	}
	if !builtins[args[0]] && !strings.Contains(args[0], "/") && !s.inPath(args[0]) {
		// ash clears its interactive flag before exec'ing, so even the login shell says "line N:"
		o.add(2, s.arg0+": exec: line "+strconv.Itoa(s.lineno)+": "+args[0]+": not found\n")
		return 127, true
	}
	code, _ := s.dispatch(args, input, o)
	return code, true
}

// export / readonly NAME[=VALUE]...; alone (or -p) they list, like ash: export HOME='/root'.
func (s *Shell) export(name string, args []string, o *output) int {
	mark := s.exported
	if name == "readonly" {
		mark = s.readonly
	}
	if len(args) == 0 || args[0] == "-p" {
		var out strings.Builder
		for _, n := range slices.Sorted(maps.Keys(mark)) {
			if v, ok := s.vars[n]; ok {
				out.WriteString(name + " " + n + "=" + singleQuote(v) + "\n")
			} else {
				out.WriteString(name + " " + n + "\n")
			}
		}
		o.add(1, out.String())
		return 0
	}
	for _, a := range args {
		n, value, hasValue := strings.Cut(a, "=")
		if !validName(n) {
			s.raise(o, name, n+": bad variable name")
			return 2
		}
		if hasValue {
			if msg := s.setVar(n, value); msg != "" {
				s.raise(o, "", msg)
				return 2
			}
		}
		mark[n] = true
	}
	return 0
}

// unset NAME...: the variables are gone (-v / -f are accepted; there are no functions).
func (s *Shell) unset(args []string, o *output) int {
	for _, n := range args {
		if n == "-v" || n == "-f" {
			continue
		}
		if s.readonly[n] {
			s.raise(o, "unset", n+": is read only")
			return 2
		}
		delete(s.vars, n)
		delete(s.exported, n)
	}
	return 0
}

// shellOptions are ash's set -o options, in its order (optletters_optnames); the login shell has
// interactive, monitor and stdin on. They can be named in set -o / +o but change nothing here.
var shellOptions = []string{"errexit", "noglob", "ignoreeof", "interactive", "monitor", "noexec", "stdin",
	"xtrace", "verbose", "noclobber", "allexport", "notify", "nounset", "vi", "pipefail"}

// set: alone, lists the variables (NAME='value', sorted); set -o lists the options; set -- ARGS (or
// set ARGS) sets $1 $2...; the option letters (-e, -x...) are accepted and change nothing.
func (s *Shell) set(args []string, o *output) int {
	if len(args) == 0 {
		vars := maps.Clone(s.vars)
		vars["LINENO"] = "" // ash shows it empty here
		var out strings.Builder
		for _, n := range slices.Sorted(maps.Keys(vars)) {
			out.WriteString(n + "=" + singleQuote(vars[n]) + "\n")
		}
		o.add(1, out.String())
		return 0
	}
	newParams := false
	for len(args) > 0 && len(args[0]) > 1 && (args[0][0] == '-' || args[0][0] == '+') {
		a := args[0]
		args = args[1:]
		if a == "--" {
			newParams = true
			break
		}
		if a != "-o" && a != "+o" {
			continue
		}
		if len(args) == 0 { // set -o: the options and whether they are on
			var out strings.Builder
			for _, opt := range shellOptions {
				on := "off"
				if s.interactive && (opt == "interactive" || opt == "monitor" || opt == "stdin") {
					on = "on"
				}
				out.WriteString(opt + strings.Repeat(" ", max(16-len(opt), 1)) + on + "\n")
			}
			o.add(1, out.String())
			return 0
		}
		if !slices.Contains(shellOptions, args[0]) { // set +o history (bash's) is not ash's
			o.add(2, s.errorf("set", "illegal option "+a+" "+args[0]))
			return 1
		}
		args = args[1:]
	}
	if newParams || len(args) > 0 {
		s.params = args
	}
	return 0
}

// shift [N]: $2 becomes $1... More than there are: nothing changes, exit code 1.
func (s *Shell) shift(args []string, o *output) int {
	n := 1
	if len(args) > 0 {
		if !isNumber(args[0]) {
			s.raise(o, "shift", "Illegal number: "+args[0])
			return 2
		}
		n, _ = strconv.Atoi(args[0])
	}
	if n > len(s.params) {
		return 1
	}
	s.params = s.params[n:]
	return 0
}

// singleQuote quotes a value the way set and export list it (ash's single_quote): 'it'"'"'s'.
func singleQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

// cd DIR, cd (to $HOME), cd - (back to $OLDPWD, printed). Sets $PWD and $OLDPWD like ash.
func (s *Shell) cd(args []string) (string, int, bool) {
	dest, show := "", false
	switch {
	case len(args) == 0:
		if dest = s.vars["HOME"]; dest == "" {
			return "", 0, false
		}
	case args[0] == "-":
		if dest, show = s.vars["OLDPWD"], true; dest == "" {
			dest = "."
		}
	default:
		dest = args[0]
	}
	dir := resolve(s.cwd, dest)
	if !s.isDir(dir) {
		reason := "No such file or directory"
		for p := dir; p != "/"; p = path.Dir(p) { // a file on the way: /etc/passwd/x
			if _, isFile := s.readFile(p); isFile {
				reason = "Not a directory"
				break
			}
		}
		return s.errorf("cd", "can't cd to "+dest+": "+reason), 2, false
	}
	s.vars["OLDPWD"], s.vars["PWD"] = s.cwd, dir
	s.exported["OLDPWD"], s.exported["PWD"] = true, true
	s.cwd = dir
	if show {
		return dir + "\n", 0, false
	}
	return "", 0, false
}
