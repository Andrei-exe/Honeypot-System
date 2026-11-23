package vfs

import (
	"slices"
	"strconv"
	"strings"
)

// Running the parsed commands, like ash's evaltree and its helpers (ash.c): lists, && ||, !, pipes and
// the compound commands (if, while, until, for, case, ( ), { }), functions, break / continue / return /
// local. Like in ash, break, continue, return (and exit) only set s.skip; every level that runs
// commands checks it and stops.

// What a break / continue / return / exit asks the levels above to do (ash's evalskip; ash ends the
// shell on exit with an exception instead).
const (
	skipBreak = 1 << iota // leave s.skipCount loops
	skipCont              // go on with the next round of the s.skipCount-th loop
	skipFunc              // return: the function ends (outside one: the "." file, or the shell)
	skipExit              // exit: the shell ends (a subshell: only it)
)

// crash ends the shell the way a real ash ends when its stack runs out (a function calling itself
// forever, commands nested too deep): killed by SIGSEGV, exit code 139. A subshell crashes alone, and
// the shell that waited for it prints "Segmentation fault" (child). Ours crashes at maxNesting levels
// of compound commands and function calls (each level is some 2KB of the session goroutine's stack);
// a real ash at some thousands.
func (s *Shell) crash() {
	s.status, s.skip, s.crashed = 139, skipExit, true
}

// stopped: nothing more may run now: an error that ends the line (or the commands budget is used
// up), or a break / continue / return / exit on its way up.
func (s *Shell) stopped() bool {
	return s.raised || s.skip != 0
}

// runCode runs shell code: one complete command at a time, each parsed and run before the next one is
// read (ash's cmdloop / evalstring), so "echo a; for" prints a, then the syntax error. line = the
// number of its first line. Returns the exit code of the last command (0 if none ran: an empty eval).
func (s *Shell) runCode(code string, line int, o *output) int {
	status, _, _ := s.runInput(code, line, false, o)
	return status
}

// runInput is runCode for a shell reading its input line by line (more): a command the code ends in
// the middle of is not an error then, it waits for the next line. rest is its text so far (to run again
// with that line after it, see RunTo) and restLine the number of its first line.
func (s *Shell) runInput(code string, line int, more bool, o *output) (status int, rest string, restLine int) {
	p := newParser(code, line)
	for !s.stopped() {
		start, startLine := p.pos, p.line
		n, done, err := p.next()
		if more && p.incomplete && !p.crashed {
			return status, code[start:], startLine
		}
		if p.crashed { // nested too deep (maxNesting)
			s.crash()
			return s.status, "", 0
		}
		if err != "" {
			s.lineno = p.line
			s.raise(o, "", "syntax error: "+err)
			return s.status, "", 0
		}
		if done {
			break
		}
		if n != nil { // nil: an empty line
			status = s.eval(n, o)
		}
	}
	return status, "", 0
}

// eval runs a parsed command. Its exit code is left in s.status ($?) and returned.
func (s *Shell) eval(n *node, o *output) int {
	if n == nil || s.stopped() {
		return s.status
	}
	switch n.kind {
	case nCmd:
		s.simple(n, o)
	case nList:
		for _, c := range n.list {
			if s.eval(c, o); s.stopped() {
				break
			}
		}
	case nAndOr: // a && b || c: each one runs only if $? says so ("a fails" skips b, then c runs)
		s.eval(n.list[0], o)
		for i, op := range n.ops {
			if s.stopped() {
				break
			}
			if (s.status == 0) == (op == tAnd) {
				s.eval(n.list[i+1], o)
			}
		}
	case nNot:
		if s.eval(n.body, o) == 0 {
			s.status = 1
		} else {
			s.status = 0
		}
	case nPipe:
		s.pipe(n, o)
	case nFunc:
		s.define(n, o)
	default: // a compound command: its redirections apply to everything it runs
		if s.nesting >= maxNesting {
			s.crash()
			break
		}
		s.nesting++
		s.lineno = s.lineOf(n)
		code := s.redirected(n.redirs, "echo", o, func(out *output) int { return s.compound(n, out) })
		if !s.raised { // (an error that ended the line already set $? to 2)
			s.status = code
		}
		s.nesting--
	}
	return s.status
}

// lineOf is the line number a command shows ($LINENO, "line N:"): inside a function, counted from the
// line the function was defined on, like ash.
func (s *Shell) lineOf(n *node) int {
	if s.funcLine > 0 {
		return n.line - s.funcLine + 1
	}
	return n.line
}

// compound runs the inside of a compound command and returns its exit code.
func (s *Shell) compound(n *node, o *output) int {
	switch n.kind {
	case nBrace:
		return s.eval(n.body, o)

	case nSubshell: // ( ): a copy of the shell; its cd, variables, exit don't reach this one
		s.child(o, func() { s.eval(n.body, o) })
		return s.status

	case nIf:
		for {
			code := s.eval(n.test, o)
			switch {
			case s.stopped():
				return code
			case code == 0:
				return s.eval(n.body, o)
			case n.orElse == nil:
				return 0
			case n.orElse.kind != nIf:
				return s.eval(n.orElse, o)
			}
			n = n.orElse // elif
		}

	case nWhile, nUntil:
		code := 0
		s.loops++
		for {
			test := s.eval(n.test, o)
			skip := s.skipLoop()
			if skip == skipFunc {
				code = test
			}
			if skip == 0 && !s.raised {
				if (test == 0) != (n.kind == nWhile) {
					break
				}
				code = s.eval(n.body, o)
				skip = s.skipLoop()
			}
			if skip&^skipCont != 0 || s.raised {
				break
			}
		}
		s.loops--
		return code

	case nFor:
		words := s.expandWords(n.words, o)
		code := 0
		s.loops++
		for _, w := range words {
			if s.raised {
				break
			}
			if msg := s.setVar(n.name, w); msg != "" {
				s.raise(o, "", msg)
				break
			}
			code = s.eval(n.body, o)
			if s.skipLoop()&^skipCont != 0 {
				break
			}
		}
		s.loops--
		return code

	case nCase:
		word := s.expandText(n.words[0], o) // no splitting, no file names
		for _, item := range n.cases {
			for _, raw := range item.patterns {
				pattern := s.expandPattern(raw, o)
				if s.raised {
					return s.status
				}
				if s.work -= (len(pattern) + 1) * (len(word) + 1); s.work >= 0 && wildMatch(pattern, word) {
					if item.body == nil {
						return 0
					}
					return s.eval(item.body, o)
				}
			}
		}
		return 0
	}
	return s.status
}

// skipLoop is what a loop does after a command ran (ash's skiploop): a break / continue for this loop
// is used up here; one for an outer loop (break 2) becomes a break of this one.
func (s *Shell) skipLoop() int {
	skip := s.skip
	if skip == skipBreak || skip == skipCont {
		if s.skipCount--; s.skipCount <= 0 {
			s.skip = 0
		} else {
			skip = skipBreak
		}
	}
	return skip
}

// pipe runs a | b | c: each command in a subshell (ash forks each one), getting as its input what the
// one before printed. Errors go to the screen at once. The exit code is the last command's.
func (s *Shell) pipe(n *node, o *output) {
	piped := ""
	for i, c := range n.list {
		last := i == len(n.list)-1
		var res output
		s.child(o, func() {
			if i > 0 {
				s.stdin = piped
			}
			s.eval(c, &res)
		})
		piped = ""
		for _, ch := range res.chunks {
			if ch.fd == 1 && !last {
				if len(piped) < maxSize {
					piped += ch.text
				}
			} else {
				o.add(ch.fd, ch.text)
			}
		}
		if s.raised { // out of forks: the rest doesn't start
			return
		}
	}
}

// define stores a function. Its commands live in the agent's RAM like the variables, so all the
// functions of a session together stay under varsQuota.
func (s *Shell) define(f *node, o *output) {
	used := len(f.name) + treeSize(f)
	for name, g := range s.funcs {
		if name != f.name {
			used += len(name) + treeSize(g)
		}
	}
	if used > varsQuota {
		s.raise(o, "", "out of memory")
		return
	}
	s.funcs[f.name] = f
	s.status = 0
}

// treeSize is about how much memory a parsed command takes: its texts, plus 64 a node.
func treeSize(n *node) int {
	if n == nil {
		return 0
	}
	size := 64 + len(n.name) + 8*len(n.ops) + treeSize(n.test) + treeSize(n.body) + treeSize(n.orElse)
	for _, w := range n.words {
		size += len(w) + 16
	}
	for _, r := range n.redirs {
		size += len(r.target) + 32
	}
	for _, c := range n.list {
		size += treeSize(c)
	}
	for _, item := range n.cases {
		size += 32 + treeSize(item.body)
		for _, p := range item.patterns {
			size += len(p) + 16
		}
	}
	return size
}

// call runs a function: its arguments are $1 $2... while it runs, the variables made local in it come
// back after, and return ends it (ash's evalfun).
func (s *Shell) call(f *node, args []string, o *output) int {
	if s.nesting >= maxNesting {
		s.crash()
		return s.status
	}
	params, funcLine := s.params, s.funcLine
	s.params, s.funcLine = args[1:], f.line
	s.locals = append(s.locals, map[string]localVar{})
	s.nesting++
	code := s.eval(f.body, o)
	s.nesting--
	s.restoreLocals(s.locals[len(s.locals)-1])
	s.locals = s.locals[:len(s.locals)-1]
	s.params, s.funcLine = params, funcLine
	if s.skip == skipFunc {
		s.skip = 0
	}
	return code
}

// localVar is a variable as it was before local changed it, to put back when the function ends.
type localVar struct {
	value         string
	set, exported bool
}

// local NAME[=VALUE]...: the variable is the function's own until it ends (unset if no value).
func (s *Shell) local(args []string, o *output) int {
	if len(s.locals) == 0 {
		s.raise(o, "local", "not in a function")
		return 2
	}
	saved := s.locals[len(s.locals)-1]
	for _, a := range args {
		name, value, hasValue := strings.Cut(a, "=")
		if name == "-" { // "local -": the options are the function's own (they change nothing here)
			continue
		}
		_, again := saved[name]
		if !again {
			v, set := s.vars[name]
			saved[name] = localVar{v, set, s.exported[name]}
		}
		switch {
		case hasValue:
			if msg := s.setVar(name, value); msg != "" {
				s.raise(o, "", msg)
				return 2
			}
		case again: // "local x" a second time changes nothing
		case s.readonly[name]:
			s.raise(o, "", name+": is read only")
			return 2
		default:
			delete(s.vars, name)
		}
	}
	return 0
}

// restoreLocals puts back the variables a function made local.
func (s *Shell) restoreLocals(saved map[string]localVar) {
	for name, v := range saved {
		if v.set {
			s.vars[name] = v.value
		} else {
			delete(s.vars, name)
		}
		if v.exported {
			s.exported[name] = true
		} else {
			delete(s.exported, name)
		}
	}
}

// breakBuiltin: break [N] / continue [N] leave (go on with) the N-th loop out; outside a loop, nothing.
func (s *Shell) breakBuiltin(name string, args []string, o *output) int {
	n := 1
	if len(args) > 0 {
		v, err := strconv.Atoi(args[0])
		if !isNumber(args[0]) || err != nil || v <= 0 {
			s.raise(o, name, "Illegal number: "+args[0])
			return 2
		}
		n = v
	}
	if n = min(n, s.loops); n > 0 {
		s.skip, s.skipCount = skipBreak, n
		if name == "continue" {
			s.skip = skipCont
		}
	}
	return 0
}

// returnBuiltin: return [N] ends the function with N (only its low 8 bits, like any exit code), or with
// $?. Outside a function it ends the "." file being read, or the shell itself.
func (s *Shell) returnBuiltin(args []string, o *output) int {
	code := s.status
	if len(args) > 0 {
		if !isNumber(args[0]) {
			s.raise(o, "return", "Illegal number: "+args[0])
			return 2
		}
		n, _ := strconv.ParseUint(args[0], 10, 64)
		code = int(n & 255)
	}
	s.skip = skipFunc
	return code
}

// isFunction reports whether a name is a function defined in this shell (for type, command -v).
func (s *Shell) isFunction(name string) bool {
	_, ok := s.funcs[name]
	return ok
}

// takesInput: whether a command that ran used up the input it shares with the commands after it
// (a "while read" loop's): the text tools read all of it unless they were given a file to read
// (read itself takes one line, see read).
func (s *Shell) takesInput(args []string) bool {
	name := s.appletName(args[0])
	if name == "busybox" && len(args) > 1 {
		name, args = args[1], args[1:]
	}
	switch name {
	case "cat", "grep", "egrep", "fgrep", "wc", "head", "tail", "cut", "tr", "sort", "uniq", "sed", "awk":
		return !slices.ContainsFunc(args[1:], func(a string) bool {
			return !strings.HasPrefix(a, "-") && s.exists(resolve(s.cwd, a))
		})
	case "crontab":
		return slices.Contains(args[1:], "-")
	}
	return false
}
