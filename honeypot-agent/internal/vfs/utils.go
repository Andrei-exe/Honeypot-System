package vfs

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
)

// More of what bots run while looking around, each as BusyBox 1.30.1 has it (measured on the real
// one): printf, test / [ / [[, which, type, command, env, read, history, help, nohup, sleep, w, who
// (date is in date.go). printf, test, type, command, read, history and help are ash builtins, the rest applets.

// printfFormat is printf's FORMAT with its arguments (C's printf conversions, \ escapes, %b; the
// format is reused while arguments are left). err: the first problem, BusyBox's words, without "sh: ".
func printfFormat(format string, args []string) (string, string) {
	var out strings.Builder
	errMsg := ""
	next := func() (string, bool) {
		if len(args) == 0 {
			return "", false
		}
		a := args[0]
		args = args[1:]
		return a, true
	}
	number := func(a string) int64 {
		t := strings.TrimSpace(a)
		if len(t) > 1 && (t[0] == '\'' || t[0] == '"') { // 'a = the character's code
			return int64(t[1])
		}
		v, err := strconv.ParseInt(t, 0, 64)
		if err != nil && t != "" {
			if u, uerr := strconv.ParseUint(t, 0, 64); uerr == nil {
				return int64(u)
			}
			if errMsg == "" {
				errMsg = "invalid number '" + a + "'"
			}
		}
		return v
	}
	for {
		used := len(args)
		for i := 0; i < len(format) && out.Len() < maxSize; i++ {
			c := format[i]
			if c == '\\' && i+1 < len(format) { // \n, \x41 (1-2 hex digits), \101 (1-3 octal digits)
				j := i + 2
				switch octal := func(b byte) bool { return b >= '0' && b <= '7' }; {
				case format[i+1] == 'x':
					for j < len(format) && j < i+4 && isHexDigit(format[j]) {
						j++
					}
				case octal(format[i+1]):
					for j < len(format) && j < i+4 && octal(format[j]) {
						j++
					}
				}
				out.WriteString(cEscapes(format[i:j]))
				i = j - 1
				continue
			}
			if c != '%' {
				out.WriteByte(c)
				continue
			}
			j := i + 1
			for j < len(format) && strings.IndexByte("-+ #0", format[j]) >= 0 {
				j++
			}
			for j < len(format) && (format[j] >= '0' && format[j] <= '9' || format[j] == '.' || format[j] == '*') {
				j++
			}
			if j == len(format) || strings.IndexByte("%diouxXcsbeEfgG", format[j]) < 0 {
				return out.String(), format[i:] + ": invalid format"
			}
			spec, conv := format[i+1:j], format[j]
			i = j
			if conv == '%' {
				out.WriteByte('%')
				continue
			}
			for strings.Contains(spec, "*") { // a width or precision from the arguments
				a, _ := next()
				spec = strings.Replace(spec, "*", strconv.FormatInt(number(a), 10), 1)
			}
			spec = capWidths(spec)
			a, _ := next()
			switch conv {
			case 's':
				fmt.Fprintf(&out, "%"+spec+"s", a)
			case 'b':
				text, _, _ := strings.Cut(cEscapes(a), `\c`)
				fmt.Fprintf(&out, "%"+spec+"s", text)
			case 'c':
				if a != "" {
					fmt.Fprintf(&out, "%"+spec+"s", a[:1])
				}
			case 'd', 'i':
				fmt.Fprintf(&out, "%"+spec+"d", number(a))
			case 'o', 'u', 'x', 'X':
				verb := map[byte]string{'o': "o", 'u': "d", 'x': "x", 'X': "X"}[conv]
				fmt.Fprintf(&out, "%"+spec+verb, uint64(number(a)))
			default:
				f, err := strconv.ParseFloat(strings.TrimSpace(a), 64)
				if err != nil && a != "" && errMsg == "" {
					errMsg = "invalid number '" + a + "'"
				}
				fmt.Fprintf(&out, "%"+spec+string(conv), f)
			}
		}
		if len(args) == 0 || len(args) == used || out.Len() >= maxSize {
			return out.String(), errMsg
		}
	}
}

// capWidths keeps the width and precision of one conversion ("-08.3") under maxSize: Go's fmt would
// really build a "%999999999s" (a gigabyte for one word), and the output is cut at maxSize anyway.
func capWidths(spec string) string {
	i := 0
	for i < len(spec) && strings.IndexByte("-+ #0", spec[i]) >= 0 {
		i++
	}
	clamp := func(digits string) string {
		if n, err := strconv.Atoi(digits); err == nil && n > maxSize || err != nil && digits != "" && strings.Trim(digits, "0123456789") == "" {
			return strconv.Itoa(maxSize) // also more digits than an int holds
		}
		return digits
	}
	width, precision, hasDot := strings.Cut(spec[i:], ".")
	if hasDot {
		return spec[:i] + clamp(width) + "." + clamp(precision)
	}
	return spec[:i] + clamp(width)
}

// printf FORMAT [ARGUMENT...] (ash's builtin: its errors start with "sh:").
func (s *Shell) printf(args []string) (string, int, bool) {
	if len(args) == 0 {
		return "sh: usage: printf FORMAT [ARGUMENT...]\n", 2, false
	}
	out, err := printfFormat(args[0], args[1:])
	if err != "" {
		s.warn("sh: " + err + "\n")
		return out, 1, false
	}
	return out, 0, false
}

// tester evaluates test's expression (BusyBox test.c): ! -a -o ( ), file tests, = != < >, -eq...
type tester struct {
	s    *Shell
	args []string
	pos  int
	err  string
}

var testUnary = "-e -f -d -r -w -x -s -z -n -L -h -b -c -p -S -t -g -u -k -O -G"
var testBinary = "= == != < > -eq -ne -lt -le -gt -ge -nt -ot -ef"

func isOp(list, a string) bool { return slices.Contains(strings.Fields(list), a) }

func (t *tester) more() bool { return t.pos < len(t.args) }

func (t *tester) or() bool {
	v := t.and()
	for t.more() && t.args[t.pos] == "-o" {
		t.pos++
		v = t.and() || v
	}
	return v
}

func (t *tester) and() bool {
	v := t.not()
	for t.more() && t.args[t.pos] == "-a" {
		t.pos++
		v = t.not() && v
	}
	return v
}

func (t *tester) not() bool {
	if t.more() && t.args[t.pos] == "!" && t.pos+1 < len(t.args) {
		t.pos++
		return !t.not()
	}
	return t.primary()
}

func (t *tester) primary() bool {
	if !t.more() {
		t.err = "argument expected"
		return false
	}
	a := t.args[t.pos]
	switch {
	case a == "(" && len(t.args)-t.pos > 2:
		t.pos++
		v := t.or()
		if !t.more() || t.args[t.pos] != ")" {
			t.err = "closing paren expected"
			return false
		}
		t.pos++
		return v
	case t.pos+2 < len(t.args) && isOp(testBinary, t.args[t.pos+1]):
		t.pos += 3
		return t.binary(a, t.args[t.pos-2], t.args[t.pos-1])
	case isOp(testUnary, a) && t.pos+1 < len(t.args):
		t.pos += 2
		return t.unary(a, t.args[t.pos-1])
	}
	t.pos++
	return a != ""
}

func (t *tester) number(a string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
	if err != nil && t.err == "" {
		t.err = a + ": bad number"
	}
	return n
}

func (t *tester) binary(a, op, b string) bool {
	switch op {
	case "=", "==":
		return a == b
	case "!=":
		return a != b
	case "<":
		return a < b
	case ">":
		return a > b
	case "-nt", "-ot", "-ef":
		return false
	}
	x, y := t.number(a), t.number(b)
	return map[string]bool{"-eq": x == y, "-ne": x != y, "-lt": x < y, "-le": x <= y, "-gt": x > y, "-ge": x >= y}[op]
}

func (t *tester) unary(op, a string) bool {
	switch op {
	case "-z":
		return a == ""
	case "-n":
		return a != ""
	case "-t":
		return false
	}
	s := t.s
	p := resolve(s.cwd, a)
	_, isFile := s.readFile(p)
	exists := isFile || s.isDir(p)
	_, isLink := fakeLinks[p]
	switch op {
	case "-e", "-r", "-w":
		return exists
	case "-f":
		return isFile && p != "/dev/null"
	case "-d":
		return s.isDir(p)
	case "-c":
		return p == "/dev/null"
	case "-L", "-h":
		return isLink
	case "-x":
		return exists && s.executable(p)
	case "-s":
		_, _, size, _ := s.stat(p)
		return exists && size != "0"
	}
	return false // -b -p -S -g -u -k: none here
}

// executable: a directory, or a file whose mode (as ls -l shows it, after its link) has an x.
func (s *Shell) executable(p string) bool {
	if target, ok := fakeLinks[p]; ok {
		p = resolve(path.Dir(p), target)
	}
	mode, _, _, _ := s.stat(p)
	return s.isDir(p) || strings.Contains(mode, "x")
}

// test EXPR, [ EXPR ], [[ EXPR ]]: exit code 0 = true, 1 = false, 2 = error ("sh: ...").
func (s *Shell) test(name string, args []string) (string, int, bool) {
	if closing := map[string]string{"[": "]", "[[": "]]"}[name]; closing != "" {
		if len(args) == 0 || args[len(args)-1] != closing {
			return "sh: missing " + closing + "\n", 2, false
		}
		args = args[:len(args)-1]
	}
	if len(args) == 0 {
		return "", 1, false
	}
	t := &tester{s: s, args: args}
	v := t.or()
	if t.err == "" && t.more() {
		t.err = t.args[t.pos] + ": unknown operand"
	}
	if t.err != "" {
		return "sh: " + t.err + "\n", 2, false
	}
	if v {
		return "", 0, false
	}
	return "", 1, false
}

// lookPath finds a command in $PATH the way the shell would: the first directory with it ("" = none).
func (s *Shell) lookPath(name string) string {
	if strings.Contains(name, "/") {
		if p := resolve(s.cwd, name); s.exists(p) {
			return name
		}
		return ""
	}
	for _, dir := range strings.Split(s.vars["PATH"], ":") {
		if dir == "" {
			dir = "."
		}
		if p := resolve(s.cwd, dir+"/"+name); s.exists(p) && !s.isDir(p) {
			return strings.TrimSuffix(dir, "/") + "/" + name
		}
	}
	return ""
}

// which COMMAND...: where in $PATH each one is (only executable files); 1 if one isn't found.
func (s *Shell) which(args []string) (string, int, bool) {
	var names []string
	for _, a := range args {
		if a != "-a" {
			names = append(names, a)
		}
	}
	if len(names) == 0 {
		return usage("which", " [COMMAND]...\n\nLocate a COMMAND")
	}
	var out strings.Builder
	code := 0
	for _, n := range names {
		if p := s.lookPath(n); p != "" && s.executable(resolve(s.cwd, p)) {
			out.WriteString(p + "\n")
		} else {
			code = 1
		}
	}
	s.ownErrors = true // not found = no output, only the exit code: what was found is output
	return out.String(), code, false
}

// The ash builtins type tells apart; the "special" ones (POSIX) end a script on an error.
var (
	specialBuiltins = strings.Fields(". : break continue eval exec exit export local readonly return set shift source times trap unset")
	shellKeywords   = strings.Fields("! case do done elif else esac fi for function if in then until while { }")
)

// describe is one line of type: "ls is /bin/ls", "cd is a shell builtin" ("" = not found).
func (s *Shell) describe(name string) string {
	switch {
	case slices.Contains(shellKeywords, name):
		return name + " is a shell keyword"
	case s.isFunction(name):
		return name + " is a function"
	case slices.Contains(specialBuiltins, name):
		return name + " is a special shell builtin"
	case builtins[name]:
		return name + " is a shell builtin"
	}
	if p := s.lookPath(name); p != "" {
		return name + " is " + p
	}
	return ""
}

// type NAME...: what each name is (builtin, keyword, file in $PATH); not found = exit code 127.
func (s *Shell) typeBuiltin(args []string) (string, int, bool) {
	var out strings.Builder
	code := 0
	for _, n := range args {
		if d := s.describe(n); d != "" {
			out.WriteString(d + "\n")
		} else {
			out.WriteString(n + ": not found\n")
			code = 127
		}
	}
	s.ownErrors = true // ash prints "x: not found" to its output too
	return out.String(), code, false
}

// commandBuiltin: command -v NAME (its path, or its name for a builtin; ash looks only at the first),
// command -V NAME (like type), command CMD ARGS (runs CMD).
func (s *Shell) commandBuiltin(args []string, input string, o *output) (int, bool) {
	if len(args) > 0 && (args[0] == "-v" || args[0] == "-V") {
		if len(args) == 1 {
			return 0, false
		}
		name := args[1]
		if args[0] == "-V" {
			out, code, _ := s.typeBuiltin(args[1:2])
			o.add(1, out)
			return code, false
		}
		switch {
		case builtins[name] || slices.Contains(shellKeywords, name) || s.isFunction(name):
			o.add(1, name+"\n")
		case s.lookPath(name) != "":
			o.add(1, s.lookPath(name)+"\n")
		default:
			return 127, false
		}
		return 0, false
	}
	if len(args) == 0 {
		return 0, false
	}
	return s.dispatch(args, input, o)
}

// envHash orders env's output like ash's variable table (hashvar: first byte << 4 + all bytes of the
// name, 39 buckets), the order the real env prints in.
func envHash(name string) int {
	h := int(name[0]) << 4
	for i := 0; i < len(name); i++ {
		h += int(name[i])
	}
	return h % 39
}

// environOrder: in one bucket, ash keeps the variables in the order they were made (findvar appends).
// First come those the shell got from its parent, in the order Dropbear sets them (USER before
// SSH_CLIENT, both in bucket 2); those made later follow (HOME before OLDPWD), here alphabetically.
var environOrder = []string{"USER", "LOGNAME", "HOME", "SHELL", "PATH", "TERM", "SSH_TTY", "SSH_CONNECTION", "SSH_CLIENT"}

// envRank is a variable's place in its bucket: its index in environOrder, or after all of them.
func envRank(name string) int {
	if i := slices.Index(environOrder, name); i >= 0 {
		return i
	}
	return len(environOrder)
}

// env [-i] [-u NAME] [NAME=VALUE]... [PROG ARGS]: prints the exported variables, or runs PROG with
// those changes (in a child shell, like any program).
func (s *Shell) env(args []string, input string, o *output) (int, bool) {
	vars := map[string]string{}
	for n := range s.exported {
		if v, ok := s.vars[n]; ok {
			vars[n] = v
		}
	}
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "-i" || a == "-":
			vars = map[string]string{}
		case a == "-u" && len(args) > 1:
			delete(vars, args[1])
			args = args[1:]
		case strings.HasPrefix(a, "-") && a != "--":
			out, _, _ := usage("env", " [-iu] [-] [name=value]... [PROG ARGS]\n\nPrint the current environment or run PROG after setting up\n"+
				"the specified environment\n\n\t-, -i\tStart with an empty environment\n\t-u\tRemove variable from the environment")
			o.add(2, "env: invalid option -- "+strings.TrimPrefix(a, "-")[:1]+"\n"+out)
			return 1, false
		case strings.Contains(a, "=") && !strings.HasPrefix(a, "="):
			n, v, _ := strings.Cut(a, "=")
			vars[n] = v
		default:
			goto run
		}
		args = args[1:]
	}
run:
	if len(args) == 0 {
		o.add(1, environText(vars, "\n"))
		return 0, false
	}
	code := 0
	s.child(o, func() {
		s.vars, s.exported = maps.Clone(vars), map[string]bool{}
		for n := range vars {
			s.exported[n] = true
		}
		if _, ok := vars["PATH"]; !ok {
			s.vars["PATH"] = "/bin:/usr/bin" // execvp's default when there is no PATH (env -i CMD)
		}
		code, _ = s.dispatch(args, input, o)
	})
	return code, false
}

// environText is an environment the way a program's environ holds it (env prints it, /proc/PID/environ):
// "NAME=value" + end each, in ash's order (hashvar mod 39, see envHash).
func environText(vars map[string]string, end string) string {
	names := slices.Collect(maps.Keys(vars))
	slices.SortFunc(names, func(a, b string) int {
		if d := envHash(a) - envHash(b); d != 0 {
			return d
		}
		if d := envRank(a) - envRank(b); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	var out strings.Builder
	for _, n := range names {
		out.WriteString(n + "=" + vars[n] + end)
	}
	return out.String()
}

// environ is what the shell passes to the commands it runs: its exported variables (environText).
func (s *Shell) environ(end string) string {
	vars := map[string]string{}
	for n := range s.exported {
		if v, ok := s.vars[n]; ok {
			vars[n] = v
		}
	}
	return environText(vars, end)
}

// read [-r] [-p PROMPT] [-t N] [-n N] [-s] [NAME...]: the first line of its input, split on $IFS
// into the names (the last gets the rest; none = REPLY). The next read gets the next line
// ("while read x"). No input (nothing came through < or |): exit code 1 (a real one would wait for
// the next line typed: simplification).
func (s *Shell) read(args []string, input string) (string, int, bool) {
	raw := false
	var names []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-r":
			raw = true
		case a == "-p" || a == "-t" || a == "-n" || a == "-u" || a == "-d":
			i++
		case strings.HasPrefix(a, "-") && len(a) > 1:
		default:
			names = append(names, a)
		}
	}
	if len(names) == 0 {
		names = []string{"REPLY"}
	}
	line, rest, found := strings.Cut(input, "\n")
	s.stdin = rest
	if !raw {
		line = strings.ReplaceAll(line, "\\", "")
	}
	ifs := s.ifs()
	fields := strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(ifs, r) })
	for i, n := range names {
		v := ""
		switch {
		case i == len(names)-1 && i < len(fields): // the last name gets the rest of the line
			idx := 0
			for k := 0; k < i; k++ {
				idx = strings.Index(line[idx:], fields[k]) + idx + len(fields[k])
			}
			v = strings.Trim(line[idx:], ifs)
		case i < len(fields):
			v = fields[i]
		}
		if msg := s.setVar(n, v); msg != "" {
			return "-sh: " + msg + "\n", 2, false
		}
	}
	if !found && line == "" {
		return "", 1, false
	}
	return "", 0, false
}

// history: the lines typed in this session, "%4d %s" from 0, like BusyBox's line editing (which keeps
// them: empty lines and the same line twice in a row are not kept). "history -c" doesn't clear it:
// ash's history ignores its arguments, so a bot hiding its traces just gets its commands listed.
func (s *Shell) historyBuiltin() (string, int, bool) {
	var out strings.Builder
	for i, line := range s.history {
		fmt.Fprintf(&out, "%4d %s\n", i, line)
	}
	return out.String(), 0, false
}

// remember adds a typed line to the history (Run calls it), kept under 64KB.
func (s *Shell) remember(line string) {
	if line == "" || len(s.history) > 0 && s.history[len(s.history)-1] == line {
		return
	}
	s.history = append(s.history, strings.Clone(line))
	for size := 0; ; {
		size = 0
		for _, l := range s.history {
			size += len(l)
		}
		if size <= 64*1024 && len(s.history) <= 999 {
			return
		}
		s.history = s.history[1:]
	}
}

// helpText is ash's help (ASH_HELP, Buildroot's config): its builtins in its table's order.
const helpText = "Built-in commands:\n------------------\n" +
	"\t. : [ [[ alias bg break cd chdir command continue echo eval exec\n" +
	"\texit export false fg getopts hash help history jobs kill let\n" +
	"\tlocal printf pwd read readonly return set shift source test times\n" +
	"\ttrap true type ulimit umask unalias unset wait\n"

// sleep N[smhd]...: checked like BusyBox, but it returns at once (the session must not hang).
func sleep(args []string) (string, int, bool) {
	if len(args) == 0 {
		return usage("sleep", " [N]...\n\nPause for a time equal to the total of the args given, where each arg can\n"+
			"have an optional suffix of (s)econds, (m)inutes, (h)ours, or (d)ays")
	}
	for _, a := range args {
		if _, err := strconv.ParseFloat(strings.TrimRight(a, "smhd"), 64); err != nil || a == "" {
			return "sleep: invalid number '" + a + "'\n", 1, false
		}
	}
	return "", 0, false
}

// wHeader is w's first line; no one is listed (simplification: the router keeps no utmp record
// of the sessions here, so neither who nor w knows the attacker's own login).
const wHeader = "USER\t\tTTY\t\tIDLE\tTIME\t\t HOST\n"
