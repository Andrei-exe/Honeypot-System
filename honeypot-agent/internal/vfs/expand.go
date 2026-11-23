package vfs

import (
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
)

// The expansions ash does on a command's words just before it runs (BusyBox 1.30.1, ash.c): quotes
// and backslashes removed; $VAR, ${VAR...}, $(...), `...`, $((...)) and ~ replaced; what an unquoted
// expansion gave split on $IFS; unquoted * ? [ matched against the files. Words stay as typed until
// then (parse keeps them so), so "X=1; echo $X" and "cd /tmp; echo $(pwd)" see the moment they run in.

// field is one word being made.
type field struct {
	text    strings.Builder // the word
	pattern strings.Builder // the same for matching files: quoted * ? [ \ escaped with \
	glob    bool            // it has an unquoted * ? or [
	keep    bool            // it exists even if empty: quotes were typed ("" is a word, an empty $X is not)
}

// expander makes the words of one command.
type expander struct {
	s      *Shell
	o      *output // where $(...)'s errors and the shell's own ("bad substitution") go
	split  bool    // split on $IFS and match files (not in an assignment or a redirection)
	inWord bool    // in the word of an unquoted ${X:-word}: its own text is split too
	// a pattern (case, ${X#...}): the * ? [ an unquoted expansion gives match like typed ones
	// (P='a*'; ${X#$P}), quoted ones only themselves (${X#"$P"})
	pattern bool
	fields  []*field
	size    int // bytes made: a command's words are capped like its output (maxSize)
}

// expandWords expands a command's words (as typed) into its arguments.
func (s *Shell) expandWords(raws []string, o *output) []string {
	e := &expander{s: s, o: o}
	// export X=$(cmd): an assignment given to export / readonly is one word, not split
	declaring := len(raws) > 0 && (raws[0] == "export" || raws[0] == "readonly")
	var words []string
	total := 0 // the words made, each counted as its length + 1: a command's words stay under 2 x maxSize
	add := func(w ...string) {
		for _, word := range w {
			if total += len(word) + 1; total <= 2*maxSize {
				words = append(words, word)
			}
		}
	}
	for i, raw := range raws {
		if raw == `"$@"` { // each parameter is one word; no parameters = no word at all
			add(s.params...) // (counted: set -- "$@" "$@" doubles them on every command)
			continue
		}
		e.fields = e.fields[:0]
		e.split = !(declaring && i > 0 && isAssignment(raw))
		e.text(raw, false)
		if s.raised {
			return nil
		}
		for _, f := range e.fields {
			if !f.keep {
				continue
			}
			if f.glob && e.split {
				if paths := s.glob(f.pattern.String()); len(paths) > 0 {
					add(paths...)
					continue
				}
			}
			add(f.text.String())
		}
	}
	return words
}

// expandText expands a word into one string, without splitting or matching files: the value of an
// assignment, a redirection's file, the inside of $((...)).
func (s *Shell) expandText(raw string, o *output) string {
	e := &expander{s: s, o: o}
	e.text(raw, false)
	var parts []string
	for _, f := range e.fields {
		parts = append(parts, f.text.String())
	}
	return strings.Join(parts, " ") // several only from "$@"
}

// expandPattern expands the pattern of ${X#pattern} and the like: quoted parts match themselves.
func (s *Shell) expandPattern(raw string, o *output) string {
	e := &expander{s: s, o: o, pattern: true}
	e.text(raw, false)
	return e.cur().pattern.String()
}

func (e *expander) cur() *field {
	if len(e.fields) == 0 {
		e.fields = append(e.fields, &field{})
	}
	return e.fields[len(e.fields)-1]
}

// char adds one character. quoted: typed in quotes or escaped, so * ? [ match only themselves.
func (e *expander) char(c byte, quoted bool) {
	f := e.cur()
	f.keep = true
	if e.size >= maxSize {
		return
	}
	e.size++
	f.text.WriteByte(c)
	switch {
	case c == '\\' || quoted && strings.IndexByte("*?[", c) >= 0:
		f.pattern.WriteByte('\\')
	case strings.IndexByte("*?[", c) >= 0:
		f.glob = true
	}
	f.pattern.WriteByte(c)
}

// value adds what an expansion gave. Unquoted, it is split on $IFS: "a  b" becomes two words.
func (e *expander) value(v string, quoted bool) {
	if quoted || !e.split {
		for i := 0; i < len(v); i++ {
			e.char(v[i], quoted || !e.pattern)
		}
		return
	}
	ifs := e.s.ifs()
	for i := 0; i < len(v); i++ {
		if strings.IndexByte(ifs, v[i]) < 0 {
			e.char(v[i], false)
		} else if e.cur().keep {
			e.fields = append(e.fields, &field{}) // the word so far is done; spaces at the start are not words
		}
	}
}

// text adds a word as typed. inQuotes: it is already inside "..." (the word of a "${X:-word}").
func (e *expander) text(raw string, inQuotes bool) {
	dq := inQuotes // inside "..."
	for i := 0; i < len(raw) && !e.s.raised; i++ {
		switch c := raw[i]; {
		case c == '\'' && !dq: // '...': everything is text
			end := strings.IndexByte(raw[i+1:], '\'')
			if end < 0 {
				end = len(raw) - i - 1
			}
			e.cur().keep = true
			for j := i + 1; j <= i+end; j++ {
				e.char(raw[j], true)
			}
			i += end + 1
		case c == '"':
			dq = !dq
			e.cur().keep = true
		case c == '\\':
			switch {
			case i+1 == len(raw):
				e.char('\\', true)
			case dq && strings.IndexByte("$`\"\\\n", raw[i+1]) < 0:
				e.char('\\', true) // in "...", a backslash only escapes $ ` " \ and newline
			default:
				if i++; raw[i] != '\n' { // backslash + newline: the line goes on
					e.char(raw[i], true)
				}
			}
		case c == '$' || c == '`':
			i = e.dollar(raw, i, dq) - 1
		case c == '~' && i == 0 && !dq:
			i = e.tilde(raw) - 1
		case e.inWord && !dq:
			e.value(string(c), false)
		default:
			e.char(c, dq)
		}
	}
}

// word adds the word of ${X:-word} / ${X:+word}. Unquoted, it is split like an expansion's result:
// ${X:-a  b} gives two words, ${X:-"a  b"} one.
func (e *expander) word(raw string, dq bool) {
	saved := e.inWord
	e.inWord = !dq
	e.text(raw, dq)
	e.inWord = saved
}

// tilde: ~ is $HOME, ~user that user's home (/etc/passwd); otherwise it stays a ~.
func (e *expander) tilde(raw string) int {
	end := strings.IndexByte(raw, '/')
	if end < 0 {
		end = len(raw)
	}
	user, home, found := raw[1:end], "", false
	if user == "" {
		home, found = e.s.vars["HOME"]
	} else if !strings.ContainsAny(user, "'\"\\$`") {
		home, found = e.s.homeOf(user)
	}
	if !found || home == "" {
		e.char('~', false)
		return 1
	}
	for i := 0; i < len(home); i++ {
		e.char(home[i], true)
	}
	return end
}

// dollar expands the $... or `...` at raw[i] and returns where it ends. "$" before anything else is
// just a "$" ("$/", "a$").
func (e *expander) dollar(raw string, i int, dq bool) int {
	if raw[i] == '`' {
		end, _ := partEnd(raw, i)
		e.value(e.s.substitute(unescapeBackquote(raw[i+1:max(end-1, i+1)]), e.o), dq)
		return end
	}
	if i+1 == len(raw) {
		e.char('$', dq)
		return i + 1
	}
	if raw[i+1] == '\'' && !dq { // $'a\tb': quoted text with C escapes
		end, _ := partEnd(raw, i)
		e.cur().keep = true
		text := cEscapes(raw[i+2 : max(end-1, i+2)])
		for j := 0; j < len(text); j++ {
			e.char(text[j], true)
		}
		return end
	}
	switch n := raw[i+1]; {
	case n == '(' || n == '{':
		end, _ := partEnd(raw, i)
		inner := raw[i+2 : max(end-1, i+2)]
		switch {
		case n == '{':
			e.braces(inner, dq)
		case strings.HasPrefix(inner, "(") && strings.HasSuffix(inner, ")"): // $((...))
			v, err := e.s.arith(e.s.expandText(inner[1:len(inner)-1], e.o))
			if err != "" {
				e.s.raise(e.o, "", err)
				break
			}
			e.value(strconv.FormatInt(v, 10), dq)
		default:
			e.value(e.s.substitute(inner, e.o), dq)
		}
		return end
	case isNameStart(n):
		j := i + 1
		for j < len(raw) && isNameChar(raw[j]) {
			j++
		}
		v, _ := e.s.lookup(raw[i+1 : j])
		e.value(v, dq)
		return j
	case n >= '0' && n <= '9' || strings.IndexByte("?$!#-*@", n) >= 0:
		e.special(n, dq)
		return i + 2
	}
	e.char('$', dq)
	return i + 1
}

// cEscapes turns the escapes of $'...' into characters: \n \t \r \a \b \e \f \v \\ \' \" \xHH \NNN.
func cEscapes(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			out.WriteByte(s[i])
			continue
		}
		i++
		if j := strings.IndexByte(`ntrabefv\'"`, s[i]); j >= 0 {
			out.WriteByte("\n\t\r\a\b\x1b\f\v\\'\""[j])
			continue
		}
		switch {
		case s[i] == 'x' && i+1 < len(s) && isHexDigit(s[i+1]): // \xHH: one or two hex digits
			n := 1
			if i+2 < len(s) && isHexDigit(s[i+2]) {
				n = 2
			}
			v, _ := strconv.ParseUint(s[i+1:i+1+n], 16, 8)
			out.WriteByte(byte(v))
			i += n
		case s[i] >= '0' && s[i] <= '7': // \NNN: one to three octal digits
			n := 1
			for n < 3 && i+n < len(s) && s[i+n] >= '0' && s[i+n] <= '7' {
				n++
			}
			v, _ := strconv.ParseUint(s[i:i+n], 8, 16)
			out.WriteByte(byte(v))
			i += n - 1
		default:
			out.WriteByte('\\')
			out.WriteByte(s[i])
		}
	}
	return out.String()
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// unescapeBackquote: inside `...`, a backslash before $ ` or \ is only there to protect it.
func unescapeBackquote(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\\", s[i+1]) >= 0 {
			i++
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

// special: $? $$ $! $# $- $* $@ $0 $1...$9.
func (e *expander) special(c byte, dq bool) {
	s := e.s
	switch {
	case c == '@' && dq: // "$@": each parameter a separate word
		for k, p := range s.params {
			if e.size++; e.size > maxSize { // empty parameters are words too: counted
				break
			}
			if k > 0 {
				e.fields = append(e.fields, &field{keep: true})
			}
			e.value(p, true)
		}
	case c == '*' || c == '@':
		sep := " "
		if ifs := s.ifs(); dq && ifs != "" {
			sep = ifs[:1]
		} else if dq {
			sep = ""
		}
		e.value(strings.Join(s.params, sep), dq)
	default:
		v, _ := s.param(string(c))
		e.value(v, dq)
	}
}

// param returns $? $$ $! $# $- $0..$N; ok = false: not set ($9 with fewer parameters, $!).
func (s *Shell) param(name string) (string, bool) {
	switch name {
	case "?":
		return strconv.Itoa(s.status), true
	case "$":
		return shellPID, true
	case "!":
		return "", false // nothing ever ran in the background
	case "#":
		return strconv.Itoa(len(s.params)), true
	case "-": // ash's option letters: s = commands from its input, m = job control, i = interactive
		switch {
		case s.interactive:
			return "smi", true // the login shell on a terminal
		case s.fromStdin:
			return "s", true // SSH without a pty, "echo cmd | sh"
		}
		return "", true // sh -c, sh FILE
	case "*", "@":
		return strings.Join(s.params, " "), len(s.params) > 0
	case "0":
		return s.arg0, true
	}
	if n, err := strconv.Atoi(name); err == nil && n >= 1 && n <= len(s.params) {
		return s.params[n-1], true
	}
	return "", false
}

// braces expands ${...}: ${X} ${#X} ${X-w} ${X:-w} ${X=w} ${X?w} ${X+w} (each also with ":", which
// counts an empty value as unset), ${X#p} ${X##p} ${X%p} ${X%%p}, ${X/p/r} ${X//p/r}, ${X:off:len}.
func (e *expander) braces(inner string, dq bool) {
	s := e.s
	if len(inner) > 1 && inner[0] == '#' && braceName(inner[1:]) == inner[1:] { // ${#X}: the length
		v, _ := s.braceValue(inner[1:])
		e.value(strconv.Itoa(len(v)), dq)
		return
	}
	name := braceName(inner)
	if name == "" {
		s.raise(e.o, "", "syntax error: bad substitution")
		return
	}
	value, set := s.braceValue(name)
	rest := inner[len(name):]
	if rest == "" {
		e.value(value, dq)
		return
	}
	colon := rest[0] == ':' && len(rest) > 1 && strings.IndexByte("-=?+", rest[1]) >= 0
	if colon {
		rest = rest[1:]
		set = set && value != ""
	}
	switch op, word := rest[0], rest[1:]; {
	case op == '-':
		if set {
			e.value(value, dq)
		} else {
			e.word(word, dq)
		}
	case op == '+':
		if set {
			e.word(word, dq)
		}
	case op == '=':
		if set {
			e.value(value, dq)
			return
		}
		value = s.expandText(word, e.o)
		if msg := s.setVar(name, value); msg != "" {
			s.raise(e.o, "", msg)
			return
		}
		e.value(value, dq)
	case op == '?':
		if set {
			e.value(value, dq)
			return
		}
		msg := s.expandText(word, e.o)
		if msg == "" {
			msg = "parameter not set"
			if colon {
				msg += " or null"
			}
		}
		s.raise(e.o, "", name+": "+msg)
	case op == '#' || op == '%':
		longest := strings.HasPrefix(word, string(op))
		if longest {
			word = word[1:]
		}
		e.value(trim(value, s.expandPattern(word, e.o), op == '#', longest, &s.work), dq)
	case op == '/':
		all := strings.HasPrefix(word, "/")
		if all {
			word = word[1:]
		}
		pattern, replacement, _ := strings.Cut(word, "/")
		e.value(replace(value, s.expandPattern(pattern, e.o), s.expandText(replacement, e.o), all, &s.work), dq)
	case op == ':': // ${X:offset} ${X:offset:length}, offsets counted like $((...))
		offText, lenText, hasLen := strings.Cut(word, ":")
		off, err := s.arith(s.expandText(offText, e.o))
		length := int64(len(value))
		if hasLen && err == "" {
			length, err = s.arith(s.expandText(lenText, e.o))
		}
		if err != "" {
			s.raise(e.o, "", err)
			return
		}
		if off < 0 {
			off = max(int64(len(value))+off, 0)
		}
		off = min(off, int64(len(value)))
		e.value(value[off:off+max(min(length, int64(len(value))-off), 0)], dq)
	default:
		s.raise(e.o, "", "syntax error: bad substitution")
	}
}

// braceName is the name at the start of a ${...}: a variable, all digits ($10), or one of ?$!#-*@0.
func braceName(inner string) string {
	switch {
	case inner == "":
		return ""
	case isNameStart(inner[0]):
		j := 1
		for j < len(inner) && isNameChar(inner[j]) {
			j++
		}
		return inner[:j]
	case inner[0] >= '0' && inner[0] <= '9':
		j := 1
		for j < len(inner) && inner[j] >= '0' && inner[j] <= '9' {
			j++
		}
		if j < len(inner) && isNameStart(inner[j]) { // ${1x}
			return ""
		}
		return inner[:j]
	case strings.IndexByte("?$!#-*@", inner[0]) >= 0:
		return inner[:1]
	}
	return ""
}

// braceValue is the value of a variable or a special parameter by name, and whether it is set.
func (s *Shell) braceValue(name string) (string, bool) {
	if isNameStart(name[0]) {
		return s.lookup(name)
	}
	return s.param(name)
}

// ${X#p} and ${X/p/r} try p at every place in X: on long values or patterns that is a lot of work
// for one word (an attacker can type a pattern of 4000 "*"), so beyond these sizes the value is left
// as it is (simplification; scripts use them on short paths and names).
const (
	trimLimit    = 1024 // the value, for # ## % %%
	replaceLimit = 128  // the value, for / // with * ? [ in the pattern (one without them is a plain replace)
	patternMax   = 256  // the pattern
)

// trim removes the shortest (or longest) prefix / suffix matching pattern: ${X#p} ${X##p} ${X%p} ${X%%p}.
// work: the line's budget (maxWork); each try costs what it reads.
func trim(value, pattern string, prefix, longest bool, work *int) string {
	if len(value) > trimLimit || len(pattern) > patternMax {
		return value
	}
	for k := 0; k <= len(value); k++ {
		if *work -= len(value) + len(pattern); *work < 0 {
			return value
		}
		n := k // how much is cut: from the shortest up, or from the longest down
		if longest {
			n = len(value) - k
		}
		if prefix && wildMatch(pattern, value[:n]) {
			return value[n:]
		}
		if !prefix && wildMatch(pattern, value[len(value)-n:]) {
			return value[:len(value)-n]
		}
	}
	return value
}

// replace changes the first (or every) longest match of pattern: ${X/p/r} ${X//p/r}.
func replace(value, pattern, replacement string, all bool, work *int) string {
	switch {
	case pattern == "":
		return value
	case !hasMeta(pattern):
		n := 1
		if all {
			n = -1
		}
		return strings.Replace(value, unescapeGlob(pattern), replacement, n)
	case len(value) > replaceLimit || len(pattern) > patternMax:
		return value
	}
	var out strings.Builder
	for i := 0; i < len(value); {
		end := -1
		for j := len(value); j > i; j-- {
			if *work -= j - i + len(pattern); *work < 0 {
				return value
			}
			if wildMatch(pattern, value[i:j]) {
				end = j
				break
			}
		}
		if end < 0 {
			out.WriteByte(value[i])
			i++
			continue
		}
		out.WriteString(replacement)
		if !all {
			return out.String() + value[end:]
		}
		i = end
	}
	return out.String()
}

// ifs is $IFS (unset: space, tab, newline).
func (s *Shell) ifs() string {
	if v, ok := s.vars["IFS"]; ok {
		return v
	}
	return " \t\n"
}

// lookup returns a variable's value and whether it is set. $RANDOM and $LINENO change by themselves.
func (s *Shell) lookup(name string) (string, bool) {
	switch name {
	case "RANDOM":
		return strconv.Itoa(rand.IntN(32768)), true
	case "LINENO":
		return strconv.Itoa(s.lineno), true
	}
	v, ok := s.vars[name]
	return v, ok
}

// homeOf returns a user's home directory from /etc/passwd (for ~user).
func (s *Shell) homeOf(user string) (string, bool) {
	passwd, _ := s.readFile("/etc/passwd")
	for _, line := range strings.Split(passwd, "\n") {
		if f := strings.Split(line, ":"); len(f) >= 6 && f[0] == user {
			return f[5], true
		}
	}
	return "", false
}

// substitute runs $(...) / `...` in a subshell and returns what it printed, without the final newlines.
// Its errors go to the screen (o) now, before the command's own output.
func (s *Shell) substitute(code string, o *output) string {
	var out output
	s.child(o, func() { s.runCode(code, s.lineno, &out) }) // its lines are counted from the command's
	s.substStatus = s.status
	var text strings.Builder
	for _, c := range out.chunks {
		if c.fd == 1 {
			text.WriteString(c.text)
		} else {
			o.add(2, c.text)
		}
	}
	return strings.TrimRight(text.String(), "\n")
}

// glob returns the paths a pattern with * ? [...] matches, sorted (ash's expmeta). A name starting
// with "." only matches a part starting with "." (then "." and ".." too). None: nil, and the word
// stays as typed.
func (s *Shell) glob(pattern string) []string {
	found := []string{""}
	parts := strings.Split(pattern, "/")
	work := 0 // names looked at: "*/../*/../*..." would list the same directories over and over
	for k, part := range parts {
		var next []string
		for _, prefix := range found {
			join := func(name string) string {
				if k == 0 {
					return name
				}
				return prefix + "/" + name
			}
			if !hasMeta(part) {
				next = append(next, join(unescapeGlob(part)))
				continue
			}
			dir := s.cwd
			if k > 0 {
				dir = resolve(s.cwd, prefix+"/")
			}
			if !s.isDir(dir) {
				continue
			}
			names := s.list(dir)
			if strings.HasPrefix(part, ".") {
				names = append([]string{".", ".."}, names...)
			}
			s.work -= len(names) + 500 // + going through all the tables for this directory (list)
			if work += len(names); work > 20000 || s.work < 0 {
				return nil // left as typed
			}
			for _, name := range names {
				if (name[0] != '.' || strings.HasPrefix(part, ".")) && wildMatch(part, name) {
					next = append(next, join(name))
				}
			}
		}
		if found = next; len(found) == 0 || len(found) > 1000 {
			return nil // (more than 1000: /*/*/*... on purpose; left as typed)
		}
	}
	var out []string
	for _, p := range found { // the parts without * ? [ must exist too ("/nope/*" matches nothing)
		full := resolve(s.cwd, p)
		if _, isFile := s.readFile(full); s.isDir(full) || isFile && !strings.HasSuffix(p, "/") {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// hasMeta reports whether a pattern part has an unescaped * ? or [.
func hasMeta(part string) bool {
	for i := 0; i < len(part); i++ {
		switch part[i] {
		case '\\':
			i++
		case '*', '?', '[':
			return true
		}
	}
	return false
}

func unescapeGlob(part string) string {
	var out strings.Builder
	for i := 0; i < len(part); i++ {
		if part[i] == '\\' && i+1 < len(part) {
			i++
		}
		out.WriteByte(part[i])
	}
	return out.String()
}

// wildMatch matches a shell pattern: * (anything, "/" too), ?, [abc] [a-z] [!a], \x. The usual
// backtracking on the last *, so it takes at most len(pattern) x len(name) steps.
func wildMatch(pattern, name string) bool {
	p, n := 0, 0
	starP, starN := -1, -1
	for p < len(pattern) || n < len(name) {
		if p < len(pattern) {
			switch c := pattern[p]; c {
			case '*':
				starP, starN = p, n+1
				p++
				continue
			case '?':
				if n < len(name) {
					p, n = p+1, n+1
					continue
				}
			case '[':
				if ok, end := matchClass(pattern, p, name, n); end > 0 {
					if ok {
						p, n = end, n+1
						continue
					}
					break
				}
				if n < len(name) && name[n] == '[' { // no closing ]: a plain [
					p, n = p+1, n+1
					continue
				}
			case '\\':
				if p+1 < len(pattern) {
					c = pattern[p+1]
					p++
				}
				fallthrough
			default:
				if n < len(name) && name[n] == c {
					p, n = p+1, n+1
					continue
				}
			}
		}
		if starN > 0 && starN <= len(name) { // try the last * one character longer
			p, n = starP+1, starN
			starN++
			continue
		}
		return false
	}
	return true
}

// matchClass matches name[n] against the [...] at pattern[p]. end = the index after "]" (-1: none).
func matchClass(pattern string, p int, name string, n int) (bool, int) {
	j := p + 1
	negate := j < len(pattern) && (pattern[j] == '!' || pattern[j] == '^')
	if negate {
		j++
	}
	matched := false
	for first := true; j < len(pattern); first = false {
		if pattern[j] == ']' && !first {
			return n < len(name) && matched != negate, j + 1
		}
		lo := pattern[j]
		if lo == '\\' && j+1 < len(pattern) {
			j++
			lo = pattern[j]
		}
		hi := lo
		if j+2 < len(pattern) && pattern[j+1] == '-' && pattern[j+2] != ']' {
			hi = pattern[j+2]
			j += 2
		}
		if n < len(name) && lo <= name[n] && name[n] <= hi {
			matched = true
		}
		j++
	}
	return false, -1
}
