package vfs

import (
	"regexp"
	"strconv"
	"strings"
)

// sed like BusyBox 1.30.1's, for what bots and scripts use: s/RE/REPLACEMENT/[gpI N] (with \1 and &),
// p, d, q, =, addresses (N, $, /RE/, ranges A,B, ! to negate), -n, -e, -f, -i (in place), -E / -r.
// Other commands (a, i, c, y, { }...) get BusyBox's "unsupported command" (simplification).

const sedUsage = " [-i[SFX]] [-nrE] [-f FILE]... [-e CMD]... [FILE]...\nor: sed [-i[SFX]] [-nrE] CMD [FILE]...\n\n" +
	"\t-e CMD\tAdd CMD to sed commands to be executed\n\t-f FILE\tAdd FILE contents to sed commands to be executed\n" +
	"\t-i[SFX]\tEdit files in-place (otherwise sends to stdout)\n\t\tOptionally back files up, appending SFX\n" +
	"\t-n\tSuppress automatic printing of pattern space\n\t-r,-E\tUse extended regex syntax\n\n" +
	"If no -e or -f, the first non-option argument is the sed command string.\n" +
	"Remaining arguments are input files (stdin if none)."

type sedAddr struct {
	kind byte // 0 = none, 'n' = line number, '$' = the last line, '/' = lines matching re
	n    int
	re   *regexp.Regexp
}

type sedCmd struct {
	from, to sedAddr // to.kind 0: a single address
	negate   bool    // A!cmd: the lines NOT addressed
	active   bool    // inside its A,B range
	cmd      byte    // s p d q =
	re       *regexp.Regexp
	repl     string
	global   bool // s///g
	nth      int  // s///N: only the Nth match
	print    bool // s///p
}

func (s *Shell) sed(args []string, input string) (string, int, bool) {
	inPlace := false
	var rest []string
	for _, a := range args { // -i[SUFFIX]: the suffix (a backup) is accepted, no backup is made
		if strings.HasPrefix(a, "-i") {
			inPlace = true
			continue
		}
		rest = append(rest, a)
	}
	opts, files, bad := options(rest, "nrEs", "ef")
	var scripts []string
	scripts = append(scripts, opts['e']...)
	for _, f := range opts['f'] {
		text, ok := s.readFile(resolve(s.cwd, f))
		if !ok {
			return "sed: can't open '" + f + "': No such file or directory\n", 1, false
		}
		scripts = append(scripts, text)
	}
	if len(scripts) == 0 && len(files) > 0 {
		scripts, files = files[:1], files[1:]
	}
	if bad != 0 || len(scripts) == 0 {
		return usage("sed", sedUsage)
	}
	extended := opts['r'] != nil || opts['E'] != nil
	cmds, err := parseSed(strings.Join(scripts, "\n"), extended)
	if err != "" {
		return "sed: " + err + "\n", 1, false
	}
	quiet := opts['n'] != nil

	if !inPlace {
		srcs, ok := s.sources(files, input, func(f, reason string) string { return "sed: " + f + ": " + reason + "\n" })
		var all strings.Builder
		for _, src := range srcs {
			all.WriteString(src.text)
		}
		code := 0
		if !ok {
			code = 1
		}
		return runSed(cmds, all.String(), quiet), code, false
	}
	for _, f := range files {
		text, ok := s.readFile(resolve(s.cwd, f))
		if !ok {
			return "sed: can't open '" + f + "': No such file or directory\n", 1, false
		}
		for i := range cmds {
			cmds[i].active = false
		}
		if _, err := s.writeFile(f, runSed(cmds, text, quiet), false); err != nil {
			return "sed: can't create '" + f + "': " + err.Error() + "\n", 1, false
		}
	}
	return "", 0, false
}

// parseSed reads a script; the error is BusyBox's text.
func parseSed(script string, extended bool) ([]sedCmd, string) {
	var cmds []sedCmd
	i := 0
	// until reads up to an unescaped delim; "\delim" becomes delim, other escapes stay for the regex
	until := func(delim byte) (string, bool) {
		var b strings.Builder
		for ; i < len(script); i++ {
			switch c := script[i]; {
			case c == '\\' && i+1 < len(script):
				i++
				if script[i] != delim {
					b.WriteByte('\\')
				}
				b.WriteByte(script[i])
			case c == delim:
				i++
				return b.String(), true
			default:
				b.WriteByte(c)
			}
		}
		return b.String(), false
	}
	address := func() (sedAddr, string) {
		switch {
		case i < len(script) && script[i] >= '0' && script[i] <= '9':
			j := i
			for j < len(script) && script[j] >= '0' && script[j] <= '9' {
				j++
			}
			n, _ := strconv.Atoi(script[i:j])
			i = j
			return sedAddr{kind: 'n', n: n}, ""
		case i < len(script) && script[i] == '$':
			i++
			return sedAddr{kind: '$'}, ""
		case i < len(script) && script[i] == '/':
			i++
			pattern, ok := until('/')
			if !ok {
				return sedAddr{}, "unmatched '/'"
			}
			re, err := compileRegex(sedEscapes(pattern), extended, false)
			if err != nil {
				return sedAddr{}, "bad regex '" + pattern + "': " + regexError(pattern, extended)
			}
			return sedAddr{kind: '/', re: re}, ""
		}
		return sedAddr{}, ""
	}
	for i < len(script) {
		if strings.IndexByte(" \t\n;", script[i]) >= 0 {
			i++
			continue
		}
		var c sedCmd
		var err string
		if c.from, err = address(); err != "" {
			return nil, err
		}
		if c.from.kind != 0 && i < len(script) && script[i] == ',' {
			i++
			if c.to, err = address(); err != "" {
				return nil, err
			}
		}
		for i < len(script) && script[i] == ' ' {
			i++
		}
		if i < len(script) && script[i] == '!' {
			c.negate = true
			i++
		}
		if i == len(script) {
			return nil, "missing command"
		}
		c.cmd = script[i]
		i++
		switch c.cmd {
		case 'p', 'd', 'q', '=':
		case 's':
			if i == len(script) {
				return nil, "unmatched 's'"
			}
			delim := script[i]
			i++
			pattern, ok1 := until(delim)
			repl, ok2 := until(delim)
			if !ok1 || !ok2 {
				return nil, "unmatched '" + string(delim) + "'"
			}
			icase := false
			for ; i < len(script) && strings.IndexByte(" \t\n;}", script[i]) < 0; i++ {
				switch f := script[i]; {
				case f == 'g':
					c.global = true
				case f == 'p':
					c.print = true
				case f == 'I' || f == 'i':
					icase = true
				case f >= '0' && f <= '9':
					c.nth = c.nth*10 + int(f-'0')
				default:
					return nil, "bad option in substitution expression"
				}
			}
			re, err := compileRegex(sedEscapes(pattern), extended, icase)
			if err != nil {
				return nil, "bad regex '" + pattern + "': " + regexError(pattern, extended)
			}
			c.re, c.repl = re, repl
		default:
			return nil, "unsupported command " + string(c.cmd)
		}
		cmds = append(cmds, c)
	}
	return cmds, ""
}

// sedEscapes: BusyBox sed turns \t and \n in a pattern into a tab and a newline before compiling it
// (grep doesn't: there \t is a "t"). "\\" stays as it is.
func sedEscapes(p string) string {
	var out strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+1 < len(p) {
			switch p[i+1] {
			case 't':
				out.WriteByte('\t')
			case 'n':
				out.WriteByte('\n')
			default:
				out.WriteString(p[i : i+2])
			}
			i++
			continue
		}
		out.WriteByte(p[i])
	}
	return out.String()
}

func (a sedAddr) matches(n int, line string, last bool) bool {
	switch a.kind {
	case 'n':
		return n == a.n
	case '$':
		return last
	case '/':
		return a.re.MatchString(line)
	}
	return true
}

// runSed runs the commands over every line of text.
func runSed(cmds []sedCmd, text string, quiet bool) string {
	var out strings.Builder
	lines := splitLines(text)
	endsInNewline := strings.HasSuffix(text, "\n")
	for n, line := range lines {
		last := n == len(lines)-1
		eol := "\n"
		if last && !endsInNewline {
			eol = ""
		}
		deleted, quit := false, false
		for k := range cmds {
			c := &cmds[k]
			selected := c.from.matches(n+1, line, last)
			if c.to.kind != 0 { // a range: from the first address to the second, inclusive
				switch {
				case c.active:
					selected = true
					if c.to.matches(n+1, line, last) || c.to.kind == 'n' && n+1 >= c.to.n {
						c.active = false
					}
				case selected:
					c.active = !(c.to.kind == 'n' && n+1 >= c.to.n) && !(c.to.kind == '$' && last)
				}
			}
			if selected == c.negate {
				continue
			}
			switch c.cmd {
			case 'p':
				out.WriteString(line + "\n")
			case '=':
				out.WriteString(strconv.Itoa(n+1) + "\n")
			case 'd':
				deleted = true
			case 'q':
				quit = true
			case 's':
				if changed, ok := sedReplace(c, line); ok {
					line = changed
					if c.print {
						out.WriteString(line + "\n")
					}
				}
			}
			if deleted || quit || out.Len() > maxSize {
				break
			}
		}
		if !deleted && !quiet {
			out.WriteString(line + eol)
		}
		if quit || out.Len() > maxSize {
			break
		}
	}
	return out.String()
}

// sedReplace does one s command on a line; ok = something was replaced.
func sedReplace(c *sedCmd, line string) (string, bool) {
	matches := c.re.FindAllStringSubmatchIndex(line, -1)
	var out strings.Builder
	done, prev := false, 0
	for k, m := range matches {
		if c.nth > 0 && k+1 < c.nth || done && !c.global {
			continue
		}
		out.WriteString(line[prev:m[0]])
		for i := 0; i < len(c.repl); i++ {
			switch ch := c.repl[i]; {
			case ch == '&':
				out.WriteString(line[m[0]:m[1]])
			case ch == '\\' && i+1 < len(c.repl):
				i++
				switch n := c.repl[i]; {
				case n >= '0' && n <= '9' && 2*int(n-'0')+1 < len(m) && m[2*int(n-'0')] >= 0:
					out.WriteString(line[m[2*int(n-'0')]:m[2*int(n-'0')+1]])
				case n == 'n':
					out.WriteByte('\n')
				case n == 't':
					out.WriteByte('\t')
				default:
					out.WriteByte(n)
				}
			default:
				out.WriteByte(ch)
			}
		}
		prev, done = m[1], true
	}
	if !done {
		return line, false
	}
	return out.String() + line[prev:], true
}
