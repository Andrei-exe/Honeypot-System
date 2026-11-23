package vfs

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The text tools of BusyBox 1.30.1 that bots pipe /proc and /etc through to size up a machine
// ("cat /proc/cpuinfo | grep name | wc -l", "free -m | grep Mem | awk '{print $2}'"): grep, wc, head,
// tail, cut, tr, sort, uniq, seq, sed (awk is in awk.go). Their output and error messages were
// measured on the real BusyBox (ash_oracle in the scratchpad, Docker busybox:1.30.1-uclibc).

// warn adds to the current applet's error output, kept apart from its output (see dispatch): a
// "wc: /x: No such file or directory" doesn't turn the counts of the other files into errors.
func (s *Shell) warn(text string) {
	s.ownErrors = true
	if len(s.errText) < maxSize {
		s.errText += text
	}
}

// source is one input of a text tool: a file, or what came through | (no file, or "-").
type source struct{ name, text string }

// sources reads a text tool's files. A missing one (or a directory) is reported with the tool's own
// message, made by msg, and skipped; ok = false then.
func (s *Shell) sources(files []string, input string, msg func(file, reason string) string) ([]source, bool) {
	if len(files) == 0 {
		return []source{{"", input}}, true
	}
	var out []source
	ok := true
	for _, f := range files {
		if f == "-" {
			out = append(out, source{f, input})
			continue
		}
		p := resolve(s.cwd, f)
		text, found := s.readFile(p)
		switch {
		case unreadable(p):
			s.warn(msg(f, "Permission denied"))
			ok = false
		case s.isDir(p):
			s.warn(msg(f, "Is a directory"))
			ok = false
		case !found:
			s.warn(msg(f, "No such file or directory"))
			ok = false
		default:
			out = append(out, source{f, text})
		}
	}
	return out, ok
}

// splitLines splits text into lines without their "\n" (a last line without one still counts).
func splitLines(text string) []string {
	lines := strings.Split(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// compileRegex compiles a grep / sed pattern the way POSIX regcomp reads it: basic (BRE: \( \) \{ \}
// are special, ( ) { } + ? | are plain) or extended (ERE). Go's regexp never backtracks, so no pattern
// can keep the CPU busy; Longest gives POSIX's leftmost-longest match.
func compileRegex(pattern string, extended, icase bool) (*regexp.Regexp, error) {
	var re strings.Builder
	if icase {
		re.WriteString("(?i)")
	}
	start := true // at the start of the pattern or a group, * is a plain *
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '[': // a bracket expression: copied, with \ made plain (it is plain in POSIX)
			j := i + 1
			re.WriteByte('[')
			if j < len(pattern) && pattern[j] == '^' {
				re.WriteByte('^')
				j++
			}
			if j < len(pattern) && pattern[j] == ']' {
				re.WriteString(`\]`)
				j++
			}
			for ; j < len(pattern) && pattern[j] != ']'; j++ {
				switch {
				case strings.HasPrefix(pattern[j:], "[:"):
					end := strings.Index(pattern[j:], ":]")
					if end < 0 {
						return nil, fmt.Errorf("brackets")
					}
					re.WriteString(pattern[j : j+end+2])
					j += end + 1
				case pattern[j] == '\\':
					re.WriteString(`\\`)
				default:
					re.WriteByte(pattern[j])
				}
			}
			if j == len(pattern) {
				return nil, fmt.Errorf("brackets")
			}
			re.WriteByte(']')
			i, start = j, false
			continue
		case c == '\\' && i+1 < len(pattern):
			i++
			n := pattern[i]
			switch {
			case !extended && strings.IndexByte("(){}|+?", n) >= 0:
				re.WriteByte(n) // \( in BRE = ( in ERE
				start = n == '(' || n == '|'
				continue
			case n >= '1' && n <= '9':
				return nil, fmt.Errorf("back references")
			case n == '<' || n == '>':
				re.WriteString(`\b`)
			case isNameChar(n) && strings.IndexByte("wWsSbB", n) < 0:
				re.WriteByte(n) // \a = a (an escaped letter means nothing special)
			default:
				re.WriteByte('\\')
				re.WriteByte(n)
			}
		case !extended && strings.IndexByte("(){}|+?", c) >= 0:
			re.WriteByte('\\')
			re.WriteByte(c)
		case c == '*' && start:
			re.WriteString(`\*`)
		default:
			re.WriteByte(c)
		}
		start = extended && (c == '(' || c == '|') || c == '^' && i == 0
	}
	compiled, err := regexp.Compile(re.String())
	if err != nil {
		return nil, err
	}
	compiled.Longest()
	return compiled, nil
}

// regexError is uClibc's regerror text for a pattern that doesn't compile.
func regexError(pattern string, extended bool) string {
	open, closeCount := strings.Count(pattern, "("), strings.Count(pattern, ")")
	if !extended {
		open, closeCount = strings.Count(pattern, `\(`), strings.Count(pattern, `\)`)
	}
	switch {
	case open != closeCount:
		return `Unmatched ( or \(`
	case strings.Count(pattern, "[") > strings.Count(pattern, "]"):
		return "Unmatched [ or [^"
	case strings.Contains(pattern, `\1`) || strings.Contains(pattern, `\2`):
		return "Invalid back reference"
	}
	return "Invalid regular expression"
}

const grepUsage = " [-HhnlLoqvsriwFE] [-m N] [-A/B/C N] PATTERN/-e PATTERN.../-f FILE [FILE]...\n\n" +
	"Search for PATTERN in FILEs (or stdin)\n\n" +
	"\t-H\tAdd 'filename:' prefix\n\t-h\tDo not add 'filename:' prefix\n\t-n\tAdd 'line_no:' prefix\n" +
	"\t-l\tShow only names of files that match\n\t-L\tShow only names of files that don't match\n" +
	"\t-c\tShow only count of matching lines\n\t-o\tShow only the matching part of line\n" +
	"\t-q\tQuiet. Return 0 if PATTERN is found, 1 otherwise\n\t-v\tSelect non-matching lines\n" +
	"\t-s\tSuppress open and read errors\n\t-r\tRecurse\n\t-i\tIgnore case\n\t-w\tMatch whole words only\n" +
	"\t-x\tMatch whole lines only\n\t-F\tPATTERN is a literal (not regexp)\n\t-E\tPATTERN is an extended regexp\n" +
	"\t-m N\tMatch up to N times per file\n\t-A N\tPrint N lines of trailing context\n" +
	"\t-B N\tPrint N lines of leading context\n\t-C N\tSame as '-A N -B N'\n\t-e PTRN\tPattern to match\n" +
	"\t-f FILE\tRead pattern from file"

// grep [-HhnlLoqvsriwxFE] [-m N] [-e PATTERN]... PATTERN [FILE]... (egrep = grep -E, fgrep = grep -F).
// Context (-A -B -C) is accepted and not shown.
func (s *Shell) grep(name string, args []string, input string) (string, int, bool) {
	opts, rest, bad := options(args, "HhnlLcoqvsirRwxFE", "emABCf")
	if bad != 0 {
		out, _, _ := usage(name, grepUsage)
		return name + ": invalid option -- " + string(bad) + "\n" + out, 2, false
	}
	patterns := opts['e']
	for _, f := range opts['f'] {
		text, ok := s.readFile(resolve(s.cwd, f))
		if !ok {
			return "grep: " + f + ": No such file or directory\n", 2, false
		}
		patterns = append(patterns, splitLines(text)...)
	}
	if opts['e'] == nil && opts['f'] == nil {
		if len(rest) == 0 {
			out, _, _ := usage(name, grepUsage)
			return out, 2, false
		}
		patterns, rest = rest[:1], rest[1:]
	}
	has := func(c byte) bool { return opts[c] != nil }
	extended := has('E') || name == "egrep"
	var res []*regexp.Regexp
	for _, p := range patterns {
		expr := p
		if has('F') || name == "fgrep" {
			expr, extended = regexp.QuoteMeta(p), true
		}
		if has('x') {
			expr = `^(` + expr + `)$`
			if !extended {
				expr = `^\(` + p + `\)$`
			}
		}
		re, err := compileRegex(expr, extended, has('i'))
		if err != nil {
			return "grep: bad regex '" + p + "': " + regexError(p, extended) + "\n", 2, false
		}
		res = append(res, re)
	}
	maxCount := -1
	if m := opts['m']; m != nil {
		maxCount, _ = strconv.Atoi(m[len(m)-1])
	}

	files := rest
	if has('r') || has('R') {
		files = s.walk(rest)
	}
	srcs, ok := s.sources(files, input, func(f, reason string) string {
		if has('s') {
			return ""
		}
		return "grep: " + f + ": " + reason + "\n"
	})
	prefix := (len(files) > 1 || has('H')) && !has('h')
	var out strings.Builder
	matchedAny := false
	for _, src := range srcs {
		name := src.name
		if name == "" || name == "-" {
			name = "(standard input)"
		}
		count := 0
		for n, line := range splitLines(src.text) {
			var found [][]int
			for _, re := range res {
				found = append(found, re.FindAllStringIndex(line, -1)...)
			}
			if has('w') {
				found = wholeWords(line, found)
			}
			if (len(found) > 0) == has('v') {
				continue
			}
			if count++; has('q') {
				return "", 0, false
			}
			if !has('c') && !has('l') && !has('L') {
				lead := ""
				if prefix {
					lead = name + ":"
				}
				if has('n') {
					lead += strconv.Itoa(n+1) + ":"
				}
				if has('o') && !has('v') {
					sort.Slice(found, func(i, j int) bool { return found[i][0] < found[j][0] })
					for _, m := range found {
						if m[1] > m[0] {
							out.WriteString(lead + line[m[0]:m[1]] + "\n")
						}
					}
				} else {
					out.WriteString(lead + line + "\n")
				}
			}
			if count == maxCount || out.Len() > maxSize {
				break
			}
		}
		matchedAny = matchedAny || count > 0
		switch {
		case has('l') && count > 0, has('L') && count == 0:
			out.WriteString(name + "\n")
		case has('c'):
			if prefix {
				out.WriteString(name + ":")
			}
			out.WriteString(strconv.Itoa(count) + "\n")
		}
	}
	switch {
	case matchedAny:
		return out.String(), 0, false
	case !ok:
		return out.String(), 2, false
	}
	return out.String(), 1, false
}

// wholeWords keeps the matches not glued to a letter, digit or _ (grep -w).
func wholeWords(line string, found [][]int) [][]int {
	var keep [][]int
	for _, m := range found {
		if (m[0] == 0 || !isNameChar(line[m[0]-1])) && (m[1] == len(line) || !isNameChar(line[m[1]])) {
			keep = append(keep, m)
		}
	}
	return keep
}

// walk lists the files under the given paths, sorted (grep -r).
func (s *Shell) walk(paths []string) []string {
	var files []string
	for _, p := range paths {
		full := resolve(s.cwd, p)
		if !s.isDir(full) {
			files = append(files, p)
			continue
		}
		var sub []string
		for _, name := range s.list(full) {
			sub = append(sub, strings.TrimSuffix(p, "/")+"/"+name)
		}
		if len(files) < 1000 {
			files = append(files, s.walk(sub)...)
		}
	}
	return files
}

// wc [-lwcmL] [FILE]...: lines, words, bytes (and the longest line) in BusyBox's columns: one number
// alone without padding, else each in 9 columns; a "total" line for several files.
func (s *Shell) wc(args []string, input string) (string, int, bool) {
	opts, files, bad := options(args, "lwcmL", "")
	if bad != 0 {
		out, _, _ := usage("wc", " [-cmlwL] [FILE]...\n\nCount lines, words, and bytes for each FILE (or stdin)\n\n"+
			"\t-c\tCount bytes\n\t-m\tCount characters\n\t-l\tCount newlines\n\t-w\tCount words\n\t-L\tPrint longest line length")
		return "wc: invalid option -- " + string(bad) + "\n" + out, 1, false
	}
	columns := ""
	for _, c := range "lwcmL" {
		if opts[byte(c)] != nil {
			columns += string(c)
		}
	}
	if columns == "" {
		columns = "lwc"
	}
	type counts map[rune]int
	count := func(text string) counts {
		longest := 0
		for _, l := range splitLines(text) {
			longest = max(longest, len(l))
		}
		return counts{'l': strings.Count(text, "\n"), 'w': len(strings.Fields(text)), 'c': len(text), 'm': len(text), 'L': longest}
	}
	padded := len(columns) > 1 || len(files) > 1
	line := func(c counts, name string) string {
		var out strings.Builder
		for i, col := range columns {
			switch {
			case !padded:
				fmt.Fprintf(&out, "%d", c[col])
			case i == 0:
				fmt.Fprintf(&out, "%9d", c[col])
			default:
				fmt.Fprintf(&out, " %9d", c[col])
			}
		}
		if name != "" {
			out.WriteString(" " + name)
		}
		return out.String() + "\n"
	}
	var out strings.Builder
	total := counts{}
	code := 0
	if len(files) == 0 {
		files = []string{""}
	}
	for _, f := range files {
		text := input
		if f != "" && f != "-" {
			p := resolve(s.cwd, f)
			var found bool
			text, found = s.readFile(p)
			switch {
			case unreadable(p):
				s.warn("wc: " + f + ": Permission denied\n")
				code = 1
				continue
			case s.isDir(p): // BusyBox still prints its (zero) counts
				s.warn("wc: " + f + ": Is a directory\n")
				code = 1
			case !found:
				s.warn("wc: " + f + ": No such file or directory\n")
				code = 1
				continue
			}
		}
		c := count(text)
		for k, v := range c {
			if k == 'L' {
				total[k] = max(total[k], v)
			} else {
				total[k] += v
			}
		}
		out.WriteString(line(c, f))
	}
	if len(files) > 1 {
		out.WriteString(line(total, "total"))
	}
	return out.String(), code, false
}

// headTail is head and tail: -n N (head: -N = all but the last N; tail: +N = from line N), -c N,
// the old -N form, and the "==> FILE <==" headers for several files.
func (s *Shell) headTail(name string, args []string, input string) (string, int, bool) {
	for i, a := range args { // "head -3" = "head -n 3" (but not the value in "head -n -3")
		if len(a) > 1 && a[0] == '-' && strings.Trim(a[1:], "0123456789") == "" && (i == 0 || args[i-1] != "-n" && args[i-1] != "-c") {
			args[i] = "-n" + a[1:]
		}
	}
	opts, files, bad := options(args, "qvf", "nc")
	if bad != 0 {
		out, _, _ := usage(name, " [OPTIONS] [FILE]...")
		return name + ": invalid option -- " + string(bad) + "\n" + out, 1, false
	}
	lines, bytes := 10, -1
	plus := false // tail -n +N
	for _, o := range []byte{'n', 'c'} {
		if v := opts[o]; v != nil {
			text := v[len(v)-1]
			plus = strings.HasPrefix(text, "+")
			n, err := strconv.Atoi(strings.TrimPrefix(text, "+"))
			if err != nil {
				return name + ": invalid number '" + text + "'\n", 1, false
			}
			if o == 'n' {
				lines = n
			} else {
				bytes = n
			}
		}
	}
	srcs, ok := s.sources(files, input, func(f, reason string) string {
		if name == "tail" {
			return "tail: can't open '" + f + "': " + reason + "\n"
		}
		return name + ": " + f + ": " + reason + "\n"
	})
	if name == "tail" && len(srcs) == 0 {
		s.warn("tail: no files\n")
	}
	var out strings.Builder
	for i, src := range srcs {
		if (len(files) > 1 || opts['v'] != nil) && opts['q'] == nil {
			if i > 0 {
				out.WriteString("\n")
			}
			out.WriteString("==> " + src.name + " <==\n")
		}
		out.WriteString(cut(src.text, name == "head", plus, lines, bytes))
	}
	code := 0
	if !ok {
		code = 1
	}
	return out.String(), code, false
}

// cut takes the part head / tail shows of one text.
func cut(text string, head, plus bool, lines, bytes int) string {
	if bytes >= 0 { // -c N
		n := min(bytes, len(text))
		switch {
		case head:
			return text[:n]
		case plus:
			return text[min(max(bytes-1, 0), len(text)):]
		}
		return text[len(text)-n:]
	}
	all := strings.SplitAfter(text, "\n")
	if all[len(all)-1] == "" {
		all = all[:len(all)-1]
	}
	switch {
	case head && lines < 0: // all but the last -lines
		return strings.Join(all[:max(len(all)+lines, 0)], "")
	case head:
		return strings.Join(all[:min(lines, len(all))], "")
	case plus:
		return strings.Join(all[min(max(lines-1, 0), len(all)):], "")
	}
	return strings.Join(all[len(all)-min(max(lines, 0), len(all)):], "")
}

// cutApplet: cut -d D -f LIST, -c LIST, -b LIST (LIST = 1,3-5,7-,-2), -s.
func (s *Shell) cutApplet(args []string, input string) (string, int, bool) {
	opts, files, bad := options(args, "sn", "dfcb")
	list := opts['f']
	if list == nil {
		list = append(opts['c'], opts['b']...)
	}
	if bad != 0 || list == nil {
		return "cut: expected a list of bytes, characters, or fields\n", 1, false
	}
	var ranges [][2]int
	for _, part := range strings.Split(list[len(list)-1], ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		from, err1 := strconv.Atoi(lo)
		to, err2 := strconv.Atoi(hi)
		switch {
		case !isRange && err1 == nil:
			to = from
		case isRange && lo == "" && err2 == nil:
			from = 1
		case isRange && hi == "" && err1 == nil:
			to = 1 << 30
		case isRange && err1 == nil && err2 == nil:
		default:
			return "cut: invalid byte or field list\n", 1, false
		}
		if from < 1 {
			return "cut: fields and positions are numbered from 1\n", 1, false
		}
		ranges = append(ranges, [2]int{from, to})
	}
	wanted := func(i int) bool {
		for _, r := range ranges {
			if i >= r[0] && i <= r[1] {
				return true
			}
		}
		return false
	}
	delim := "\t"
	if d := opts['d']; d != nil && d[len(d)-1] != "" {
		delim = d[len(d)-1][:1]
	}
	srcs, ok := s.sources(files, input, func(f, reason string) string { return "cut: " + f + ": " + reason + "\n" })
	var out strings.Builder
	for _, src := range srcs {
		for _, line := range splitLines(src.text) {
			var kept []string
			if opts['f'] == nil { // characters / bytes
				var b strings.Builder
				for i := 0; i < len(line); i++ {
					if wanted(i + 1) {
						b.WriteByte(line[i])
					}
				}
				out.WriteString(b.String() + "\n")
				continue
			}
			if !strings.Contains(line, delim) {
				if opts['s'] == nil {
					out.WriteString(line + "\n")
				}
				continue
			}
			for i, f := range strings.Split(line, delim) {
				if wanted(i + 1) {
					kept = append(kept, f)
				}
			}
			out.WriteString(strings.Join(kept, delim) + "\n")
		}
	}
	code := 0
	if !ok {
		code = 1
	}
	return out.String(), code, false
}

// trSet expands a tr set: a-z ranges, [:lower:] classes, \n \t \\ \NNN escapes.
func trSet(set string) []byte {
	classes := map[string]string{
		"[:lower:]": "abcdefghijklmnopqrstuvwxyz", "[:upper:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"[:digit:]": "0123456789", "[:space:]": " \t\n\r\f\v", "[:blank:]": " \t",
		"[:alpha:]": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		"[:alnum:]": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		"[:punct:]": "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", "[:xdigit:]": "0123456789ABCDEFabcdef",
	}
	set = cEscapes(set)
	var out []byte
	for i := 0; i < len(set); i++ {
		if strings.HasPrefix(set[i:], "[:") {
			if end := strings.Index(set[i:], ":]"); end > 0 {
				if chars, ok := classes[set[i:i+end+2]]; ok {
					out = append(out, chars...)
					i += end + 1
					continue
				}
			}
		}
		if i+2 < len(set) && set[i+1] == '-' {
			for c := int(set[i]); c <= int(set[i+2]); c++ {
				out = append(out, byte(c))
			}
			i += 2
			continue
		}
		out = append(out, set[i])
	}
	return out
}

// tr [-cds] SET1 [SET2]: translate, delete (-d) or squeeze (-s) characters of its input.
func (s *Shell) tr(args []string, input string) (string, int, bool) {
	opts, sets, bad := options(args, "cdsC", "")
	if bad != 0 || len(sets) == 0 {
		out, _, _ := usage("tr", " [-cds] STRING1 [STRING2]\n\nTranslate, squeeze, or delete characters from stdin, writing to stdout\n\n"+
			"\t-c\tTake complement of STRING1\n\t-d\tDelete input characters coded STRING1\n"+
			"\t-s\tSqueeze multiple output characters of STRING2 into one character")
		return out, 1, false
	}
	set1 := trSet(sets[0])
	var set2 []byte
	if len(sets) > 1 {
		set2 = trSet(sets[1])
	}
	var table [256]int // the byte each byte becomes
	var inSet1 [256]bool
	for _, c := range set1 {
		inSet1[c] = true
	}
	if opts['c'] != nil || opts['C'] != nil { // -c: every byte NOT in SET1 (tr -cd 0-9 keeps the digits)
		for i := range inSet1 {
			inSet1[i] = !inSet1[i]
		}
	}
	for i := range table {
		table[i] = i
	}
	for i, c := range set1 {
		switch {
		case opts['d'] != nil:
		case len(set2) > 0:
			table[c] = int(set2[min(i, len(set2)-1)])
		}
	}
	squeeze := [256]bool{}
	if opts['s'] != nil {
		last := set2
		if len(last) == 0 || opts['d'] != nil {
			last = set1
		}
		for _, c := range last {
			squeeze[c] = true
		}
	}
	var out strings.Builder
	prev := -1
	for i := 0; i < len(input); i++ {
		c := input[i]
		if opts['d'] != nil && inSet1[c] {
			continue
		}
		b := byte(table[c])
		if squeeze[b] && int(b) == prev {
			continue
		}
		out.WriteByte(b)
		prev = int(b)
	}
	return out.String(), 0, false
}

// sortApplet: sort [-nrufb] [-k N] [-t C] [FILE]...
func (s *Shell) sortApplet(args []string, input string) (string, int, bool) {
	opts, files, _ := options(args, "nrufbsdgcz", "kto")
	srcs, ok := s.sources(files, input, func(f, reason string) string { return "sort: " + f + ": " + reason + "\n" })
	if !ok {
		return "", 2, false
	}
	var lines []string
	for _, src := range srcs {
		lines = append(lines, splitLines(src.text)...)
	}
	field := 0
	if k := opts['k']; k != nil {
		field, _ = strconv.Atoi(strings.SplitN(k[len(k)-1], ",", 2)[0])
	}
	key := func(line string) string {
		if field < 1 {
			return line
		}
		var parts []string
		if t := opts['t']; t != nil && t[len(t)-1] != "" {
			parts = strings.Split(line, t[len(t)-1][:1])
		} else {
			parts = strings.Fields(line)
		}
		if field > len(parts) {
			return ""
		}
		return parts[field-1]
	}
	number := func(line string) float64 {
		k := strings.TrimSpace(key(line))
		end := 0
		for end < len(k) && (k[end] >= '0' && k[end] <= '9' || k[end] == '.' || end == 0 && k[end] == '-') {
			end++
		}
		v, _ := strconv.ParseFloat(k[:end], 64)
		return v
	}
	less := func(a, b string) bool {
		if opts['n'] != nil || opts['g'] != nil {
			if na, nb := number(a), number(b); na != nb {
				return na < nb
			}
		}
		ka, kb := key(a), key(b)
		if opts['f'] != nil {
			ka, kb = strings.ToUpper(ka), strings.ToUpper(kb)
		}
		if ka != kb {
			return ka < kb
		}
		return a < b
	}
	sort.SliceStable(lines, func(i, j int) bool {
		if opts['r'] != nil {
			return less(lines[j], lines[i])
		}
		return less(lines[i], lines[j])
	})
	var out strings.Builder
	for i, l := range lines {
		if opts['u'] != nil && i > 0 && key(l) == key(lines[i-1]) {
			continue
		}
		out.WriteString(l + "\n")
	}
	return out.String(), 0, false
}

// uniq [-cdu] [FILE]: adjacent equal lines once (-c: with "%7d " before, -d: only repeated, -u: only single).
func (s *Shell) uniq(args []string, input string) (string, int, bool) {
	opts, files, _ := options(args, "cdui", "fs")
	if len(files) > 0 && files[0] != "-" {
		text, ok := s.readFile(resolve(s.cwd, files[0]))
		if !ok {
			return "uniq: can't open '" + files[0] + "': No such file or directory\n", 1, false
		}
		input = text
	}
	var out strings.Builder
	lines := splitLines(input)
	for i := 0; i < len(lines); {
		j := i + 1
		for j < len(lines) && (lines[j] == lines[i] || opts['i'] != nil && strings.EqualFold(lines[j], lines[i])) {
			j++
		}
		n := j - i
		if (opts['d'] == nil || n > 1) && (opts['u'] == nil || n == 1) {
			if opts['c'] != nil {
				fmt.Fprintf(&out, "%7d ", n)
			}
			out.WriteString(lines[i] + "\n")
		}
		i = j
	}
	return out.String(), 0, false
}

// seq [-w] [-s SEP] [FIRST [INC]] LAST (whole numbers; the output stops at maxSize).
func seq(args []string) (string, int, bool) {
	opts, nums, _ := options(args, "w", "s")
	if len(nums) == 0 || len(nums) > 3 {
		return usage("seq", " [-w] [-s SEP] [FIRST [INC]] LAST\n\nPrint numbers from FIRST to LAST, in steps of INC.\n"+
			"FIRST, INC default to 1.\n\n\t-w\tPad to last with leading zeros\n\t-s SEP\tString separator")
	}
	v := []int64{1, 1, 0}
	pos := map[int][]int{1: {2}, 2: {0, 2}, 3: {0, 1, 2}}[len(nums)]
	for i, n := range nums {
		x, err := strconv.ParseInt(n, 10, 64)
		if err != nil {
			return "seq: invalid number '" + n + "'\n", 1, false
		}
		v[pos[i]] = x
	}
	first, inc, last := v[0], v[1], v[2]
	sep := "\n"
	if s := opts['s']; s != nil {
		sep = s[len(s)-1]
	}
	width := 0
	if opts['w'] != nil {
		width = max(len(strconv.FormatInt(first, 10)), len(strconv.FormatInt(last, 10)))
	}
	var out strings.Builder
	for x, n := first, 0; inc != 0 && (inc > 0 && x <= last || inc < 0 && x >= last) && out.Len() < maxSize; x, n = x+inc, n+1 {
		if n > 0 {
			out.WriteString(sep)
		}
		fmt.Fprintf(&out, "%0*d", width, x)
	}
	if out.Len() > 0 {
		out.WriteString("\n")
	}
	return out.String(), 0, false
}
