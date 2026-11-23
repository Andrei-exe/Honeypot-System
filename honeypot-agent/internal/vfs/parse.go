package vfs

import (
	"slices"
	"strconv"
	"strings"
)

// The parser: shell code becomes a tree of commands, the way ash builds it (BusyBox 1.30.1 ash.c:
// list, andor, pipeline, parse_command, simplecmd, readtoken, xxreadtoken, readtoken1). It is a port
// of that code, function for function, so its syntax errors are ash's own: which token came, and
// which one was expected instead. Words stay as typed (quotes, $X, $(...) still in them): expand.go
// takes them apart when the command runs.

// The kinds of node (ash's NCMD, NPIPE...).
const (
	nCmd      = iota // a simple command: words and redirections
	nList            // commands one after another (; & newline)
	nAndOr           // list[0] && list[1] || list[2]...: ops[i] (tAnd or tOr) is between list[i] and list[i+1]
	nNot             // ! body
	nPipe            // list[0] | list[1] | ...
	nSubshell        // ( body )
	nBrace           // { body; }
	nIf              // if test; then body; else orElse; fi (an elif is another nIf, in orElse)
	nWhile           // while test; do body; done
	nUntil           // until test; do body; done
	nFor             // for name in words; do body; done
	nCase            // case words[0] in cases esac
	nFunc            // name() body: defines a function
)

// node is one command of the tree, like ash's union node: only the fields of its kind are used.
type node struct {
	kind   int
	line   int      // the line it starts on: $LINENO and "line N:" while it runs
	words  []string // nCmd: its words (NAME=value ones first); nFor: those after "in"; nCase: its word
	redirs []redir  // nCmd and the compound commands, in the order written
	name   string   // nFor: the loop's variable; nFunc: the function's name

	test, body, orElse *node   // nIf, nWhile, nUntil; body also for nNot, nSubshell, nBrace, nFor, nFunc
	list               []*node // nList, nAndOr, nPipe
	ops                []int   // nAndOr
	cases              []caseItem
}

// maxNesting is how deep compound commands ("{ { { ...", "if ...; then if") and function calls may be
// one inside the other, when read and when run. A real ash does both recursively and crashes when its
// stack runs out (exit code 139: 100000 nested { } do it); ours "crashes" here (see crash).
const maxNesting = 200

// caseItem is one "pattern|pattern) commands ;;" of a case.
type caseItem struct {
	patterns []string // as typed
	body     *node    // nil: none ("x) ;;")
}

// eofNode is what the parser gives at the end of the code (ash's NODE_EOF).
var eofNode = &node{}

// The tokens (ash's TEOF, TNL...), in the order of tokname_array: from tSemi on they are written in
// quotes in the errors (unexpected "fi"), the first four not (unexpected end of file, ... word).
const (
	tEOF = iota
	tNL
	tRedir
	tWord
	tSemi
	tBackgnd
	tAnd
	tOr
	tPipe
	tLP
	tRP
	tEndCase
	tNot // the keywords, from here on
	tCase
	tDo
	tDone
	tElif
	tElse
	tEsac
	tFi
	tFor
	tFunction
	tIf
	tIn
	tThen
	tUntil
	tWhile
	tBegin
	tEnd
)

var tokenNames = []string{"end of file", "newline", "redirection", "word", ";", "&", "&&", "||", "|", "(", ")",
	";;", "!", "case", "do", "done", "elif", "else", "esac", "fi", "for", "function", "if", "in", "then",
	"until", "while", "{", "}"}

// tokenName is a token the way an error names it (ash's tokname).
func tokenName(t int) string {
	if t < tSemi {
		return tokenNames[t]
	}
	return `"` + tokenNames[t] + `"`
}

// endsList: the tokens that end the commands of a case item (ash's tokendlist).
func endsList(t int) bool {
	switch t {
	case tEOF, tRP, tEndCase, tDo, tDone, tElif, tElse, tEsac, tFi, tThen, tEnd:
		return true
	}
	return false
}

// What the next read token may be (ash's checkkwd).
const (
	chkNL  = 1 // newlines are skipped
	chkKwd = 2 // a word can be a keyword: only at the start of a command ("echo if" is just text)
)

// parser reads code token by token. Like ash, it stops at the first syntax error (fail panics,
// next recovers: ash longjmps back to its main loop the same way).
type parser struct {
	src  string
	pos  int
	line int // the line being read (ash's g_parsefile->linno)
	tok  int // the last token read (lasttoken)
	// its text if it is a word, as typed (wordtext). Its quotes and backslashes are still in it, so a
	// quoted word ("if", \for, "2">x) never equals a keyword, a name or a number: ash needs a flag
	// for that (quoteflag), we don't
	word     string
	redir    redir // the redirection just read, without its target yet
	pushback bool  // read the last token again (tokpushback)
	checkkwd int
	depth    int  // compound commands being read, one inside the other
	crashed  bool // nested deeper than maxNesting: the shell "crashed"
	// the code ended before the command did ("for i in 1 2", an open quote, "\" at the end of the
	// last line): a shell reading its input line by line would read the next line (with PS2) instead
	incomplete bool
}

type syntaxError string

func newParser(code string, line int) *parser {
	return &parser{src: code, line: line}
}

// next parses the next complete command (ash's parsecmd): up to a newline that isn't inside an if,
// a loop, quotes... done = nothing left, or a syntax error (err, ash's message), or p.crashed.
func (p *parser) next() (n *node, done bool, err string) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(syntaxError)
			if !ok {
				panic(r)
			}
			n, done, err = nil, true, string(e)
			if p.tok == tEOF { // "unexpected end of file": what was missing may come on the next line
				p.incomplete = true
			}
		}
	}()
	p.pushback, p.checkkwd, p.depth, p.incomplete = false, 0, 0, false
	n = p.list(1)
	return n, n == eofNode, ""
}

func (p *parser) fail(msg string) {
	panic(syntaxError(msg))
}

// unexpected: "unexpected X" (the last token), plus "(expecting Y)" if a token is given (>= 0).
func (p *parser) unexpected(expecting int) {
	msg := "unexpected " + tokenName(p.tok)
	if expecting >= 0 {
		msg += " (expecting " + tokenName(expecting) + ")"
	}
	p.fail(msg)
}

// list reads commands joined by ; & and newlines. nlflag 1: a newline ends it (the top level);
// 2: it may be empty (a case item); 0: it goes on to the keyword that ends it (then, do, fi...).
func (p *parser) list(nlflag int) *node {
	var n *node
	for {
		switch p.peek() {
		case tNL:
			if nlflag&1 != 0 {
				return n
			}
		case tEOF:
			if n == nil && nlflag&1 != 0 {
				return eofNode
			}
			return n
		}
		p.checkkwd = chkNL | chkKwd
		if nlflag == 2 && endsList(p.peek()) {
			return n
		}
		nlflag |= 2
		c := p.andOr()
		t := p.read()
		if n == nil {
			n = &node{kind: nList}
		}
		n.list = append(n.list, c) // "&" would run it in the background: here it runs like ";"
		switch t {
		case tNL, tEOF:
			p.pushback = true
		case tBackgnd, tSemi:
		default:
			if nlflag&1 != 0 {
				p.unexpected(-1)
			}
			p.pushback = true
			return n
		}
	}
}

// andOr reads pipelines joined by && and || (ash makes a tree of them; a list runs the same).
func (p *parser) andOr() *node {
	n := p.pipeline()
	if t := p.read(); t != tAnd && t != tOr {
		p.pushback = true
		return n
	}
	chain := &node{kind: nAndOr, list: []*node{n}}
	for t := p.tok; t == tAnd || t == tOr; t = p.read() {
		p.checkkwd = chkNL | chkKwd
		chain.ops = append(chain.ops, t)
		chain.list = append(chain.list, p.pipeline())
	}
	p.pushback = true
	return chain
}

// pipeline reads [!] command | command...
func (p *parser) pipeline() *node {
	negate := false
	if p.read() == tNot {
		negate = true
		p.checkkwd = chkKwd
	} else {
		p.pushback = true
	}
	n := p.command()
	if p.read() == tPipe {
		pipe := &node{kind: nPipe, list: []*node{n}}
		for {
			p.checkkwd = chkNL | chkKwd
			pipe.list = append(pipe.list, p.command())
			if p.read() != tPipe {
				break
			}
		}
		n = pipe
	}
	p.pushback = true
	if negate {
		n = &node{kind: nNot, body: n}
	}
	return n
}

// command reads one command: a compound one (if, while, until, for, case, ( ), { }) with the
// redirections after it, or a simple one (ash's parse_command).
func (p *parser) command() *node {
	if p.depth++; p.depth > maxNesting {
		p.crashed = true
		p.fail("")
	}
	defer func() { p.depth-- }()
	line := p.line
	n := &node{line: line}
	end := tEOF // the keyword that must close it
	switch p.read() {
	default:
		p.unexpected(-1)
	case tIf:
		n.kind = nIf
		n.test = p.list(0)
		if p.read() != tThen {
			p.unexpected(tThen)
		}
		n.body = p.list(0)
		last := n
		for p.read() == tElif {
			elif := &node{kind: nIf, line: p.line}
			last.orElse, last = elif, elif
			elif.test = p.list(0)
			if p.read() != tThen {
				p.unexpected(tThen)
			}
			elif.body = p.list(0)
		}
		if p.tok == tElse {
			last.orElse = p.list(0)
		} else {
			p.pushback = true
		}
		end = tFi
	case tWhile, tUntil:
		n.kind = nWhile
		if p.tok == tUntil {
			n.kind = nUntil
		}
		n.test = p.list(0)
		if p.read() != tDo {
			p.unexpected(tDo)
		}
		n.body = p.list(0)
		end = tDone
	case tFor:
		if p.read() != tWord || !validName(p.word) {
			p.fail("bad for loop variable")
		}
		n.kind, n.name = nFor, p.word
		p.checkkwd = chkNL | chkKwd
		if p.read() == tIn {
			n.words = []string{}
			for p.read() == tWord {
				n.words = append(n.words, p.word)
			}
			if p.tok != tNL && p.tok != tSemi {
				p.unexpected(-1)
			}
		} else {
			n.words = []string{`"$@"`} // "for i; do" goes through the parameters
			if p.tok != tSemi {
				p.pushback = true
			}
		}
		p.checkkwd = chkNL | chkKwd
		if p.read() != tDo {
			p.unexpected(tDo)
		}
		n.body = p.list(0)
		end = tDone
	case tCase:
		n.kind = nCase
		if p.read() != tWord {
			p.unexpected(tWord)
		}
		n.words = []string{p.word}
		p.checkkwd = chkNL | chkKwd
		if p.read() != tIn {
			p.unexpected(tIn)
		}
		p.checkkwd = chkNL | chkKwd
		for t := p.read(); t != tEsac; {
			if p.tok == tLP { // "(x)": the "(" is optional
				p.read()
			}
			var item caseItem
			for {
				item.patterns = append(item.patterns, p.word) // (like ash, whatever the token was)
				if p.read() != tPipe {
					break
				}
				p.read()
			}
			if p.tok != tRP {
				p.unexpected(tRP)
			}
			item.body = p.list(2)
			n.cases = append(n.cases, item)
			p.checkkwd = chkNL | chkKwd
			if t = p.read(); t != tEsac {
				if t != tEndCase {
					p.unexpected(tEndCase)
				}
				p.checkkwd = chkNL | chkKwd
				t = p.read()
			}
		}
		return p.redirections(n)
	case tLP:
		n.kind = nSubshell
		n.body = p.list(0)
		end = tRP
	case tBegin:
		n.kind = nBrace
		n.body = p.list(0)
		end = tEnd
	case tFunction, tWord, tRedir:
		p.pushback = true
		return p.simpleCommand()
	}
	if p.read() != end {
		p.unexpected(end)
	}
	return p.redirections(n)
}

// redirections reads the ones written after a compound command: "done > f", "} 2>&1".
func (p *parser) redirections(n *node) *node {
	p.checkkwd = chkKwd
	for p.read() == tRedir {
		n.redirs = append(n.redirs, p.target())
	}
	p.pushback = true
	return n
}

// target reads the word after a redirection (ash's parsefname); keywords are just words there.
func (p *parser) target() redir {
	r := p.redir
	if p.read() != tWord {
		p.unexpected(-1)
	}
	r.target = p.word
	return r
}

// simpleCommand reads the words and redirections of a simple command (ash's simplecmd), or a function
// definition: "NAME() COMMAND", "function NAME COMMAND".
func (p *parser) simpleCommand() *node {
	n := &node{kind: nCmd, line: p.line}
	var assigns, args []string
	isFunction := false // after "function": the name comes, then the body
	brackets := false   // inside [[ ... ]]: && and || are its -a and -o (bash's, on in Buildroot's ash)
	for {
		switch t := p.read(); t {
		case tFunction:
			if p.peek() != tWord {
				p.unexpected(tWord)
			}
			isFunction = true
			continue
		case tAnd, tOr:
			if !brackets {
				p.pushback = true
				n.words = append(assigns, args...)
				return n
			}
			p.word = map[int]string{tAnd: "-a", tOr: "-o"}[t]
			fallthrough
		case tWord:
			switch p.word {
			case "[[":
				brackets = true
			case "]]":
				brackets = false
			}
			if len(args) == 0 && isAssignment(p.word) {
				assigns = append(assigns, p.word)
			} else {
				args = append(args, p.word)
			}
			if isFunction {
				p.checkkwd = chkNL | chkKwd
				switch p.peek() {
				case tBegin, tIf, tCase, tUntil, tWhile, tFor:
					if f := p.function(args, assigns, n.redirs, false); f != nil {
						return f
					}
					n.words = append(assigns, args...)
					return n
				case tLP:
					isFunction = false
				default:
					p.unexpected(-1)
				}
			}
		case tRedir:
			n.redirs = append(n.redirs, p.target())
		case tLP:
			if f := p.function(args, assigns, n.redirs, !isFunction); f != nil {
				return f
			}
			fallthrough
		default:
			p.pushback = true
			n.words = append(assigns, args...)
			return n
		}
	}
}

// function reads a function's body if the words so far are just its name ("f(" or "function f"):
// nil if not (then the "(" is unexpected). parens: the "()" are still to be read.
func (p *parser) function(args, assigns []string, redirs []redir, parens bool) *node {
	if len(args) != 1 || len(assigns) > 0 || len(redirs) > 0 {
		return nil
	}
	if parens && p.read() != tRP {
		p.unexpected(tRP)
	}
	name := args[0]
	if !validName(name) || slices.Contains(specialBuiltins, name) {
		p.fail("bad function name")
	}
	p.checkkwd = chkNL | chkKwd
	f := &node{kind: nFunc, name: name, line: p.line}
	f.body = p.command()
	return f
}

// peek reads the next token and leaves it to be read again.
func (p *parser) peek() int {
	t := p.read()
	p.pushback = true
	return t
}

// read returns the next token: skips newlines and knows keywords if checkkwd says so (ash's readtoken).
func (p *parser) read() int {
	kwd := p.checkkwd
	t := p.lex()
	if kwd&chkNL != 0 {
		for t == tNL {
			t = p.lex()
		}
	}
	if t == tWord && kwd&chkKwd != 0 {
		if k := slices.Index(tokenNames[tNot:], p.word); k >= 0 {
			t = tNot + k
			p.tok = t
		}
	}
	p.checkkwd = 0
	return t
}

// lex reads the next token from the code (ash's xxreadtoken): an operator, a newline, the end, or a
// word / redirection (lexWord). Spaces, tabs and \r (a CRLF line) separate; # starts a comment.
func (p *parser) lex() int {
	if p.pushback {
		p.pushback = false
		return p.tok
	}
	for {
		if p.pos >= len(p.src) {
			p.tok = tEOF
			return p.tok
		}
		c := p.src[p.pos]
		next := byte(0)
		if p.pos+1 < len(p.src) {
			next = p.src[p.pos+1]
		}
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			p.pos++
			continue
		case c == '\\' && next == '\n': // the line goes on
			p.pos += 2
			p.line++
			p.incomplete = p.incomplete || p.pos == len(p.src)
			continue
		case c == '#':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
			continue
		case c == '\n':
			p.pos++
			p.line++
			p.tok = tNL
		case c == '(':
			p.pos++
			p.tok = tLP
		case c == ')':
			p.pos++
			p.tok = tRP
		case c == '&' && next == '>': // "&>file" (bash's, on in Buildroot's ash): a redirection
			return p.lexWord()
		case c == '&' || c == '|' || c == ';':
			p.pos++
			single, double := map[byte]int{'&': tBackgnd, '|': tPipe, ';': tSemi}[c], map[byte]int{'&': tAnd, '|': tOr, ';': tEndCase}[c]
			p.tok = single
			if next == c {
				p.pos++
				p.tok = double
			}
		default:
			return p.lexWord()
		}
		return p.tok
	}
}

// lexWord reads a word, kept as typed (ash's readtoken1): it ends at a space, a newline or one of
// ; & | < > ( ) outside quotes. A word of only digits (or none) right before > or < is a redirection:
// "2>file", ">>file".
func (p *parser) lexWord() int {
	var w strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if strings.IndexByte(" \t\r\n;&|<>()", c) >= 0 {
			break
		}
		if c == '\\' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '\n' { // the line goes on
			p.pos += 2
			p.line++
			p.incomplete = p.incomplete || p.pos == len(p.src)
			continue
		}
		if c == '\\' || c == '\'' || c == '"' || c == '`' || c == '$' && p.pos+1 < len(p.src) && strings.IndexByte("({'", p.src[p.pos+1]) >= 0 {
			end, err := partEnd(p.src, p.pos) // kept whole: quotes, $(...), ${...}, `...`
			part := p.src[p.pos:end]
			p.line += strings.Count(part, "\n")
			p.pos = end
			if err != "" { // (only at the end of the code: an open quote, $(, ${, `)
				p.incomplete = true
				p.fail(err)
			}
			w.WriteString(part)
			continue
		}
		w.WriteByte(c)
		p.pos++
	}
	c, next := byte(0), byte(0)
	if p.pos < len(p.src) {
		c = p.src[p.pos]
	}
	if p.pos+1 < len(p.src) {
		next = p.src[p.pos+1]
	}
	if (c == '<' || c == '>' || c == '&' && next == '>') && (w.Len() == 0 || isFDNumber(w.String())) {
		return p.lexRedir(w.String())
	}
	p.word, p.tok = w.String(), tWord
	return p.tok
}

// lexRedir reads a redirection's operator (ash's parseredir); fd = the digits before it, if any.
func (p *parser) lexRedir(fd string) int {
	c, next := p.src[p.pos], byte(0)
	if p.pos+1 < len(p.src) {
		next = p.src[p.pos+1]
	}
	r := redir{fd: 1, op: string(c)}
	p.pos++
	switch {
	case c == '&': // &>
		r.op = "&>"
		p.pos++
	case c == '>' && (next == '>' || next == '&' || next == '|'):
		r.op += string(next)
		p.pos++
	case c == '<' && (next == '<' || next == '&' || next == '>'):
		r.op += string(next)
		p.pos++
		if r.op == "<<" && p.pos < len(p.src) && p.src[p.pos] == '-' { // <<- (tabs stripped): same for us
			p.pos++
		}
	}
	if c == '<' {
		r.fd = 0
	}
	if r.op == ">|" {
		r.op = ">" // ">|" overwrites even with noclobber, which we never have
	}
	if fd != "" {
		r.fd, _ = strconv.Atoi(fd)
	}
	p.redir, p.tok = r, tRedir
	return p.tok
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
