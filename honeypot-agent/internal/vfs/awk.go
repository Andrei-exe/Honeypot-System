package vfs

import (
	"regexp"
	"strconv"
	"strings"
)

// awk: the part of the language bots use to cut numbers out of /proc and free ("awk '{print $2}'",
// "awk -F: '{print $1}'", "awk 'NR==2 {print $4;}'", "awk 'END{print NR}'"): patterns (BEGIN, END,
// expressions, /regex/), print / printf (also > FILE), next, exit, assignments ($2 = "x", n++),
// fields, NR NF FNR FS OFS ORS FILENAME, + - * / % string concatenation, comparisons, ~ !~ && || !,
// and length substr index tolower toupper sprintf int. No arrays, loops, if or user functions
// (simplification): those get BusyBox's syntax error. Nothing here can loop: the work is bounded by
// the lines of input times the size of the program.

const awkUsage = " [OPTIONS] [AWK_PROGRAM] [FILE]...\n\n\t-v VAR=VAL\tSet variable\n\t-F SEP\t\tUse SEP as field separator\n" +
	"\t-f FILE\t\tRead program from FILE\n\t-e AWK_PROGRAM"

// awkVal is a value: a string, which is also a number when it looks like one (fields, input) or was
// computed as one.
type awkVal struct {
	s     string
	n     float64
	isNum bool
}

func awkNum(n float64) awkVal { return awkVal{s: awkFormat(n), n: n, isNum: true} }

// awkStr is a value from input: numeric if it looks like a number ("strnum").
func awkStr(s string) awkVal {
	if n, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return awkVal{s: s, n: n, isNum: true}
	}
	return awkVal{s: s}
}

func (v awkVal) num() float64 {
	if v.isNum {
		return v.n
	}
	t := strings.TrimSpace(v.s)
	end := 0
	for end < len(t) && strings.IndexByte("+-.0123456789eE", t[end]) >= 0 {
		end++
	}
	for ; end > 0; end-- { // the longest number at the start ("12abc" = 12)
		if n, err := strconv.ParseFloat(t[:end], 64); err == nil {
			return n
		}
	}
	return 0
}

// awkFormat prints a number like awk: whole numbers as integers, others with %.6g.
func awkFormat(n float64) string {
	if n == float64(int64(n)) && n < 1e16 && n > -1e16 {
		return strconv.FormatInt(int64(n), 10)
	}
	return strconv.FormatFloat(n, 'g', 6, 64)
}

// awk expressions: a small tree, evaluated per line.
type awkExpr struct {
	op   string // "num" "str" "re" "var" "field" "call" "assign" "postinc" "preinc" "neg" "not" "concat" or a binary operator
	val  awkVal
	name string
	re   *regexp.Regexp
	args []*awkExpr
}

type awkStmt struct {
	kind  string // "print" "printf" "next" "exit" "expr"
	args  []*awkExpr
	file  *awkExpr // print > FILE
	appnd bool     // >>
}

type awkItem struct {
	begin, end bool
	pattern    *awkExpr  // nil: every line
	action     []awkStmt // nil: print $0
}

type awkParser struct {
	src string
	pos int
	err string
}

func (p *awkParser) fail(msg string) {
	if p.err == "" {
		p.err = msg
	}
}

func (p *awkParser) space(newlines bool) {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\\' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '\n':
			p.pos++
		case c == '\n' && newlines:
			p.pos++
		case c == '#':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		default:
			return
		}
	}
}

// peek reports whether the program goes on with tok (after spaces).
func (p *awkParser) peek(tok string) bool {
	p.space(false)
	return p.pos <= len(p.src) && strings.HasPrefix(p.src[p.pos:], tok)
}

func (p *awkParser) eat(tok string) bool {
	if p.peek(tok) {
		p.pos += len(tok)
		return true
	}
	return false
}

func (p *awkParser) word() string {
	p.space(false)
	start := p.pos
	for p.pos < len(p.src) && isNameChar(p.src[p.pos]) {
		p.pos++
	}
	return p.src[start:p.pos]
}

// program: items separated by newlines or ";".
func (p *awkParser) program() []awkItem {
	var items []awkItem
	for p.err == "" {
		p.space(true)
		for p.eat(";") {
			p.space(true)
		}
		if p.pos >= len(p.src) {
			break
		}
		var it awkItem
		save := p.pos
		switch w := p.word(); w {
		case "BEGIN":
			it.begin = true
		case "END":
			it.end = true
		default:
			p.pos = save
			if !p.peek("{") {
				it.pattern = p.expr(false)
			}
		}
		if p.peek("{") {
			it.action = p.block()
			if it.action == nil {
				it.action = []awkStmt{} // "{}": nothing, not "print"
			}
		} else if it.begin || it.end {
			p.fail("Unexpected token")
		}
		items = append(items, it)
	}
	return items
}

func (p *awkParser) block() []awkStmt {
	p.eat("{")
	var stmts []awkStmt
	for p.err == "" {
		p.space(true)
		if p.eat("}") {
			return stmts
		}
		if p.eat(";") {
			continue
		}
		if p.pos >= len(p.src) {
			p.fail("Unexpected end of string")
			return nil
		}
		stmts = append(stmts, p.statement())
	}
	return stmts
}

func (p *awkParser) statement() awkStmt {
	save := p.pos
	switch w := p.word(); w {
	case "print", "printf":
		st := awkStmt{kind: w}
		paren := p.peek("(") // print("a", "b"): the list in parentheses
		for p.err == "" && !p.peek(";") && !p.peek("}") && !p.peek("\n") && !p.peek(">") && p.pos < len(p.src) {
			st.args = append(st.args, p.expr(true))
			if !p.eat(",") {
				break
			}
		}
		_ = paren
		if p.eat(">") {
			st.appnd = p.eat(">")
			st.file = p.concat(true)
		}
		return st
	case "next", "exit":
		return awkStmt{kind: w}
	case "if", "while", "for", "do", "function", "delete", "getline", "return":
		p.fail("Unexpected token") // not simulated
		return awkStmt{}
	}
	p.pos = save
	return awkStmt{kind: "expr", args: []*awkExpr{p.expr(false)}}
}

// expr: an assignment, or || && ~ comparisons concatenation + - * / unary. inPrint: ">" is not a
// comparison but print's redirection.
func (p *awkParser) expr(inPrint bool) *awkExpr {
	left := p.or(inPrint)
	for _, op := range []string{"+=", "-=", "*=", "/=", "%=", "="} {
		if (left.op == "var" || left.op == "field") && p.peek(op) && !p.peek("==") {
			p.pos += len(op)
			return &awkExpr{op: "assign", name: op, args: []*awkExpr{left, p.expr(inPrint)}}
		}
	}
	return left
}

func (p *awkParser) or(inPrint bool) *awkExpr {
	left := p.and(inPrint)
	for p.err == "" && p.eat("||") {
		left = &awkExpr{op: "||", args: []*awkExpr{left, p.and(inPrint)}}
	}
	return left
}

func (p *awkParser) and(inPrint bool) *awkExpr {
	left := p.match(inPrint)
	for p.err == "" && p.eat("&&") {
		left = &awkExpr{op: "&&", args: []*awkExpr{left, p.match(inPrint)}}
	}
	return left
}

func (p *awkParser) match(inPrint bool) *awkExpr {
	left := p.compare(inPrint)
	for p.err == "" {
		op := ""
		switch {
		case p.eat("!~"):
			op = "!~"
		case p.peek("~"):
			p.pos++
			op = "~"
		default:
			return left
		}
		left = &awkExpr{op: op, args: []*awkExpr{left, p.compare(inPrint)}}
	}
	return left
}

func (p *awkParser) compare(inPrint bool) *awkExpr {
	left := p.concat(inPrint)
	for _, op := range []string{"==", "!=", "<=", ">=", "<", ">"} {
		if op == ">" && inPrint || !p.peek(op) {
			continue
		}
		p.pos += len(op)
		return &awkExpr{op: op, args: []*awkExpr{left, p.concat(inPrint)}}
	}
	return left
}

// concat: operands next to each other are joined ($1 " " $2).
func (p *awkParser) concat(inPrint bool) *awkExpr {
	left := p.additive()
	for p.err == "" {
		p.space(false)
		if p.pos >= len(p.src) || strings.IndexByte("$\"(!", p.src[p.pos]) < 0 && !isNameChar(p.src[p.pos]) && p.src[p.pos] != '.' {
			return left
		}
		if save := p.pos; isNameStart(p.src[p.pos]) { // "in", "getline"... are not operands
			if w := p.word(); w == "in" || w == "getline" {
				p.fail("Unexpected token")
			}
			p.pos = save
		}
		left = &awkExpr{op: "concat", args: []*awkExpr{left, p.additive()}}
	}
	return left
}

func (p *awkParser) additive() *awkExpr {
	left := p.multiplicative()
	for p.err == "" {
		switch {
		case p.peek("+") && !p.peek("++") && !p.peek("+="), p.peek("-") && !p.peek("--") && !p.peek("-="):
			op := p.src[p.pos : p.pos+1]
			p.pos++
			left = &awkExpr{op: op, args: []*awkExpr{left, p.multiplicative()}}
		default:
			return left
		}
	}
	return left
}

func (p *awkParser) multiplicative() *awkExpr {
	left := p.unary()
	for p.err == "" {
		switch {
		case (p.peek("*") || p.peek("/") || p.peek("%")) && !p.peek("*=") && !p.peek("/=") && !p.peek("%="):
			op := p.src[p.pos : p.pos+1]
			p.pos++
			left = &awkExpr{op: op, args: []*awkExpr{left, p.unary()}}
		default:
			return left
		}
	}
	return left
}

func (p *awkParser) unary() *awkExpr {
	switch {
	case p.eat("!"):
		return &awkExpr{op: "not", args: []*awkExpr{p.unary()}}
	case p.eat("++"), p.eat("--"):
		dir := p.src[p.pos-2 : p.pos]
		return &awkExpr{op: "preinc", name: dir, args: []*awkExpr{p.primary()}}
	case p.peek("-") || p.peek("+"):
		neg := p.src[p.pos] == '-'
		p.pos++
		e := p.unary()
		if neg {
			return &awkExpr{op: "neg", args: []*awkExpr{e}}
		}
		return &awkExpr{op: "+", args: []*awkExpr{{op: "num", val: awkNum(0)}, e}}
	}
	e := p.primary()
	if (e.op == "var" || e.op == "field") && (p.peek("++") || p.peek("--")) {
		p.pos += 2
		return &awkExpr{op: "postinc", name: p.src[p.pos-2 : p.pos], args: []*awkExpr{e}}
	}
	return e
}

func (p *awkParser) primary() *awkExpr {
	p.space(false)
	if p.pos >= len(p.src) {
		p.fail("Unexpected end of string")
		return &awkExpr{op: "str"}
	}
	switch c := p.src[p.pos]; {
	case c == '"':
		var b strings.Builder
		for p.pos++; p.pos < len(p.src) && p.src[p.pos] != '"'; p.pos++ {
			if p.src[p.pos] == '\\' && p.pos+1 < len(p.src) {
				p.pos++
				b.WriteString(cEscapes("\\" + string(p.src[p.pos])))
				continue
			}
			b.WriteByte(p.src[p.pos])
		}
		if p.pos >= len(p.src) {
			p.fail("Unexpected end of string")
			return &awkExpr{op: "str"}
		}
		p.pos++ // the closing "
		return &awkExpr{op: "str", val: awkVal{s: b.String()}}
	case c == '/':
		end := p.pos + 1
		for end < len(p.src) && p.src[end] != '/' {
			if p.src[end] == '\\' {
				end++
			}
			end++
		}
		if end >= len(p.src) {
			p.fail("Unexpected end of string")
			return &awkExpr{op: "str"}
		}
		re, err := compileRegex(p.src[p.pos+1:end], true, false)
		p.pos = end + 1
		if err != nil {
			p.fail("Unexpected token")
			return &awkExpr{op: "str"}
		}
		return &awkExpr{op: "re", re: re}
	case c == '$':
		p.pos++
		return &awkExpr{op: "field", args: []*awkExpr{p.unaryNoIncrement()}}
	case c == '(':
		p.pos++
		e := p.expr(false)
		if !p.eat(")") {
			p.fail("Unexpected token")
		}
		return e
	case c >= '0' && c <= '9' || c == '.':
		end := p.pos
		for end < len(p.src) && (strings.IndexByte("0123456789.", p.src[end]) >= 0 ||
			(p.src[end] == 'e' || p.src[end] == 'E') && end+1 < len(p.src) && strings.IndexByte("0123456789+-", p.src[end+1]) >= 0) {
			if p.src[end] == 'e' || p.src[end] == 'E' {
				end++
			}
			end++
		}
		n, err := strconv.ParseFloat(p.src[p.pos:end], 64)
		if err != nil {
			p.fail("Unexpected token")
		}
		p.pos = end
		return &awkExpr{op: "num", val: awkNum(n)}
	case isNameStart(c):
		name := p.word()
		if p.pos < len(p.src) && p.src[p.pos] == '(' {
			p.pos++
			call := &awkExpr{op: "call", name: name}
			for p.err == "" && !p.eat(")") {
				call.args = append(call.args, p.expr(false))
				if !p.eat(",") && !p.peek(")") {
					p.fail("Unexpected token")
				}
			}
			return call
		}
		if name == "length" { // length without ()
			return &awkExpr{op: "call", name: name}
		}
		if p.peek("[") {
			p.fail("Unexpected token") // arrays are not simulated
		}
		return &awkExpr{op: "var", name: name}
	}
	p.fail("Unexpected token")
	p.pos = len(p.src)
	return &awkExpr{op: "str"}
}

// unaryNoIncrement: what follows $ ($1, $NF, $(i+1), $-1), without taking a ++ after it.
func (p *awkParser) unaryNoIncrement() *awkExpr {
	if p.eat("-") {
		return &awkExpr{op: "neg", args: []*awkExpr{p.primary()}}
	}
	return p.primary()
}

// awkRun is one run of an awk program.
type awkRun struct {
	s      *Shell
	vars   map[string]awkVal
	fields []string // $1... (the split of $0)
	line   string   // $0
	out    strings.Builder
	files  map[string]bool // files print > already wrote (the first > empties it)
	next   bool
	exit   bool
}

func (r *awkRun) get(name string) awkVal {
	switch name {
	case "NF":
		return awkNum(float64(len(r.fields)))
	}
	if v, ok := r.vars[name]; ok {
		return v
	}
	return awkVal{}
}

func (r *awkRun) split() {
	fs := r.get("FS").s
	switch {
	case fs == " ":
		r.fields = strings.Fields(r.line)
	case r.line == "":
		r.fields = nil
	case len(fs) == 1:
		r.fields = strings.Split(r.line, fs)
	default:
		re, err := compileRegex(fs, true, false)
		if err != nil {
			r.fields = strings.Split(r.line, fs)
			return
		}
		r.fields = re.Split(r.line, -1)
	}
}

func (r *awkRun) field(i int) awkVal {
	switch {
	case i == 0:
		return awkStr(r.line)
	case i > 0 && i <= len(r.fields):
		return awkStr(r.fields[i-1])
	}
	return awkVal{}
}

func (r *awkRun) set(target *awkExpr, v awkVal) {
	if target.op == "var" {
		if target.name == "NF" {
			n := min(max(int(v.num()), 0), 1000) // like $1000: NF=1000000 would fill the RAM
			for len(r.fields) < n {
				r.fields = append(r.fields, "")
			}
			r.fields = r.fields[:n]
			r.line = strings.Join(r.fields, r.get("OFS").s)
			return
		}
		r.vars[target.name] = v
		return
	}
	if target.op != "field" { // ++0: nothing to change (BusyBox would refuse it at the parse)
		return
	}
	i := int(r.eval(target.args[0]).num())
	switch {
	case i == 0:
		r.line = v.s
		r.split()
	case i > 0 && i <= 1000: // $1000000 = "x" would fill the RAM with empty fields
		for len(r.fields) < i {
			r.fields = append(r.fields, "")
		}
		r.fields[i-1] = v.s
		r.line = strings.Join(r.fields, r.get("OFS").s)
	}
}

func awkBool(b bool) awkVal {
	if b {
		return awkNum(1)
	}
	return awkNum(0)
}

func (v awkVal) truth() bool {
	if v.isNum {
		return v.n != 0
	}
	return v.s != ""
}

func (r *awkRun) eval(e *awkExpr) awkVal {
	switch e.op {
	case "num", "str":
		return e.val
	case "re":
		return awkBool(e.re.MatchString(r.line))
	case "var":
		return r.get(e.name)
	case "field":
		return r.field(int(r.eval(e.args[0]).num()))
	case "assign":
		v := r.eval(e.args[1])
		if e.name != "=" {
			v = awkArith(e.name[:1], r.eval(e.args[0]).num(), v.num())
		}
		r.set(e.args[0], v)
		return v
	case "postinc", "preinc":
		old := r.eval(e.args[0]).num()
		v := old + 1
		if e.name == "--" {
			v = old - 1
		}
		r.set(e.args[0], awkNum(v))
		if e.op == "postinc" {
			return awkNum(old)
		}
		return awkNum(v)
	case "neg":
		return awkNum(-r.eval(e.args[0]).num())
	case "not":
		return awkBool(!r.eval(e.args[0]).truth())
	case "concat": // capped: x = x x on every line would double a string per line
		joined := r.eval(e.args[0]).s + r.eval(e.args[1]).s
		return awkVal{s: joined[:min(len(joined), maxSize)]}
	case "&&":
		return awkBool(r.eval(e.args[0]).truth() && r.eval(e.args[1]).truth())
	case "||":
		return awkBool(r.eval(e.args[0]).truth() || r.eval(e.args[1]).truth())
	case "~", "!~":
		var re *regexp.Regexp
		if e.args[1].op == "re" {
			re = e.args[1].re
		} else if compiled, err := compileRegex(r.eval(e.args[1]).s, true, false); err == nil {
			re = compiled
		} else {
			return awkNum(0)
		}
		return awkBool(re.MatchString(r.eval(e.args[0]).s) == (e.op == "~"))
	case "==", "!=", "<", "<=", ">", ">=":
		a, b := r.eval(e.args[0]), r.eval(e.args[1])
		c := strings.Compare(a.s, b.s)
		if a.isNum && b.isNum {
			c = 0
			if a.n < b.n {
				c = -1
			} else if a.n > b.n {
				c = 1
			}
		}
		return awkBool(map[string]bool{"==": c == 0, "!=": c != 0, "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}[e.op])
	case "+", "-", "*", "/", "%":
		return awkArith(e.op, r.eval(e.args[0]).num(), r.eval(e.args[1]).num())
	case "call":
		return r.call(e)
	}
	return awkVal{}
}

func awkArith(op string, a, b float64) awkVal {
	switch op {
	case "+":
		return awkNum(a + b)
	case "-":
		return awkNum(a - b)
	case "*":
		return awkNum(a * b)
	case "/":
		if b == 0 {
			return awkNum(0) // BusyBox: "awk: cmd. line:1: Division by zero" (simplification)
		}
		return awkNum(a / b)
	}
	if b == 0 {
		return awkNum(0)
	}
	return awkNum(a - float64(int64(a/b))*b) // awk.c: L_d -= (long long)(L_d / R_d) * R_d (5%0.3 = 0.2)
}

func (r *awkRun) call(e *awkExpr) awkVal {
	arg := func(i int) awkVal {
		if i < len(e.args) {
			return r.eval(e.args[i])
		}
		return awkVal{}
	}
	switch e.name {
	case "length":
		if len(e.args) == 0 {
			return awkNum(float64(len(r.line)))
		}
		return awkNum(float64(len(arg(0).s)))
	case "substr":
		text := arg(0).s
		start := int(arg(1).num())
		end := len(text) + 1
		if len(e.args) > 2 {
			end = start + int(arg(2).num())
		}
		start, end = max(start, 1), min(end, len(text)+1)
		if start >= end {
			return awkVal{}
		}
		return awkVal{s: text[start-1 : end-1]}
	case "index":
		return awkNum(float64(strings.Index(arg(0).s, arg(1).s) + 1))
	case "tolower":
		return awkVal{s: strings.ToLower(arg(0).s)}
	case "toupper":
		return awkVal{s: strings.ToUpper(arg(0).s)}
	case "int":
		return awkNum(float64(int64(arg(0).num())))
	case "sprintf":
		var args []string
		for i := 1; i < len(e.args); i++ {
			args = append(args, arg(i).s)
		}
		text, _ := printfFormat(arg(0).s, args)
		return awkVal{s: text}
	}
	return awkVal{} // an unknown function: nothing (BusyBox would stop at the parse)
}

func (r *awkRun) exec(stmts []awkStmt) {
	for _, st := range stmts {
		if r.next || r.exit || r.out.Len() > maxSize {
			return
		}
		switch st.kind {
		case "next":
			r.next = true
		case "exit":
			r.exit = true
		case "expr":
			r.eval(st.args[0])
		case "print", "printf":
			var text string
			if st.kind == "print" {
				var parts []string
				for _, a := range st.args {
					parts = append(parts, r.eval(a).s)
				}
				if len(st.args) == 0 {
					parts = []string{r.line}
				}
				text = strings.Join(parts, r.get("OFS").s) + r.get("ORS").s
			} else if len(st.args) > 0 {
				var args []string
				for _, a := range st.args[1:] {
					args = append(args, r.eval(a).s)
				}
				text, _ = printfFormat(r.eval(st.args[0]).s, args)
			}
			if st.file == nil {
				r.out.WriteString(text)
				continue
			}
			name := r.eval(st.file).s
			appendTo := st.appnd || r.files[name]
			r.files[name] = true
			r.s.writeFile(name, text, appendTo)
		}
	}
}

func (s *Shell) awk(args []string, input string) (string, int, bool) {
	fs := " "
	vars := map[string]awkVal{}
	var program string
	var files []string
	hasProgram := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		value := func() string { // "-F:" or "-F :"
			if len(a) > 2 {
				return a[2:]
			}
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case hasProgram || a == "-" || !strings.HasPrefix(a, "-"):
			if !hasProgram {
				program, hasProgram = a, true
			} else {
				files = append(files, a)
			}
		case strings.HasPrefix(a, "-F"):
			fs = cEscapes(value())
		case strings.HasPrefix(a, "-v"):
			if name, v, ok := strings.Cut(value(), "="); ok {
				vars[name] = awkStr(cEscapes(v))
			}
		case strings.HasPrefix(a, "-f"):
			f := value()
			text, ok := s.readFile(resolve(s.cwd, f))
			if !ok {
				return "awk: " + f + ": No such file or directory\n", 1, false
			}
			program, hasProgram = text, true
		case strings.HasPrefix(a, "-e"):
			program, hasProgram = value(), true
		default:
			out, _, _ := usage("awk", awkUsage)
			return "awk: invalid option -- " + a[1:2] + "\n" + out, 1, false
		}
	}
	if !hasProgram {
		return usage("awk", awkUsage)
	}
	p := &awkParser{src: program}
	items := p.program()
	if p.err != "" {
		return "awk: cmd. line:1: " + p.err + "\n", 1, false
	}
	for name, v := range map[string]string{"FS": fs, "OFS": " ", "ORS": "\n", "NR": "0", "FNR": "0", "SUBSEP": "\x1c"} {
		if _, set := vars[name]; !set {
			vars[name] = awkStr(v)
		}
	}
	r := &awkRun{s: s, vars: vars, files: map[string]bool{}}
	run := func(begin, end bool) {
		for _, it := range items {
			if r.exit || it.begin != begin || it.end != end {
				continue
			}
			if !begin && !end && it.pattern != nil && !r.eval(it.pattern).truth() {
				continue
			}
			if it.action == nil {
				r.out.WriteString(r.line + r.get("ORS").s)
				continue
			}
			r.exec(it.action)
			if r.next {
				return
			}
		}
	}
	run(true, false)
	srcs, ok := s.sources(files, input, func(f, reason string) string { return "awk: " + f + ": " + reason + "\n" })
	for _, src := range srcs {
		if r.exit || !ok {
			break
		}
		r.vars["FILENAME"], r.vars["FNR"] = awkVal{s: src.name}, awkNum(0)
		for _, line := range splitLines(src.text) {
			if r.exit || r.out.Len() > maxSize {
				break
			}
			r.vars["NR"] = awkNum(r.get("NR").num() + 1)
			r.vars["FNR"] = awkNum(r.get("FNR").num() + 1)
			r.line, r.next = line, false
			r.split()
			run(false, false)
		}
	}
	r.exit = false
	run(false, true)
	if !ok {
		return r.out.String(), 1, false
	}
	return r.out.String(), 0, false
}
