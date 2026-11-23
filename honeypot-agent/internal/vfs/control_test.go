package vfs

import (
	"strings"
	"testing"
	"time"
)

// The control structures (6d): if, while, until, for, case, { }, !, functions, break / continue / return /
// local, and the syntax errors around them. Every expected output here is what the real BusyBox 1.30.1
// ash printed for the same line, typed with its newline (an interactive "-sh" in Docker, image
// busybox:1.30.1-uclibc), byte for byte.
func TestControlStructures(t *testing.T) {
	tests := []struct {
		line string
		want string
		code int
	}{
		{`for i in 1 2 3; do echo $i; done`, "1\n2\n3\n", 0},
		{`for i in a b; do echo $i; done; echo $i`, "a\nb\nb\n", 0},
		{`for i; do echo $i; done; echo $?`, "0\n", 0},
		{`set -- x y; for i; do echo $i; done`, "x\ny\n", 0},
		{`for i in; do echo x; done; echo $?`, "0\n", 0},
		{`for i in $(seq 1 3); do echo n$i; done`, "n1\nn2\nn3\n", 0},
		{`for i in 1 2 3; do echo $i; break; done; echo $?`, "1\n0\n", 0},
		{`for i in 1 2 3; do continue; echo $i; done; echo end $?`, "end 0\n", 0},
		{`for i in 1 2; do for j in a b; do echo $i$j; break 2; done; done`, "1a\n", 0},
		{`for i in 1 2; do for j in a b; do continue 2; echo no; done; echo no2; done; echo ok`, "ok\n", 0},
		{`for i in 1 2; do for j in a b; do echo $i$j; break 5; done; done; echo $?`, "1a\n0\n", 0},
		{`break; echo $?`, "0\n", 0},
		{`continue; echo $?`, "0\n", 0},
		{`for i in 1; do break 0; echo after; done; echo $?`, "-sh: break: Illegal number: 0\n", 2},
		{`for i in 1; do break abc; echo after; done; echo $?`, "-sh: break: Illegal number: abc\n", 2},
		{`for i in 1; do break 1 2; echo after; done; echo $?`, "0\n", 0},
		{`for 1 in a; do echo; done`, "-sh: syntax error: bad for loop variable\n", 2},
		{`for "i" in a; do echo; done`, "-sh: syntax error: bad for loop variable\n", 2},
		{`for i in a b do echo $i; done`, "-sh: syntax error: unexpected \"done\" (expecting \"do\")\n", 2},
		{`for i in 1 2 3; do echo $i; done | wc -l`, "3\n", 0},
		{`for i in 1 2; do echo $i; done > /tmp/x; cat /tmp/x`, "1\n2\n", 0},
		{`for i do echo $i; done; echo r$?`, "r0\n", 0},
		{"for i\ndo echo x; done; echo $?", "0\n", 0},
		{"for i in 1 2\ndo echo $i\ndone", "1\n2\n", 0},
		{`for`, "-sh: syntax error: bad for loop variable\n", 2},
		{`for i`, "-sh: syntax error: unexpected end of file (expecting \"do\")\n", 2},
		{`for i in`, "-sh: syntax error: unexpected end of file (expecting \"do\")\n", 2},
		{`for i in 1`, "-sh: syntax error: unexpected end of file (expecting \"do\")\n", 2},
		{`for i in 1;`, "-sh: syntax error: unexpected end of file (expecting \"do\")\n", 2},
		{`for i in 1; do`, "-sh: syntax error: unexpected end of file\n", 2},
		{`for i in 1; do echo`, "-sh: syntax error: unexpected end of file (expecting \"done\")\n", 2},
		{`for i in 1; do echo; done; done`, "-sh: syntax error: unexpected \"done\"\n", 2},
		{`for i in 1 2; do echo $i; exit 4; done; echo no`, "1\n", 4},
		{`for i in 1 2; do echo $i; ${x?}; done; echo after`, "1\n-sh: x: parameter not set\n", 2},
		{`false; for i in 1; do :; done; echo $?`, "0\n", 0},
		{`for i in 1; do false; done; echo $?`, "1\n", 0},
		{`X=1 for i in a; do :; done`, "-sh: syntax error: unexpected \"do\"\n", 2},
		{`echo for if then do done fi esac`, "for if then do done fi esac\n", 0},
		{`i=0; while [ $i -lt 3 ]; do echo $i; i=$((i+1)); done`, "0\n1\n2\n", 0},
		{`until true; do echo x; done; echo $?`, "0\n", 0},
		{`while false; do :; done; echo $?`, "0\n", 0},
		{`while true; do echo x; break; done; echo $?`, "x\n0\n", 0},
		{`x=0; until [ $x = 3 ]; do x=$((x+1)); echo u$x; done`, "u1\nu2\nu3\n", 0},
		{`seq 1 3 | while read a; do echo [$a]; done`, "[1]\n[2]\n[3]\n", 0},
		{`seq 1 3 > /tmp/i; while read a; do echo [$a]; done < /tmp/i`, "[1]\n[2]\n[3]\n", 0},
		{`seq 1 3 > /tmp/i; { read a; read b; echo $b-$a; } < /tmp/i`, "2-1\n", 0},
		{`seq 1 3 | { read a; cat; }`, "2\n3\n", 0},
		{`seq 1 3 | { read a; read b; echo $a$b; }; echo [$a]`, "12\n[]\n", 0},
		{`while`, "-sh: syntax error: unexpected end of file\n", 2},
		{`while true`, "-sh: syntax error: unexpected end of file (expecting \"do\")\n", 2},
		{`while true; do`, "-sh: syntax error: unexpected end of file\n", 2},
		{`while true; do done`, "-sh: syntax error: unexpected \"done\"\n", 2},
		{`while true do; done`, "-sh: syntax error: unexpected \"done\" (expecting \"do\")\n", 2},
		{`while :; do echo once; break; done`, "once\n", 0},
		{`i=0; while i=$((i+1)); [ $i -le 2 ]; do echo w$i; done`, "w1\nw2\n", 0},
		{`if true; then echo y; fi`, "y\n", 0},
		{`if false; then echo y; else echo n; fi`, "n\n", 0},
		{`if false; then echo 1; elif true; then echo 2; else echo 3; fi`, "2\n", 0},
		{`if false; then echo 1; elif false; then echo 2; fi; echo $?`, "0\n", 0},
		{`if false; then echo y; fi; echo $?`, "0\n", 0},
		{`false; if true; then :; fi; echo $?`, "0\n", 0},
		{`if [ -d /tmp ]; then echo dir; fi`, "dir\n", 0},
		{`if true; then fi`, "-sh: syntax error: unexpected \"fi\"\n", 2},
		{`if true then echo; fi`, "-sh: syntax error: unexpected \"fi\" (expecting \"then\")\n", 2},
		{`if true; then echo a; fi > /tmp/o; cat /tmp/o`, "a\n", 0},
		{`if ! false; then echo neg; fi`, "neg\n", 0},
		{`! true; echo $?`, "1\n", 0},
		{`! false; echo $?`, "0\n", 0},
		{`! echo hi | grep x; echo $?`, "0\n", 0},
		{`! ! true; echo $?`, "-sh: syntax error: unexpected \"!\"\n", 2},
		{`if (exit 3); then :; else echo $?; fi`, "3\n", 0},
		{`if`, "-sh: syntax error: unexpected end of file\n", 2},
		{`if true`, "-sh: syntax error: unexpected end of file (expecting \"then\")\n", 2},
		{`if true;`, "-sh: syntax error: unexpected end of file (expecting \"then\")\n", 2},
		{`if true; then`, "-sh: syntax error: unexpected end of file\n", 2},
		{`if true; then echo`, "-sh: syntax error: unexpected end of file (expecting \"fi\")\n", 2},
		{`if true; then echo; else`, "-sh: syntax error: unexpected end of file\n", 2},
		{`if true; then echo; elif`, "-sh: syntax error: unexpected end of file\n", 2},
		{`fi`, "-sh: syntax error: unexpected \"fi\"\n", 2},
		{`then`, "-sh: syntax error: unexpected \"then\"\n", 2},
		{`else`, "-sh: syntax error: unexpected \"else\"\n", 2},
		{`elif`, "-sh: syntax error: unexpected \"elif\"\n", 2},
		{`done`, "-sh: syntax error: unexpected \"done\"\n", 2},
		{`do echo`, "-sh: syntax error: unexpected \"do\"\n", 2},
		{`esac`, "-sh: syntax error: unexpected \"esac\"\n", 2},
		{`in`, "-sh: syntax error: unexpected \"in\"\n", 2},
		{`}`, "-sh: syntax error: unexpected \"}\"\n", 2},
		{`{`, "-sh: syntax error: unexpected end of file\n", 2},
		{`!`, "-sh: syntax error: unexpected newline\n", 2},
		{`echo !`, "!\n", 0},
		{`echo a ! b`, "a ! b\n", 0},
		{`true && if true; then echo y; fi`, "y\n", 0},
		{`if true; then echo y; fi && echo z`, "y\nz\n", 0},
		{`while false; do :; done || echo w`, "", 0},
		{`if true; then echo y; fi | tr y Y`, "Y\n", 0},
		{`if true; then echo a; fi; fi`, "-sh: syntax error: unexpected \"fi\"\n", 2},
		{`case abc in a*) echo A;; b*) echo B;; esac`, "A\n", 0},
		{`case bcd in a*) echo A;; b*) echo B;; esac`, "B\n", 0},
		{`case x in a|x) echo m;; esac`, "m\n", 0},
		{`case "a b" in "a b") echo q;; esac`, "q\n", 0},
		{`case x in (x) echo paren;; esac`, "paren\n", 0},
		{`case x in x) echo last; esac`, "last\n", 0},
		{`case x in esac; echo $?`, "0\n", 0},
		{`case x in y) ;; esac; echo $?`, "0\n", 0},
		{`false; case x in y) echo;; esac; echo $?`, "0\n", 0},
		{`case x in *) false;; esac; echo $?`, "1\n", 0},
		{`case x in x) ;; esac; echo $?`, "0\n", 0},
		{`case "*" in \*) echo star;; esac`, "star\n", 0},
		{`X='*'; case abc in $X) echo glob;; esac`, "glob\n", 0},
		{`X='*'; case abc in "$X") echo q;; *) echo noq;; esac`, "noq\n", 0},
		{`case x in x) echo a;; x) echo b;; esac`, "a\n", 0},
		{`case x in x echo; esac`, "-sh: syntax error: unexpected word (expecting \")\")\n", 2},
		{`case`, "-sh: syntax error: unexpected newline (expecting word)\n", 2},
		{`case x`, "-sh: syntax error: unexpected end of file (expecting \"in\")\n", 2},
		{`case x in`, "-sh: syntax error: unexpected end of file (expecting \")\")\n", 2},
		{`case x in x`, "-sh: syntax error: unexpected newline (expecting \")\")\n", 2},
		{`case x in x)`, "-sh: syntax error: unexpected end of file (expecting \";;\")\n", 2},
		{`case x in x) echo`, "-sh: syntax error: unexpected end of file (expecting \";;\")\n", 2},
		{`case x in x) echo;;`, "-sh: syntax error: unexpected end of file (expecting \")\")\n", 2},
		{`case x y in x) echo;; esac`, "-sh: syntax error: unexpected word (expecting \"in\")\n", 2},
		{`case x in x) echo a;; ;; esac`, "-sh: syntax error: unexpected word (expecting \")\")\n", 2},
		{`case $nope in "") echo empty;; esac`, "empty\n", 0},
		{`case ~ in /root) echo tilde;; esac`, "tilde\n", 0},
		{`case abc in a?c) echo q;; esac`, "q\n", 0},
		{`case b in [abc]) echo cls;; esac`, "cls\n", 0},
		{`case abc in *b*) echo has;; esac`, "has\n", 0},
		{"case x in\nx) echo nl\n;;\nesac", "nl\n", 0},
		{`case x in x) echo a;; esac | tr a A`, "A\n", 0},
		{`case 1 in 1) echo one;; esac > /tmp/c; cat /tmp/c`, "one\n", 0},
		{`echo a ;; echo b`, "-sh: syntax error: unexpected \";;\"\n", 2},
		{`echo a;;`, "-sh: syntax error: unexpected \";;\"\n", 2},
		{`;;`, "-sh: syntax error: unexpected \";;\"\n", 2},
		{`{ echo a; echo b; }`, "a\nb\n", 0},
		{`{ echo a; echo b; } | wc -l`, "2\n", 0},
		{`{ echo a; echo b; } > /tmp/b; cat /tmp/b`, "a\nb\n", 0},
		{`{ cd /tmp; }; pwd`, "/tmp\n", 0},
		{`(cd /tmp); pwd`, "/root\n", 0},
		{`{ echo a }`, "-sh: syntax error: unexpected end of file (expecting \"}\")\n", 2},
		{`{echo a; }`, "-sh: syntax error: unexpected \"}\"\n", 2},
		{`echo }`, "}\n", 0},
		{`echo {`, "{\n", 0},
		{`{ }`, "-sh: syntax error: unexpected \"}\"\n", 2},
		{`{ exit 3; }; echo no`, "", 3},
		{`{ echo a; } 2>&1 | cat`, "a\n", 0},
		{`{ echo a; echo b >&2; } 2>/dev/null`, "a\n", 0},
		{`{ X=5; }; echo $X`, "5\n", 0},
		{`(echo a; echo b) > /tmp/s; cat /tmp/s`, "a\nb\n", 0},
		{`(echo a; echo b) | wc -l`, "2\n", 0},
		{`f() { echo in f $1; }; f x; f y`, "in f x\nin f y\n", 0},
		{`f() { return 3; }; f; echo $?`, "3\n", 0},
		{`f() { echo $#; }; f a b c`, "3\n", 0},
		{`f() { local x=1; echo $x; }; x=0; f; echo $x`, "1\n0\n", 0},
		{`f() { local x; echo [$x]; x=2; }; x=0; f; echo $x`, "[]\n0\n", 0},
		{`f() { local y=3; }; f; echo [$y]`, "[]\n", 0},
		{`local x=1`, "-sh: local: not in a function\n", 2},
		{`local x=1; echo $?`, "-sh: local: not in a function\n", 2},
		{`f() echo hi; f`, "hi\n", 0},
		{`f () { echo sp; }; f`, "sp\n", 0},
		{`function f { echo bash; }; f`, "bash\n", 0},
		{`function f() { echo bash2; }; f`, "bash2\n", 0},
		{`function`, "-sh: syntax error: unexpected newline (expecting word)\n", 2},
		{`function f`, "-sh: syntax error: unexpected end of file\n", 2},
		{`f() { echo $0; }; f`, "-sh\n", 0},
		{`f() { echo a; }; type f`, "f is a function\n", 0},
		{`f() { echo a; }; command -v f`, "f\n", 0},
		{`f() { echo a; }; command -V f`, "f is a function\n", 0},
		{`type for`, "for is a shell keyword\n", 0},
		{`type break`, "break is a special shell builtin\n", 0},
		{`type local`, "local is a special shell builtin\n", 0},
		{`type return`, "return is a special shell builtin\n", 0},
		{`type function`, "function is a shell keyword\n", 0},
		{`type {`, "{ is a shell keyword\n", 0},
		{`echo (`, "-sh: syntax error: unexpected newline (expecting \")\")\n", 2},
		{`echo a (`, "-sh: syntax error: unexpected \"(\"\n", 2},
		{`echo a(b`, "-sh: syntax error: unexpected \"(\"\n", 2},
		{`echo a)b`, "-sh: syntax error: unexpected \")\"\n", 2},
		{`echo )`, "-sh: syntax error: unexpected \")\"\n", 2},
		{`echo a)`, "-sh: syntax error: unexpected \")\"\n", 2},
		{`f(`, "-sh: syntax error: unexpected newline (expecting \")\")\n", 2},
		{`f()`, "-sh: syntax error: unexpected end of file\n", 2},
		{`f() {`, "-sh: syntax error: unexpected end of file\n", 2},
		{`f() { echo a`, "-sh: syntax error: unexpected end of file (expecting \"}\")\n", 2},
		{`cd() { echo mycd; }; cd /tmp; pwd`, "mycd\n/root\n", 0},
		{`exit() { echo x; }`, "-sh: syntax error: bad function name\n", 2},
		{`1f() { :; }`, "-sh: syntax error: bad function name\n", 2},
		{`f-g() { :; }`, "-sh: syntax error: bad function name\n", 2},
		{`f() { echo a; }; unset -f f; f`, "-sh: f: not found\n", 127},
		{`f() { echo a; }; unset f; f`, "a\n", 0},
		{`f() { echo $1; shift; echo $1; }; set -- p q; f a b; echo $1`, "a\nb\np\n", 0},
		{`f() { echo "$@"; }; f "a b" c`, "a b c\n", 0},
		{`f() { echo $#; }; set -- a b; f; echo $#`, "0\n2\n", 0},
		{`f() { break; }; for i in 1 2; do f; echo $i; done`, "", 0},
		{`f() { return 4; echo no; }; f; echo $?`, "4\n", 0},
		{`return 5; echo no`, "", 5},
		{`return; echo $?`, "", 0},
		{`f() { return; }; false; f; echo $?`, "1\n", 0},
		{`f() { false; return; }; f; echo $?`, "1\n", 0},
		{`f() { echo a; } > /tmp/f; f; cat /tmp/f`, "a\n", 0},
		{`f() { echo $1; }; f 1 | tr 1 X`, "X\n", 0},
		{`f() { X=in; }; f; echo $X`, "in\n", 0},
		{`f() { exit 6; }; f; echo no`, "", 6},
		{`f() { ${x?}; echo no; }; f; echo after`, "-sh: x: parameter not set\n", 2},
		{`f() { for i in 1 2; do return 7; done; }; f; echo $?`, "7\n", 0},
		{`f() { g; }; g() { echo g; }; f`, "g\n", 0},
		{`f() { echo "$*"; }; IFS=,; f a b`, "a,b\n", 0},
		{`for i in 1 2; do (break); echo $i; done`, "1\n2\n", 0},
		{`for i in 1 2; do echo $i; done | while read x; do echo got$x; done`, "got1\ngot2\n", 0},
		{`cd /tmp || cd /; for a in x86 arm arm7 mips; do echo $a; done`, "x86\narm\narm7\nmips\n", 0},
		{`for i in 1 2 3; do echo $i > /tmp/.f$i; done; cat /tmp/.f*`, "1\n2\n3\n", 0},
		{`if [ -f /tmp/nope ]; then echo y; else echo n; fi; echo $?`, "n\n0\n", 0},
		{`for i in 1 2 3; do if [ $i = 2 ]; then continue; fi; echo $i; done`, "1\n3\n", 0},
		{`x=$(for i in a b; do echo $i; done); echo $x`, "a b\n", 0},
		{`echo $(if true; then echo sub; fi)`, "sub\n", 0},
		{`eval 'for i in 1 2; do echo e$i; done'`, "e1\ne2\n", 0},
		{`sh -c 'for i in 1 2; do echo s$i; done'`, "s1\ns2\n", 0},
		{`for i in a b; do echo $i; done; echo $LINENO`, "a\nb\n1\n", 0},
		// more, for the mutations: the cases a wrong change would get wrong
		{`i=0; while [ $i -lt 3 ]; do i=$((i+1)); [ $i = 2 ] && continue; echo $i; done`, "1\n3\n", 0},
		{`(f() { echo in; }); f; echo $?`, "-sh: f: not found\n127\n", 0},
		{`f() { echo out; }; (f() { echo in; }; f); f`, "in\nout\n", 0},
		{`f() { while return 5; do :; done; }; f; echo $?`, "5\n", 0},
		{`false; case x in x) ;; esac; echo $?`, "0\n", 0},
		{`x=0; f() { local x=1; local x; echo $x; }; f; echo $x`, "1\n0\n", 0},
		{`seq 1 3 | while read l; do echo l$l; sh -c 'read x; echo got $x'; done`, "l1\ngot 2\nl3\ngot\n", 0},
		{`seq 1 3 > /tmp/i; read a < /tmp/i; read b; echo [$a][$b]`, "[1][]\n", 0},
		{`seq 1 3 | { cat >/dev/null; read x; echo [$x]; }`, "[]\n", 0},
		{`false; eval false; echo $?; eval true; echo $?`, "1\n0\n", 0},
		{`x=1; f() { local x; export x=2; env | grep ^x=; }; f; echo [$x]; env | grep ^x=`, "x=2\n[1]\n", 1},
		{`f() { echo $# $1; }; set -- a b c; f; f x; echo $# $1`, "0\n1 x\n3 a\n", 0},
		{`if false; then :; elif false; then :; elif true; then echo third; fi`, "third\n", 0},
		{`while false; do :; done; until true; do :; done; echo $?`, "0\n", 0},
		{`f() { return; }; (exit 6); f; echo $?`, "6\n", 0},
		{`echo '"if"'; "if" true; echo $?`, "\"if\"\n-sh: if: not found\n127\n", 0},
		{`f() { echo "<$1>"; }; f "a  b"; f '' x`, "<a  b>\n<>\n", 0},
		{`for x in 'a b' c; do echo [$x]; done`, "[a b]\n[c]\n", 0},
		{`set -- 1 2; for a in "$@"; do echo [$a]; done; for a in "$*"; do echo [$a]; done`, "[1]\n[2]\n[1 2]\n", 0},
		{`cd /tmp; touch fa fb; for f in f*; do echo $f; done`, "fa\nfb\n", 0},
		{`case /tmp/x in /tmp/*) echo tmp;; esac; case a.sh in *.sh|*.py) echo script;; esac`, "tmp\nscript\n", 0},
		{`X=b; case abc in a${X}c) echo var;; esac; case abc in a"b"c) echo q;; esac`, "var\nq\n", 0},
		{`case abc in A*) echo up;; [a-c]bc) echo range;; esac`, "range\n", 0},
		{`case '' in '') echo empty;; esac; case "x y" in x*) echo sp;; esac`, "empty\nsp\n", 0},
		{`{ echo out; echo err >&2; } > /tmp/o 2>&1; cat /tmp/o`, "out\nerr\n", 0},
		{`for i in 1 2; do echo $i; done 2>/dev/null | cat`, "1\n2\n", 0},
		{`if true; then echo a; fi; if false; then echo b; else echo c; fi | tr c C`, "a\nC\n", 0},
		{`true | false && echo y || echo n`, "n\n", 0},
		{`false || true && echo both`, "both\n", 0},
		{`! true || echo neg`, "neg\n", 0},
		{`f() { echo f; }; f && echo ok; f | wc -l`, "f\nok\n1\n", 0},
		{`for i in 1 2 3; do echo $i; [ $i = 2 ] && break; done; echo after`, "1\n2\nafter\n", 0},
		{`uname -m | while read a; do case $a in arm*) echo ARM;; *) echo other;; esac; done`, "ARM\n", 0}, // uname -m: armv7l here, x86_64 in the oracle's container
		{`cd /tmp && for a in arm mips x86; do echo "cp bin.$a .b"; done | sh`, "cp: can't stat 'bin.arm': No such file or directory\ncp: can't stat 'bin.mips': No such file or directory\ncp: can't stat 'bin.x86': No such file or directory\n", 1},
	}
	for _, tt := range tests {
		if got, code := runTyped(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
	}
}

// The same in SSH sessions without a pty, compared with the real ash started like Dropbear starts it
// (ssh_oracle in the scratchpad): line numbers in loops, functions, eval and $(...), return outside a
// function, "while read" loops sharing their input with the commands inside.
func TestControlSessions(t *testing.T) {
	tests := []struct {
		exec                  bool
		input, stdout, stderr string
		code                  int
	}{
		{true, "for i in 1\ndo\nfoo\ndone\necho $LINENO", "5\n", "sh: foo: not found\n", 0},
		{true, "echo a\nfor\necho b", "a\n", "sh: syntax error: bad for loop variable\n", 2},
		{true, "f() {\necho $LINENO\nfoo\n}\necho x\nf", "x\n2\n", "sh: foo: not found\n", 127},
		{true, "return 3; echo no\necho no2", "", "", 3},
		{true, "if true\nthen\n  nope\nfi; echo $?", "127\n", "sh: nope: not found\n", 0},
		{true, "case x in\nx) bad;;\nesac", "", "sh: bad: not found\n", 127},
		{true, "echo (", "", "sh: syntax error: unexpected end of file (expecting \")\")\n", 2},
		{true, "echo hi >", "", "sh: syntax error: unexpected end of file\n", 2},
		{true, "local x", "", "sh: local: line 1: not in a function\n", 2},
		{true, "break 0; echo no", "", "sh: break: line 1: Illegal number: 0\n", 2},
		{true, "for i in 1 2; do echo $i; done | while read x; do echo [$x]; done", "[1]\n[2]\n", "", 0},
		{false, "case x in x) echo m;; esac\necho after\n", "m\nafter\n", "", 0},
		{false, "return 4\necho after\n", "", "", 4},
		{false, "local x\necho after\n", "", "-sh: local: line 1: not in a function\n", 2},
		{true, "echo\necho\neval 'echo $LINENO; nosuchx'\neval ';'", "\n\n1\n", "sh: eval: line 1: nosuchx: not found\nsh: eval: line 1: syntax error: unexpected \";\"\n", 2},
		{true, "echo\necho\neval 'cd /nope'", "\n\n", "sh: cd: line 1: can't cd to /nope: No such file or directory\n", 2},
		{true, "echo\necho\necho $(echo $LINENO; cd /nope)", "\n\n3\n", "sh: cd: line 3: can't cd to /nope: No such file or directory\n", 0},
		{true, "f() {\n\ncd /nope\n}\necho\nf", "\n", "sh: cd: line 3: can't cd to /nope: No such file or directory\n", 2},
		{true, "f() { return 300; }; f; echo $?; g() { return -1; }; g; echo $?", "44\n", "sh: return: line 1: Illegal number: -1\n", 2},
		{true, "f() { return abc; }; f; echo $?", "", "sh: return: line 1: Illegal number: abc\n", 2},
		{true, "P='a*'; X=abcabc; echo ${X#$P} ${X#\"$P\"} ${X##$P}", "bcabc abcabc\n", "", 0},
		{true, "for i in 1 2\ndo\n  echo $LINENO\ndone", "3\n3\n", "", 0},
		{true, "x=1; readonly x; for x in a; do echo in; done; echo after", "", "sh: x: is read only\n", 2},
		{true, "false; . /dev/null; echo $?; false; eval ''; echo $?", "0\n0\n", "", 0},
		{true, "[[ 1 = 1 && 2 = 2 ]]; echo $?; [[ 1 = 2 || 2 = 2 ]]; echo $?; [[ 1 = 2 && 2 = 2 ]]; echo $?", "0\n0\n1\n", "", 0},
		{true, "f() { echo a; }; command f; echo $?", "127\n", "sh: f: not found\n", 0},
		{true, "false; f() { :; }; echo $?", "0\n", "", 0},
		{true, "seq 1 3 > /tmp/i; while read l; do echo [$l]; grep 1 /tmp/i; done < /tmp/i", "[1]\n1\n[2]\n1\n[3]\n1\n", "", 0},
		{true, "seq 1 3 > /tmp/i; while read l; do echo [$l]; x=$(echo $l | tr 1 X); echo $x; done < /tmp/i", "[1]\nX\n[2]\n2\n[3]\n3\n", "", 0},
		{true, "seq 1 3 > /tmp/i; while read l; do echo [$l]; sh -c 'echo in'; done < /tmp/i", "[1]\nin\n[2]\nin\n[3]\nin\n", "", 0},
		{true, "f() { echo $1; }; for i in a b; do f $i; done | tr ab AB", "A\nB\n", "", 0},
		{true, "i=0; while :; do i=$((i+1)); [ $i -gt 3 ] && break; echo $i; done", "1\n2\n3\n", "", 0},
		{true, "case a in a) echo 1 ;& b) echo 2;; esac", "", "sh: syntax error: unexpected \"&\"\n", 2},
		{true, "case a in\n  a)\n    echo one\n    ;;\n  *)\n    echo other\n    ;;\nesac", "one\n", "", 0},
		{true, "if true; then\n  echo $LINENO\n  nosuchy\nfi", "2\n", "sh: nosuchy: not found\n", 127},
		{true, "{ echo a; nosuchz; } 2>&1 | tr a A", "A\nsh: nosuchz: not found\n", "", 0},
		{true, "for i in 1 2; do echo $i; done; echo $i; for j in; do echo no; done; echo [$j]", "1\n2\n2\n[]\n", "", 0},
		{true, "until false; do echo u; break; done; while break; do echo no; done; echo end", "u\nend\n", "", 0},
		{true, "for i in 1 2 3; do for j in a b; do [ $j = b ] && continue 2; echo $i$j; done; done", "1a\n2a\n3a\n", "", 0},
		{false, "f() { echo f; }\nf\nunset -f f\nf\necho $?\n", "f\n127\n", "-sh: f: not found\n", 0},
		{false, "f() { exit 3; }\necho a\nf\necho no\n", "a\n", "", 3},
		{false, "eval 'return 7'\necho no\n", "", "", 7},
		{false, "echo 'return 2; echo no' > /tmp/r; . /tmp/r; echo after $?\n", "after 2\n", "", 0},
		// a crash (function calling itself): the shell that waited says so
		{true, "echo\necho\nf() {\necho $LINENO\n}\nf", "\n\n2\n", "", 0},
		{true, "echo 'a\nb'\necho $LINENO", "a\nb\n3\n", "", 0},
		{true, "f() f; f; echo $?", "", "", 139},
		{true, "sh -c 'f() f; f'; echo $?", "139\n", "Segmentation fault\n", 0},
		{true, "f() { echo $LINENO; }\n\n\nf", "1\n", "", 0},
		{false, "f() { return 3; }\nf\necho $?\nreturn\necho no\n", "3\n", "", 0},
		{false, "for i in 1 2; do echo $i; done\ncase a in a) echo A;; esac\nwhile false; do :; done; echo $?\n", "1\n2\nA\n0\n", "", 0},
		{true, "ulimit -c 0; (f() f; f); echo $?", "139\n", "Segmentation fault\n", 0},
		{true, "ulimit -c 0; x=$(f() f; f); echo $? [$x]", "139 []\n", "Segmentation fault\n", 0},
		{true, "ulimit -c 0; { f() f; f; } | cat; echo $?", "0\n", "Segmentation fault\n", 0},
		{true, "ulimit -c 0; f() f; f | cat; echo $?", "0\n", "Segmentation fault\n", 0},
		{true, "ulimit -c 0; sh -c 'f() f; f'; echo $?", "139\n", "Segmentation fault\n", 0},
		{true, "ulimit -c 0; echo 'f() f; f' | sh; echo $?", "139\n", "Segmentation fault\n", 0},
		{false, "ulimit -c 0\n(f() f; f); echo $?\n", "139\n", "Segmentation fault\n", 0},
		// several lines on stdin: a command not finished waits for the next ones (6e)
		{false, "for i in 1 2\ndo\necho $i\ndone\necho $LINENO\n", "1\n2\n5\n", "", 0},
		{false, "f() {\nnope\n}\nf\necho $?\n", "127\n", "-sh: nope: not found\n", 0},
		{false, "if true; then\necho in\nfi; fi\necho after\n", "", "-sh: syntax error: unexpected \"fi\"\n", 2},
		{false, "for i in 1; do\n", "", "-sh: syntax error: unexpected end of file\n", 2},
		{false, "echo 'a\nb'; echo $LINENO\nnosuch\n", "a\nb\n2\n", "-sh: nosuch: not found\n", 127},
		{false, "echo a \\\nb\necho $LINENO\n", "a b\n3\n", "", 0},
		{false, "echo a &&\n\necho b\n", "a\nb\n", "", 0},
		{false, "for i in 1 2\ndo\n  cd /nope\ndone\n", "", "-sh: cd: line 3: can't cd to /nope: No such file or directory\n-sh: cd: line 3: can't cd to /nope: No such file or directory\n", 2},
		{false, "echo \"open\n", "", "-sh: syntax error: unterminated quoted string\n", 2},
		{false, "for i in 1 2\ndo echo $i; done", "1\n2\n", "", 0},
		{false, "case $(echo x) in\n  x) echo X\n  ;;\nesac\n", "X\n", "", 0},
	}
	for _, tt := range tests {
		if stdout, stderr, code := runSSH(tt.input, tt.exec); stdout != tt.stdout || stderr != tt.stderr || code != tt.code {
			t.Errorf("exec %v %q\n got: %q %q, exit %d\nwant: %q %q, exit %d",
				tt.exec, tt.input, stdout, stderr, code, tt.stdout, tt.stderr, tt.code)
		}
	}
}

// A function calling itself for ever, or commands nested too deep, crash the shell like a real ash out
// of stack (exit code 139, the session ends); in a subshell only the subshell. Quickly, and the shell's
// own counters are back to 0 after.
func TestShellCrash(t *testing.T) {
	nested := strings.Repeat("{ ", 300) + "echo deep" + strings.Repeat("; }", 300)
	tests := []struct {
		line string
		want string
		code int
		exit bool
	}{
		{"f() { f; }; f; echo never", "", 139, true},
		{"f() { local x=$1; f $(($1+1)); }; f 1", "", 139, true},
		{"f() { (f); }; (f); echo $?", "-sh: can't fork: Resource temporarily unavailable\n2\n", 0, false}, // subshells: out of forks first
		{"f() { " + strings.Repeat("{ ", 150) + "f" + strings.Repeat("; }", 150) + "; }; f", "", 139, true},
		{"f() { " + strings.Repeat("{ ", 150) + "f" + strings.Repeat("; }", 150) + "; }; (f); echo $?", "Segmentation fault\n139\n", 0, false},
		{"f() f; f", "", 139, true}, // no { }: only the calls count
		{"(exit 139); echo $?", "139\n", 0, false},
		{nested, "", 139, true},
		{"(" + nested + "); echo $?", "", 139, true}, // too deep already to read
		{"sh -c '" + nested + "'; echo $?", "Segmentation fault\n139\n", 0, false},
		// eval reads its code apart: deep enough only together, when they run
		{"Y='" + strings.Repeat("{ ", 150) + "echo deep" + strings.Repeat("; }", 150) + "'; " + strings.Repeat("{ ", 100) + `eval "$Y"` + strings.Repeat("; }", 100), "", 139, true},
		{strings.Repeat("{ ", 190) + "echo deep" + strings.Repeat("; }", 190), "deep\n", 0, false},
	}
	for _, tt := range tests {
		sh := NewShell()
		start := time.Now()
		got, code, exit := sh.Run(tt.line)
		if got != tt.want || code != tt.code || exit != tt.exit || time.Since(start) > time.Second {
			t.Errorf("Run(%.70q)\n got: %q, exit code %d, exit %v\nwant: %q, exit code %d, exit %v", tt.line, got, code, exit, tt.want, tt.code, tt.exit)
		}
		if sh.nesting != 0 || sh.loops != 0 || len(sh.locals) != 0 || sh.funcLine != 0 || sh.depth != 0 {
			t.Errorf("Run(%.70q): left nesting %d, loops %d, locals %d, funcLine %d, depth %d", tt.line, sh.nesting, sh.loops, len(sh.locals), sh.funcLine, sh.depth)
		}
	}
}

// Lines that leave a command unfinished (6e): the shell waits for the next lines with $PS2 ("> "),
// like ash reading its terminal; a real error on the way still comes at once. Compared with the real
// ash run interactively on the same lines (sh -i, prompts shown, PS1='# '; its name is "sh" there):
// prompts and output, errors, exit code.
func TestContinuationLines(t *testing.T) {
	tests := []struct {
		input, out, errs string
		code             int
	}{
		{"for i in 1 2\ndo echo $i\ndone\necho $LINENO\n", "# > > 1\n2\n# 4\n# ", "", 0},
		{"echo 'a\nb'\necho \"c\nd\"\n", "# > a\nb\n# > c\nd\n# ", "", 0},
		{"echo a \\\nb\n", "# > a b\n# ", "", 0},
		{"echo a &&\necho b\n", "# > a\nb\n# ", "", 0},
		{"case x in\nx) echo X;;\nesac\n", "# > > X\n# ", "", 0},
		{"f() {\necho in f\n}\nf\n", "# > > # in f\n# ", "", 0},
		{"for i in 1\ndo echo (\necho after\n", "# > # after\n# ", "-sh: syntax error: unexpected newline (expecting \")\")\n", 0},
		{"if true\nthen\nfi\necho after\n", "# > > # after\n# ", "-sh: syntax error: unexpected \"fi\"\n", 0},
		{"echo $(echo a\necho b)\n", "# > a b\n# ", "", 0},
		{"PS2='more: '\nfor i in 1\ndo :; done\n", "# # more: # ", "", 0},
		{"echo a |\ntr a b\n", "# > b\n# ", "", 0},
		{"for i in 1\n\n\ndo echo $i; done\n", "# > > > 1\n# ", "", 0},
		{"for i in 1; do\n", "# > # ", "-sh: syntax error: unexpected end of file\n", 2},
		{"echo \\\n", "# > \n", "", 0},
		{"while true\ndo exit 3\ndone\n", "# > > ", "", 3},
		{"{ echo a\necho b; }\n", "# > a\nb\n# ", "", 0},
		{"echo a\\\nb\n", "# > ab\n# ", "", 0}, // "\" + newline inside a word
		{"echo 'x'\\\n\"y\"\n", "# > xy\n# ", "", 0},
	}
	for _, tt := range tests {
		var out, errs strings.Builder
		sh := NewShell()
		sh.vars["PS1"] = "# "
		code, exit := 0, false
		for _, line := range strings.SplitAfter(tt.input, "\n") {
			if line == "" {
				break
			}
			out.WriteString(sh.Prompt())
			if code, exit = sh.RunTo(strings.TrimSuffix(line, "\n"), &out, &errs); exit {
				break
			}
		}
		if !exit { // the input ends: ash shows its prompt, reads the end, and after an error the prompt again
			out.WriteString(sh.Prompt())
			before := errs.Len()
			if code = sh.EndOfInput(&out, &errs); errs.Len() > before {
				out.WriteString(sh.Prompt())
			}
		}
		if out.String() != tt.out || errs.String() != tt.errs || code != tt.code {
			t.Errorf("%q\n got: %q %q, exit code %d\nwant: %q %q, exit code %d", tt.input, out.String(), errs.String(), code, tt.out, tt.errs, tt.code)
		}
	}
}

// A command that never ends (an open quote, more and more lines) waits at most maxPending bytes: then
// it gets the error ash would give at the end of its input, and the shell is back to $PS1.
func TestPendingLimit(t *testing.T) {
	sh := NewShell()
	line := strings.Repeat("x", 1000)
	got, _, _ := sh.Run(`echo "` + line)
	for i := 0; got == "" && i < 200; i++ {
		if sh.Prompt() != "> " || len(sh.pending) > maxPending {
			t.Fatalf("line %d: prompt %q, %d bytes waiting", i, sh.Prompt(), len(sh.pending))
		}
		got, _, _ = sh.Run(line)
	}
	if got != "-sh: syntax error: unterminated quoted string\n" || sh.pending != "" || sh.Prompt() != "root@gateway:~# " {
		t.Errorf("after %d bytes: %q, %d bytes waiting, prompt %q", maxPending, got, len(sh.pending), sh.Prompt())
	}
	if got, _, _ := sh.Run("echo $LINENO"); got != "67\n" { // every line read counts
		t.Errorf("$LINENO after: %q", got)
	}
}
