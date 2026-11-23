package vfs

import (
	"strings"
	"testing"
)

// sshVars is what Dropbear adds to the environment of the oracle's sessions (PUBLIC_IP 198.51.100.7).
var sshVars = map[string]string{"SSH_CLIENT": "203.0.113.9 40000 22", "SSH_CONNECTION": "203.0.113.9 40000 198.51.100.7 22"}

// runSSH runs input the way an SSH session without a pty does: exec = sh -c with the whole input; else the
// login shell reads it line by line (a last line without a newline counts) until EOF, exit or an error
// that ends it. Returns what went to stdout and stderr and the exit code.
func runSSH(input string, exec bool) (stdout, stderr string, code int) {
	var out, errs strings.Builder
	sh := NewSSHShell("root", sshVars, false, exec)
	if exec {
		code, _ = sh.RunTo(input, &out, &errs)
		return out.String(), errs.String(), code
	}
	for _, line := range strings.SplitAfter(input, "\n") {
		if line == "" {
			break
		}
		exit := false
		if code, exit = sh.RunTo(strings.TrimSuffix(line, "\n"), &out, &errs); exit {
			break
		}
	}
	return out.String(), errs.String(), code
}

// SSH sessions without a pty, compared with the real BusyBox 1.30.1 ash started like Dropbear 2019.78 starts
// it (ssh_oracle in the scratchpad): the login shell "-sh" reading its input, and sh -c COMMAND (exec).
// Only the container's own values were replaced: its PIDs ($$, $PPID), its kernel, and SHLVL 2 in the
// login shell (the oracle started it from another sh; Dropbear's clean environment gives 1).
func TestSSHSessions(t *testing.T) {
	tests := []struct {
		exec                  bool
		input, stdout, stderr string
		code                  int
	}{
		{false, "echo $0 $- $$ $PPID $LINENO\nnosuch\ncd /nope\necho after $?\necho $LINENO\n", "-sh s 517 356 1\nafter 2\n5\n", "-sh: nosuch: not found\n-sh: cd: line 3: can't cd to /nope: No such file or directory\n", 0},
		{false, "env\n", "USER=root\nSSH_CLIENT=203.0.113.9 40000 22\nSHLVL=1\nHOME=/root\nPS1=\\u@\\h:\\w\\$ \nLOGNAME=root\nPATH=/bin:/sbin:/usr/bin:/usr/sbin\nSHELL=/bin/sh\nPWD=/root\nSSH_CONNECTION=203.0.113.9 40000 198.51.100.7 22\n", "", 0},
		{false, "set\n", "HOME='/root'\nHOSTNAME='gateway'\nIFS=' \t\n'\nLINENO=''\nLOGNAME='root'\nOPTIND='1'\nPATH='/bin:/sbin:/usr/bin:/usr/sbin'\nPPID='356'\nPS1='\\u@\\h:\\w\\$ '\nPS2='> '\nPS4='+ '\nPWD='/root'\nSHELL='/bin/sh'\nSHLVL='1'\nSSH_CLIENT='203.0.113.9 40000 22'\nSSH_CONNECTION='203.0.113.9 40000 198.51.100.7 22'\nUSER='root'\n", "", 0},
		{false, "echo a\necho ${x?unset}\necho never\n", "a\n", "-sh: x: unset\n", 2},
		{false, "echo a\nexit 3\necho never\n", "a\n", "", 3},
		{false, "echo a\nfalse\n", "a\n", "", 1},
		{false, "uname -m; nosuch; echo $?\nexport X=1; echo $X\n", "armv7l\n127\n1\n", "-sh: nosuch: not found\n", 0},
		{false, "cd /tmp\npwd\nls /nope; echo $?\n", "/tmp\n1\n", "ls: /nope: No such file or directory\n", 0},
		{false, "echo a; exit\necho never\n", "a\n", "", 0},
		{false, "export 1a; echo b\necho c\n", "", "-sh: export: line 1: 1a: bad variable name\n", 2},
		{false, "", "", "", 0},
		{false, "echo no newline at end", "no newline at end\n", "", 0},
		{false, "(exit 4); echo $?\nsh -c 'nosuch'; echo $?\n", "4\n127\n", "sh: nosuch: not found\n", 0},
		{true, "echo $0 $- $$ $PPID $LINENO; nosuch; cd /nope; echo after", "sh 517 356 1\nafter\n", "sh: nosuch: not found\nsh: cd: line 1: can't cd to /nope: No such file or directory\n", 0},
		{true, "env", "USER=root\nSSH_CLIENT=203.0.113.9 40000 22\nSHLVL=1\nHOME=/root\nLOGNAME=root\nPATH=/bin:/sbin:/usr/bin:/usr/sbin\nSHELL=/bin/sh\nPWD=/root\nSSH_CONNECTION=203.0.113.9 40000 198.51.100.7 22\n", "", 0},
		{true, "set", "HOME='/root'\nHOSTNAME='gateway'\nIFS=' \t\n'\nLINENO=''\nLOGNAME='root'\nOPTIND='1'\nPATH='/bin:/sbin:/usr/bin:/usr/sbin'\nPPID='356'\nPS1='\\w \\$ '\nPS2='> '\nPS4='+ '\nPWD='/root'\nSHELL='/bin/sh'\nSHLVL='1'\nSSH_CLIENT='203.0.113.9 40000 22'\nSSH_CONNECTION='203.0.113.9 40000 198.51.100.7 22'\nUSER='root'\n", "", 0},
		{true, "echo a; echo ${x?unset}; echo never", "a\n", "sh: x: unset\n", 2},
		{true, "echo a\necho $LINENO\nnosuch\necho b", "a\n2\nb\n", "sh: nosuch: not found\n", 0},
		{true, "exit 5", "", "", 5},
		{true, "uname -a; cat /etc/hostname; false", "Linux gateway 4.14.180 #1 SMP Thu Jun  4 12:00:00 UTC 2020 armv7l GNU/Linux\ngateway\n", "", 1},
		{true, "cd /tmp && pwd; echo $PWD $OLDPWD", "/tmp\n/tmp /root\n", "", 0},
		{true, "history; echo $?", "0\n", "", 0},
		{true, "echo $HOSTNAME $PS1 x$TERM", "gateway \\w \\$ x\n", "", 0},
		{false, "echo a\n;\necho never\n", "a\n", "-sh: syntax error: unexpected \";\"\n", 2},
		{false, "eval ';' ; echo b\necho c\n", "", "-sh: eval: line 1: syntax error: unexpected \";\"\n", 2},
		{true, "echo a; ;; echo never", "", "sh: syntax error: unexpected \";;\"\n", 2},
		{false, "false\nexit\n", "", "", 1},
		{true, "false; exit", "", "", 1},
		{false, "echo a\nhistory\necho $?\n", "a\n0\n", "", 0}, // the history is line editing's: none without a pty
		{false, "cd /tmp\ncd /nope\necho $OLDPWD $LINENO\nexport A=1; env\n", "/root 3\nUSER=root\nSSH_CLIENT=203.0.113.9 40000 22\nSHLVL=1\nHOME=/root\nOLDPWD=/root\nPS1=\\u@\\h:\\w\\$ \nA=1\nLOGNAME=root\nPATH=/bin:/sbin:/usr/bin:/usr/sbin\nSHELL=/bin/sh\nPWD=/tmp\nSSH_CONNECTION=203.0.113.9 40000 198.51.100.7 22\n", "-sh: cd: line 2: can't cd to /nope: No such file or directory\n", 0},
	}
	for _, tt := range tests {
		if stdout, stderr, code := runSSH(tt.input, tt.exec); stdout != tt.stdout || stderr != tt.stderr || code != tt.code {
			t.Errorf("exec %v %q\n got: %q %q, exit %d\nwant: %q %q, exit %d",
				tt.exec, tt.input, stdout, stderr, code, tt.stdout, tt.stderr, tt.code)
		}
	}
}

// Who logged in and how the shell was started: $USER and $LOGNAME are the login's name (every user here
// has uid 0: whoami, the prompt say root); only the login shell on a pty is interactive, sh -c never
// (ash's iflag: a terminal and no -c); on a pty Dropbear adds TERM and SSH_TTY.
func TestShellKinds(t *testing.T) {
	pty := map[string]string{"TERM": "xterm", "SSH_TTY": "/dev/pts/0"}
	tests := []struct {
		sh   *Shell
		want string
	}{
		{NewLoginShell("admin"), "admin admin root vt102 smi\n"},
		{NewSSHShell("support", pty, true, false), "support support root xterm smi\n"},
		{NewSSHShell("support", pty, true, true), "support support root xterm\n"},
		{NewSSHShell("user", nil, false, false), "user user root s\n"},
	}
	for _, tt := range tests {
		if got, _, _ := tt.sh.Run("echo $USER $LOGNAME $(whoami) $TERM $-"); got != tt.want {
			t.Errorf("got %q, want %q", got, tt.want)
		}
	}
	if p := NewSSHShell("admin", pty, true, false).Prompt(); p != "root@gateway:~# " {
		t.Errorf("prompt: %q", p)
	}
}
