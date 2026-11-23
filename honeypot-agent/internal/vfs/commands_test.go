package vfs

import "testing"

// mkdir and sync like BusyBox 1.30.1's: every expected output here is what the real one printed for the
// same line (ash_oracle, typed with its newline; "ls -1" because the oracle has no terminal, where ls
// prints one name a line anyway).
func TestMkdirSync(t *testing.T) {
	tests := []struct {
		line string
		want string
		code int
	}{
		{`mkdir /tmp; echo $?; mkdir -p /tmp; echo $?`, "mkdir: can't create directory '/tmp': File exists\n1\n0\n", 0},
		{`cd /tmp; mkdir r1; cd r1; mkdir a a; echo $?; ls -1`, "mkdir: can't create directory 'a': File exists\n1\na\n", 0},
		{`cd /tmp; mkdir r2; cd r2; mkdir a/b/c; echo $?; mkdir -p a/b/c; echo $?; ls -1 a/b`, "mkdir: can't create directory 'a/b/c': No such file or directory\n1\n0\nc\n", 0},
		{`cd /tmp; mkdir r3; cd r3; mkdir -pv x/y; echo $?; mkdir -pv x/y x/z; echo $?`, "created directory: 'x/'\ncreated directory: 'x/y'\n0\ncreated directory: 'x/z'\n0\n", 0},
		{`cd /tmp; mkdir r4; cd r4; mkdir -v z; mkdir --verbose zz; mkdir --parents q/w; ls -1; ls -1 q`, "created directory: 'z'\ncreated directory: 'zz'\nq\nz\nzz\nw\n", 0},
		{`mkdir; echo $?`, "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: mkdir [OPTIONS] DIRECTORY...\n\nCreate DIRECTORY\n\n\t-m MODE\tMode\n\t-p\tNo error if exists; make parent directories as needed\n1\n", 0},
		{`cd /tmp; mkdir r5; cd r5; mkdir -m 755 m; mkdir -m u+x,go=rx n; mkdir -m0700 o; echo $?; ls -1`, "0\nm\nn\no\n", 0},
		{`mkdir -m xyz /tmp/r6; echo $?; mkdir -m 999 /tmp/r6; echo $?; ls -1 -d /tmp/r6`, "mkdir: invalid mode 'xyz'\n1\nmkdir: invalid mode '999'\n1\nls: /tmp/r6: No such file or directory\n", 1},
		{`mkdir -x /tmp/r7; echo $?`, "mkdir: invalid option -- x\nBusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: mkdir [OPTIONS] DIRECTORY...\n\nCreate DIRECTORY\n\n\t-m MODE\tMode\n\t-p\tNo error if exists; make parent directories as needed\n1\n", 0},
		{`mkdir --mode; echo $?`, "mkdir: option `--mode' requires an argument\nBusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: mkdir [OPTIONS] DIRECTORY...\n\nCreate DIRECTORY\n\n\t-m MODE\tMode\n\t-p\tNo error if exists; make parent directories as needed\n1\n", 0},
		{`mkdir --foo x; echo $?`, "mkdir: unrecognized option `--foo'\nBusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: mkdir [OPTIONS] DIRECTORY...\n\nCreate DIRECTORY\n\n\t-m MODE\tMode\n\t-p\tNo error if exists; make parent directories as needed\n1\n", 0},
		{`cd /tmp; mkdir r8; cd r8; touch f; mkdir f; mkdir -p f; mkdir -p f/g; mkdir f/g; echo $?`, "mkdir: can't create directory 'f': File exists\nmkdir: can't create directory 'f': File exists\nmkdir: can't create directory 'f/': Not a directory\nmkdir: can't create directory 'f/g': Not a directory\n1\n", 0},
		{`cd /tmp; mkdir r9; cd r9; mkdir b -p c/d; ls -1; ls -1 c`, "b\nc\nd\n", 0},
		{`mkdir /etc/passwd; mkdir -p /etc/passwd/x; echo $?`, "mkdir: can't create directory '/etc/passwd': File exists\nmkdir: can't create directory '/etc/passwd/': Not a directory\n1\n", 0},
		{`cd /tmp; mkdir r10; cd r10; mkdir -- -dash; ls -1`, "-dash\n", 0},
		{`cd /tmp; mkdir r11; cd r11; mkdir a /nope/b c; echo $?; ls -1`, "mkdir: can't create directory '/nope/b': No such file or directory\n1\na\nc\n", 0},
		{`mkdir /; echo $?; mkdir .; echo $?; mkdir -p /; echo $?`, "0\n0\n0\n", 0},
		{`mkdir ..; echo $?; mkdir /tmp/; echo $?`, "mkdir: can't create directory '..': File exists\n1\nmkdir: can't create directory '/tmp/': File exists\n1\n", 0},
		{`cd /tmp; mkdir r12; cd r12; mkdir -p a//b/; ls -1 a`, "b\n", 0},
		{`mkdir ''; echo $?; mkdir -p ''; echo $?`, "mkdir: can't create directory '': No such file or directory\n1\nmkdir: can't create directory '': No such file or directory\n1\n", 0},
		{`mkdir /proc/x; echo $?`, "mkdir: can't create directory '/proc/x': No such file or directory\n1\n", 0},
		{`cd /tmp; mkdir r13 && cd r13 && mkdir x && cd x && pwd`, "/tmp/r13/x\n", 0},
		{`sync; echo $?`, "0\n", 0},
		{`sync -x; echo $?; sync /tmp; echo $?`, "sync: ignoring all arguments\n0\nsync: ignoring all arguments\n0\n", 0},
		{`type sync; which sync`, "sync is /bin/sync\n/bin/sync\n", 0},
	}
	for _, tt := range tests {
		if got, code := runTyped(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
	}
}
