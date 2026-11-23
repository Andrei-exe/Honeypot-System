package vfs

import (
	"net"
	"strconv"
	"strings"
)

// The download tools of BusyBox 1.30.1 (networking/wget.c, tftp.c, ftpgetput.c) with Buildroot
// 2019.05.3's config (wget without HTTPS); their messages were measured on the real BusyBox. Nothing
// is ever downloaded: the router's way out is blocked upstream (connections time out), and names don't
// resolve except those in /etc/hosts (resolv.conf points at 192.168.1.1, the router itself, which runs
// no DNS server). The services log the URL (extracted_url) before the line runs.

const wgetUsage = " [-c|--continue] [--spider] [-q|--quiet] [-O|--output-document FILE]\n" +
	"\t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n" +
	"\t[-S|--server-response] [-U|--user-agent AGENT] [-T SEC] URL...\n\n" +
	"Retrieve files via HTTP or FTP\n\n" +
	"\t--spider\tOnly check URL existence: $? is 0 if exists\n" +
	"\t-c\t\tContinue retrieval of aborted transfer\n" +
	"\t-q\t\tQuiet\n" +
	"\t-P DIR\t\tSave to DIR (default .)\n" +
	"\t-S    \t\tShow server response\n" +
	"\t-T SEC\t\tNetwork read timeout is SEC seconds\n" +
	"\t-O FILE\t\tSave to FILE ('-' for stdout)\n" +
	"\t-U STR\t\tUse STR for User-Agent header\n" +
	"\t-Y on/off\tUse proxy"

// wgetLong are wget's long options (Buildroot: DESKTOP adds the ignored ones). Like in wget.c, those
// without a letter get a byte of their own: \xff and \xfe take a value, \xf0 marks the ignored ones.
var wgetLong = map[string]byte{
	"continue": 'c', "quiet": 'q', "server-response": 'S', "output-document": 'O', "directory-prefix": 'P',
	"proxy": 'Y', "user-agent": 'U', "timeout": 'T', "tries": 't', "header": '\xff', "post-data": '\xfe',
	"spider": '\xfd', "no-check-certificate": '\xfc', "passive-ftp": '\xf0', "no-cache": '\xf0',
	"no-verbose": '\xf0', "no-clobber": '\xf0', "no-host-directories": '\xf0', "no-parent": '\xf0',
}

// wget [OPTIONS] URL...: it says where it connects, then dies on the first URL.
func (s *Shell) wget(args []string) (string, int, bool) {
	opts, urls, complaint := getopt("wget", args, "cqSO:P:Y:U:T:t:n::\xff:\xfe:\xfd\xfc\xf0", wgetLong)
	if complaint != "" {
		return usageAfter(complaint, "wget", wgetUsage)
	}
	for _, t := range opts['T'] { // -T SEC must be a number (xatoi_positive)
		if _, err := strconv.ParseUint(t, 10, 31); err != nil {
			return "wget: invalid number '" + t + "'\n", 1, false
		}
	}
	if len(urls) == 0 {
		return usage("wget", wgetUsage)
	}

	// parse_url: "http://" or "ftp://" (no https in this build), or no scheme at all = http
	url, host, port := urls[0], urls[0], 80
	if scheme, rest, ok := strings.Cut(url, "://"); ok {
		switch scheme {
		case "http":
		case "ftp":
			port = 21
		default:
			return "wget: not an http or ftp url: " + url + "\n", 1, false
		}
		host = rest
	}
	if end := strings.IndexAny(host, "/?#"); end >= 0 {
		host = host[:end]
	}
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:] // user:password@
	}
	dotted, ip, v6, complaint := s.address(host, port)
	if complaint != "" {
		return "wget: " + complaint + "\n", 1, false
	}
	out := ""
	if opts['q'] == nil {
		out = "Connecting to " + host + " (" + dotted + ")\n"
	}
	return out + cantConnect("wget", ip, v6), 1, false
}

const tftpUsage = " [OPTIONS] HOST [PORT]\n\nTransfer a file from/to tftp server\n\n" +
	"\t-l FILE\tLocal FILE\n\t-r FILE\tRemote FILE\n\t-g\tGet file\n\t-p\tPut file\n" +
	"\t-b SIZE\tTransfer blocks of SIZE octets"

// tftp -g|-p [-l LOCAL] [-r REMOTE] [-b SIZE] HOST [PORT]. UDP: the request gets no answer, so after
// its retries (about 11s on a real one, none here) it gives up with "timeout".
func (s *Shell) tftp(args []string) (string, int, bool) {
	opts, rest, complaint := getopt("tftp", args, "gpl:r:b:", nil)
	if complaint != "" {
		return usageAfter(complaint, "tftp", tftpUsage)
	}
	get := opts['g'] != nil
	if get == (opts['p'] != nil) { // exactly one of -g and -p
		return usage("tftp", tftpUsage)
	}
	if b := opts['b']; b != nil {
		if n, err := strconv.ParseUint(b[len(b)-1], 10, 32); err != nil || n < 8 || n > 65564 {
			return "tftp: bad blocksize '" + b[len(b)-1] + "'\n", 1, false
		}
	}
	remote, local := lastValue(opts['r']), lastValue(opts['l'])
	switch {
	case opts['r'] != nil && opts['l'] == nil:
		local = remote[strings.LastIndexByte(remote, '/')+1:] // saved under the remote file's name
	case opts['r'] == nil:
		remote = local
	}
	if (opts['r'] == nil && opts['l'] == nil) || len(rest) == 0 {
		return usage("tftp", tftpUsage)
	}
	port := 69
	if len(rest) > 1 {
		if n, err := strconv.ParseUint(rest[1], 10, 16); err == nil {
			port = int(n) // not a number: tftp keeps 69 (bb_lookup_port)
		}
	}
	_, ip, v6, complaint := s.address(rest[0], port)
	if complaint != "" {
		return "tftp: " + complaint + "\n", 1, false
	}
	if local != "-" {
		p := resolve(s.cwd, local)
		if get { // created (emptied) before the transfer, deleted when it fails
			if _, err := s.writeFile(local, "", false); err != nil {
				return "tftp: can't open '" + local + "': " + err.Error() + "\n", 1, false
			}
			delete(s.files, p)
			delete(s.mtimes, p)
		} else if _, ok := s.readFile(p); !ok && !s.isDir(p) {
			return "tftp: can't open '" + local + "': No such file or directory\n", 1, false
		}
	}
	if v6 && !ip.IsLoopback() {
		return "tftp: sendto: Network is unreachable\n", 1, false
	}
	return "tftp: timeout\n", 1, false
}

const ftpgetUsage = " [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE\n\nDownload a file via FTP\n\n" +
	"\t-c\tContinue previous transfer\n\t-v\tVerbose\n\t-u USER\tUsername\n\t-p PASS\tPassword\n\t-P NUM\tPort"

// ftpget [-cv] [-u USER] [-p PASS] [-P PORT] HOST [LOCAL_FILE] REMOTE_FILE. Not in Buildroot's default
// config, but this vendor enabled it (like telnetd).
func (s *Shell) ftpget(args []string) (string, int, bool) {
	opts, rest, complaint := getopt("ftpget", args, "cvu:p:P:", nil)
	if complaint != "" {
		return usageAfter(complaint, "ftpget", ftpgetUsage)
	}
	if len(rest) < 2 || len(rest) > 3 {
		return usage("ftpget", ftpgetUsage)
	}
	port := 21
	if n, err := strconv.ParseUint(lastValue(opts['P']), 10, 16); err == nil {
		port = int(n)
	}
	dotted, ip, v6, complaint := s.address(rest[0], port)
	if complaint != "" {
		return "ftpget: " + complaint + "\n", 1, false
	}
	out := ""
	if opts['v'] != nil { // simplification: a real one prints it on its output, not with the error
		out = "Connecting to " + rest[0] + " (" + dotted + ")\n"
	}
	return out + cantConnect("ftpget", ip, v6), 1, false
}

// lastValue is the value of an option given last ("" = not given).
func lastValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

// address resolves "host[:port]" like BusyBox's xhost2sockaddr (libbb/xconnect.c): "[v6]:port" or
// "v4:port", an IP or a name from /etc/hosts. It returns the address as BusyBox prints it ("1.2.3.4:80",
// "[::1]:80"), or complaint: "bad address 'x'", "bad port spec 'x'".
func (s *Shell) address(host string, port int) (dotted string, ip net.IP, v6 bool, complaint string) {
	name, portText, hasPort := host, "", false
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 || end+1 < len(host) && host[end+1] != ':' {
			return "", nil, false, "bad address '" + host + "'"
		}
		name = host[1:end]
		if end+1 < len(host) {
			portText, hasPort = host[end+2:], true
		}
	} else if strings.Count(host, ":") == 1 { // more than one ":" = an IPv6 address without a port
		name, portText, hasPort = strings.Cut(host, ":")
	}
	if hasPort {
		n, err := strconv.ParseUint(portText, 10, 16)
		if err != nil {
			return "", nil, false, "bad port spec '" + host + "'"
		}
		port = int(n)
	}

	ip = net.ParseIP(name)
	if ip == nil {
		found, _ := s.lookupHost(name)
		ip = net.ParseIP(found)
		name = found
	}
	if ip == nil {
		return "", nil, false, "bad address '" + host + "'"
	}
	if strings.Contains(name, ":") {
		return "[" + ip.String() + "]:" + strconv.Itoa(port), ip, true, ""
	}
	return ip.String() + ":" + strconv.Itoa(port), ip, false, ""
}

// lookupHost finds a name in /etc/hosts (the attacker may have changed it), like uClibc's resolver:
// its address and the line's first name (the canonical one). "" = not there.
func (s *Shell) lookupHost(name string) (ip, canonical string) {
	hosts, _ := s.readFile("/etc/hosts")
	for _, line := range splitLines(hosts) {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
			continue
		}
		for _, n := range fields[1:] {
			if strings.EqualFold(n, name) {
				return fields[0], fields[1]
			}
		}
	}
	return "", ""
}

// cantConnect is xconnect's message when the router can't reach ip: its own addresses refuse
// (simplification: even port 80, where lighttpd listens), there is no IPv6 route, other LAN addresses
// don't answer and the rest of the internet is blocked upstream.
func cantConnect(applet string, ip net.IP, v6 bool) string {
	ip4 := ip.To4()
	reason := "Connection timed out"
	switch {
	case ip.IsLoopback() || ip.IsUnspecified() || ip.Equal(net.IPv4(192, 168, 1, 1)):
		reason = "Connection refused"
	case v6:
		reason = "Network is unreachable"
	case ip4[0] == 192 && ip4[1] == 168 && ip4[2] == 1:
		reason = "No route to host"
	}
	if v6 {
		return applet + ": can't connect to remote host: " + reason + "\n"
	}
	return applet + ": can't connect to remote host (" + ip.String() + "): " + reason + "\n"
}
