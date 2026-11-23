package services

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
	"honeypot-agent/internal/vfs"
)

const (
	ftpMaxLine       = 4096 // vsftpd's VSFTP_MAX_COMMAND_LINE, the \r\n included
	ftpMaxCommands   = 50
	ftpMaxLoginTries = 3   // max_login_fails
	vsftpdMaxLogin   = 128 // VSFTP_PASSWORD_MAX
)

// ftpIdleTimeout is vsftpd's idle_session_timeout (300s); after it vsftpd says "421 Timeout."
// and hangs up. A variable only so the test can shorten it.
var ftpIdleTimeout = 300 * time.Second

// ftpClients counts the open FTP sessions: vsftpd's STAT shows how many there were when a session started.
var ftpClients atomic.Int32

// RunFTP serves a fake vsftpd on address until ctx is cancelled.
// Returns nil after a clean shutdown, or an error if it fails (usually the port is in use).
func RunFTP(ctx context.Context, address string, nodeID string, shipper *shipper.Shipper) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	listener = limitConnections(listener, "FTP")
	defer listener.Close()

	log.Println("FTP node running")
	return serve(ctx, listener, func(conn net.Conn) { handleFTP(conn, nodeID, shipper) })
}

// handleFTP runs one FTP session: login, then commands, answered like vsftpd 3.0.3 (prelogin.c, postlogin.c).
// It never opens a data connection, so nothing is ever transferred.
func handleFTP(conn net.Conn, nodeID string, shipper *shipper.Shipper) {
	defer conn.Close()
	clients := int(ftpClients.Add(1))
	defer ftpClients.Add(-1)

	ip, portText, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		ip = conn.RemoteAddr().String()
	}
	port, _ := strconv.Atoi(portText)
	sessionID := newSessionID()

	// newEvent fills in the fields shared by every event of this session
	newEvent := func(eventType string) models.HoneypotEvent {
		return models.HoneypotEvent{
			Timestamp:  models.Now(),
			NodeID:     nodeID,
			EventType:  eventType,
			SourceIP:   ip,
			SourcePort: port,
			TargetPort: 21,
			Protocol:   "FTP",
			SessionID:  sessionID,
		}
	}

	reply := func(text string) {
		fmt.Fprint(conn, text+"\r\n")
	}

	shipper.EmitEvent(newEvent("session_start"))
	defer func() { shipper.EmitEvent(newEvent("session_end")) }()

	s := &ftpSession{remoteIP: ip, clients: clients, ascii: true, umask: 0o77}
	r := bufio.NewReaderSize(conn, ftpMaxLine)
	failed := 0
	var pace pacer // commands sent all at once are answered one by one (common.go)

	reply("220 (vsFTPd 3.0.3)")

	for i := 0; i < ftpMaxCommands; i++ {
		conn.SetDeadline(time.Now().Add(ftpIdleTimeout))
		raw, err := r.ReadSlice('\n') // a last line without \n is dropped, like vsftpd does
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			reply("500 Input line too long.")
			return
		case errors.Is(err, os.ErrDeadlineExceeded):
			conn.SetWriteDeadline(time.Now().Add(time.Second)) // the old deadline has passed
			reply("421 Timeout.")                              // like vsftpd (ftpcmdio.c)
			return
		case err != nil:
			return
		}

		// vsftpd strips the \r\n only; the command is what comes before the first space, in capitals
		line := strings.TrimRight(strings.TrimSuffix(string(raw), "\n"), "\r")
		if line == "" {
			continue // ignored, like vsftpd
		}
		pace.wait() // even before login: refused commands are logged too
		cmd, arg, _ := strings.Cut(line, " ")
		if line == " " {
			cmd = " "
		}
		cmd = asciiUpper(cmd)

		switch {
		case cmd == "QUIT":
			reply("221 Goodbye.")
			return

		case cmd == "USER" && !s.loggedIn:
			s.user = arg // even an unknown name gets asked for its password
			reply("331 Please specify the password.")

		case cmd == "PASS" && !s.loggedIn:
			if s.user == "" {
				reply("503 Login with USER first.")
				continue
			}
			success := ftpLoginOK(s.user, arg)

			event := newEvent("login_attempt")
			event.Credentials = &models.Credentials{
				Username: s.user,
				Password: arg,
				Success:  success,
			}
			shipper.EmitEvent(event)

			if success {
				s.login()
				reply("230 Login successful.")
				continue
			}
			time.Sleep(time.Second) // delay_failed_login
			reply("530 Login incorrect.")
			s.user = "" // the next PASS needs a USER again
			if failed++; failed >= ftpMaxLoginTries {
				return
			}

		case cmd == "USER" || cmd == "PASS": // after login: not logged, a PASS would put a password in the command
			reply(s.answer(cmd, arg))

		default:
			// every other command is logged, before login too
			event := newEvent("command_exec")
			event.PayloadDetails = &models.PayloadDetails{
				Command:      line,
				ExtractedURL: downloadURL(line),
			}
			shipper.EmitEvent(event)

			text := s.answer(cmd, arg)
			reply(text)
			if strings.HasPrefix(text, "500 HTTP") {
				return // vsftpd hangs up on HTTP
			}
		}
	}
}

// ftpLoginOK is vsftpd's handle_login: "ftp" and "anonymous" (any case) log in with any password,
// everyone else only with the shared weakCredentials. A password over 128 bytes always fails.
func ftpLoginOK(user, pass string) bool {
	if len(pass) > vsftpdMaxLogin {
		return false
	}
	return ftpAnonymous(user) || weakCredentials[user+":"+pass]
}

func ftpAnonymous(user string) bool {
	user = asciiUpper(user)
	return user == "FTP" || user == "ANONYMOUS"
}

// asciiUpper is C's toupper on each byte (strings.ToUpper would also change non-ASCII letters).
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// ftpSession is the state of one FTP session, as vsftpd keeps it.
type ftpSession struct {
	remoteIP  string
	clients   int    // FTP sessions open when this one started, this one included (STAT)
	user      string // after USER; "ftp" once logged in anonymously
	loggedIn  bool
	anonymous bool
	root      string // the chroot in the vfs: /home/ftp for anonymous, "" for the local users
	home, cwd string // inside the chroot
	ascii     bool   // TYPE A (the start) or TYPE I
	port      bool   // PORT / EPRT gave an address (we never connect to it)
	restart   int64  // REST
	umask     uint32 // SITE UMASK
}

// login starts the session of s.user: anonymous is chrooted in ftp's home, a local user (all of ours
// have /root as home in /etc/passwd) starts there and sees everything.
func (s *ftpSession) login() {
	s.loggedIn, s.anonymous = true, ftpAnonymous(s.user)
	s.home = "/root"
	if s.anonymous {
		s.user, s.root, s.home = "ftp", "/home/ftp", "/"
	}
	s.cwd = s.home
}

// path is where arg points inside the chroot: relative to the current directory, ~ = the login directory.
func (s *ftpSession) path(arg string) string {
	if arg == "~" || strings.HasPrefix(arg, "~/") {
		arg = s.home + arg[1:]
	}
	if !strings.HasPrefix(arg, "/") {
		arg = s.cwd + "/" + arg
	}
	return path.Clean(arg)
}

// stat and lstat look p (inside the chroot) up in the vfs. An empty name is no file, like stat("").
func (s *ftpSession) stat(arg string) (vfs.FileInfo, bool) {
	if arg == "" {
		return vfs.FileInfo{}, false
	}
	return vfs.Stat(path.Join(s.root, s.path(arg)))
}

func (s *ftpSession) lstat(p string) (vfs.FileInfo, bool) {
	return vfs.Lstat(path.Join(s.root, p))
}

// ftpFeatures is FEAT without the PASV / EPSV lines (pasv_enable=NO) and without SSL (no OpenSSL).
const ftpFeatures = "211-Features:\r\n EPRT\r\n MDTM\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End"

const ftpHelp = "214-The following commands are recognized.\r\n" +
	" ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n" +
	" MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n" +
	" RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n" +
	" XPWD XRMD\r\n" +
	"214 Help OK."

// answer is vsftpd's reply to a command (all but QUIT and the USER / PASS of the login). Multi-line replies
// are joined with \r\n.
func (s *ftpSession) answer(cmd, arg string) string {
	if !s.loggedIn { // parse_username_password in prelogin.c
		switch cmd {
		case "FEAT":
			return ftpFeatures
		case "OPTS":
			return ftpOpts(arg)
		}
		return "530 Please login with USER and PASS."
	}

	switch cmd { // process_post_login in postlogin.c
	case "PWD", "XPWD":
		return `257 "` + s.cwd + `" is the current directory` // (vsftpd doubles a ", no path here has one)
	case "CWD", "XCWD", "CDUP", "XCUP":
		if cmd == "CDUP" || cmd == "XCUP" {
			arg = ".."
		}
		if f, ok := s.stat(arg); ok && f.IsDir() {
			s.cwd = s.path(arg)
			return "250 Directory successfully changed."
		}
		return "550 Failed to change directory."
	case "RETR":
		return s.retr(arg)
	case "NOOP":
		return "200 NOOP ok."
	case "SYST":
		return "215 UNIX Type: L8"
	case "HELP":
		return ftpHelp
	case "LIST", "NLST":
		if !s.port {
			return "425 Use PORT or PASV first."
		}
		s.port = false
		return "425 Failed to establish connection."
	case "TYPE":
		switch asciiUpper(arg) {
		case "I", "L8", "L 8":
			s.ascii = false
			return "200 Switching to Binary mode."
		case "A", "A N":
			s.ascii = true
			return "200 Switching to ASCII mode."
		}
		return "500 Unrecognised TYPE command."
	case "PORT":
		return s.portCommand(arg)
	case "EPRT":
		return s.eprt(arg)
	case "REST":
		s.restart = ftpFileSize(arg)
		return fmt.Sprintf("350 Restart position accepted (%d).", s.restart)
	case "SIZE":
		if f, ok := s.stat(arg); ok && f.IsRegular() {
			return fmt.Sprintf("213 %d", f.Size)
		}
		return "550 Could not get file size."
	case "MDTM": // "MDTM time file" would set the time: not with write_enable off
		if f, ok := s.stat(arg); ok && f.IsRegular() {
			return "213 " + f.ModTime.UTC().Format("20060102150405")
		}
		return "550 Could not get file modification time."
	case "SITE":
		if !s.anonymous {
			return s.site(arg)
		}
	case "ABOR", "\xff\xf4\xff\xf2ABOR": // the second: an ABOR sent as urgent Telnet data
		return "225 No transfer to ABOR."
	case "STRU":
		if asciiUpper(arg) == "F" {
			return "200 Structure set to F."
		}
		return "504 Bad STRU command."
	case "MODE":
		if asciiUpper(arg) == "S" {
			return "200 Mode set to S."
		}
		return "504 Bad MODE command."
	case "ALLO":
		return "202 ALLO command ignored."
	case "REIN", "ACCT", "SMNT":
		return "502 " + cmd + " not implemented."
	case "FEAT":
		return ftpFeatures
	case "OPTS":
		return ftpOpts(arg)
	case "STAT":
		if arg == "" {
			return s.status()
		}
		return s.statFile(arg)
	case "USER":
		switch {
		case s.anonymous:
			return "530 Can't change from guest user."
		case arg == s.user:
			return "331 Any password will do."
		}
		return "530 Can't change to another user."
	case "PASS":
		return "230 Already logged in."
	case "GET", "POST", "HEAD", "OPTIONS", "CONNECT":
		return "500 HTTP protocol commands not allowed."
	}

	switch cmd {
	// no PASV (pasv_enable=NO), no writes (write_enable off), no SSL: refused, not unknown
	case "PASV", "EPSV", "STOR", "APPE", "STOU", "MKD", "XMKD", "RMD", "XRMD", "DELE", "RNFR", "RNTO",
		"SITE", "PBSZ", "PROT":
		return "550 Permission denied."
	}
	return "500 Unknown command."
}

func ftpOpts(arg string) string {
	if asciiUpper(arg) == "UTF8 ON" {
		return "200 Always in UTF8 mode."
	}
	return "501 Option not understood."
}

// retr is RETR: never a transfer. The checks come in vsftpd's order; only the failed connection
// forgets the PORT.
func (s *ftpSession) retr(arg string) string {
	restart := s.restart
	s.restart = 0
	if !s.port {
		return "425 Use PORT or PASV first."
	}
	if s.ascii && restart != 0 {
		return "550 No support for resume of ASCII transfer."
	}
	if f, ok := s.stat(arg); !ok || !f.IsRegular() {
		return "550 Failed to open file."
	}
	s.port = false
	return "425 Failed to establish connection."
}

// portCommand is PORT h1,h2,h3,h4,p1,p2. vsftpd (port_promiscuous=NO) accepts only the client's own address
// and a port from 1024: an FTP bounce to anyone else gets "Illegal PORT command".
func (s *ftpSession) portCommand(arg string) string {
	s.port = false
	v, ok := ftpNumbers(arg, ",", 6)
	if !ok || !s.dataAddressOK(v[:4], int(v[4])<<8|int(v[5])) {
		return "500 Illegal PORT command."
	}
	s.port = true
	return "200 PORT command successful. Consider using PASV."
}

// eprt is EPRT |1|address|port|; IPv6 (2) is a "bad protocol" on an IPv4 server.
func (s *ftpSession) eprt(arg string) string {
	s.port = false
	before, rest, _ := strings.Cut(arg, "|")
	proto, rest, _ := strings.Cut(rest, "|")
	if before != "" {
		return "500 Bad EPRT command."
	}
	if cAtoi(proto) != 1 {
		return "500 Bad EPRT protocol."
	}
	address, rest, _ := strings.Cut(rest, "|")
	portText, after, _ := strings.Cut(rest, "|")
	ip, ok := ftpNumbers(address, ".", 4)
	port := cAtoi(portText)
	if !ok || after != "" || portText == "" || port < 0 || port > 65535 {
		return "500 Bad EPRT command."
	}
	if !s.dataAddressOK(ip, port) {
		return "500 Illegal EPRT command."
	}
	s.port = true
	return "200 EPRT command successful. Consider using EPSV."
}

func (s *ftpSession) dataAddressOK(ip []byte, port int) bool {
	return net.IP(ip).Equal(net.ParseIP(s.remoteIP)) && port >= 1024
}

// ftpNumbers is vsf_sysutil_parse_uchar_string_sep: exactly n numbers 0-255 separated by sep, each read
// with atoi (so an empty one is 0).
func ftpNumbers(text, sep string, n int) ([]byte, bool) {
	out := make([]byte, n)
	for i := range n {
		field, rest, _ := strings.Cut(text, sep)
		if (i < n-1) == (rest == "") { // too few or too many fields
			return nil, false
		}
		v := cAtoi(field)
		if v < 0 || v > 255 {
			return nil, false
		}
		out[i], text = byte(v), rest
	}
	return out, true
}

// cAtoi is C's atoi: leading spaces, a sign, then the digits up to the first other character.
func cAtoi(text string) int {
	text = strings.TrimLeft(text, " \t\n\v\f\r")
	sign := 1
	if text != "" && (text[0] == '-' || text[0] == '+') {
		if text[0] == '-' {
			sign = -1
		}
		text = text[1:]
	}
	n := 0
	for i := 0; i < len(text) && '0' <= text[i] && text[i] <= '9' && n < 1<<24; i++ {
		n = n*10 + int(text[i]-'0')
	}
	return sign * n // capped: anything that large is out of range anyway
}

// ftpFileSize is vsftpd's REST number: only digits, at most 15 of them, else 0.
func ftpFileSize(text string) int64 {
	if len(text) > 15 {
		return 0
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || strings.ContainsAny(text, "+-") {
		return 0
	}
	return n
}

// site is SITE for a local user: only UMASK and HELP (CHMOD needs write_enable).
func (s *ftpSession) site(arg string) string {
	sub, value, _ := strings.Cut(arg, " ")
	switch asciiUpper(sub) {
	case "UMASK":
		if value == "" {
			return "200 Your current UMASK is " + ftpOctal(s.umask)
		}
		var n uint32 // vsf_sysutil_octal_to_uint: the octal digits up to the first other character
		for i := 0; i < len(value) && '0' <= value[i] && value[i] <= '7'; i++ {
			n = n<<3 + uint32(value[i]-'0')
		}
		s.umask = n & 0o777
		return "200 UMASK set to " + ftpOctal(s.umask)
	case "HELP":
		return "214 UMASK HELP"
	}
	return "500 Unknown SITE command."
}

func ftpOctal(n uint32) string {
	if n == 0 {
		return "0"
	}
	return "0" + strconv.FormatUint(uint64(n), 8)
}

// status is STAT without an argument (the reply nmap's ftp-syst shows).
func (s *ftpSession) status() string {
	typ := "BINARY"
	if s.ascii {
		typ = "ASCII"
	}
	return "211-FTP server status:\r\n" +
		"     Connected to " + s.remoteIP + "\r\n" +
		"     Logged in as " + s.user + "\r\n" +
		"     TYPE: " + typ + "\r\n" +
		"     No session bandwidth limit\r\n" +
		"     Session timeout in seconds is 300\r\n" +
		"     Control connection is plain text\r\n" +
		"     Data connections will be plain text\r\n" +
		"     At session startup, client count was " + strconv.Itoa(s.clients) + "\r\n" +
		"     vsFTPd 3.0.3 - secure, fast, stable\r\n" +
		"211 End of status"
}

// statFile is STAT PATH: ls -la of PATH on the control connection (handle_dir_common). PATH is a directory,
// or a filter (a name or a pattern) inside the directory before its last /, or in the current one.
// Options ("-l") are dropped; a path that doesn't exist lists nothing.
func (s *ftpSession) statFile(arg string) string {
	filter := arg
	if strings.HasPrefix(arg, "-") {
		_, filter, _ = strings.Cut(arg, " ")
	}
	dir := "."
	if f, ok := s.stat(filter); ok && f.IsDir() {
		dir, filter = filter, ""
	} else if i := strings.LastIndex(filter, "/"); i >= 0 {
		dir, filter = filter[:i], filter[i+1:]
		if dir == "" {
			dir = "/"
		}
	}

	var out strings.Builder
	out.WriteString("213-Status follows:\r\n")
	if f, ok := s.stat(dir); ok && f.IsDir() {
		dir = s.path(dir)
		names := append([]string{".", ".."}, vfs.ReadDir(path.Join(s.root, dir))...)
		for _, name := range names {
			if match, _ := path.Match(filter, name); filter != "" && !match {
				continue
			}
			if f, ok := s.lstat(path.Join(dir, name)); ok {
				out.WriteString(ftpListLine(name, f))
			}
		}
	}
	out.WriteString("213 End of status")
	return out.String()
}

// ftpListLine is one line of vsftpd's listing (build_dir_line in ls.c): numeric owner and group.
func ftpListLine(name string, f vfs.FileInfo) string {
	if f.Target != "" {
		name += " -> " + f.Target
	}
	date := f.ModTime.UTC().Format("Jan 02 15:04")
	if age := time.Since(f.ModTime); age < 0 || age > 182*24*time.Hour {
		date = f.ModTime.UTC().Format("Jan 02  2006")
	}
	return fmt.Sprintf("%s %4d %-8d %-8d %8d %s %s\r\n", f.Mode, f.Links, 0, 0, f.Size, date, name)
}
