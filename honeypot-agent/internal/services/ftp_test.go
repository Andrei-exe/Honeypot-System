package services

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"honeypot-agent/internal/shipper"
	"honeypot-agent/internal/vfs"
)

// ftpStep is one line sent and the whole reply. A line starting with \x00 is special: "\x00long N" = N x "A",
// "\x00raw TEXT" = TEXT without \r\n, "\x00close" = the client stops sending (half-close).
type ftpStep struct{ send, want string }

// ftpEOF ends a reply when the server hung up.
const ftpEOF = "(closed)"

var ftpReplyEnd = regexp.MustCompile(`(^|\r\n)\d{3} [^\r\n]*\r\n$`)

// ftpRead reads one reply: up to its last line ("DDD text"), the server hanging up or the timeout.
func ftpRead(conn net.Conn, timeout time.Duration) string {
	conn.SetReadDeadline(time.Now().Add(timeout))
	var got []byte
	buf := make([]byte, 4096)
	for !ftpReplyEnd.Match(got) {
		n, err := conn.Read(buf)
		got = append(got, buf[:n]...)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			return string(got) + ftpEOF
		}
	}
	return string(got)
}

// Whole FTP sessions compared with the real vsftpd 3.0.3 (built from source without PAM and SSL, like
// Buildroot's, run with our /etc/vsftpd.conf; the files it was asked about made like ours: same content,
// mode, date, tmpfs directories). The replies are copied from it, byte for byte.
func TestFTPLikeVsftpd(t *testing.T) {
	old := routerDelay
	routerDelay = time.Millisecond // ~250 commands: without the pacer's 200-300ms each
	t.Cleanup(func() { routerDelay = old })

	sessions := []struct {
		name  string
		steps []ftpStep
	}{
		{"prelogin", []ftpStep{
			{"", ""},
			{" ", "530 Please login with USER and PASS.\r\n"},
			{"  ", "530 Please login with USER and PASS.\r\n"},
			{"syst", "530 Please login with USER and PASS.\r\n"},
			{"FEAT", "211-Features:\r\n EPRT\r\n MDTM\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n"},
			{"OPTS UTF8 ON", "200 Always in UTF8 mode.\r\n"},
			{"opts utf8 on", "200 Always in UTF8 mode.\r\n"},
			{"OPTS foo", "501 Option not understood.\r\n"},
			{"HELP", "530 Please login with USER and PASS.\r\n"},
			{"GET / HTTP/1.0", "530 Please login with USER and PASS.\r\n"},
			{"PASS x", "503 Login with USER first.\r\n"},
			{"USER", "331 Please specify the password.\r\n"},
			{"PASS x", "503 Login with USER first.\r\n"},
			{"USER root", "331 Please specify the password.\r\n"},
			{"PASS wrong", "530 Login incorrect.\r\n"},
			{"PASS root", "503 Login with USER first.\r\n"},
			{"USER root", "331 Please specify the password.\r\n"},
			{"PASS wrong2", "530 Login incorrect.\r\n"},
			{"USER bob", "331 Please specify the password.\r\n"},
			{"PASS x", "530 Login incorrect.\r\n"},
			{"NOOP", "(closed)"},
		}},
		{"anonymous", []ftpStep{
			{"USER anonymous", "331 Please specify the password.\r\n"},
			{"PASS x", "230 Login successful.\r\n"},
			{"PWD", "257 \"/\" is the current directory\r\n"},
			{"CWD /etc", "550 Failed to change directory.\r\n"},
			{"CWD ..", "250 Directory successfully changed.\r\n"},
			{"CDUP", "250 Directory successfully changed.\r\n"},
			{"CWD ~", "250 Directory successfully changed.\r\n"},
			{"PWD", "257 \"/\" is the current directory\r\n"},
			{"CWD /", "250 Directory successfully changed.\r\n"},
			{"STAT", "211-FTP server status:\r\n     Connected to 127.0.0.1\r\n     Logged in as ftp\r\n     TYPE: ASCII\r\n     No session bandwidth limit\r\n     Session timeout in seconds is 300\r\n     Control connection is plain text\r\n     Data connections will be plain text\r\n     At session startup, client count was 1\r\n     vsFTPd 3.0.3 - secure, fast, stable\r\n211 End of status\r\n"},
			{"STAT /", "213-Status follows:\r\ndr-xr-xr-x    2 0        0              40 Jun 04  2020 .\r\ndr-xr-xr-x    2 0        0              40 Jun 04  2020 ..\r\n213 End of status\r\n"},
			{"STAT -la", "213-Status follows:\r\ndr-xr-xr-x    2 0        0              40 Jun 04  2020 .\r\ndr-xr-xr-x    2 0        0              40 Jun 04  2020 ..\r\n213 End of status\r\n"},
			{"STAT /nope", "213-Status follows:\r\n213 End of status\r\n"},
			{"SIZE /x", "550 Could not get file size.\r\n"},
			{"MDTM /", "550 Could not get file modification time.\r\n"},
			{"RETR x", "425 Use PORT or PASV first.\r\n"},
			{"LIST", "425 Use PORT or PASV first.\r\n"},
			{"SITE HELP", "550 Permission denied.\r\n"},
			{"SITE UMASK", "550 Permission denied.\r\n"},
			{"USER anonymous", "530 Can't change from guest user.\r\n"},
			{"USER root", "530 Can't change from guest user.\r\n"},
			{"PASS x", "230 Already logged in.\r\n"},
			{"STOR x", "550 Permission denied.\r\n"},
			{"MKD x", "550 Permission denied.\r\n"},
			{"PORT 127,0,0,1,4,1", "200 PORT command successful. Consider using PASV.\r\n"},
			{"RETR /", "550 Failed to open file.\r\n"},
			{"RETR /etc/passwd", "550 Failed to open file.\r\n"},
			{"QUIT", "221 Goodbye.\r\n"},
		}},
		{"ftpuser", []ftpStep{
			{"USER FtP", "331 Please specify the password.\r\n"},
			{"PASS ", "230 Login successful.\r\n"},
			{"STAT", "211-FTP server status:\r\n     Connected to 127.0.0.1\r\n     Logged in as ftp\r\n     TYPE: ASCII\r\n     No session bandwidth limit\r\n     Session timeout in seconds is 300\r\n     Control connection is plain text\r\n     Data connections will be plain text\r\n     At session startup, client count was 1\r\n     vsFTPd 3.0.3 - secure, fast, stable\r\n211 End of status\r\n"},
			{"TYPE I", "200 Switching to Binary mode.\r\n"},
			{"STAT", "211-FTP server status:\r\n     Connected to 127.0.0.1\r\n     Logged in as ftp\r\n     TYPE: BINARY\r\n     No session bandwidth limit\r\n     Session timeout in seconds is 300\r\n     Control connection is plain text\r\n     Data connections will be plain text\r\n     At session startup, client count was 1\r\n     vsFTPd 3.0.3 - secure, fast, stable\r\n211 End of status\r\n"},
			{"SITE CHMOD 777 x", "550 Permission denied.\r\n"},
			{"QUIT", "221 Goodbye.\r\n"},
		}},
		{"admin", []ftpStep{
			{"USER admin", "331 Please specify the password.\r\n"},
			{"PASS admin", "230 Login successful.\r\n"},
			{"PWD", "257 \"/root\" is the current directory\r\n"},
			{"STAT", "211-FTP server status:\r\n     Connected to 127.0.0.1\r\n     Logged in as admin\r\n     TYPE: ASCII\r\n     No session bandwidth limit\r\n     Session timeout in seconds is 300\r\n     Control connection is plain text\r\n     Data connections will be plain text\r\n     At session startup, client count was 1\r\n     vsFTPd 3.0.3 - secure, fast, stable\r\n211 End of status\r\n"},
			{"USER admin", "331 Any password will do.\r\n"},
			{"USER root", "530 Can't change to another user.\r\n"},
			{"QUIT", "221 Goodbye.\r\n"},
		}},
		{"root_cwd", []ftpStep{
			{"user root", "331 Please specify the password.\r\n"},
			{"pass root", "230 Login successful.\r\n"},
			{"PWD", "257 \"/root\" is the current directory\r\n"},
			{"XPWD", "257 \"/root\" is the current directory\r\n"},
			{"CWD /etc", "250 Directory successfully changed.\r\n"},
			{"PWD", "257 \"/etc\" is the current directory\r\n"},
			{"CWD ppp/peers", "250 Directory successfully changed.\r\n"},
			{"PWD", "257 \"/etc/ppp/peers\" is the current directory\r\n"},
			{"CDUP", "250 Directory successfully changed.\r\n"},
			{"PWD", "257 \"/etc/ppp\" is the current directory\r\n"},
			{"XCUP", "250 Directory successfully changed.\r\n"},
			{"PWD", "257 \"/etc\" is the current directory\r\n"},
			{"CWD /nope", "550 Failed to change directory.\r\n"},
			{"CWD /etc/passwd", "550 Failed to change directory.\r\n"},
			{"CWD", "550 Failed to change directory.\r\n"},
			{"CWD ~", "250 Directory successfully changed.\r\n"},
			{"PWD", "257 \"/root\" is the current directory\r\n"},
			{"CWD ~/../tmp", "250 Directory successfully changed.\r\n"},
			{"PWD", "257 \"/tmp\" is the current directory\r\n"},
			{"XCWD /", "250 Directory successfully changed.\r\n"},
			{"CDUP", "250 Directory successfully changed.\r\n"},
			{"PWD", "257 \"/\" is the current directory\r\n"},
			{"TYPE", "500 Unrecognised TYPE command.\r\n"},
			{"TYPE X", "500 Unrecognised TYPE command.\r\n"},
			{"TYPE i", "200 Switching to Binary mode.\r\n"},
			{"TYPE L 8", "200 Switching to Binary mode.\r\n"},
			{"TYPE L8", "200 Switching to Binary mode.\r\n"},
			{"TYPE A N", "200 Switching to ASCII mode.\r\n"},
			{"TYPE a", "200 Switching to ASCII mode.\r\n"},
			{"STAT", "211-FTP server status:\r\n     Connected to 127.0.0.1\r\n     Logged in as root\r\n     TYPE: ASCII\r\n     No session bandwidth limit\r\n     Session timeout in seconds is 300\r\n     Control connection is plain text\r\n     Data connections will be plain text\r\n     At session startup, client count was 1\r\n     vsFTPd 3.0.3 - secure, fast, stable\r\n211 End of status\r\n"},
			{"CWD /etc/ppp", "250 Directory successfully changed.\r\n"},
			{"PWD", "257 \"/etc/ppp\" is the current directory\r\n"},
			{"QUIT", "221 Goodbye.\r\n"},
		}},
		{"root_files", []ftpStep{
			{"USER root", "331 Please specify the password.\r\n"},
			{"PASS root", "230 Login successful.\r\n"},
			{"SIZE /etc/ppp/peers/isp", "213 109\r\n"},
			{"SIZE /etc/ppp", "550 Could not get file size.\r\n"},
			{"SIZE /nope", "550 Could not get file size.\r\n"},
			{"SIZE", "550 Could not get file size.\r\n"},
			{"SIZE etc/ppp/peers/isp", "550 Could not get file size.\r\n"},
			{"SIZE ~/../etc/ppp/peers/isp", "213 109\r\n"},
			{"MDTM /etc/ppp/peers/isp", "213 20200604120000\r\n"},
			{"MDTM /etc/ppp", "550 Could not get file modification time.\r\n"},
			{"MDTM 20200101000000 /etc/ppp/peers/isp", "550 Could not get file modification time.\r\n"},
			{"MDTM", "550 Could not get file modification time.\r\n"},
			{"STAT /etc/ppp/peers", "213-Status follows:\r\ndrwxr-xr-x    2 0        0              60 Jun 04  2020 .\r\ndrwxr-xr-x    3 0        0              80 Jun 04  2020 ..\r\n-rw-r--r--    1 0        0             109 Jun 04  2020 isp\r\n213 End of status\r\n"},
			{"STAT /etc/ppp/peers/isp", "213-Status follows:\r\n-rw-r--r--    1 0        0             109 Jun 04  2020 isp\r\n213 End of status\r\n"},
			{"STAT /etc/ppp/peers/i*", "213-Status follows:\r\n-rw-r--r--    1 0        0             109 Jun 04  2020 isp\r\n213 End of status\r\n"},
			{"STAT -l /etc/ppp/peers", "213-Status follows:\r\ndrwxr-xr-x    2 0        0              60 Jun 04  2020 .\r\ndrwxr-xr-x    3 0        0              80 Jun 04  2020 ..\r\n-rw-r--r--    1 0        0             109 Jun 04  2020 isp\r\n213 End of status\r\n"},
			{"STAT /nope", "213-Status follows:\r\n213 End of status\r\n"},
			{"STAT /etc/ppp/peers/nope", "213-Status follows:\r\n213 End of status\r\n"},
			{"STAT /etc/ppp/peers/", "213-Status follows:\r\ndrwxr-xr-x    2 0        0              60 Jun 04  2020 .\r\ndrwxr-xr-x    3 0        0              80 Jun 04  2020 ..\r\n-rw-r--r--    1 0        0             109 Jun 04  2020 isp\r\n213 End of status\r\n"},
			{"STAT /etc/ppp/peers/*p", "213-Status follows:\r\n-rw-r--r--    1 0        0             109 Jun 04  2020 isp\r\n213 End of status\r\n"},
			{"CWD /", "250 Directory successfully changed.\r\n"},
			{"STAT etc/ppp/peers", "213-Status follows:\r\ndrwxr-xr-x    2 0        0              60 Jun 04  2020 .\r\ndrwxr-xr-x    3 0        0              80 Jun 04  2020 ..\r\n-rw-r--r--    1 0        0             109 Jun 04  2020 isp\r\n213 End of status\r\n"},
			{"CWD /etc/ppp/peers", "250 Directory successfully changed.\r\n"},
			{"STAT -la", "213-Status follows:\r\ndrwxr-xr-x    2 0        0              60 Jun 04  2020 .\r\ndrwxr-xr-x    3 0        0              80 Jun 04  2020 ..\r\n-rw-r--r--    1 0        0             109 Jun 04  2020 isp\r\n213 End of status\r\n"},
			{"STAT .", "213-Status follows:\r\ndrwxr-xr-x    2 0        0              60 Jun 04  2020 .\r\ndrwxr-xr-x    3 0        0              80 Jun 04  2020 ..\r\n-rw-r--r--    1 0        0             109 Jun 04  2020 isp\r\n213 End of status\r\n"},
			{"STAT isp", "213-Status follows:\r\n-rw-r--r--    1 0        0             109 Jun 04  2020 isp\r\n213 End of status\r\n"},
			{"STAT x*", "213-Status follows:\r\n213 End of status\r\n"},
			{"QUIT", "221 Goodbye.\r\n"},
		}},
		{"root_retr", []ftpStep{
			{"USER root", "331 Please specify the password.\r\n"},
			{"PASS root", "230 Login successful.\r\n"},
			{"REST 100", "350 Restart position accepted (100).\r\n"},
			{"RETR /etc/ppp/peers/isp", "425 Use PORT or PASV first.\r\n"},
			{"REST abc", "350 Restart position accepted (0).\r\n"},
			{"REST 99999999999999999", "350 Restart position accepted (0).\r\n"},
			{"REST -5", "350 Restart position accepted (0).\r\n"},
			{"REST +5", "350 Restart position accepted (0).\r\n"},
			{"REST 12345678901", "350 Restart position accepted (12345678901).\r\n"},
			{"REST 999999999999999", "350 Restart position accepted (999999999999999).\r\n"},
			{"PORT 127,0,0,1,4,1", "200 PORT command successful. Consider using PASV.\r\n"},
			{"REST 5", "350 Restart position accepted (5).\r\n"},
			{"RETR /etc/ppp/peers/isp", "550 No support for resume of ASCII transfer.\r\n"},
			{"RETR /nope", "550 Failed to open file.\r\n"},
			{"RETR /etc/ppp", "550 Failed to open file.\r\n"},
			{"RETR", "550 Failed to open file.\r\n"},
			{"RETR /etc/ppp/peers/isp", "425 Failed to establish connection.\r\n"},
			{"RETR /etc/ppp/peers/isp", "425 Use PORT or PASV first.\r\n"},
			{"TYPE I", "200 Switching to Binary mode.\r\n"},
			{"PORT 127,0,0,1,4,1", "200 PORT command successful. Consider using PASV.\r\n"},
			{"REST 5", "350 Restart position accepted (5).\r\n"},
			{"RETR /etc/ppp/peers/isp", "425 Failed to establish connection.\r\n"},
			{"LIST", "425 Use PORT or PASV first.\r\n"},
			{"PORT 127,0,0,1,4,1", "200 PORT command successful. Consider using PASV.\r\n"},
			{"LIST -la /etc", "425 Failed to establish connection.\r\n"},
			{"NLST", "425 Use PORT or PASV first.\r\n"},
			{"PORT 127,0,0,1,4,1", "200 PORT command successful. Consider using PASV.\r\n"},
			{"NLST /nope", "425 Failed to establish connection.\r\n"},
			{"QUIT", "221 Goodbye.\r\n"},
		}},
		{"root_port", []ftpStep{
			{"USER root", "331 Please specify the password.\r\n"},
			{"PASS root", "230 Login successful.\r\n"},
			{"PORT 127,0,0,1,0,80", "500 Illegal PORT command.\r\n"},
			{"PORT 8,8,8,8,4,1", "500 Illegal PORT command.\r\n"},
			{"PORT 1,2,3", "500 Illegal PORT command.\r\n"},
			{"PORT 127,0,0,1,4,1,5", "500 Illegal PORT command.\r\n"},
			{"PORT 127,0,0,1,256,1", "500 Illegal PORT command.\r\n"},
			{"PORT 127, 0,0,1,4,1", "200 PORT command successful. Consider using PASV.\r\n"},
			{"PORT 127,0,0,1,4,1x", "200 PORT command successful. Consider using PASV.\r\n"},
			{"PORT 127,0,0,1,4,", "500 Illegal PORT command.\r\n"},
			{"PORT 127,0,,1,4,1", "200 PORT command successful. Consider using PASV.\r\n"},
			{"PORT", "500 Illegal PORT command.\r\n"},
			{"PORT 127,0,0,1,4,1", "200 PORT command successful. Consider using PASV.\r\n"},
			{"PORT x", "500 Illegal PORT command.\r\n"},
			{"LIST", "425 Use PORT or PASV first.\r\n"},
			{"PORT 127,0,0,1,3,255", "500 Illegal PORT command.\r\n"},
			{"PORT 127,0,0,1,4,0", "200 PORT command successful. Consider using PASV.\r\n"},
			{"PORT -127,0,0,1,4,1", "500 Illegal PORT command.\r\n"},
			{"PORT 127,0,0, 1,4,1", "200 PORT command successful. Consider using PASV.\r\n"},
			{"PORT 127,0,0,1,\t4,1", "200 PORT command successful. Consider using PASV.\r\n"},
			{"EPRT |1|127.0.0.1|1025|", "200 EPRT command successful. Consider using EPSV.\r\n"},
			{"LIST", "425 Failed to establish connection.\r\n"},
			{"EPRT |2|::1|1025|", "500 Bad EPRT protocol.\r\n"},
			{"EPRT |1|8.8.8.8|1025|", "500 Illegal EPRT command.\r\n"},
			{"EPRT |1|127.0.0.1|80|", "500 Illegal EPRT command.\r\n"},
			{"EPRT foo", "500 Bad EPRT command.\r\n"},
			{"EPRT |1|127.0.0.1||", "500 Bad EPRT command.\r\n"},
			{"EPRT |1|127.0.0.1|70000|", "500 Bad EPRT command.\r\n"},
			{"EPRT |3|x|1|", "500 Bad EPRT protocol.\r\n"},
			{"EPRT |1|127.0.0.1|1025", "200 EPRT command successful. Consider using EPSV.\r\n"},
			{"EPRT x|1|127.0.0.1|1025|", "500 Bad EPRT command.\r\n"},
			{"EPRT |1|127.0.0|1025|", "500 Bad EPRT command.\r\n"},
			{"EPRT |01|127.0.0.1|1025|x", "500 Bad EPRT command.\r\n"},
			{"EPRT", "500 Bad EPRT protocol.\r\n"},
			{"EPRT |1|127.0.0.1|1023|", "500 Illegal EPRT command.\r\n"},
			{"EPRT |1|127.0.0.1|-1|", "500 Bad EPRT command.\r\n"},
			{"QUIT", "221 Goodbye.\r\n"},
		}},
		{"root_write", []ftpStep{
			{"USER root", "331 Please specify the password.\r\n"},
			{"PASS root", "230 Login successful.\r\n"},
			{"PASV", "550 Permission denied.\r\n"},
			{"EPSV", "550 Permission denied.\r\n"},
			{"P@SW", "500 Unknown command.\r\n"},
			{"EPSV ALL", "550 Permission denied.\r\n"},
			{"STOR x", "550 Permission denied.\r\n"},
			{"APPE x", "550 Permission denied.\r\n"},
			{"STOU", "550 Permission denied.\r\n"},
			{"MKD x", "550 Permission denied.\r\n"},
			{"XMKD x", "550 Permission denied.\r\n"},
			{"RMD x", "550 Permission denied.\r\n"},
			{"XRMD x", "550 Permission denied.\r\n"},
			{"DELE x", "550 Permission denied.\r\n"},
			{"RNFR x", "550 Permission denied.\r\n"},
			{"RNTO y", "550 Permission denied.\r\n"},
			{"SITE", "500 Unknown SITE command.\r\n"},
			{"SITE HELP", "214 UMASK HELP\r\n"},
			{"site help", "214 UMASK HELP\r\n"},
			{"SITE UMASK", "200 Your current UMASK is 077\r\n"},
			{"SITE UMASK 022", "200 UMASK set to 022\r\n"},
			{"SITE UMASK", "200 Your current UMASK is 022\r\n"},
			{"SITE UMASK 9", "200 UMASK set to 0\r\n"},
			{"SITE UMASK 0", "200 UMASK set to 0\r\n"},
			{"SITE UMASK 7777", "200 UMASK set to 0777\r\n"},
			{"SITE UMASK abc", "200 UMASK set to 0\r\n"},
			{"SITE UMASK 0012", "200 UMASK set to 012\r\n"},
			{"SITE CHMOD 777 x", "500 Unknown SITE command.\r\n"},
			{"SITE EXEC id", "500 Unknown SITE command.\r\n"},
			{"QUIT", "221 Goodbye.\r\n"},
		}},
		{"root_misc", []ftpStep{
			{"USER root", "331 Please specify the password.\r\n"},
			{"PASS root", "230 Login successful.\r\n"},
			{"ABOR", "225 No transfer to ABOR.\r\n"},
			{"STRU F", "200 Structure set to F.\r\n"},
			{"STRU r", "504 Bad STRU command.\r\n"},
			{"MODE s", "200 Mode set to S.\r\n"},
			{"MODE B", "504 Bad MODE command.\r\n"},
			{"ALLO 100", "202 ALLO command ignored.\r\n"},
			{"REIN", "502 REIN not implemented.\r\n"},
			{"ACCT x", "502 ACCT not implemented.\r\n"},
			{"SMNT x", "502 SMNT not implemented.\r\n"},
			{"FEAT", "211-Features:\r\n EPRT\r\n MDTM\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n"},
			{"OPTS UTF8 ON", "200 Always in UTF8 mode.\r\n"},
			{"OPTS UTF8 OFF", "501 Option not understood.\r\n"},
			{"OPTS", "501 Option not understood.\r\n"},
			{"HELP", "214-The following commands are recognized.\r\n ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n XPWD XRMD\r\n214 Help OK.\r\n"},
			{"NOOP", "200 NOOP ok.\r\n"},
			{"SYST", "215 UNIX Type: L8\r\n"},
			{"USER root", "331 Any password will do.\r\n"},
			{"USER Root", "530 Can't change to another user.\r\n"},
			{"USER", "530 Can't change to another user.\r\n"},
			{"PASS x", "230 Already logged in.\r\n"},
			{"PBSZ 0", "550 Permission denied.\r\n"},
			{"PROT P", "550 Permission denied.\r\n"},
			{"AUTH TLS", "500 Unknown command.\r\n"},
			{"", ""},
			{" ", "500 Unknown command.\r\n"},
			{"  ", "500 Unknown command.\r\n"},
			{"foo", "500 Unknown command.\r\n"},
			{"noop", "200 NOOP ok.\r\n"},
			{"GET / HTTP/1.0", "500 HTTP protocol commands not allowed.\r\n"},
			{"NOOP", "(closed)"},
		}},
		{"root_post", []ftpStep{
			{"USER root", "331 Please specify the password.\r\n"},
			{"PASS root", "230 Login successful.\r\n"},
			{"POST /x", "500 HTTP protocol commands not allowed.\r\n"},
			{"NOOP", "(closed)"},
		}},
		{"longline", []ftpStep{
			{"\u0000long 4094", "530 Please login with USER and PASS.\r\n"},
			{"\u0000long 4095", "500 Input line too long.\r\n"},
			{"NOOP", "(closed)"},
		}},
		{"partial", []ftpStep{
			{"\u0000raw SYST", ""},
			{"\u0000close", "(closed)"},
		}},
	}

	for _, session := range sessions {
		var out bytes.Buffer
		s := shipper.NewShipper(&out, "", "")
		addr, done := serveOne(t, func(c net.Conn) { handleFTP(c, "ftp-test", s) })
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if banner := ftpRead(conn, 5*time.Second); banner != "220 (vsFTPd 3.0.3)\r\n" {
			t.Errorf("%s: banner %q", session.name, banner)
		}
		for _, step := range session.steps {
			switch {
			case step.send == "\x00close":
				conn.(*net.TCPConn).CloseWrite()
			case strings.HasPrefix(step.send, "\x00long "):
				n, _ := strconv.Atoi(step.send[6:])
				conn.Write([]byte(strings.Repeat("A", n) + "\r\n"))
			case strings.HasPrefix(step.send, "\x00raw "):
				conn.Write([]byte(step.send[5:]))
			default:
				conn.Write([]byte(step.send + "\r\n")) // after the server hung up, the error doesn't matter
			}
			timeout := 5 * time.Second
			if step.want == "" {
				timeout = 300 * time.Millisecond // no reply expected: how long we wait for one
			}
			if got := ftpRead(conn, timeout); got != step.want {
				t.Errorf("%s: %.40q\n got: %q\nwant: %q", session.name, step.send, got, step.want)
			}
		}
		conn.Close()
		waitDone(t, done)
	}
}

// anonymous logs in with any password (like vsftpd with anonymous_enable): as "anonymous" or "ftp", in any
// case; everyone else only with the shared weakCredentials. A password over 128 bytes never logs in.
func TestFTPLoginOK(t *testing.T) {
	tests := []struct {
		user, pass string
		want       bool
	}{
		{"anonymous", "", true},
		{"Anonymous", "bot@example.com", true},
		{"ftp", "ftp", true},
		{"FTP", "", true},
		{"root", "root", true},
		{"admin", "", true}, // empty password is in weakCredentials
		{"root", "wrong", false},
		{"ftpuser", "ftp", false},
		{"anonymous", strings.Repeat("a", 129), false},
		{"anonymouſ", "x", false}, // only ASCII letters change case, like C's toupper
	}
	for _, tt := range tests {
		if got := ftpLoginOK(tt.user, tt.pass); got != tt.want {
			t.Errorf("ftpLoginOK(%q, %.20q) = %v, want %v", tt.user, tt.pass, got, tt.want)
		}
	}
}

// A listing line shows the time for the last 6 months and the year for older or future dates, like vsftpd's
// vsf_sysutil_statbuf_get_date (the oracle only had 2020 files).
func TestFTPListDates(t *testing.T) {
	recent := time.Now().Add(-time.Hour)
	tests := []struct {
		modTime time.Time
		want    string
	}{
		{recent, recent.UTC().Format("Jan 02 15:04")},
		{time.Now().Add(-200 * 24 * time.Hour), time.Now().Add(-200 * 24 * time.Hour).UTC().Format("Jan 02  2006")},
		{time.Now().Add(time.Hour), time.Now().Add(time.Hour).UTC().Format("Jan 02  2006")},
	}
	for _, tt := range tests {
		f := vfs.FileInfo{Mode: "-rw-r--r--", Links: 1, Size: 5, ModTime: tt.modTime}
		want := "-rw-r--r--    1 0        0               5 " + tt.want + " x\r\n"
		if got := ftpListLine("x", f); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

// A whole FTP session: commands before login are refused (but logged), and even with PORT pointing at a
// listener of the client's, LIST/RETR never open the data connection. A PORT to anyone else (an FTP
// bounce) is refused like vsftpd does.
func TestFTPSession(t *testing.T) {
	// the client's own data port: even this may never get a connection from us
	victim, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer victim.Close()
	connected := make(chan bool, 1)
	go func() {
		if c, err := victim.Accept(); err == nil {
			c.Close()
			connected <- true
		}
	}()
	port := victim.Addr().(*net.TCPAddr).Port

	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleFTP(c, "ftp-test", s) })

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)

	if banner := readUntil(t, r, "\r\n"); banner != "220 (vsFTPd 3.0.3)\r\n" {
		t.Errorf("banner: %q", banner)
	}

	portCommand := fmt.Sprintf("PORT 127,0,0,1,%d,%d", port/256, port%256) // FTP writes the port as 2 bytes
	steps := []struct{ send, want string }{
		{"SYST", "530 Please login with USER and PASS."},
		{"USER root", "331 Please specify the password."},
		{"PASS root", "230 Login successful."},
		{"PASV", "550 Permission denied."},
		{"PORT 203,0,113,7,0,80", "500 Illegal PORT command."},
		{portCommand, "200 PORT command successful. Consider using PASV."},
		{"LIST", "425 Failed to establish connection."},
		{portCommand, "200 PORT command successful. Consider using PASV."},
		{"RETR /etc/passwd", "425 Failed to establish connection."},
		{"QUIT", "221 Goodbye."},
	}
	for _, step := range steps {
		fmt.Fprint(conn, step.send+"\r\n")
		if got := readUntil(t, r, "\r\n"); got != step.want+"\r\n" {
			t.Errorf("%s: got %q, want %q", step.send, got, step.want)
		}
	}
	waitDone(t, done)

	select {
	case <-connected:
		t.Error("the FTP server connected to the PORT address")
	case <-time.After(200 * time.Millisecond):
	}

	events := parseEvents(t, out.String())
	checkSession(t, events, "FTP", 21)

	logins := ofType(events, "login_attempt")
	if len(logins) != 1 || logins[0].Credentials.Username != "root" ||
		logins[0].Credentials.Password != "root" || !logins[0].Credentials.Success {
		t.Errorf("login_attempt events: %+v", logins)
	}

	// USER, PASS and QUIT are not commands; SYST before login is logged too
	var commands []string
	for _, e := range ofType(events, "command_exec") {
		commands = append(commands, e.PayloadDetails.Command)
	}
	want := []string{"SYST", "PASV", "PORT 203,0,113,7,0,80", portCommand, "LIST", portCommand, "RETR /etc/passwd"}
	if !slices.Equal(commands, want) {
		t.Errorf("command_exec: %q\n           want %q", commands, want)
	}
}

// STAT's "client count" is the number of FTP sessions open when this one started, this one included.
func TestFTPStatCountsClients(t *testing.T) {
	old := routerDelay
	routerDelay = time.Millisecond
	t.Cleanup(func() { routerDelay = old })

	s := shipper.NewShipper(io.Discard, "", "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go handleFTP(c, "ftp-test", s)
		}
	}()

	var conns []net.Conn
	for range 2 {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ftpRead(conn, 5*time.Second) // the banner: the session has started
		conns = append(conns, conn)
	}
	for _, line := range []string{"USER ftp", "PASS x"} {
		fmt.Fprint(conns[1], line+"\r\n")
		ftpRead(conns[1], 5*time.Second)
	}
	fmt.Fprint(conns[1], "STAT\r\n")
	if got := ftpRead(conns[1], 5*time.Second); !strings.Contains(got, "     At session startup, client count was 2\r\n") {
		t.Errorf("STAT: %q", got)
	}
}

// After login, USER and PASS are answered but never logged: a PASS would put a password in the command.
func TestFTPPassNeverLogged(t *testing.T) {
	old := routerDelay
	routerDelay = time.Millisecond
	t.Cleanup(func() { routerDelay = old })

	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleFTP(c, "ftp-test", s) })
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "USER ftp\r\nPASS a\r\nPASS secret\r\nUSER root\r\nNOOP\r\nQUIT\r\n")
	io.ReadAll(conn)
	waitDone(t, done)

	events := parseEvents(t, out.String())
	if strings.Contains(out.String(), "secret") {
		t.Errorf("the second PASS was logged: %s", out.String())
	}
	if n := len(ofType(events, "command_exec")); n != 1 {
		t.Errorf("%d command_exec events (only NOOP expected)", n)
	}
}

// Commands sent all at once are answered one by one, 200-300ms apart (pacer), even before login
// (refused commands are logged too, so without it no password was needed for a flood).
func TestFTPCommandsArePaced(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleFTP(c, "ftp-test", s) })

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	readUntil(t, r, "\r\n") // the banner

	start := time.Now()
	fmt.Fprint(conn, strings.Repeat("SYST\r\n", 5)+"QUIT\r\n")    // 6 lines in one write
	all, _ := io.ReadAll(r)                                       // until QUIT ends the session
	if took := time.Since(start); took < 5*200*time.Millisecond { // the first runs at once, then 5 waits
		t.Errorf("6 commands sent at once took %v (expected at least 1s)", took)
	}
	want := strings.Repeat("530 Please login with USER and PASS.\r\n", 5) + "221 Goodbye.\r\n"
	if string(all) != want {
		t.Errorf("got %q", all)
	}
	waitDone(t, done)
	if n := len(ofType(parseEvents(t, out.String()), "command_exec")); n != 5 {
		t.Errorf("%d command_exec events (expected 5)", n)
	}
}

// After vsftpd's idle timeout (300s, shortened here) the server says "421 Timeout." and hangs up.
func TestFTPIdleTimeout(t *testing.T) {
	old := ftpIdleTimeout
	ftpIdleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { ftpIdleTimeout = old })

	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	addr, done := serveOne(t, func(c net.Conn) { handleFTP(c, "ftp-test", s) })

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	all, err := io.ReadAll(conn) // say nothing and wait until the server hangs up
	if err != nil {
		t.Fatalf("the server did not hang up: %v", err)
	}
	if string(all) != "220 (vsFTPd 3.0.3)\r\n421 Timeout.\r\n" {
		t.Errorf("got %q", all)
	}
	waitDone(t, done)
	checkSession(t, parseEvents(t, out.String()), "FTP", 21)
}
