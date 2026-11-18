// Command loadgen is a load generator for the honeypot agent: a test tool only, not part of the
// agent image, to be pointed only at our own honeypot. The agent allows 10 connections per IP,
// so for more load run several copies, each in its own container/IP (README, "Load testing").
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
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
		"brute = -n parallel SSH brute-force loops (full handshake + wrong password)")
	n       = flag.Int("n", 10, "sessions per service (hold) or parallel loops (brute)")
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

	if *mode == "brute" {
		runBrute(duration)
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
				}
			}
		}()
	}
	wg.Wait()

	total := rejected.Load()
	fmt.Printf("brute %s: ssh logins rejected=%d (%.0f/s) errors=%d\n", d, total, float64(total)/d.Seconds(), errs.Load())
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
