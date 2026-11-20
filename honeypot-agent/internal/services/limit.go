package services

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

const (
	maxConnsPerService = 200              // max open connections per service
	maxConnsPerIP      = 10               // ...of which at most this many from one IP
	minSlotTime        = time.Second      // a connection's slot stays taken at least this long (see Close)
	maxAcceptDelay     = time.Second      // max pause after repeated Accept errors
	limitLogEvery      = 10 * time.Second // log about limits at most this often
)

// limitListener wraps a net.Listener and only changes Accept: it enforces the connection
// limits (extra connections are closed right away) and backs off on Accept errors
// (e.g. "too many open files") instead of spinning the CPU at 100%.
type limitListener struct {
	net.Listener // embedded: Close() and Addr() come from the real listener
	name         string

	mu    sync.Mutex     // guards total and perIP (changed from many goroutines)
	total int            // open connections right now
	perIP map[string]int // open connections per IP

	lastLog time.Time // only used by the Accept goroutine -> no mutex needed
}

// limitConnections wraps l with the limits. The result is used exactly like l.
func limitConnections(l net.Listener, name string) net.Listener {
	return &limitListener{Listener: l, name: name, perIP: map[string]int{}}
}

// Accept returns the next connection that fits the limits.
// Transient errors are retried; it only returns an error once the listener is closed.
func (l *limitListener) Accept() (net.Conn, error) {
	var delay time.Duration
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil, err // listener closed: no point retrying
			}
			// transient error -> wait 5ms, 10ms, 20ms... up to 1s, then retry
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay = min(delay*2, maxAcceptDelay)
			}
			l.logRarely("accept error: %v (waiting %v)", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0

		ip := remoteIP(conn)
		if !l.acquire(ip) {
			l.logRarely("too many connections (limit: %d in total, %d per IP) - rejecting the one from %s",
				maxConnsPerService, maxConnsPerIP, ip)
			conn.Close()
			continue
		}
		return &limitedConn{Conn: conn, release: func() { l.release(ip) }, accepted: time.Now()}, nil
	}
}

// acquire takes a slot for ip. Returns false if a limit has been reached.
func (l *limitListener) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= maxConnsPerService || l.perIP[ip] >= maxConnsPerIP {
		return false
	}
	l.total++
	l.perIP[ip]++
	return true
}

// release frees the slot when the connection closes.
func (l *limitListener) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	l.perIP[ip]--
	if l.perIP[ip] == 0 {
		delete(l.perIP, ip) // otherwise the map grows forever with IPs that left
	}
}

// logRarely logs at most once every limitLogEvery, so a flood of connections
// doesn't turn into thousands of log lines per second.
func (l *limitListener) logRarely(format string, args ...any) {
	if time.Since(l.lastLog) < limitLogEvery {
		return
	}
	l.lastLog = time.Now()
	log.Printf(l.name+": "+format, args...)
}

// limitedConn is a net.Conn that frees its limit slot when closed.
type limitedConn struct {
	net.Conn
	once     sync.Once
	release  func()
	accepted time.Time // when Accept let it in (zero = long ago: the slot is freed right away)
}

// Close may be called more than once (on SSH both the library and our defer close the conn).
// sync.Once releases the slot exactly once, otherwise the counters would go negative.
//
// A slot is freed only minSlotTime after Accept, even if the client left sooner. Otherwise a bot
// connecting and closing in a loop makes hundreds of sessions a second (2 events each, measured:
// 1300 events/s from one IP on Telnet) and buries the other events. Now at most maxConnsPerIP new
// connections per second per IP, maxConnsPerService per service. Longer sessions see no change.
func (c *limitedConn) Close() error {
	c.once.Do(func() {
		if wait := minSlotTime - time.Since(c.accepted); wait > 0 {
			time.AfterFunc(wait, c.release) // runs c.release in its own goroutine after wait
		} else {
			c.release()
		}
	})
	return c.Conn.Close()
}

// remoteIP returns the connection's IP, without the port.
func remoteIP(conn net.Conn) string {
	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return ip
}
