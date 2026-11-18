package services

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// One IP can't hold more than maxConnsPerIP connections at once; closing one frees a slot.
func TestPerIPLimit(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0") // :0 = any free port
	if err != nil {
		t.Fatal(err)
	}
	listener := limitConnections(raw, "TEST")
	defer listener.Close()

	accepted := make(chan net.Conn, 100)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	// open maxConnsPerIP + 1 connections from 127.0.0.1
	var clients []net.Conn
	for i := 0; i < maxConnsPerIP+1; i++ {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		clients = append(clients, c)
	}

	var serverSide []net.Conn
	for i := 0; i < maxConnsPerIP; i++ {
		select {
		case c := <-accepted:
			serverSide = append(serverSide, c)
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d connections were accepted", i, maxConnsPerIP)
		}
	}

	// the last connection must be closed by the server: reading gives EOF
	last := clients[len(clients)-1]
	last.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := last.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the extra connection should have been closed (EOF), got: %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("a connection over the limit was accepted")
	case <-time.After(200 * time.Millisecond):
	}

	// close one -> a new connection must get in
	serverSide[0].Close()
	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("closing a connection did not free its slot")
	}
}

// Total limit: different IPs still can't go past maxConnsPerService.
func TestTotalLimit(t *testing.T) {
	l := limitConnections(nil, "TEST").(*limitListener)
	for i := 0; i < maxConnsPerService; i++ {
		if !l.acquire(fmt.Sprintf("10.0.%d.%d", i/250, i%250)) {
			t.Fatalf("connection %d should have been accepted", i)
		}
	}
	if l.acquire("8.8.8.8") {
		t.Fatal("went past the total limit")
	}
	l.release("10.0.0.0")
	if !l.acquire("8.8.8.8") {
		t.Fatal("there should be a free slot after release")
	}
}

// Calling Close twice (happens on SSH) releases the slot only once.
func TestDoubleCloseReleasesOnce(t *testing.T) {
	l := limitConnections(nil, "TEST").(*limitListener)
	l.acquire("1.2.3.4")
	a, b := net.Pipe()
	defer b.Close()
	conn := &limitedConn{Conn: a, release: func() { l.release("1.2.3.4") }}

	conn.Close()
	conn.Close()
	if l.total != 0 || len(l.perIP) != 0 {
		t.Fatalf("after 2x Close: total=%d, perIP=%v (should be 0 and empty)", l.total, l.perIP)
	}
}

// flakyListener is a fake listener that fails the first failUntil calls,
// then returns one connection, then behaves as closed.
type flakyListener struct {
	calls     atomic.Int64
	failUntil int64
	conn      net.Conn
}

func (f *flakyListener) Accept() (net.Conn, error) {
	n := f.calls.Add(1)
	if n <= f.failUntil {
		return nil, errors.New("accept4: too many open files")
	}
	if f.conn != nil {
		c := f.conn
		f.conn = nil
		return c, nil
	}
	return nil, net.ErrClosed
}
func (f *flakyListener) Close() error   { return nil }
func (f *flakyListener) Addr() net.Addr { return &net.TCPAddr{} }

// On Accept errors it waits (5ms, 10ms, 20ms...) instead of spinning.
func TestAcceptBacksOffOnErrors(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	fake := &flakyListener{failUntil: 5, conn: a}
	listener := limitConnections(fake, "TEST")

	start := time.Now()
	conn, err := listener.Accept()
	elapsed := time.Since(start)
	if err != nil || conn == nil {
		t.Fatalf("after 5 errors we should get the connection, got err=%v", err)
	}
	if calls := fake.calls.Load(); calls != 6 {
		t.Fatalf("Accept was called %d times (should be 6: 5 errors + the connection)", calls)
	}
	// 5+10+20+40+80 = 155ms of pauses in total
	if elapsed < 150*time.Millisecond {
		t.Fatalf("no pause between errors (it took only %v)", elapsed)
	}

	// closed listener -> Accept must stop, not retry
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed listener: expected net.ErrClosed, got %v", err)
	}
}
