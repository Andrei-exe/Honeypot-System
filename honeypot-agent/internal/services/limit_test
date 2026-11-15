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

// Un IP nu poate tine mai mult de maxConnsPerIP conexiuni deodata; cand inchide una, se elibereaza locul.
func TestPerIPLimit(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0") // :0 = orice port liber
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

	// deschidem maxConnsPerIP + 1 conexiuni de pe 127.0.0.1
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
			t.Fatalf("au fost acceptate doar %d conexiuni din %d", i, maxConnsPerIP)
		}
	}

	// ultima conexiune trebuie inchisa de server: citirea da EOF
	last := clients[len(clients)-1]
	last.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := last.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("conexiunea in plus trebuia inchisa (EOF), am primit: %v", err)
	}
	select {
	case <-accepted:
		t.Fatal("a fost acceptata o conexiune peste limita")
	case <-time.After(200 * time.Millisecond):
	}

	// inchidem una -> o conexiune noua trebuie sa intre
	serverSide[0].Close()
	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("dupa ce s-a inchis o conexiune, locul nu s-a eliberat")
	}
}

// Limita totala: IP-uri diferite, dar tot nu trec de maxConnsPerService.
func TestTotalLimit(t *testing.T) {
	l := limitConnections(nil, "TEST").(*limitListener)
	for i := 0; i < maxConnsPerService; i++ {
		if !l.acquire(fmt.Sprintf("10.0.%d.%d", i/250, i%250)) {
			t.Fatalf("conexiunea %d trebuia acceptata", i)
		}
	}
	if l.acquire("8.8.8.8") {
		t.Fatal("a trecut de limita totala")
	}
	l.release("10.0.0.0")
	if !l.acquire("8.8.8.8") {
		t.Fatal("dupa release trebuia sa fie loc")
	}
}

// Close chemat de 2 ori (se intampla la SSH) elibereaza locul O SINGURA data.
func TestDoubleCloseReleasesOnce(t *testing.T) {
	l := limitConnections(nil, "TEST").(*limitListener)
	l.acquire("1.2.3.4")
	a, b := net.Pipe()
	defer b.Close()
	conn := &limitedConn{Conn: a, release: func() { l.release("1.2.3.4") }}

	conn.Close()
	conn.Close()
	if l.total != 0 || len(l.perIP) != 0 {
		t.Fatalf("dupa 2x Close: total=%d, perIP=%v (trebuia 0 si gol)", l.total, l.perIP)
	}
}

// flakyListener = un listener fals care da eroare la primele failUntil apeluri,
// apoi intoarce o conexiune, apoi se "inchide".
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

// La erori de Accept, asteapta (5ms, 10ms, 20ms...) in loc sa se invarta in gol.
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
		t.Fatalf("dupa 5 erori trebuia sa primim conexiunea, am primit err=%v", err)
	}
	if calls := fake.calls.Load(); calls != 6 {
		t.Fatalf("Accept a fost chemat de %d ori (trebuia 6: 5 erori + conexiunea)", calls)
	}
	// 5+10+20+40+80 = 155ms de pauza in total
	if elapsed < 150*time.Millisecond {
		t.Fatalf("n-a facut pauza intre erori (a durat doar %v)", elapsed)
	}

	// listener inchis -> Accept trebuie sa se opreasca, nu sa reincerce
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("listener inchis: trebuia net.ErrClosed, am primit %v", err)
	}
}
