package services

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

const (
	maxConnsPerService = 200              // cate conexiuni deodata accepta un serviciu, in total
	maxConnsPerIP      = 10               // ...din care cate pot veni de la acelasi IP
	maxAcceptDelay     = time.Second      // pauza maxima dupa erori repetate la Accept
	limitLogEvery      = 10 * time.Second // cat de des avem voie sa scriem in log despre limite
)

// limitListener "imbraca" un net.Listener obisnuit si ii schimba doar metoda Accept:
//  1. limite: max maxConnsPerService conexiuni deodata, din care max maxConnsPerIP de la acelasi IP.
//     Peste limita, conexiunea e inchisa imediat (asa face si un server real supraincarcat).
//  2. pauza crescatoare cand Accept da eroare (ex: "too many open files"),
//     ca sa nu ne invartim in gol cu procesorul la 100%.
type limitListener struct {
	net.Listener // "embedding": limitListener primeste automat Close() si Addr() de la listener-ul real
	name         string

	mu    sync.Mutex     // protejeaza total si perIP (se schimba din mai multe goroutine-uri)
	total int            // cate conexiuni sunt deschise acum
	perIP map[string]int // cate conexiuni are deschise fiecare IP

	lastLog time.Time // folosit doar din goroutine-ul care face Accept -> nu are nevoie de mutex
}

// limitConnections pune limitele peste un listener. Ce primeste inapoi se foloseste exact ca inainte.
func limitConnections(l net.Listener, name string) net.Listener {
	return &limitListener{Listener: l, name: name, perIP: map[string]int{}}
}

// Accept intoarce urmatoarea conexiune care incape in limite.
// Erorile trecatoare le reincearca singur; intoarce eroare doar daca listener-ul a fost inchis.
func (l *limitListener) Accept() (net.Conn, error) {
	var delay time.Duration
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil, err // listener-ul a fost inchis: gata, nu mai are rost sa reincercam
			}
			// eroare trecatoare -> asteptam 5ms, 10ms, 20ms... maxim 1s, apoi incercam iar
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay = min(delay*2, maxAcceptDelay)
			}
			l.logRarely("eroare la accept: %v (astept %v)", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0

		ip := remoteIP(conn)
		if !l.acquire(ip) {
			l.logRarely("prea multe conexiuni (limita: %d in total, %d per IP) - o refuz pe cea de la %s",
				maxConnsPerService, maxConnsPerIP, ip)
			conn.Close()
			continue
		}
		return &limitedConn{Conn: conn, release: func() { l.release(ip) }}, nil
	}
}

// acquire ocupa un loc pentru ip, daca mai e loc. Intoarce false daca s-a atins o limita.
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

// release elibereaza locul cand se inchide conexiunea.
func (l *limitListener) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	l.perIP[ip]--
	if l.perIP[ip] == 0 {
		delete(l.perIP, ip) // altfel map-ul ar creste la infinit cu IP-uri care au plecat
	}
}

// logRarely scrie in log cel mult o data la 10 secunde.
// La un atac, fara asta am avea mii de linii pe secunda (exact bug-ul pe care il reparam).
func (l *limitListener) logRarely(format string, args ...any) {
	if time.Since(l.lastLog) < limitLogEvery {
		return
	}
	l.lastLog = time.Now()
	log.Printf(l.name+": "+format, args...)
}

// limitedConn = o conexiune obisnuita care, cand e inchisa, elibereaza locul din limita.
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

// Close poate fi chemat de mai multe ori pe aceeasi conexiune (ex: la SSH o inchide si biblioteca,
// si defer-ul nostru). sync.Once face ca locul sa fie eliberat O SINGURA data -
// altfel numaratoarea ar scadea de doua ori si ar ajunge pe minus.
func (c *limitedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// remoteIP = IP-ul de la care vine conexiunea, fara port.
func remoteIP(conn net.Conn) string {
	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return ip
}
