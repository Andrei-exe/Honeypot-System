package services

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

// shutdownWait is how long a service waits for its sessions to end when the agent stops.
// Docker sends SIGKILL 10 seconds after SIGTERM; the shipper needs the rest of that time.
const shutdownWait = 3 * time.Second

// serve is the accept loop shared by FTP, Telnet and SSH: each connection gets its own goroutine
// running handle. When ctx is cancelled (the agent is stopping) it stops accepting, closes the
// connections that are still open and waits for their handlers, so every session ends normally
// and emits its session_end. Returns nil after a shutdown, or the error if Accept really failed.
func serve(ctx context.Context, listener net.Listener, handle func(net.Conn)) error {
	// When ctx is cancelled, close the listener: the Accept below then returns an error.
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()

	var (
		wg   sync.WaitGroup        // one count per running handler
		mu   sync.Mutex            // guards open (changed from many goroutines)
		open = map[net.Conn]bool{} // connections whose handler is still running
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				return err // not a shutdown: a real failure
			}
			break
		}

		mu.Lock()
		open[conn] = true
		mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()
			handle(conn)
			mu.Lock()
			delete(open, conn)
			mu.Unlock()
		}()
	}

	// Shutdown: closing a connection makes its handler's next Read/Write fail right away, so the
	// handler returns and its deferred session_end runs. The handler closes the conn again
	// itself; limitedConn's sync.Once makes that harmless.
	mu.Lock()
	for conn := range open {
		conn.Close()
	}
	mu.Unlock()

	if !waitTimeout(&wg, shutdownWait) {
		log.Printf("oprire: unele sesiuni nu s-au terminat in %v", shutdownWait)
	}
	return nil
}

// waitTimeout waits for wg, but at most d. Returns false if the time ran out.
func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}
