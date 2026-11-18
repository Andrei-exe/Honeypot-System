package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"honeypot-agent/internal/services"
	"honeypot-agent/internal/shipper"
)

// shipperCloseWait is how long the last events may take to reach the threat-engine on shutdown.
// With the services' 3s, it stays under the 10s Docker waits before SIGKILL.
const shipperCloseWait = 5 * time.Second

// main starts the four fake services and the event shipper, then runs until SIGTERM
// (docker stop) or Ctrl+C, and shuts down cleanly: no new connections, the open sessions
// are ended (each emits session_end), and the shipper sends what is left.
// Ports are unprivileged; Docker maps them to 80/21/23/22 on the host.
func main() {
	shipperURL := os.Getenv("SHIPPER_URL")     // empty = events go to stdout only
	shipperToken := os.Getenv("SHIPPER_TOKEN") // shared secret with the receiver (optional)

	s := shipper.NewShipper(os.Stdout, shipperURL, shipperToken)

	// ctx is cancelled when SIGTERM or SIGINT arrives; every service watches it.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	var wg sync.WaitGroup
	start := func(name string, run func(context.Context, string, string, *shipper.Shipper) error,
		address, nodeID string) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// RunX returns nil after a shutdown; an error means it crashed (usually the port is in use).
			if err := run(ctx, address, nodeID, s); err != nil {
				log.Fatal(name, ": ", err)
			}
		}()
	}
	start("HTTP", services.RunHTTP, ":8080", "http-01")
	start("FTP", services.RunFTP, ":2121", "ftp-01")
	start("TELNET", services.RunTelnet, ":2323", "telnet-01")
	start("SSH", services.RunSSH, ":2222", "ssh-01")

	<-ctx.Done() // blocks until the signal arrives
	stop()       // a second Ctrl+C now kills the program right away (default behaviour)
	log.Println("oprire: nu mai accept conexiuni, inchid sesiunile deschise")

	wg.Wait()                 // all four services have ended their sessions
	s.Close(shipperCloseWait) // only now: the last session_end events are already queued
	log.Println("oprit curat")
}
