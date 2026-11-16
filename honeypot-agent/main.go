package main

import (
	"log"
	"os"

	"honeypot-agent/internal/services"
	"honeypot-agent/internal/shipper"
)

// main starts the four fake services and the event shipper, then blocks forever.
// Ports are unprivileged; Docker maps them to 80/21/23/22 on the host.
func main() {
	shipperURL := os.Getenv("SHIPPER_URL")     // empty = events go to stdout only
	shipperToken := os.Getenv("SHIPPER_TOKEN") // shared secret with the receiver (optional)

	s := shipper.NewShipper(os.Stdout, shipperURL, shipperToken)

	// RunX only returns on a fatal error (usually the port is already in use).
	go func() { log.Fatal("HTTP: ", services.RunHTTP(":8080", "http-01", s)) }()
	go func() { log.Fatal("FTP: ", services.RunFTP(":2121", "ftp-01", s)) }()
	go func() { log.Fatal("TELNET: ", services.RunTelnet(":2323", "telnet-01", s)) }()
	go func() { log.Fatal("SSH: ", services.RunSSH(":2222", "ssh-01", s)) }()

	select {}
}
