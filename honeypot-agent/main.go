package main

import (
	"log"
	"os"

	"honeypot-agent/internal/services"
	"honeypot-agent/internal/shipper"
)

func main() {
	s := shipper.NewShipper(os.Stdout)

	go func() { log.Fatal("HTTP: ", services.RunHTTP(":8080", "http-01", s)) }()
	go func() { log.Fatal("FTP: ", services.RunFTP(":2121", "ftp-01", s)) }()
	go func() { log.Fatal("TELNET: ", services.RunTelnet(":2323", "telnet-01", s)) }()
	go func() { log.Fatal("SSH: ", services.RunSSH(":2222", "ssh-01", s)) }()

	select {}
}
