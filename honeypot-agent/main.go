package main

import (
	"os"

	"honeypot-agent/internal/services"
	"honeypot-agent/internal/shipper"
)

func main() {
	s := shipper.NewShipper(os.Stdout)
	go services.RunHTTP(":8080", "http-01", s)
	go services.RunFTP(":2121", "ftp-01", s)
	select {}
}
