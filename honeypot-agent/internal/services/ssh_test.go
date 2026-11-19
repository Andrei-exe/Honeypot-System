package services

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"honeypot-agent/internal/shipper"
)

// newTestKey makes a throwaway ed25519 key in memory (RunSSH would write the host key to disk).
func newTestKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// sshDial logs in as root with password, the way a bot does. It also returns the login methods
// the server offered (the list it sends back after the client's first, empty "none" attempt).
func sshDial(addr, password string) (client *ssh.Client, offered []string, err error) {
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		// called before every login attempt; AllowedMethods = what the server offers.
		// Returning nil, nil means "carry on normally with Auth".
		AuthCallback: func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			if offered == nil {
				offered = slices.Clone(ctx.AllowedMethods)
			}
			return nil, nil
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // test only: the server key is a throwaway one
		Timeout:         5 * time.Second,
	}
	client, err = ssh.Dial("tcp", addr, config)
	return client, offered, err
}

// checkOfferedMethods: exactly what Dropbear offers, publickey + password. keyboard-interactive
// (OpenSSH has it, Dropbear doesn't) would give the persona away.
func checkOfferedMethods(t *testing.T, offered []string) {
	t.Helper()
	sorted := slices.Sorted(slices.Values(offered)) // the order is chosen by x/crypto, not by us
	if !slices.Equal(sorted, []string{"password", "publickey"}) {
		t.Errorf("offered login methods: %v (expected publickey and password, like Dropbear)", offered)
	}
}

// Wrong password: refused, logged, and the session still ends with session_end.
func TestSSHWrongPassword(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", s) })

	client, offered, err := sshDial(addr, "wrong")
	if err == nil {
		client.Close()
		t.Fatal("a wrong password was accepted")
	}
	checkOfferedMethods(t, offered)
	waitDone(t, done)

	events := parseEvents(t, out.String())
	checkSession(t, events, "SSH", 22)
	logins := ofType(events, "login_attempt")
	if len(logins) != 1 || logins[0].Credentials.Username != "root" ||
		logins[0].Credentials.Password != "wrong" || logins[0].Credentials.Success {
		t.Errorf("login_attempt events: %+v", logins)
	}
}

// Right password: Dropbear banner, port forwarding refused (we must never be a proxy),
// and an exec command (ssh root@host "...") runs in the fake shell.
func TestSSHSession(t *testing.T) {
	var out bytes.Buffer
	s := shipper.NewShipper(&out, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", s) })

	client, offered, err := sshDial(addr, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	checkOfferedMethods(t, offered)

	if v := string(client.ServerVersion()); v != "SSH-2.0-dropbear_2019.78" {
		t.Errorf("server version: %q", v)
	}

	// ssh -L / -D (local forwarding, SOCKS proxy) = "direct-tcpip" channel -> refused
	if c, err := client.Dial("tcp", "203.0.113.7:80"); err == nil {
		c.Close()
		t.Error("local port forwarding was accepted")
	}
	// ssh -R (remote forwarding) = "tcpip-forward" global request -> refused
	if l, err := client.Listen("tcp", "127.0.0.1:0"); err == nil {
		l.Close()
		t.Error("remote port forwarding was accepted")
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("uname -m; cat /etc/hostname") // err != nil if the exit status isn't 0
	if err != nil || string(output) != "armv7l\ngateway\n" {
		t.Errorf("exec: %q, %v", output, err)
	}
	client.Close()
	waitDone(t, done)

	events := parseEvents(t, out.String())
	checkSession(t, events, "SSH", 22)

	logins := ofType(events, "login_attempt")
	if len(logins) != 1 || logins[0].Credentials.Password != "root" || !logins[0].Credentials.Success {
		t.Errorf("login_attempt events: %+v", logins)
	}
	commands := ofType(events, "command_exec")
	if len(commands) != 1 || commands[0].PayloadDetails.Command != "uname -m; cat /etc/hostname" {
		t.Errorf("command_exec events: %+v", commands)
	}
}
