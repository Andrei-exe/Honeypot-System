package services

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"honeypot-agent/internal/shipper"
)

// newTestKey makes a throwaway ECDSA key in memory (RunSSH would write the host key to disk).
func newTestKey(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

// readServerKexInit does what a scanner does: it sends a version line, then reads the server's
// first binary packet (KEXINIT, not encrypted yet) and returns its 10 algorithm lists as sent.
func readServerKexInit(t *testing.T, addr string) []string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "SSH-2.0-scanner\r\n")
	r := bufio.NewReader(conn)
	readUntil(t, r, "\r\n") // the server's version line

	// packet = length (4 bytes) | padding length (1) | payload | padding
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, length)
	if _, err := io.ReadFull(r, packet); err != nil {
		t.Fatal(err)
	}
	payload := packet[1 : len(packet)-int(packet[0])]
	if payload[0] != 20 { // SSH_MSG_KEXINIT
		t.Fatalf("first message type %d, expected KEXINIT (20)", payload[0])
	}

	// after the type byte and a 16-byte random cookie: 10 name-lists, each length (4) + text
	p := payload[17:]
	var lists []string
	for range 10 {
		n := binary.BigEndian.Uint32(p)
		lists = append(lists, string(p[4:4+n]))
		p = p[4+n:]
	}
	return lists
}

// The algorithm lists must be Dropbear 2019.78's (as Buildroot 2019.05.3 builds it), in its order:
// that's what scanners fingerprint. Only kex-strict-s-v00 is extra (x/crypto always adds it).
func TestSSHAlgorithmsLikeDropbear(t *testing.T) {
	s := shipper.NewShipper(io.Discard, "", "")
	hostKey := newTestKey(t)
	addr, done := serveOne(t, func(c net.Conn) { handleSSH(c, hostKey, "ssh-test", s) })

	lists := readServerKexInit(t, addr)
	want := []string{
		// key exchange: Dropbear's list (without its kexguess2@matt.ucc.asn.au) + x/crypto's kex-strict
		"curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384," +
			"ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1," +
			"kex-strict-s-v00@openssh.com",
		"ecdsa-sha2-nistp256",                            // host key: no ed25519 (Dropbear 2020.79+)
		"aes128-ctr,aes256-ctr", "aes128-ctr,aes256-ctr", // ciphers, both directions
		"hmac-sha1,hmac-sha2-256", "hmac-sha1,hmac-sha2-256", // MACs
		"none", "none", // compression (Buildroot's "small" Dropbear has no zlib)
		"", "", // languages
	}
	for i := range want {
		if lists[i] != want[i] {
			t.Errorf("list %d:\n got: %s\nwant: %s", i, lists[i], want[i])
		}
	}
	waitDone(t, done)
}

// The host key is created once and then read back: same key = same fingerprint after a restart.
func TestHostKeyIsKeptOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), sshHostKeyFile)
	first, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKey().Type() != "ecdsa-sha2-nistp256" {
		t.Errorf("host key type %s, expected ecdsa-sha2-nistp256", first.PublicKey().Type())
	}
	if !bytes.Equal(first.PublicKey().Marshal(), again.PublicKey().Marshal()) {
		t.Error("the second start made a new key: the fingerprint would change")
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
