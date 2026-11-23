package vfs

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"sync/atomic"
)

// Dropbear's host key file, /etc/dropbear/dropbear_ecdsa_host_key: the public key the way SSH sends it
// (type, curve, point), then the private number (buf_put_ecdsa_priv_key in Dropbear's ecdsa.c).
// The public part is the key our SSH server really serves, so its fingerprint matches what clients see.
// The private number is made up: the real one never goes where an attacker can read it, so it doesn't
// belong to that point (only someone who copies the file out and does the curve math can tell).

const hostKeyFile = "/etc/dropbear/dropbear_ecdsa_host_key"

// servedHostKey is the SSH server's public key (SetHostKey); nil until it has started.
var servedHostKey atomic.Pointer[[]byte]

// SetHostKey gives the vfs the public key the SSH server serves (ecdsa-sha2-nistp256, in SSH's wire
// format). Atomic: shells of the other services may already be reading the file.
func SetHostKey(publicKey []byte) {
	servedHostKey.Store(&publicKey)
}

// fakePublicKey and fakePrivateNumber: a made-up key that is a real one (the point is the number's), for
// the file until SSH has started, and in the tests. The number is the file's private part either way.
var fakePublicKey, fakePrivateNumber = fakeHostKey()

func fakeHostKey() (public, private []byte) {
	d := sha256.Sum256([]byte("gateway dropbear ecdsa"))
	key, err := ecdh.P256().NewPrivateKey(d[:])
	if err != nil {
		panic(err) // only for a number not below the curve's order: not this one
	}
	field := func(b, f []byte) []byte { // Dropbear writes each part as length (4 bytes) + bytes
		return append(binary.BigEndian.AppendUint32(b, uint32(len(f))), f...)
	}
	public = field(nil, []byte("ecdsa-sha2-nistp256"))
	public = field(public, []byte("nistp256"))
	public = field(public, key.PublicKey().Bytes()) // the point: 04 | X | Y

	// an mpint (buf_putmpint): no leading zero bytes, but a 0 in front when the top bit is set
	n := bytes.TrimLeft(d[:], "\x00")
	if n[0]&0x80 != 0 {
		n = append([]byte{0}, n...)
	}
	return public, field(nil, n)
}

// dropbearHostKey is the file's content now.
func dropbearHostKey() string {
	public := fakePublicKey
	if served := servedHostKey.Load(); served != nil && len(*served) > 0 {
		public = *served
	}
	return string(public) + string(fakePrivateNumber)
}
