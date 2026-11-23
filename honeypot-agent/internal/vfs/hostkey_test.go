package vfs

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// dropbearFields splits a key file into Dropbear's length-prefixed parts.
func dropbearFields(t *testing.T, file []byte) [][]byte {
	var fields [][]byte
	for len(file) > 0 {
		if len(file) < 4 || int(binary.BigEndian.Uint32(file)) > len(file)-4 {
			t.Fatalf("broken field in %x", file)
		}
		n := binary.BigEndian.Uint32(file)
		fields = append(fields, file[4:4+n])
		file = file[4+n:]
	}
	return fields
}

// The key file is in Dropbear's format (type, curve, point, mpint), the point is on the curve, and the
// private number is an mpint like buf_putmpint writes it. Before SSH starts the made-up key is a real
// pair (the point is the number's); after SetHostKey the public part is the served key, the size the same.
func TestDropbearHostKey(t *testing.T) {
	t.Cleanup(func() { servedHostKey.Store(nil) })

	check := func(want []byte) {
		file, _ := readBuiltin(hostKeyFile)
		f := dropbearFields(t, []byte(file))
		if len(f) != 4 || string(f[0]) != "ecdsa-sha2-nistp256" || string(f[1]) != "nistp256" {
			t.Fatalf("fields: %q", f)
		}
		if _, err := ecdh.P256().NewPublicKey(f[2]); err != nil {
			t.Errorf("the point is not on the curve: %v", err)
		}
		// a negative number (top bit set) or a 0 in front that isn't needed: not what buf_putmpint writes
		if d := f[3]; d[0]&0x80 != 0 || (d[0] == 0 && (len(d) == 1 || d[1]&0x80 == 0)) {
			t.Errorf("not an mpint: %x", d)
		}
		if !bytes.HasPrefix([]byte(file), want) {
			t.Errorf("public part %x, want %x", file[:len(want)], want)
		}
		if out, _, _ := NewShell().Run("ls -l " + hostKeyFile); !bytes.Contains([]byte(out), []byte(" 140 ")) {
			t.Errorf("ls -l: %q", out)
		}
	}

	check(fakePublicKey)
	f := dropbearFields(t, append(append([]byte{}, fakePublicKey...), fakePrivateNumber...))
	key, err := ecdh.P256().NewPrivateKey(bytes.TrimLeft(f[3], "\x00"))
	if err != nil || !bytes.Equal(key.PublicKey().Bytes(), f[2]) {
		t.Errorf("before SSH starts, the point is not the private number's (%v)", err)
	}

	other, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	served := append(append([]byte{}, fakePublicKey[:4+19+4+8]...), 0, 0, 0, 65)
	served = append(served, other.PublicKey().Bytes()...)
	SetHostKey(served)
	check(served)
	SetHostKey(nil) // back to the made-up key (the services tests reset it this way)
	check(fakePublicKey)
}
