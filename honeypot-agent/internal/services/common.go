package services

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
	"honeypot-agent/internal/vfs"
)

// weakCredentials are the user:password pairs that "log in" on Telnet, SSH and FTP (FTP also
// accepts "anonymous"). Most are Mirai factory defaults; "root:" means an empty password.
// Every user here must also exist in the fake /etc/passwd (vfs/fs.go) with uid 0.
var weakCredentials = map[string]bool{
	// classic
	"root:root":       true,
	"root:admin":      true,
	"root:password":   true,
	"root:123456":     true,
	"root:12345":      true,
	"root:1234":       true,
	"root:":           true,
	"admin:admin":     true,
	"admin:password":  true,
	"admin:1234":      true,
	"admin:12345":     true,
	"admin:":          true,
	"user:user":       true,
	"support:support": true,

	// from the Mirai list (factory defaults)
	"root:xc3511":       true,
	"root:vizxv":        true,
	"root:888888":       true,
	"root:xmhdipc":      true,
	"root:default":      true,
	"root:juantech":     true,
	"root:54321":        true,
	"root:666666":       true,
	"root:7ujMko0vizxv": true,
	"admin:admin1234":   true,
	"admin:smcadmin":    true,
}

// urlRegex finds download URLs in commands (wget http://..., tftp://...) for extracted_url.
var urlRegex = regexp.MustCompile(`(?:https?|ftp|tftp)://[^\s'";|&<>()]+`)

// newSessionID returns 8 random bytes as 16 hex characters.
func newSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// runShellLine logs the line as command_exec and runs it in the fake shell (Telnet and SSH).
// Returns the output (lines end in \n), the exit code of the last command and whether the session should end.
func runShellLine(sh *vfs.Shell, line string,
	newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) (string, int, bool) {

	line = strings.TrimSpace(line)
	if line == "" {
		return "", 0, false
	}

	// log the whole line exactly as sent (including ; && |)
	event := newEvent("command_exec")
	event.PayloadDetails = &models.PayloadDetails{
		Command:      line,
		ExtractedURL: urlRegex.FindString(line),
	}
	shipper.EmitEvent(event)

	return sh.Run(line)
}
