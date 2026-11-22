package services

import (
	"crypto/rand"
	"encoding/hex"
	mrand "math/rand/v2" // rand is crypto/rand here (the session IDs)
	"regexp"
	"strings"
	"time"

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

// routerDelay is how long the cheap router takes to answer, at least: an HTTP request (http.go) or
// the next command of a session (pacer). Plus up to half of it at random, like a real device.
const routerDelay = 200 * time.Millisecond

// routerAnswerTime is one answer time: 200-300ms.
func routerAnswerTime() time.Duration {
	return routerDelay + mrand.N(routerDelay/2)
}

// pacer spaces out the commands of one session (Telnet, SSH shell, FTP): at most one per 200-300ms.
// Whoever waits for each answer before sending the next command (a person, most bots) never waits
// here; a bot that sends 50 commands at once gets them answered one by one. Without it one IP made
// 530 events/s (10 sessions/s x 53 events) and a few IPs were more than the shipper can deliver.
type pacer struct {
	next time.Time // the earliest time the next command may run (zero: right away)
}

// wait blocks until the next command may run, then books the time for the one after it.
func (p *pacer) wait() {
	time.Sleep(time.Until(p.next)) // a time already past = no wait at all
	p.next = time.Now().Add(routerAnswerTime())
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
