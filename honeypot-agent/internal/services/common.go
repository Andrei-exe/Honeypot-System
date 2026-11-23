package services

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	mrand "math/rand/v2" // rand is crypto/rand here (the session IDs)
	"path"
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
// A variable only so the long oracle sessions in the tests can shorten it.
var routerDelay = 200 * time.Millisecond

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

// downloadURL is the URL for extracted_url: the first one with a scheme in the line, else what a wget,
// tftp -g or ftpget in it would fetch: BusyBox's wget takes "1.2.3.4/x" as http://1.2.3.4/x, tftp and
// ftpget take a host and a file name (-> tftp://host/file, ftp://host/file).
func downloadURL(line string) string {
	if url := urlRegex.FindString(line); url != "" {
		return url
	}
	commands := strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(";&|\n()`", r) })
	for _, command := range commands {
		words := strings.Fields(command)
		for i := range words {
			words[i] = strings.Trim(words[i], `'"`)
		}
		for len(words) > 0 && (path.Base(words[0]) == "busybox" || words[0] == "nohup") {
			words = words[1:] // "busybox wget ...", "nohup wget ..."
		}
		if len(words) > 0 {
			if url := commandURL(path.Base(words[0]), words[1:]); url != "" {
				return url
			}
		}
	}
	return ""
}

// commandURL is the URL a download command without "scheme://" would fetch ("" = none). The options
// that take a value are skipped with it, so "wget -O /tmp/x 1.2.3.4/y" gives http://1.2.3.4/y.
func commandURL(name string, args []string) string {
	withValue := map[string]string{"wget": "OPYUTt", "tftp": "lrb", "ftpget": "upP"}[name]
	if withValue == "" {
		return ""
	}
	opts := map[byte]string{}
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "--"): // wget's long options: those with a value take the next word
			long, _, hasValue := strings.Cut(a[2:], "=")
			if !hasValue && strings.Contains(" output-document directory-prefix proxy user-agent timeout tries header post-data ", " "+long+" ") {
				i++
			}
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				opts[a[j]] = ""
				if strings.IndexByte(withValue, a[j]) >= 0 {
					value := a[j+1:]
					if value == "" && i+1 < len(args) {
						i++
						value = args[i]
					}
					opts[a[j]] = value
					break
				}
			}
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) == 0 || rest[0] == "" || strings.ContainsAny(rest[0], "$`") {
		return "" // nothing to fetch, or an address the shell would only know when it runs
	}
	host := rest[0]
	switch name {
	case "wget":
		if strings.Contains(host, "://") {
			return "" // a scheme the regex doesn't know: BusyBox's wget refuses it
		}
		return "http://" + host
	case "tftp":
		remote := opts['r']
		if remote == "" {
			remote = opts['l']
		}
		if _, get := opts['g']; !get || remote == "" {
			return "" // -p sends a file, it doesn't fetch one
		}
		if len(rest) > 1 {
			host += ":" + rest[1]
		}
		return "tftp://" + host + "/" + strings.TrimPrefix(remote, "/")
	default: // ftpget HOST [LOCAL] REMOTE
		if len(rest) < 2 {
			return ""
		}
		if port := opts['P']; port != "" {
			host += ":" + port
		}
		return "ftp://" + host + "/" + strings.TrimPrefix(rest[len(rest)-1], "/")
	}
}

// newSessionID returns 8 random bytes as 16 hex characters.
func newSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// runShellLine logs the line as command_exec and runs it in the fake shell (Telnet and SSH), writing
// its output to out and its errors to errs (lines end in \n). An empty line isn't logged, but the shell
// still counts it ($LINENO). Returns the exit code ($?) and whether the shell ended.
func runShellLine(sh *vfs.Shell, line string, out, errs io.Writer,
	newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) (int, bool) {

	line = strings.TrimSpace(line)
	if line != "" {
		// log the whole line exactly as sent (including ; && |)
		event := newEvent("command_exec")
		event.PayloadDetails = &models.PayloadDetails{
			Command:      line,
			ExtractedURL: downloadURL(line),
		}
		shipper.EmitEvent(event)
	}
	return sh.RunTo(line, out, errs)
}
