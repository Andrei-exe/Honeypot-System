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

// Combinatii user:parola cu care "intra" atacatorul - aceeasi lista la Telnet, SSH si FTP.
// (la FTP merge in plus "anonymous" cu orice parola, vezi ftpLoginOK)
//
// Cele mai multe sunt din lista publica a lui Mirai (codul lui a fost publicat in 2016):
// parolele din fabrica ale unor camere, DVR-uri si routere. Daca bot-ul nu nimereste una
// dintre ele, nu intra -> nu-i vedem comenzile si URL-ul malware-ului.
// "root:" = parola goala (Enter direct la Password:).
// Toti userii de aici exista si in /etc/passwd-ul fals (vfs/fs.go), cu uid 0.
var weakCredentials = map[string]bool{
	// clasice
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

	// din lista Mirai (parole de fabrica)
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

// Prinde URL-uri din comenzi (wget http://..., tftp://...) -> ajung in extracted_url.
var urlRegex = regexp.MustCompile(`(?:https?|ftp|tftp)://[^\s'";|&<>()]+`)

// newSessionID = 8 bytes random -> 16 caractere hexa (ex: 9f3a1c0e7b2d4a55).
func newSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// runShellLine logheaza linia ca "command_exec" si o da shell-ului fals.
// O folosesc si Telnet, si SSH. Intoarce ce afisam (cu \n) si daca sesiunea se inchide.
func runShellLine(sh *vfs.Shell, line string,
	newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) (string, bool) {

	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}

	// logam linia INTREAGA, asa cum a trimis-o atacatorul (cu tot cu ; && |)
	event := newEvent("command_exec")
	event.PayloadDetails = &models.PayloadDetails{
		Command:      line,
		ExtractedURL: urlRegex.FindString(line),
	}
	shipper.EmitEvent(event)

	return sh.Run(line)
}
