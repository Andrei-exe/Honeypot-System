package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"time"

	"net"
	"net/http"
	"net/url"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
	"honeypot-agent/internal/vfs"
)

// sessionKey is the context key under which ConnContext stores a connection's session_id.
type sessionKey struct{}

const (
	// httpDelay is the shortest time the router takes to answer a request (see the handler).
	httpDelay = 200 * time.Millisecond

	// lighttpdMaxHeader is lighttpd's server.max-request-field-size (default 8192, server.c): a
	// longer request line + headers gets 431 (connections.c). It also keeps every event small.
	lighttpdMaxHeader = 8192
)

// The field names read as credentials, in a form body or in the URL. The password is kept out of
// raw_data and http_path: it goes only in credentials.
var (
	userFields     = []string{"username", "log", "user"}
	passwordFields = []string{"password", "pass", "pwd"}
)

// RunHTTP serves a fake router login page (lighttpd) and logs every request, until ctx is cancelled.
// Submitted credentials are logged as login_attempt and always rejected.
// Returns nil after a clean shutdown, or an error if it fails (usually the port is in use).
func RunHTTP(ctx context.Context, address string, nodeID string, shipper *shipper.Shipper) error {
	handler := func(w http.ResponseWriter, r *http.Request) {
		ip, portText, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		port, _ := strconv.Atoi(portText)
		sessionID, _ := r.Context().Value(sessionKey{}).(string) // set by ConnContext below

		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096)) // read at most 4KB of the body

		event := models.HoneypotEvent{
			Timestamp:  models.Now(),
			NodeID:     nodeID,
			EventType:  "http_request",
			SourceIP:   ip,
			SourcePort: port,
			TargetPort: 80,
			Protocol:   "HTTP",
			SessionID:  sessionID,
			PayloadDetails: &models.PayloadDetails{
				HTTPMethod:    r.Method,
				HTTPPath:      r.URL.RequestURI(),
				HTTPUserAgent: r.UserAgent(),
				RawData:       string(body),
			},
		}

		// credentials from a login form, from the URL (GET /login.cgi?user=admin&pwd=admin, common
		// in IoT exploits) or from Basic Auth
		form, _ := url.ParseQuery(string(body))
		query := r.URL.Query()
		user, pass := formValue(form, userFields...), formValue(form, passwordFields...)
		switch {
		case pass != "":
			event.PayloadDetails.RawData = withoutPasswords(string(body))
		case formValue(query, passwordFields...) != "":
			user, pass = formValue(query, userFields...), formValue(query, passwordFields...)
			path := r.URL.EscapedPath() // = http_path without the password
			if rest := withoutPasswords(r.URL.RawQuery); rest != "" {
				path += "?" + rest
			}
			event.PayloadDetails.HTTPPath = path
		}

		basicUser, basicPass, isBasic := r.BasicAuth()
		if isBasic {
			user, pass = basicUser, basicPass
		}

		if user != "" || pass != "" {
			event.EventType = "login_attempt"
			event.Credentials = &models.Credentials{
				Username: user,
				Password: pass,
				Success:  false,
			}
		}

		shipper.EmitEvent(event)

		// A cheap router is slow: every answer takes 200-300ms (random, like a real device). This also
		// caps a flood: a request keeps its connection busy that long and there are at most 200
		// connections (10 per IP, limit.go), so at most 200 / 0.2s = 1000 events/s (50/s per IP), which
		// the shipper can deliver. Without it, one fast scanner made 4000 events/s and most were lost.
		time.Sleep(httpDelay + rand.N(httpDelay/2))

		if headerSize(r) > lighttpdMaxHeader {
			lighttpdTooLarge(w) // lighttpd doesn't even parse it: no 404, no Basic Auth
			return
		}

		// Like lighttpd with the vendor's lighttpd.conf (vfs/web.go): only the files in /var/www exist
		// (a fake that answers 200 to any path is a classic tell), login.cgi is a program.
		w.Header().Set("Server", "lighttpd/1.4.53") // the version in Buildroot 2019.05.3 (see vfs/fs.go)
		w.Header().Set("Content-Type", "text/html") // mimetype.assign for .html; the CGI says the same
		file, exists := vfs.WebFile(r.URL.Path)
		switch {
		case isBasic:
			// ask for Basic Auth only from clients that already sent it. Any path: lighttpd checks
			// the login (mod_auth) before it looks for the file, and answers with its own page.
			w.Header().Set("WWW-Authenticate", `Basic realm="Gateway"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, lighttpdErrorPage("401 Unauthorized"))
		case !exists:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, lighttpdErrorPage("404 Not Found"))
		case event.EventType == "login_attempt":
			w.WriteHeader(http.StatusUnauthorized) // what login.cgi answers to a wrong password
			fmt.Fprint(w, vfs.LoginPage(true))
		case strings.HasSuffix(r.URL.Path, ".cgi"):
			fmt.Fprint(w, vfs.LoginPage(false)) // login.cgi without a password shows the form
		default:
			fmt.Fprint(w, file) // a static file (index.html), exactly as it is in the filesystem
		}
	}

	// timeouts so slow clients can't hold connections open forever
	server := &http.Server{
		Handler:           http.HandlerFunc(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		// Go's default is 1MB (a 1MB path would go into one event). Over this + 4KB, Go answers its own
		// 431 and the handler never runs; between lighttpdMaxHeader and that, the handler answers like lighttpd.
		MaxHeaderBytes: lighttpdMaxHeader,
		// called once per new TCP connection: keep-alive requests on it share one session_id
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, sessionKey{}, newSessionID())
		},
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	log.Println("HTTP node running")

	// When ctx is cancelled: Shutdown stops accepting, closes idle keep-alive connections and
	// waits for the requests in progress (at most shutdownWait).
	shutdownDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		waitCtx, cancel := context.WithTimeout(context.Background(), shutdownWait)
		defer cancel()
		server.Shutdown(waitCtx)
		close(shutdownDone)
	})
	defer stop()

	err = server.Serve(limitConnections(listener, "HTTP"))
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone // Serve returns as soon as Shutdown starts; wait until it has finished
		return nil
	}
	return err
}

// formValue returns the first non-empty value among the given form field names.
func formValue(v url.Values, names ...string) string {
	for _, n := range names {
		x := v.Get(n)
		if x != "" {
			return x
		}
	}
	return ""
}

// withoutPasswords returns a form body without its password fields; the other fields stay as sent.
func withoutPasswords(body string) string {
	var kept []string
	for _, field := range strings.Split(body, "&") {
		name, _, _ := strings.Cut(field, "=")
		name, _ = url.QueryUnescape(name) // "pass%77ord" is "password" too
		if !slices.Contains(passwordFields, name) {
			kept = append(kept, field)
		}
	}
	return strings.Join(kept, "&")
}

// headerSize is the size of the request line + headers + blank line, what lighttpd compares with
// lighttpdMaxHeader. Go doesn't keep the raw bytes, so it's rebuilt as "Name: value\r\n" per header:
// exact for a normal client, a few bytes off if it put extra spaces around the values.
func headerSize(r *http.Request) int {
	size := len(r.Method) + 1 + len(r.RequestURI) + 1 + len(r.Proto) + 2 // "GET /x HTTP/1.1\r\n"
	if r.Host != "" {
		size += len("Host: ") + len(r.Host) + 2 // Go moves the Host header out of r.Header
	}
	for name, values := range r.Header {
		for _, value := range values {
			size += len(name) + len(": ") + len(value) + 2
		}
	}
	return size + 2
}

// lighttpdTooLarge answers like lighttpd 1.4.53 to a too-large header: HTTP/1.0 (the request was
// never parsed), "431 " with no text (http_kv.c has none for 431), then it closes the connection.
// Written by hand (Hijack): net/http would add its own status text and header order.
func lighttpdTooLarge(w http.ResponseWriter) {
	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	page := lighttpdErrorPage("431 ")
	fmt.Fprintf(buf, "HTTP/1.0 431 \r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n"+
		"Date: %s\r\nServer: lighttpd/1.4.53\r\n\r\n%s", len(page), time.Now().UTC().Format(http.TimeFormat), page)
	buf.Flush()
}

// lighttpdErrorPage is the page lighttpd 1.4.53 builds itself for an error (src/connections.c), for
// a status like "404 Not Found" (its text from http_kv.c; older versions had "404 - Not Found").
func lighttpdErrorPage(status string) string {
	return `<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>` + status + `</title>
 </head>
 <body>
  <h1>` + status + `</h1>
 </body>
</html>
`
}
