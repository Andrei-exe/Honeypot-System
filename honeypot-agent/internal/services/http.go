package services

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"strconv"
	"strings"
	"time"

	"net"
	"net/http"
	"net/url"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
)

// sessionKey is the context key under which ConnContext stores a connection's session_id.
type sessionKey struct{}

// passwordFields are the form fields read as the password; they are kept out of raw_data.
var passwordFields = []string{"password", "pass", "pwd"}

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

		// credentials from a login form (common field names) or from Basic Auth
		values, _ := url.ParseQuery(string(body))
		user := formValue(values, "username", "log", "user")
		pass := formValue(values, passwordFields...)
		if pass != "" {
			event.PayloadDetails.RawData = withoutPasswords(string(body)) // the password goes only in credentials
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

		w.Header().Set("Server", "lighttpd/1.4.55")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if isBasic {
			// ask for Basic Auth only from clients that already sent it
			w.Header().Set("WWW-Authenticate", `Basic realm="Gateway"`)
		}
		if event.EventType == "login_attempt" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, fakeLoginPage(true))
			return
		}
		fmt.Fprint(w, fakeLoginPage(false))
	}

	// timeouts so slow clients can't hold connections open forever
	server := &http.Server{
		Handler:           http.HandlerFunc(handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
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

// fakeLoginPage returns the router login HTML; showError adds the "Invalid username or password" line.
func fakeLoginPage(showError bool) string {
	errorHTML := ""
	if showError {
		errorHTML = `<p style="color: #ff4d4d; font-size: 14px;">Invalid username or password</p>`
	}

	return fmt.Sprintf(`<!DOCTYPE html>
		<html>
		<head>
			<title>Gateway - Login</title>
			<style>
				body { font-family: Arial, sans-serif; background: #1a1a1a; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
				.box { background: #2a2a2a; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); width: 300px; }
				h2 { margin-top: 0; font-size: 20px; border-bottom: 1px solid #444; padding-bottom: 10px; }
				input { width: 100%%; padding: 10px; margin: 8px 0; box-sizing: border-box; background: #333; border: 1px solid #555; color: #fff; border-radius: 4px; }
				button { width: 100%%; padding: 10px; background: #ff793b; border: none; color: white; font-weight: bold; border-radius: 4px; cursor: pointer; margin-top: 10px; }
				button:hover { background: #cc6225; }
			</style>
		</head>
		<body>
			<div class="box">
				<h2>Gateway Router</h2>
				<p style="color: #aaa; font-size: 13px; margin-top: 0;">Please log in to manage your router.</p>
				%s
				<form method="POST" action="/login">
					<input type="text" name="username" placeholder="Username" required>
					<input type="password" name="password" placeholder="Password" required>
					<button type="submit">Log In</button>
				</form>
			</div>
		</body>
		</html>`, errorHTML)
}
