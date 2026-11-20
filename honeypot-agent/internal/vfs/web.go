package vfs

import "path"

// The web interface: the files lighttpd serves (port 80) live in the fake filesystem too, so the
// web server and "cat /var/www/index.html" in the shell show the same thing.

// webRoot is lighttpd's server.document-root (Buildroot creates /var/www for it).
const webRoot = "/var/www"

// lighttpdConf is the vendor's short config. Buildroot installs lighttpd's sample one, which
// can't even start on this router (it wants a "lighttpd" user), so a vendor writes its own.
const lighttpdConf = `# Gateway web interface
server.modules       = ( "mod_access", "mod_cgi" )
server.document-root = "/var/www"
server.port          = 80
server.pid-file      = "/var/run/lighttpd.pid"
index-file.names     = ( "index.html" )
cgi.assign           = ( ".cgi" => "" )
mimetype.assign      = ( ".html" => "text/html", ".css" => "text/css",
                         ".js" => "application/javascript", ".png" => "image/png" )
`

// LoginPage is the router's login page: the file /var/www/index.html, and what login.cgi
// answers (with showError after a wrong password).
func LoginPage(showError bool) string {
	errorLine := ""
	if showError {
		errorLine = "\n    <p class=\"error\">Invalid username or password</p>"
	}
	return `<!DOCTYPE html>
<html>
<head>
  <title>Gateway - Login</title>
  <style>
    body { font-family: Arial, sans-serif; background: #1a1a1a; color: #fff; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .box { background: #2a2a2a; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); width: 300px; }
    h2 { margin-top: 0; font-size: 20px; border-bottom: 1px solid #444; padding-bottom: 10px; }
    .hint { color: #aaa; font-size: 13px; margin-top: 0; }
    .error { color: #ff4d4d; font-size: 14px; }
    input { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; background: #333; border: 1px solid #555; color: #fff; border-radius: 4px; }
    button { width: 100%; padding: 10px; background: #ff793b; border: none; color: white; font-weight: bold; border-radius: 4px; cursor: pointer; margin-top: 10px; }
    button:hover { background: #cc6225; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Gateway Router</h2>
    <p class="hint">Please log in to manage your router.</p>` + errorLine + `
    <form method="POST" action="/login.cgi">
      <input type="text" name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Log In</button>
    </form>
  </div>
</body>
</html>
`
}

// WebFile returns the file the web server sends for a URL path ("/" = index.html) and whether it
// exists. The path is cleaned first (like lighttpd does), so "/../../etc/passwd" stays in webRoot.
func WebFile(urlPath string) (string, bool) {
	p := path.Join(webRoot, path.Clean("/"+urlPath))
	if fakeDirs[p] {
		p += "/index.html" // index-file.names
	}
	return readBuiltin(p) // only the built-in files: an attacker's files are only in their shell
}
