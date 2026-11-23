package vfs

import (
	"path"
	"strconv"
	"time"
)

// The FTP server: vsftpd (port 21) sees the same filesystem as the shell, so CWD, SIZE, MDTM and STAT
// agree with cd, ls -l and cat. FTP never writes (write_enable is off), so it sees only the firmware's files.

// vsftpdConf is the vendor's /etc/vsftpd.conf (Buildroot installs vsftpd's sample only if the vendor has
// none). vsftpd 3.0.3's defaults do the rest: no writes, anonymous ("ftp" or "anonymous", any password)
// chrooted in ftp's home, local users in their home, without chroot. No PASV: we never open a data connection.
const vsftpdConf = `listen=YES
anonymous_enable=YES
local_enable=YES
pasv_enable=NO
`

// FileInfo is what stat(2) says about a path.
type FileInfo struct {
	Mode    string // like ls -l: "drwxr-xr-x", "-rw-r--r--", "lrwxrwxrwx"
	Links   int
	Size    int64
	ModTime time.Time
	Target  string // a symlink's target
}

// IsDir reports whether f is a directory.
func (f FileInfo) IsDir() bool { return f.Mode[0] == 'd' }

// IsRegular reports whether f is a regular file (not a directory, link or device).
func (f FileInfo) IsRegular() bool { return f.Mode[0] == '-' }

// Lstat describes the clean absolute path p itself, without following a symlink.
func Lstat(p string) (FileInfo, bool) {
	var fs Shell // a shell without a session: only the built-in files
	if fakeLinks[p] == "" && !fs.exists(p) {
		return FileInfo{}, false
	}
	mode, links, size, target := fs.stat(p)
	n, _ := strconv.ParseInt(size, 10, 64) // a device's "major, minor" -> 0, its real st_size
	return FileInfo{Mode: mode, Links: links, Size: n, ModTime: fs.mtime(p), Target: target}, true
}

// Stat is Lstat after following symlinks, like stat(2).
func Stat(p string) (FileInfo, bool) {
	for i := 0; i < 8 && fakeLinks[p] != ""; i++ {
		p = resolve(path.Dir(p), fakeLinks[p]) // /usr/bin/wget -> ../../bin/busybox -> /bin/busybox
	}
	return Lstat(p)
}

// ReadDir returns the names in the directory dir, sorted, without . and ..
func ReadDir(dir string) []string {
	var fs Shell
	return fs.list(dir)
}
