package vfs

import (
	"slices"
	"testing"
)

// What the FTP server sees agrees with the shell's ls -l: Lstat shows a symlink itself, Stat follows it
// (an applet -> /bin/busybox), and vsftpd's own directories have the modes vsftpd.mk gives them.
func TestFTPView(t *testing.T) {
	tests := []struct {
		stat             func(string) (FileInfo, bool)
		path, mode       string
		size             int64
		ok, dir, regular bool
	}{
		{Lstat, "/usr/bin/wget", "lrwxrwxrwx", 17, true, false, false},
		{Stat, "/usr/bin/wget", "-rwxr-xr-x", int64(binarySizes["/bin/busybox"]), true, false, true},
		{Stat, "/home/ftp", "dr-xr-xr-x", 40, true, true, false}, // anonymous's chroot: empty, not writable
		{Stat, "/usr/share/empty", "drwx------", 40, true, true, false},
		{Stat, "/etc/vsftpd.conf", "-rw-r--r--", int64(len(vsftpdConf)), true, false, true},
		{Stat, "/proc/uptime", "-r--r--r--", 0, true, false, true},
		{Stat, "/dev/null", "crw-rw-rw-", 0, true, false, false},
		{Stat, "/nope", "", 0, false, false, false},
	}
	for _, tt := range tests {
		f, ok := tt.stat(tt.path)
		if ok != tt.ok {
			t.Errorf("%s: found %v", tt.path, ok)
		} else if ok && (f.Mode != tt.mode || f.Size != tt.size || f.IsDir() != tt.dir || f.IsRegular() != tt.regular) {
			t.Errorf("%s: %+v", tt.path, f)
		}
	}

	if names := ReadDir("/home/ftp"); len(names) != 0 {
		t.Errorf("/home/ftp: %q", names)
	}
	if names := ReadDir("/home"); !slices.Equal(names, []string{"ftp"}) {
		t.Errorf("/home: %q", names)
	}
	if got, _, _ := NewShell().Run("ls -ld /home/ftp; cat /etc/vsftpd.conf"); got !=
		"dr-xr-xr-x    2 root     root            40 Jun  4  2020 /home/ftp\n"+vsftpdConf {
		t.Errorf("the shell sees: %q", got)
	}
}
