package vfs

import (
	"strings"
	"testing"
)

// Background jobs: sessions typed line by line on a terminal, compared with the real BusyBox 1.30.1 ash
// (sh -i on a tty, through script). Where a real job would take time (sleep 60), ours is "Running".
func TestBackgroundJobs(t *testing.T) {
	const pad = "                       " // "Done" + 23 = column 33
	sessions := [][]struct{ line, want string }{
		{ // a miner's loop: it prints once and runs on, quietly (it used to end in "can't fork")
			{"while true; do echo x; sleep 60; done &", "x\n"},
			{"jobs", "[1]+  Running                    while true; do echo x; sleep 60; done\n"},
			{"echo st=$?", "st=0\n"},
			{"false & wait $!; echo w=$?", "w=1\n[2]+  Done(1)                    false\n"}, // waited: reported now
			{"cd /tmp & pwd", "/root\n"},                                     // a job is a subshell
			{"export X=1 & echo X=$X", "X=\n[2]-  Done" + pad + "cd /tmp\n"}, // at the prompt after the next line
			{":", "[3]+  Done" + pad + "export X=1\n"},
			{"for i in 1 2; do sleep 9; done > /dev/null &", ""},
			{"{ echo 'q r' \"$a b\" `echo x` ${x:-y} $1 a=$b \\z >/dev/null 2>&1 </dev/null 3>&-; sleep 9; } &", ""},
			{"! sleep 9 | cat &", ""},
			{"jobs", "[4]+  Running                    !sleep 9 | cat\n" +
				"[3]-  Running                    echo \"q r\" \"${a} b\" $(...) ${x:-y} ${1} a=${b} z 1>/dev/null 2>&1 0</dev/null 3>&-; sleep 9\n" +
				"[2]   Running                    for i in 1 2; do sleep 9; done\n" +
				"[1]   Running                    while true; do echo x; sleep 60; done\n"},
		},
		{
			{"sleep 9 &", ""},
			{"sleep 8 &", ""},
			{"sleep 7 | cat &", ""},
			{"sleep 6 &", ""},
			{"kill %1; echo k=$?", "k=0\n"},
			// (a real kill followed by other commands is often reported at that prompt already: timing)
			{"kill -9 %3 %4; kill %9; echo k9=$?", "-sh: kill: %9: no such job\nk9=2\n[1]   Terminated                 sleep 9\n"},
			{":", "[4]+  Killed                     sleep 6\n[3]+  Killed                     sleep 7 | cat\n"},
			{"wait %7; wait abc; jobs %8; echo $?", "-sh: wait: %7: no such job\n-sh: wait: Illegal number: abc\n" +
				"-sh: jobs: %8: no such job\n2\n"},
			{"fg; echo fg=$?", "sleep 8\nfg=0\n"}, // (a real fg waits for it)
			{"bg %2; echo bg=$?", "-sh: bg: %2: no such job\nbg=2\n"},
			{"wait 4444; echo $?", "127\n"},
			{"jobs -p | wc -l", "0\n"}, // the subshell of a pipe has no jobs
			{"fg; echo $?", "-sh: fg: No current job\n2\n"},
		},
		{ // a program of the attacker's runs for ever; $! is its PID; bg; the lowest free number
			{"cd /tmp; printf '\\177ELF' > m; ./m & echo $!", "531\n"},
			{"echo a & echo $!", "a\n532\n"},
			{"bg; jobs -l", "[2] echo a\n[2]+  532 Done                   echo a\n[1]+  531 Running                ./m\n"}, // shown, forgotten
			{"sleep 0 & kill -0 %1 $!; wait", "[2]+  Done" + pad + "sleep 0\n"},                                            // sleep 0 ends; kill -0 kills nothing
			{"kill -s sigkill 531; sleep 1 &", ""},                                                                         // signal names in any case, SIG or not
			{"jobs", "[2]+  Running                    sleep 1\n[1]-  Killed                     ./m\n"},
		},
		{ // the numbers: the lowest free one; %- is the job before the newest; jobs -p; a job's $? is 0
			{"sleep 1 & sleep 2 & sleep 3 & kill %2; false & echo $?", "0\n"},
			{"jobs -p; bg %-", "534\n533\n532\n531\n[1] sleep 1\n"}, // the ended [4] and [2] shown, forgotten...
			{"sleep 4 &", ""},
			{"jobs %2; (jobs); jobs -p | wc -l", "[2]+  Running                    sleep 4\n0\n"}, // ...so sleep 4 is [2]
			{"{ echo a; sleep 9; echo b; } &", "a\n"},                                             // b would come later
			{"X=1 Y=$a sleep 9 & if false; then :; elif true; then sleep 9; else :; fi &", ""},
			{"jobs %5 %6", "[5]-  Running                    sleep 9\n" +
				"[6]+  Running                    if false; then :; else if true; then sleep 9; else :; fi; fi\n"},
		},
	}
	for _, session := range sessions {
		sh := noColors()
		for _, tt := range session {
			if got, _, _ := sh.Run(tt.line); got != tt.want {
				t.Errorf("Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
			}
		}
	}

	// without job control (SSH without a pty, sh -c): no reports, no commands kept, no fg / bg
	sh := NewSSHShell("root", nil, false, false)
	for _, tt := range []struct{ line, want string }{
		{"false &", ""},
		{"wait", ""},
		{"jobs", "[1]+  Done(1)                    \n"},
		{"sleep 9 &", ""},
		{"fg", "-sh: fg: line 5: job (null) not created under job control\n"},
		{"kill %1; jobs", "[1]+  Terminated                 \n"},
		{"true | true &", ""},
		{"jobs", "[1]+  Done" + pad + " | \n"}, // a pipeline: a process each, their commands unknown
	} {
		if got, _, _ := sh.Run(tt.line); got != tt.want {
			t.Errorf("SSH Run(%q)\n got: %q\nwant: %q", tt.line, got, tt.want)
		}
	}
	if got, _, _ := NewSSHShell("root", nil, false, true).Run("sleep 9 & jobs; echo $!"); got != "[1]+  Running                    \n531\n" {
		t.Errorf("sh -c: %q", got)
	}
}

// A job can't keep the shell busy or fill its memory: it stops (running) after maxBackground commands,
// and the rest of the line runs; more than maxJobs jobs: the fork fails.
func TestBackgroundLimits(t *testing.T) {
	sh := noColors()
	if got, _, _ := sh.Run("while :; do :; done & echo after"); got != "after\n" {
		t.Errorf("an endless job: %q", got)
	}
	if got, _, _ := sh.Run("while :; do : & done; echo never"); got != "-sh: can't fork: Resource temporarily unavailable\n" {
		t.Errorf("endless jobs: %q", got)
	}
	if len(sh.jobs) != maxJobs {
		t.Errorf("%d jobs kept", len(sh.jobs))
	}
	if got, _, _ := sh.Run("echo ok"); !strings.HasPrefix(got, "ok\n[32]+  Done") { // the next line runs
		t.Errorf("after: %q", got)
	}
	long := strings.Repeat("x", 2000)
	if sh := noColors(); true {
		sh.Run("echo " + long + " &")
		if len(sh.jobs) != 1 || len(sh.jobs[0].cmds[0]) != maxJobText {
			t.Errorf("a long job's text: %v", sh.jobs)
		}
	}
}
