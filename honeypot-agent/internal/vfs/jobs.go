package vfs

import (
	"strconv"
	"strings"
)

// Background jobs ("cmd &"), like ash's jobs.c part of ash.c. A real job runs alongside the shell; ours
// has no clock, so it runs at once, as a subshell (its cd and variables stay in it), and stops where it
// would go on for a while: at a sleep, at a program the attacker wrote ("./xmrig &": it never ends), or
// after maxBackground commands. It is "Running" from then on, without a word (a miner's
// "while :; do ./x; sleep 60; done &" prints nothing, where the shell used to say "can't fork").
// A job that ended is reported at the prompt after the next line ("[1]+  Done   cmd"), on a terminal.

// job is one background job: the processes of "cmd &" (several for a pipeline).
type job struct {
	num, pid int
	cmds     []string // each process's command, as ash writes it (cmdtxt); "" without job control
	running  bool
	status   string // how it ended: "Done", "Done(1)", "Terminated"...
	code     int    // its exit code ($? for wait)
	report   int    // the line after which the prompt reports it (s.linesRead)
}

const (
	maxBackground = 1000 // the commands one job may run before it counts as running for ever
	maxJobs       = 32   // jobs a shell keeps (running, or ended and not reported yet); more: the fork fails
	maxJobText    = 512  // bytes of a job's command kept: what jobs shows
)

// background runs "cmd &" (evaltree's NBACKGND): a job; $! is its PID, $? 0.
func (s *Shell) background(n *node, o *output) {
	if len(s.jobs) >= maxJobs {
		s.raise(o, "", "can't fork: Resource temporarily unavailable")
		return
	}
	outer := s.budget
	s.budget = min(outer, maxBackground)
	given, wasBackground := s.budget, s.inBackground
	s.child(o, func() {
		s.inBackground, s.stdin = true, "" // its input: /dev/null (a terminal's would stop it)
		s.eval(n.body, o)
	})
	s.inBackground = wasBackground
	j := &job{num: 1, running: s.frozen, code: s.status, report: s.linesRead + 1}
	s.frozen = false
	s.budget = outer - (given - s.budget)
	j.status = exitStatus(j.code)
	for s.findJob(j.num) != nil {
		j.num++ // the lowest free number
	}
	s.lastPID++
	j.pid = s.lastPID
	procs := []*node{n.body}
	if n.body.kind == nPipe {
		procs = n.body.list
	}
	for _, p := range procs {
		text := ""
		if s.interactive { // only job control keeps the commands (ash: doing_jobctl)
			text = cmdtxt(p)
		}
		if len(text) > maxJobText {
			text = text[:maxJobText]
		}
		j.cmds = append(j.cmds, text)
	}
	s.jobs = append(s.jobs, j)
	s.bgPID, s.status = j.pid, 0
}

// exitStatus is how a job that ended shows (sprint_status48): "Done", "Done(N)".
func exitStatus(code int) string {
	if code == 0 {
		return "Done"
	}
	return "Done(" + strconv.Itoa(code) + ")"
}

// stopJob: the session's sleep, its own program or its budget would keep the job going: from here on it
// is running (stopped tells every level to stop; background clears it).
func (s *Shell) stopJob() bool {
	if s.inBackground {
		s.frozen = true
	}
	return s.inBackground
}

func (s *Shell) findJob(num int) *job {
	for _, j := range s.jobs {
		if j.num == num {
			return j
		}
	}
	return nil
}

// jobLine is a job the way ash's showjob writes it: "[1]+  Running" padded to 33, then its commands.
// + is the newest job, - the one before (curjob, prev_job); pids adds the PID (jobs -l).
func (s *Shell) jobLine(j *job, pids bool) string {
	mark := " "
	switch n := len(s.jobs); {
	case n > 0 && s.jobs[n-1] == j:
		mark = "+"
	case n > 1 && s.jobs[n-2] == j:
		mark = "-"
	}
	line := "[" + strconv.Itoa(j.num) + "]" + mark + "  "
	if pids {
		line += strconv.Itoa(j.pid) + " "
	}
	if j.running {
		line += "Running"
	} else {
		line += j.status
	}
	line += strings.Repeat(" ", max(33-len(line), 1)) + strings.Join(j.cmds, " | ")
	return line + "\n"
}

// freeJob forgets a job that ended, once it was shown.
func (s *Shell) freeJob(j *job) {
	for i, k := range s.jobs {
		if k == j {
			s.jobs = append(s.jobs[:i:i], s.jobs[i+1:]...)
			return
		}
	}
}

// reportJobs is what the interactive shell prints before its prompt (showjobs SHOW_CHANGED): the jobs that
// ended, newest first, then forgets them.
func (s *Shell) reportJobs(o *output) {
	for i := len(s.jobs) - 1; i >= 0; i-- {
		if j := s.jobs[i]; !j.running && j.report <= s.linesRead {
			o.add(2, s.jobLine(j, false))
			s.freeJob(j)
		}
	}
}

// getJob finds the job a builtin names: %N, %% / %+ / nothing = the newest, %- the one before, or a PID.
func (s *Shell) getJob(name string) (*job, string) {
	n := len(s.jobs)
	switch name {
	case "", "%", "%%", "%+":
		if n == 0 {
			return nil, "No current job"
		}
		return s.jobs[n-1], ""
	case "%-":
		if n < 2 {
			return nil, name + ": no such job"
		}
		return s.jobs[n-2], ""
	}
	if num, ok := strings.CutPrefix(name, "%"); ok {
		if k, err := strconv.Atoi(num); err == nil {
			if j := s.findJob(k); j != nil {
				return j, ""
			}
		}
		return nil, name + ": no such job"
	}
	for _, j := range s.jobs {
		if strconv.Itoa(j.pid) == name {
			return j, ""
		}
	}
	return nil, name + ": no such job"
}

// jobs [-lp] [JOB...]: the jobs, newest first; those that ended are shown once, then forgotten.
func (s *Shell) jobsBuiltin(args []string, o *output) int {
	pids, onlyPIDs := false, false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && len(args[0]) > 1 {
		pids = pids || strings.Contains(args[0], "l")
		onlyPIDs = onlyPIDs || strings.Contains(args[0], "p")
		args = args[1:]
	}
	show := func(j *job) {
		if onlyPIDs {
			o.add(1, strconv.Itoa(j.pid)+"\n")
		} else {
			o.add(1, s.jobLine(j, pids))
		}
		if !j.running {
			s.freeJob(j)
		}
	}
	if len(args) == 0 {
		for i := len(s.jobs) - 1; i >= 0; i-- {
			show(s.jobs[i])
		}
		return 0
	}
	code := 0
	for _, a := range args {
		j, err := s.getJob(a)
		if err != "" {
			o.add(2, s.errorf("jobs", err))
			code = 2
			continue
		}
		show(j)
	}
	return code
}

// wait [JOB...]: the exit code of the job (127: not a child of this shell). A job that ended is reported
// at this prompt. Simplification: one still running doesn't make it wait (a real one would, for ever).
func (s *Shell) wait(args []string, o *output) int {
	if len(args) == 0 {
		for _, j := range s.jobs {
			j.report = min(j.report, s.linesRead)
		}
		return 0
	}
	code := 0
	for _, a := range args {
		if !strings.HasPrefix(a, "%") && !isNumber(a) {
			o.add(2, s.errorf("wait", "Illegal number: "+a))
			return 2
		}
		j, err := s.getJob(a)
		switch {
		case err != "" && strings.HasPrefix(a, "%"):
			o.add(2, s.errorf("wait", err))
			code = 2
		case err != "":
			code = 127 // a PID that isn't one of its jobs
		case j.running:
			code = 0
		default:
			code, j.report = j.code, min(j.report, s.linesRead)
		}
	}
	return code
}

// fg / bg [JOB]: only with job control (the interactive shell). fg prints the job's command and takes it
// back (simplification: one still running returns at once), bg prints "[N] command".
func (s *Shell) fgBg(name string, args []string, o *output) int {
	if len(args) == 0 {
		args = []string{""}
	}
	j, err := s.getJob(args[0])
	if err == "" && !s.interactive {
		if args[0] == "" {
			args[0] = "(null)" // uClibc's printf of ash's NULL
		}
		err = "job " + args[0] + " not created under job control"
	}
	if err != "" {
		o.add(2, s.errorf(name, err))
		return 2
	}
	text := strings.Join(j.cmds, " | ") + "\n"
	if name == "bg" {
		o.add(1, "["+strconv.Itoa(j.num)+"] "+text)
		return 0
	}
	o.add(1, text)
	s.freeJob(j)
	if j.running {
		return 0
	}
	return j.code
}

// signalNames are the signals kill knows by name and how a job they end shows (uClibc's strsignal).
var signalNames = []struct{ name, shown string }{
	1: {"HUP", "Hangup"}, 2: {"INT", "Interrupt"}, 3: {"QUIT", "Quit"}, 4: {"ILL", "Illegal instruction"},
	5: {"TRAP", "Trace/breakpoint trap"}, 6: {"ABRT", "Aborted"}, 7: {"BUS", "Bus error"},
	8: {"FPE", "Floating point exception"}, 9: {"KILL", "Killed"}, 10: {"USR1", "User defined signal 1"},
	11: {"SEGV", "Segmentation fault"}, 12: {"USR2", "User defined signal 2"}, 13: {"PIPE", "Broken pipe"},
	14: {"ALRM", "Alarm clock"}, 15: {"TERM", "Terminated"},
}

// kill [-SIGNAL | -s SIGNAL] TARGET...: %N and the PIDs of jobs end that job (reported at the next prompt
// but one, like a job that ended); signal 0 and the others (STOP, CONT...) leave it. Other PIDs: nothing
// happens (simplification: the router's processes don't die).
func (s *Shell) kill(args []string, o *output) int {
	sig := 15
	if len(args) > 0 && strings.HasPrefix(args[0], "-") && len(args[0]) > 1 {
		name := strings.TrimPrefix(args[0], "-")
		args = args[1:]
		if name == "s" && len(args) > 0 {
			name, args = args[0], args[1:]
		}
		sig = -1
		if n, err := strconv.Atoi(name); err == nil {
			sig = n
		}
		for i, sn := range signalNames {
			if sn.name != "" && strings.TrimPrefix(strings.ToUpper(name), "SIG") == sn.name {
				sig = i
			}
		}
	}
	code := 0
	for _, a := range args {
		j, err := s.getJob(a)
		if err != "" && strings.HasPrefix(a, "%") {
			o.add(2, s.errorf("kill", err))
			code = 2
			continue
		}
		if j != nil && j.running && sig > 0 && sig < len(signalNames) {
			j.running, j.status, j.code, j.report = false, signalNames[sig].shown, 128+sig, s.linesRead+1
		}
	}
	return code
}

// cmdtxt writes a command the way ash shows it in jobs (cmdtxt in ash.c): rebuilt from the parsed tree,
// so spaces are single, { } and the redirections of a block are left out, a command's redirections get
// their descriptor (1>/dev/null), the words are written by cmdWord.
func cmdtxt(n *node) string {
	if n == nil {
		return ""
	}
	list := func(nodes []*node, sep string) string {
		parts := make([]string, len(nodes))
		for i, c := range nodes {
			parts[i] = cmdtxt(c)
		}
		return strings.Join(parts, sep)
	}
	switch n.kind {
	case nCmd:
		var parts []string
		words := n.words
		for len(words) > 0 && isAssignment(words[0]) {
			words = words[1:] // X=1 cmd: ash keeps the assignments apart and doesn't show them
		}
		for _, w := range words {
			parts = append(parts, cmdWord(w))
		}
		for _, r := range n.redirs {
			switch r.op {
			case "<<":
				parts = append(parts, "<<...")
			case "&>":
				parts = append(parts, "1>&"+cmdWord(r.target))
			default:
				parts = append(parts, strconv.Itoa(r.fd)+r.op+cmdWord(r.target))
			}
		}
		return strings.Join(parts, " ")
	case nList:
		return list(n.list, "; ")
	case nAndOr:
		text := cmdtxt(n.list[0])
		for i, op := range n.ops {
			if op == tAnd {
				text += " && "
			} else {
				text += " || "
			}
			text += cmdtxt(n.list[i+1])
		}
		return text
	case nPipe:
		return list(n.list, " | ")
	case nNot:
		return "!" + cmdtxt(n.body)
	case nSubshell:
		return "(" + cmdtxt(n.body) + ")"
	case nBrace, nBackgnd:
		return cmdtxt(n.body)
	case nIf:
		text := "if " + cmdtxt(n.test) + "; then " + cmdtxt(n.body)
		if n.orElse != nil {
			text += "; else " + cmdtxt(n.orElse)
		}
		return text + "; fi"
	case nWhile, nUntil:
		word := "while "
		if n.kind == nUntil {
			word = "until "
		}
		return word + cmdtxt(n.test) + "; do " + cmdtxt(n.body) + "; done"
	case nFor:
		words := make([]string, len(n.words))
		for i, w := range n.words {
			words[i] = cmdWord(w)
		}
		return "for " + n.name + " in " + strings.Join(words, " ") + "; do " + cmdtxt(n.body) + "; done"
	case nCase:
		text := "case " + cmdWord(n.words[0]) + " in "
		for _, c := range n.cases {
			text += cmdWord(c.patterns[0]) + ") " + cmdtxt(c.body) + ";; " // only the first pattern, like ash
		}
		return text + "esac"
	case nFunc:
		return n.name + "() { ... }"
	}
	return ""
}

// cmdWord writes a word the way ash's cmdputs does from its parsed form: quotes become "...", $X ${X},
// $(...) and `...` "$(...)", an escaped character loses its backslash.
func cmdWord(w string) string {
	var b strings.Builder
	quoted := false // inside "..."
	for i := 0; i < len(w); {
		c := w[i]
		switch {
		case c == '"':
			quoted = !quoted
			b.WriteByte('"')
			i++
		case c == '\\' && i+1 < len(w):
			if quoted && !strings.ContainsRune("$`\"\\", rune(w[i+1])) {
				b.WriteByte('\\') // "a\b": the backslash stays
			}
			b.WriteByte(w[i+1])
			i += 2
		case c == '\'' && !quoted:
			end, _ := partEnd(w, i)
			b.WriteString(`"` + strings.TrimSuffix(w[i+1:end], "'") + `"`)
			i = end
		case c == '`':
			end, _ := partEnd(w, i)
			b.WriteString("$(...)")
			i = end
		case c == '$' && i+1 < len(w) && strings.IndexByte("({'", w[i+1]) >= 0:
			end, _ := partEnd(w, i)
			part := w[i:end]
			if strings.HasPrefix(part, "$(") && !strings.HasPrefix(part, "$((") {
				part = "$(...)"
			}
			b.WriteString(part) // ${X...} and $((...)) as written
			i = end
		case c == '$' && i+1 < len(w) && strings.IndexByte("@*#?-$!0123456789", w[i+1]) >= 0:
			b.WriteString("${" + w[i+1:i+2] + "}")
			i += 2
		case c == '$' && i+1 < len(w) && isNameStart(w[i+1]):
			j := i + 2
			for j < len(w) && isNameChar(w[j]) {
				j++
			}
			b.WriteString("${" + w[i+1:j] + "}")
			i = j
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}
