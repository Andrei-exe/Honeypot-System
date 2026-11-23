package vfs

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// date and the time formats it reads and prints (BusyBox 1.30.1's coreutils/date.c, uClibc's strftime).

// date [-uR] [-I[SPEC]] [-d TIME] [+FORMAT]: the router's clock, in UTC (no time zone is set).
// date -s TIME prints TIME and doesn't change the clock (simplification).
func date(args []string) (string, int, bool) {
	const dateUsage = " [OPTIONS] [+FMT] [TIME]\n\nDisplay time (using +FMT), or set time\n\n" +
		"\t[-s,--set] TIME\tSet time to TIME\n\t-u,--utc\tWork in UTC (don't convert to local time)\n" +
		"\t-R,--rfc-2822\tOutput RFC-2822 compliant date string\n\t-I[SPEC]\tOutput ISO-8601 compliant date string\n" +
		"\t\t\tSPEC='date' (default) for date only,\n\t\t\t'hours', 'minutes', or 'seconds' for date and\n" +
		"\t\t\ttime to the indicated precision\n\t-r,--reference FILE\tDisplay last modification time of FILE\n" +
		"\t-d,--date TIME\tDisplay TIME, not 'now'\n\t-D FMT\t\tUse FMT for -d TIME conversion\n\n" +
		"Recognized TIME formats:\n\thh:mm[:ss]\n\t[YYYY.]MM.DD-hh:mm[:ss]\n\tYYYY-MM-DD hh:mm[:ss]\n" +
		"\t[[[[[YY]YY]MM]DD]hh]mm[.ss]\n\t'date TIME' form accepts MMDDhhmm[[YY]YY][.ss] instead"
	t := now().UTC()
	format := "%a %b %e %H:%M:%S %Z %Y"
	var when string
	hasWhen, utc, fixedFormat := false, false, false
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		value := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case a == "--help":
			return usage("date", dateUsage)
		case a == "-u" || a == "--utc":
			utc = true // TZ=UTC0: uClibc then writes "UTC" for %z too
		case a == "-R" || a == "--rfc-2822":
			format, fixedFormat = "%a, %d %b %Y %H:%M:%S %z", true
		case strings.HasPrefix(a, "-I"):
			fixedFormat = true
			format = map[string]string{"": "%Y-%m-%d", "date": "%Y-%m-%d", "hours": "%Y-%m-%dT%H%z",
				"minutes": "%Y-%m-%dT%H:%M%z", "seconds": "%Y-%m-%dT%H:%M:%S%z"}[strings.TrimPrefix(a, "-I")]
			if format == "" {
				return "date: invalid argument '" + strings.TrimPrefix(a, "-I") + "' for 'date -I'\n", 1, false
			}
		case a == "-d" || a == "--date" || a == "-s" || a == "--set":
			when, hasWhen = value(), true
		case strings.HasPrefix(a, "--date="):
			when, hasWhen = strings.TrimPrefix(a, "--date="), true
		case a == "-D" || a == "-r":
			value()
		case strings.HasPrefix(a, "+"):
			format, fixedFormat = a[1:], false
		case strings.HasPrefix(a, "-") && len(a) > 1:
			out, _, _ := usage("date", dateUsage)
			return "date: invalid option -- " + a[1:2] + "\n" + out, 1, false
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) > 1 {
		return usage("date", dateUsage)
	}
	if hasWhen {
		parsed, ok := parseDate(when, t)
		if !ok {
			return "date: invalid date '" + when + "'\n", 1, false
		}
		t = parsed
	}
	if utc && fixedFormat { // -R / -I under -u say "UTC"; a +%z of the user's stays +0000 (measured)
		format = strings.ReplaceAll(format, "%z", "%Z")
	}
	return strftime(format, t) + "\n", 0, false
}

// parseDate reads the TIME of date -d: @SECONDS, YYYY-MM-DD [hh:mm[:ss]], hh:mm[:ss] (today).
func parseDate(text string, today time.Time) (time.Time, bool) {
	if secs, ok := strings.CutPrefix(text, "@"); ok {
		n, err := strconv.ParseInt(secs, 10, 64)
		return time.Unix(n, 0).UTC(), err == nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, text); err == nil {
			return t, true
		}
	}
	for _, layout := range []string{"15:04:05", "15:04"} {
		if t, err := time.Parse(layout, text); err == nil {
			return time.Date(today.Year(), today.Month(), today.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC), true
		}
	}
	return time.Time{}, false
}

// strftime formats t like uClibc's strftime (the conversions BusyBox's date passes on).
func strftime(format string, t time.Time) string {
	var out strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 == len(format) {
			out.WriteByte(format[i])
			continue
		}
		i++
		hour12 := t.Hour() % 12
		if hour12 == 0 {
			hour12 = 12
		}
		switch format[i] {
		case 'a':
			out.WriteString(t.Format("Mon"))
		case 'A':
			out.WriteString(t.Format("Monday"))
		case 'b', 'h':
			out.WriteString(t.Format("Jan"))
		case 'B':
			out.WriteString(t.Format("January"))
		case 'c':
			out.WriteString(t.Format("Mon Jan _2 15:04:05 2006"))
		case 'C':
			fmt.Fprintf(&out, "%02d", t.Year()/100)
		case 'd':
			fmt.Fprintf(&out, "%02d", t.Day())
		case 'D', 'x':
			out.WriteString(t.Format("01/02/06"))
		case 'e':
			fmt.Fprintf(&out, "%2d", t.Day())
		case 'F':
			out.WriteString(t.Format("2006-01-02"))
		case 'H':
			fmt.Fprintf(&out, "%02d", t.Hour())
		case 'I':
			fmt.Fprintf(&out, "%02d", hour12)
		case 'j':
			fmt.Fprintf(&out, "%03d", t.YearDay())
		case 'k':
			fmt.Fprintf(&out, "%2d", t.Hour())
		case 'l':
			fmt.Fprintf(&out, "%2d", hour12)
		case 'm':
			fmt.Fprintf(&out, "%02d", int(t.Month()))
		case 'M':
			fmt.Fprintf(&out, "%02d", t.Minute())
		case 'n':
			out.WriteByte('\n')
		case 'p', 'P':
			out.WriteString(t.Format("PM"))
		case 'r':
			fmt.Fprintf(&out, "%02d:%02d:%02d %s", hour12, t.Minute(), t.Second(), t.Format("PM"))
		case 'R':
			out.WriteString(t.Format("15:04"))
		case 's':
			out.WriteString(strconv.FormatInt(t.Unix(), 10))
		case 'S':
			fmt.Fprintf(&out, "%02d", t.Second())
		case 't':
			out.WriteByte('\t')
		case 'T', 'X':
			out.WriteString(t.Format("15:04:05"))
		case 'u':
			fmt.Fprintf(&out, "%d", (int(t.Weekday())+6)%7+1)
		case 'w':
			fmt.Fprintf(&out, "%d", int(t.Weekday()))
		case 'y':
			fmt.Fprintf(&out, "%02d", t.Year()%100)
		case 'Y':
			fmt.Fprintf(&out, "%d", t.Year())
		case 'z':
			out.WriteString("+0000")
		case 'Z':
			out.WriteString("UTC")
		case '%':
			out.WriteByte('%')
		default:
			out.WriteByte('%')
			out.WriteByte(format[i])
		}
	}
	return out.String()
}
