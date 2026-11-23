package vfs

import "strings"

// The option parsers the applets share: options (single letters) and getopt (BusyBox's getopt32,
// with long options and uClibc's messages).

// options splits a tool's arguments into single-letter options and the rest ("-vi" = -v -i).
// takesValue: the letters followed by a value ("-n 5", "-n5"); "--" ends the options.
// bad = an unknown letter (the caller shows its usage).
func options(args []string, letters, takesValue string) (opts map[byte][]string, rest []string, bad byte) {
	opts = map[byte][]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return opts, append(rest, args[i+1:]...), 0
		}
		if len(a) < 2 || a[0] != '-' {
			rest = append(rest, a)
			continue
		}
		for j := 1; j < len(a); j++ {
			c := a[j]
			switch {
			case strings.IndexByte(takesValue, c) >= 0:
				value := a[j+1:]
				if value == "" && i+1 < len(args) {
					i++
					value = args[i]
				}
				opts[c] = append(opts[c], value)
				j = len(a)
			case strings.IndexByte(letters, c) >= 0:
				opts[c] = append(opts[c], "")
			default:
				return opts, rest, c
			}
		}
	}
	return opts, rest, 0
}

// getopt parses arguments like BusyBox's getopt32 over uClibc's getopt_long, for the applets whose
// messages for a wrong option were measured. spec is BusyBox's: a letter, "x:" takes a value, "x::" an
// optional one stuck to it ("-nv"). long maps "--name" to its letter ("--name=value", "--name value",
// a unique start of the name is enough). complaint = getopt's message; the caller adds its usage.
func getopt(applet string, args []string, spec string, long map[string]byte) (opts map[byte][]string, rest []string, complaint string) {
	kinds := map[byte]int{} // 0 = no value, 1 = a value, 2 = an optional value
	for i := 0; i < len(spec); i++ {
		c := spec[i]
		for i+1 < len(spec) && spec[i+1] == ':' {
			kinds[c]++
			i++
		}
		if _, ok := kinds[c]; !ok {
			kinds[c] = 0
		}
	}
	opts = map[byte][]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return opts, append(rest, args[i+1:]...), ""
		case strings.HasPrefix(a, "--"):
			name, value, hasValue := strings.Cut(a[2:], "=")
			var full string
			letters := map[byte]bool{}
			for n, c := range long {
				if n == name { // an exact name always wins
					full, letters = n, map[byte]bool{c: true}
					break
				}
				if strings.HasPrefix(n, name) {
					full = n
					letters[c] = true
				}
			}
			switch {
			case len(letters) == 0:
				return opts, rest, applet + ": unrecognized option `" + a + "'\n"
			case len(letters) > 1: // starts more than one name (two names of one letter are fine)
				return opts, rest, applet + ": option `" + a + "' is ambiguous\n"
			}
			c := long[full]
			switch {
			case kinds[c] == 0 && hasValue:
				return opts, rest, applet + ": option `--" + full + "' doesn't allow an argument\n"
			case kinds[c] > 0 && !hasValue:
				if i+1 == len(args) {
					return opts, rest, applet + ": option `" + a + "' requires an argument\n"
				}
				i++
				value = args[i]
			}
			opts[c] = append(opts[c], value)
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				c := a[j]
				kind, ok := kinds[c]
				switch {
				case !ok:
					return opts, rest, applet + ": invalid option -- " + string(c) + "\n"
				case kind == 0:
					opts[c] = append(opts[c], "")
					continue
				case kind == 1 && j+1 == len(a):
					if i+1 == len(args) {
						return opts, rest, applet + ": option requires an argument -- " + string(c) + "\n"
					}
					i++
					opts[c] = append(opts[c], args[i])
				default: // the rest of the word is the value
					opts[c] = append(opts[c], a[j+1:])
				}
				break
			}
		default:
			rest = append(rest, a) // "-" alone too
		}
	}
	return opts, rest, ""
}
