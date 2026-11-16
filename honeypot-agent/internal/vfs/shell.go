package vfs

import "strings"

// Banner = ce vede atacatorul imediat dupa login (si la Telnet, si la SSH).
const Banner = "\nBusyBox v1.30.1 built-in shell (ash)\n\n"

// Shell = shell-ul fals al UNEI conexiuni.
// Fiecare atacator primeste unul nou (NewShell): directorul curent si fisierele
// create de el sunt doar ale lui, alt atacator nu le vede.
type Shell struct {
	cwd   string            // directorul curent
	files map[string]string // fisiere create de atacator (echo > x, touch, cp)
	dirs  map[string]bool   // directoare create de atacator (mkdir)
}

func NewShell() *Shell {
	return &Shell{
		cwd:   "/root",
		files: map[string]string{},
		dirs:  map[string]bool{},
	}
}

// Prompt = "root@gateway:~# ", cu directorul curent in el (/root se scrie ~, ca la shell-urile reale).
func (s *Shell) Prompt() string {
	dir := s.cwd
	if dir == "/root" || strings.HasPrefix(dir, "/root/") {
		dir = "~" + dir[len("/root"):]
	}
	return "root@gateway:" + dir + "# "
}

// step = o comanda din linie + felul in care e legata de comanda dinainte.
type step struct {
	op   string   // ";" = oricum, "&&" = doar daca aia a mers, "||" = doar daca aia a picat, "|" = primeste output-ul ei
	args []string // comanda si argumentele, fara ghilimele
}

// Run executa o linie intreaga, ex: "cd /tmp && wget http://x/bot; chmod +x bot".
// Intoarce ce apare pe ecran (cu \n la capat de rand) si daca atacatorul a dat exit.
func (s *Shell) Run(line string) (string, bool) {
	var screen strings.Builder
	code := 0        // codul ultimei comenzi rulate: 0 = a mers, altceva = eroare
	piped := ""      // output-ul pastrat pentru comanda urmatoare, daca e legata cu |
	skipped := false // daca am sarit peste comanda dinainte (din cauza lui && sau ||)

	steps := parse(line)
	for i, st := range steps {
		if len(st.args) == 0 {
			continue // ex: ";;" sau un "&" la final
		}
		if (st.op == "&&" && code != 0) || (st.op == "||" && code == 0) || (st.op == "|" && skipped) {
			skipped = true
			continue
		}
		skipped = false

		input := ""
		if st.op == "|" {
			input = piped
		}

		out, c, exit := s.exec(st.args, input)
		code = c
		if exit {
			return screen.String(), true
		}

		// daca urmatoarea comanda e legata cu |, output-ul nu ajunge pe ecran, ci la ea
		if i+1 < len(steps) && steps[i+1].op == "|" {
			piped = out
		} else if screen.Len() < maxSize {
			screen.WriteString(out)
		}
	}
	return screen.String(), false
}

// parse imparte linia in comenzi dupa ; && || | (dar nu si intre ghilimele),
// iar fiecare comanda in cuvinte (dupa spatii). Ghilimelele dispar, ca in shell-ul real.
func parse(line string) []step {
	steps := []step{{op: ";"}}
	var word strings.Builder
	inWord := false
	var quote byte // ' sau " cand suntem intre ghilimele, 0 altfel

	endWord := func() {
		if inWord {
			last := &steps[len(steps)-1]
			last.args = append(last.args, word.String())
			word.Reset()
			inWord = false
		}
	}
	newStep := func(op string) {
		endWord()
		steps = append(steps, step{op: op})
	}

	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0: // intre ghilimele totul e text, pana la ghilimeaua de inchidere
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inWord = true // "" e tot un cuvant (gol)
		case c == ' ' || c == '\t' || c == '\r':
			endWord()
		case c == ';' || c == '\n':
			newStep(";")
		case c == '&' && strings.HasSuffix(word.String(), ">"):
			word.WriteByte(c) // 2>&1 e redirectare, nu operator
		case c == '&' || c == '|':
			if i+1 < len(line) && line[i+1] == c {
				newStep(line[i : i+2]) // && sau ||
				i++
			} else if c == '|' {
				newStep("|")
			} else {
				newStep(";") // un singur & = "ruleaza in fundal" -> pentru noi e ca ;
			}
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	endWord()
	return steps
}

// redirect = unde trebuie sa ajunga output-ul unei comenzi.
type redirect struct {
	file       string // > fisier: output-ul se scrie aici, nu pe ecran
	append     bool   // >> fisier: adauga la final, nu suprascrie
	hideErrors bool   // 2>/dev/null: nu afisam erorile
}

// parseRedirects scoate redirectarile din argumente:
// ["echo", "hi", ">", "a.txt"] -> ["echo", "hi"] + redirect{file: "a.txt"}
func parseRedirects(args []string) ([]string, redirect) {
	var clean []string
	var r redirect
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "1>") {
			a = a[1:] // 1> e acelasi lucru cu >
		}

		switch {
		case a == "2>&1":
			// "erorile merg unde merge si output-ul" - la noi oricum sunt impreuna
		case strings.HasPrefix(a, "2>"):
			r.hideErrors = true
			if a == "2>" {
				i++ // "2> fisier": sarim si peste numele fisierului
			}
		case strings.HasPrefix(a, ">"):
			r.append = strings.HasPrefix(a, ">>")
			r.file = strings.TrimLeft(a, ">")
			if r.file == "" && i+1 < len(args) {
				i++ // "> fisier", cu spatiu intre ele
				r.file = args[i]
			}
			if strings.HasPrefix(r.file, "&") {
				r.file = "" // >&2 = "trimite la erori" -> tot pe ecran ajunge
			}
		default:
			clean = append(clean, a)
		}
	}
	return clean, r
}

// exec ruleaza o singura comanda (fara ; && || |), cu tot cu redirectari.
// Intoarce ce afiseaza, codul de iesire si daca e exit.
func (s *Shell) exec(args []string, input string) (string, int, bool) {
	args, r := parseRedirects(args)

	out, code, exit := "", 0, false
	if len(args) > 0 { // "> fisier" singur e valid: doar creeaza fisierul gol
		out, code, exit = s.command(args, input)
	}

	// Pe un sistem real, erorile merg pe alt "canal" (stderr) decat output-ul normal (stdout).
	// La noi sunt in acelasi text, asa ca folosim o regula simpla:
	// daca comanda a picat (cod != 0), tot ce a scris e mesajul de eroare.
	failed := code != 0
	if failed && r.hideErrors {
		out = "" // 2>/dev/null: eroarea dispare
	}
	if r.file != "" {
		content := out
		if failed {
			content = "" // eroarea ramane pe ecran, in fisier nu ajunge nimic (dar fisierul se creeaza)
		}
		if msg := s.writeFile(r.file, content, r.append); msg != "" {
			return msg, 1, exit
		}
		if !failed {
			out = "" // a ajuns in fisier, nu pe ecran
		}
	}
	return out, code, exit
}
