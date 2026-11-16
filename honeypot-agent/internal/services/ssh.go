package services

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"honeypot-agent/internal/models"
	"honeypot-agent/internal/shipper"
	"honeypot-agent/internal/vfs"
)

const (
	sshIdleTimeout = 60 * time.Second
	sshMaxCommands = 50
	sshMaxAuth     = 6 // cate parole are voie sa incerce pe o conexiune (ca OpenSSH)

	// Banner-ul pe care il vede atacatorul inainte de orice.
	// Telnet-ul nostru se da drept router cu BusyBox, iar routerele de genul
	// folosesc Dropbear, nu OpenSSH -> povestea trebuie sa fie aceeasi peste tot.
	sshServerVersion = "SSH-2.0-dropbear_2019.78"

	// Cheia serverului e salvata pe disc ca sa NU se schimbe la fiecare restart.
	sshHostKeyFile = "ssh_host_ed25519_key"
)

func RunSSH(address string, nodeID string, shipper *shipper.Shipper) error {
	hostKey, err := loadOrCreateHostKey(sshHostKeyFile)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	// limite de conexiuni + pauza la erori de accept (vezi limit.go).
	// La SSH conteaza dublu: fiecare handshake inseamna criptografie, adica procesor.
	listener = limitConnections(listener, "SSH")
	defer listener.Close()

	log.Println("SSH node running")
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err // limitListener reincearca singur erorile trecatoare; aici ajung doar cele fatale
		}
		// fiecare atacator primeste goroutine-ul lui, exact ca la telnet
		go handleSSH(conn, hostKey, nodeID, shipper)
	}
}

func handleSSH(conn net.Conn, hostKey ssh.Signer, nodeID string, shipper *shipper.Shipper) {
	defer conn.Close()

	ip, portText, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		ip = conn.RemoteAddr().String()
	}
	port, _ := strconv.Atoi(portText)

	sessionID := newSessionID()

	// campurile comune, la fel ca in http.go / telnet.go
	newEvent := func(eventType string) models.HoneypotEvent {
		return models.HoneypotEvent{
			Timestamp:  models.Now(),
			NodeID:     nodeID,
			EventType:  eventType,
			SourceIP:   ip,
			SourcePort: port,
			TargetPort: 22,
			Protocol:   "SSH",
			SessionID:  sessionID,
		}
	}

	shipper.EmitEvent(newEvent("session_start"))
	defer func() { shipper.EmitEvent(newEvent("session_end")) }()

	// ---------- Faza 1: handshake + login ----------
	// Biblioteca face criptografia; noi doar decidem ce parole "merg".
	config := &ssh.ServerConfig{
		ServerVersion: sshServerVersion,
		MaxAuthTries:  sshMaxAuth,
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			// cat timp atacatorul tot incearca parole, nu-l dam afara
			conn.SetDeadline(time.Now().Add(sshIdleTimeout))

			user := meta.User()
			pass := string(password)
			success := weakCredentials[user+":"+pass] // lista comuna, din common.go

			event := newEvent("login_attempt")
			event.Credentials = &models.Credentials{
				Username: user,
				Password: pass,
				Success:  success,
			}
			shipper.EmitEvent(event)

			if success {
				return nil, nil // nil error = "intra, boss"
			}
			time.Sleep(time.Second) // si SSH-ul real are delay la parola gresita
			return nil, errors.New("password rejected")
		},
		// Dropbear ofera exact 2 metode de login: "publickey" si "password" (fara keyboard-interactive,
		// pe care il are OpenSSH). Ca sa aratam la fel, acceptam sa ni se propuna chei, dar le refuzam
		// pe toate -> clientul trece pe parola. Fara callback-ul asta am oferi doar "password".
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			conn.SetDeadline(time.Now().Add(sshIdleTimeout))
			return nil, errors.New("public key rejected")
		},
	}
	config.AddHostKey(hostKey)

	// daca nici nu termina handshake-ul in 60s, pa
	conn.SetDeadline(time.Now().Add(sshIdleTimeout))

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return // handshake picat sau toate parolele gresite
	}
	defer sshConn.Close()

	// cereri "globale" (ex: port forwarding) -> le refuzam pe toate
	go ssh.DiscardRequests(reqs)

	// ---------- Faza 2: canalul de sesiune ----------
	// Un client SSH poate deschide mai multe "canale" pe aceeasi conexiune.
	// Noi servim doar primul canal de tip "session" (shell sau exec).
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		handleSSHSession(conn, channel, requests, newEvent, shipper)
		return
	}
}

// handleSSHSession asteapta sa vada ce vrea clientul: shell interactiv sau o singura comanda (exec).
func handleSSHSession(conn net.Conn, channel ssh.Channel, requests <-chan *ssh.Request,
	newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) {

	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "pty-req", "env", "window-change":
			// "da, sigur, ai terminal" - nu ne pasa de detalii
			req.Reply(true, nil)

		case "exec":
			// ssh root@host "uname -a" -> comanda vine direct aici, fara prompt
			var payload struct{ Command string }
			ssh.Unmarshal(req.Payload, &payload)
			req.Reply(true, nil)
			go ssh.DiscardRequests(requests)

			// fara terminal: raspunsul merge direct pe canal, cu \n simplu (ca la un server real)
			output, _ := runShellLine(vfs.NewShell(), payload.Command, newEvent, shipper)
			fmt.Fprint(channel, output)
			sendExitStatus(channel)
			return

		case "shell":
			// ssh root@host -> vrea prompt interactiv
			req.Reply(true, nil)
			go ssh.DiscardRequests(requests)

			runSSHShell(conn, channel, newEvent, shipper)
			sendExitStatus(channel)
			return

		default:
			// sftp, x11 si alte figuri -> refuzat
			req.Reply(false, nil)
		}
	}
}

// runSSHShell e bucla de shell fals, aproape identica cu Faza 2 din telnet.go.
func runSSHShell(conn net.Conn, channel ssh.Channel,
	newEvent func(string) models.HoneypotEvent, shipper *shipper.Shipper) {

	// fiecare conexiune primeste shell-ul ei (cu directorul curent si fisierele ei)
	sh := vfs.NewShell()

	// term.Terminal face pentru noi echo-ul, backspace-ul si sagetile.
	// Cu pty, clientul NU mai afiseaza singur ce tasteaza - serverul trebuie sa i-o trimita inapoi.
	// Bonus: cand scriem in el, transforma singur \n in \r\n.
	terminal := term.NewTerminal(channel, sh.Prompt())
	fmt.Fprint(terminal, vfs.Banner)

	for i := 0; i < sshMaxCommands; i++ {
		conn.SetDeadline(time.Now().Add(sshIdleTimeout))

		terminal.SetPrompt(sh.Prompt()) // promptul se schimba dupa cd
		line, err := terminal.ReadLine()
		if err != nil {
			return
		}

		output, exit := runShellLine(sh, line, newEvent, shipper)
		fmt.Fprint(terminal, output)
		if exit {
			return
		}
	}
}

// sendExitStatus ii spune clientului "comanda s-a terminat cu codul 0", ca un server real.
func sendExitStatus(channel ssh.Channel) {
	status := struct{ Status uint32 }{0}
	channel.SendRequest("exit-status", false, ssh.Marshal(&status))
}

// loadOrCreateHostKey citeste cheia serverului de pe disc sau o genereaza prima data.
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, err
	}
	log.Println("generated new SSH host key:", path)
	return ssh.NewSignerFromKey(privateKey)
}
