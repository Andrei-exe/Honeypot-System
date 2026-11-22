DEFAULT_RECOMMENDATION = "Urmareste IP-ul si blocheaza-l in firewall daca revine."

RECOMMENDATIONS = [
    ("fisier-momeala", "Tine parolele (Wi-Fi, PPPoE) in fisiere citibile doar de root si schimba-le daca cineva a avut shell."),
    ("secret-momeala", "Parolele furate din fisiere sunt refolosite: schimba-le peste tot unde apar, nu doar pe acest aparat."),
    ("login REUSIT", "Schimba parolele implicite; nu lasa conturi root sau admin cu parole simple."),
    ("brute-force", "Dezactiveaza login-ul cu parola pe SSH (doar chei) si pune fail2ban."),
    ("login pe cont critic", "Interzice login-ul direct ca root (PermitRootLogin no) si foloseste chei SSH."),
    ("reverse shell", "Filtreaza conexiunile de iesire si urmareste procesele bash/nc pornite de servicii."),
    ("persistenta", "Verifica periodic crontab si ~/.ssh/authorized_keys pe serverele reale."),
    ("sterge", "Trimite log-urile pe alt server, ca un atacator sa nu le poata sterge."),
    ("descarcare", "Blocheaza traficul de iesire neasteptat si monteaza /tmp cu noexec."),
    ("executabil", "Monteaza /tmp si /dev/shm cu noexec, ca fisierele de acolo sa nu poata rula."),
    ("citeste", "Restrange accesul la fisierele de sistem si nu folosi conturi cu drepturi de root."),
    ("tipic Mirai", "Schimba parolele din fabrica ale routerelor si camerelor; dezactiveaza Telnet."),
    ("Log4Shell", "Actualizeaza Log4j la o versiune reparata si blocheaza LDAP/RMI spre exterior."),
    ("SQL injection", "Foloseste interogari parametrizate in aplicatie si un WAF in fata ei."),
    ("ruleze", "Nu trimite niciodata date de la utilizator direct in comenzi sau in eval()."),
    ("ruleaza cod", "Urmareste procesele: un serviciu web sau SSH n-ar trebui sa porneasca python/perl."),
    ("payload ascuns", "Urmareste procesele si comenzile cu base64: asa se ascunde malware-ul."),
    ("fundal", "Urmareste procesele pornite cu nohup sau & de conturile de servicii."),
    ("netcat", "Sterge netcat de pe serverele unde nu e nevoie de el si filtreaza iesirea."),
    ("scaneaza", "Separa reteaua, ca un server compromis sa nu le poata vedea pe celelalte."),
    ("path traversal", "Valideaza caile primite si ruleaza aplicatia web cu drepturi minime."),
    ("XSS", "Escapeaza tot textul venit de la utilizatori inainte sa-l afisezi."),
    ("cauta", "Nu publica fisiere de configurare (.env, .git) sau panouri de administrare pe internet."),
    ("afla", "Normal dupa un login reusit: important e cum a intrat, vezi alertele de login."),
    ("probe pe portul", "Inchide in firewall porturile pe care nu le folosesti."),
]


def recommend(alert):
    """Ce ar trebui facut pe un server REAL atacat la fel. Cauta un cuvant cheie in motivul alertei."""
    reason = alert.get("alert_reason", "").lower()
    for keyword, recommendation in RECOMMENDATIONS:
        if keyword.lower() in reason:
            return recommendation
    return DEFAULT_RECOMMENDATION
