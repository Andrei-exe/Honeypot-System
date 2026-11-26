DEFAULT_RECOMMENDATION = "Urmareste IP-ul si blocheaza-l in firewall daca revine."

# (codurile regulilor din filters.py, ce ar trebui facut pe un server REAL atacat la fel)
RECOMMENDATIONS = [
    (["honeytoken_read"], "Tine parolele (Wi-Fi, PPPoE) in fisiere citibile doar de root si schimba-le daca cineva a avut shell."),
    (["honeytoken_login"], "Parolele furate din fisiere sunt refolosite: schimba-le peste tot unde apar, nu doar pe acest aparat."),
    (["login_success"], "Schimba parolele implicite; nu lasa conturi root sau admin cu parole simple."),
    (["brute_force"], "Dezactiveaza login-ul cu parola pe SSH (doar chei) si pune fail2ban."),
    (["critical_user_login"], "Interzice login-ul direct ca root (PermitRootLogin no) si foloseste chei SSH."),
    (["reverse_shell"], "Filtreaza conexiunile de iesire si urmareste procesele bash/nc pornite de servicii."),
    (["ssh_key_persistence", "cron_persistence"], "Verifica periodic crontab si ~/.ssh/authorized_keys pe serverele reale."),
    (["clear_logs", "clear_history"], "Trimite log-urile pe alt server, ca un atacator sa nu le poata sterge."),
    (["download_attempt", "download_command", "file_download"], "Blocheaza traficul de iesire neasteptat si monteaza /tmp cu noexec."),
    (["make_executable"], "Monteaza /tmp si /dev/shm cu noexec, ca fisierele de acolo sa nu poata rula."),
    (["read_shadow", "read_passwd"], "Restrange accesul la fisierele de sistem si nu folosi conturi cu drepturi de root."),
    (["busybox_probe", "shell_probe"], "Schimba parolele din fabrica ale routerelor si camerelor; dezactiveaza Telnet."),
    (["web_log4shell"], "Actualizeaza Log4j la o versiune reparata si blocheaza LDAP/RMI spre exterior."),
    (["web_sql_injection"], "Foloseste interogari parametrizate in aplicatie si un WAF in fata ei."),
    (["web_command_injection", "web_code_injection"], "Nu trimite niciodata date de la utilizator direct in comenzi sau in eval()."),
    (["python_exec", "perl_exec"], "Urmareste procesele: un serviciu web sau SSH n-ar trebui sa porneasca python/perl."),
    (["decode_payload"], "Urmareste procesele si comenzile cu base64: asa se ascunde malware-ul."),
    (["background_process"], "Urmareste procesele pornite cu nohup sau & de conturile de servicii."),
    (["netcat"], "Sterge netcat de pe serverele unde nu e nevoie de el si filtreaza iesirea."),
    (["network_scan"], "Separa reteaua, ca un server compromis sa nu le poata vedea pe celelalte."),
    (["web_path_traversal"], "Valideaza caile primite si ruleaza aplicatia web cu drepturi minime."),
    (["web_xss"], "Escapeaza tot textul venit de la utilizatori inainte sa-l afisezi."),
    (["web_shadow_probe", "web_webshell_probe", "web_env_probe", "web_git_probe",
      "web_wordpress_probe", "web_phpmyadmin_probe", "web_actuator_probe"],
     "Nu publica fisiere de configurare (.env, .git) sau panouri de administrare pe internet."),
    (["system_discovery", "user_discovery"], "Normal dupa un login reusit: important e cum a intrat, vezi alertele de login."),
    (["port_probe"], "Inchide in firewall porturile pe care nu le folosesti."),
]

BY_RULE = {}
for rules, recommendation in RECOMMENDATIONS:
    for rule in rules:
        BY_RULE[rule] = recommendation


def recommend(rule):
    """Ce ar trebui facut pe un server REAL atacat la fel, dupa codul regulii care a dat alerta."""
    return BY_RULE.get(rule, DEFAULT_RECOMMENDATION)
