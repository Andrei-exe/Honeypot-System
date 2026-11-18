#!/bin/sh
# Blocheaza conexiunile NOI pornite din containerele expuse: agentul (br-honeynet) si
# dashboard-ul (br-frontend). Ei raspund in continuare celor care se conecteaza la ei,
# dar nu pot deschide singuri conexiuni spre internet, spre alte retele sau spre host.
# Un honeypot sanatos nu iese niciodata -> o incercare apare in log ca "honeypot-egress:".
#
# Pe server (Linux), ca root, DUPA ce porneste Docker. Se poate rula de oricate ori.
#   sh egress-firewall.sh           pune regulile (le sare pe cele care exista deja)
#   sh egress-firewall.sh remove    le scoate
# Dupa reboot regulile dispar -> le repune unitatea systemd honeypot-egress.service.
set -eu

BRIDGES="br-honeynet br-frontend"   # numele fixate in docker-compose.yml (driver_opts)
LOG="-m limit --limit 6/min -j LOG --log-prefix honeypot-egress:"
ACTION="${1:-add}"

# rule LANT REGULA... : pune regula PRIMA in lant, daca nu exista (-C = verifica),
# sau o scoate, la "remove".
rule() {
	chain=$1
	shift
	if [ "$ACTION" = remove ]; then
		while iptables -C "$chain" "$@" 2>/dev/null; do
			iptables -D "$chain" "$@"
		done
	else
		iptables -C "$chain" "$@" 2>/dev/null || iptables -I "$chain" "$@"
	fi
}

# DOCKER-USER = lantul lasat de Docker pentru regulile noastre (Docker nu-l modifica).
# Exista doar cat ruleaza Docker cu backend-ul iptables.
if ! iptables -n -L DOCKER-USER >/dev/null 2>&1; then
	echo "eroare: lantul DOCKER-USER nu exista (Docker nu ruleaza, sau foloseste nftables direct)" >&2
	exit 1
fi

for br in $BRIDGES; do
	# Trafic care TRECE prin host (spre internet / alte retele). "! -o $br" lasa traficul
	# din aceeasi retea (ex. loadgen -> agent). Doar starea NEW: raspunsurile sunt ESTABLISHED.
	# -I pune regula in varf -> intai REJECT, apoi LOG deasupra lui (LOG nu opreste pachetul).
	rule DOCKER-USER -i "$br" ! -o "$br" -m conntrack --ctstate NEW -j REJECT
	# shellcheck disable=SC2086 # $LOG trebuie sa se imparta in cuvinte
	rule DOCKER-USER -i "$br" ! -o "$br" -m conntrack --ctstate NEW $LOG

	# Trafic catre host-ul insusi (ex. SSH-ul real al serverului).
	rule INPUT -i "$br" -m conntrack --ctstate NEW -j REJECT
	# shellcheck disable=SC2086
	rule INPUT -i "$br" -m conntrack --ctstate NEW $LOG
done

if [ "$ACTION" = remove ]; then
	echo "egress-firewall: reguli scoase"
else
	echo "egress-firewall: reguli active pentru $BRIDGES"
fi
