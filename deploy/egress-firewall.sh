#!/bin/sh
# Blocks NEW connections started by the exposed containers: agent (br-honeynet) and dashboard (br-frontend).
# They still answer whoever connects to them, but can't reach the internet, other networks or the host.
# A healthy honeypot never connects out, so every attempt is logged as "honeypot-egress:".

# Usage (on the server, as root, after Docker starts; safe to rerun): sh egress-firewall.sh [remove]
# The rules are gone after a reboot; the honeypot-egress.service systemd unit puts them back.
set -eu

BRIDGES="br-honeynet br-frontend"   # names fixed in docker-compose.yml (driver_opts)
LOG="-m limit --limit 6/min -j LOG --log-prefix honeypot-egress:"
ACTION="${1:-add}"

# rule CHAIN RULE...: inserts the rule FIRST in the chain if it isn't there yet (-C = check),
# or removes it, on "remove".
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

# DOCKER-USER = the chain Docker leaves for our own rules (Docker never changes it).
# It exists only while Docker runs with the iptables backend.
if ! iptables -n -L DOCKER-USER >/dev/null 2>&1; then
	echo "error: the DOCKER-USER chain does not exist (Docker is not running, or it uses nftables directly)" >&2
	exit 1
fi

for br in $BRIDGES; do
	# Traffic routed THROUGH the host (internet / other networks). "! -o $br" allows traffic within
	# the same network (e.g. loadgen -> agent). Only state NEW: replies to clients are ESTABLISHED.
	# -I inserts at the top -> REJECT first, then LOG above it (LOG doesn't stop the packet).
	rule DOCKER-USER -i "$br" ! -o "$br" -m conntrack --ctstate NEW -j REJECT
	# shellcheck disable=SC2086 # $LOG must be split into words
	rule DOCKER-USER -i "$br" ! -o "$br" -m conntrack --ctstate NEW $LOG

	# Traffic to the host itself (e.g. the server's real SSH).
	rule INPUT -i "$br" -m conntrack --ctstate NEW -j REJECT
	# shellcheck disable=SC2086
	rule INPUT -i "$br" -m conntrack --ctstate NEW $LOG
done

if [ "$ACTION" = remove ]; then
	echo "egress-firewall: rules removed"
else
	echo "egress-firewall: rules active for $BRIDGES"
fi
