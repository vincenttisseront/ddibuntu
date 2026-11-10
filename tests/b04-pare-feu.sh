#!/usr/bin/env bash
# Batterie 04 — pare-feu : rendu, syntaxe, puis comportement réel entre deux espaces de noms réseau
# (ip netns + veth) : ports autorisés joignables, autres refusés, réseaux d'administration respectés,
# administration jamais verrouillée (retour arrière), autres tables nftables préservées.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

FW="$RFS/usr/local/sbin/ddibuntu-fw"
PROBE="$ROOT/tests/probe.py"
export DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu"
export DDI_FW_CONF="$T_TMP/fw.conf" DDI_NFT_FILE="$T_TMP/fw.nft" DDI_FW_STATE="$T_TMP/state"
mkdir -p "$DDI_FW_STATE"
SRV=ddit-srv; CLI=ddit-cli
SRV_IP=10.99.0.1; ADMIN_IP=10.99.0.10; OTHER_IP=10.99.0.20
ADMIN_NET=10.99.0.8/29        # .8 à .15 : contient ADMIN_IP, pas OTHER_IP

fw() { "$FW" "$@"; }
fw_srv() { ip netns exec "$SRV" "$FW" "$@"; }
probe() { ip netns exec "$CLI" python3 "$PROBE" "$1" "$SRV_IP" "$2" "${3:-}"; }   # proto port [source]

cleanup() {
  [ -f "$T_TMP/listener.pid" ] && kill "$(cat "$T_TMP/listener.pid")" 2>/dev/null
  ip netns del "$SRV" 2>/dev/null; ip netns del "$CLI" 2>/dev/null
  return 0
}
trap 'cleanup; rm -rf "$T_TMP"' EXIT

echo "== Rendu et syntaxe =="
fw set ADMIN_NETS "$ADMIN_NET" >/dev/null
fw render > "$T_TMP/r1"; fw render > "$T_TMP/r2"
check "rendu déterministe (deux rendus identiques)" cmp "$T_TMP/r1" "$T_TMP/r2"
expect_grep "ensemble admin4 contient le réseau d'administration" "elements = \{ $ADMIN_NET \}" "$T_TMP/r1"
expect_grep "ports d'administration 22 et 443 réservés à admin4" 'ip saddr @admin4 tcp dport \{ 22, 443 \} accept' "$T_TMP/r1"
expect_grep "NDP IPv6 accepté (sans lui, IPv6 ne fonctionne plus)" 'nd-neighbor-solicit' "$T_TMP/r1"
expect_grep "réponses DHCP clientes acceptées (sport 67 vers 68)" 'udp sport 67 udp dport 68 accept' "$T_TMP/r1"
expect_grep "chaîne forward : drop" 'hook forward priority filter; policy drop' "$T_TMP/r1"
for v in "10.0.0.0/8" "2001:db8::/32" "10.0.0.0/8, 2001:db8::/32" ""; do
  fw set ADMIN_NETS "$v" >/dev/null 2>&1
  check "nft -c valide pour ADMIN_NETS=[$v]" fw check
done
fw set ADMIN_NETS "$ADMIN_NET" >/dev/null
fw set OPEN_TCP "8080, 9000" >/dev/null; fw set OPEN_UDP "53" >/dev/null
check "nft -c valide avec ports ouverts à tous (TCP 8080/9000, UDP 53)" fw check
fw set ADMIN_TCP "" >/dev/null
fw render > "$T_TMP/r3"
expect_nogrep "ADMIN_TCP vide : aucune règle d'administration" '@admin4 tcp' "$T_TMP/r3"
check "nft -c valide avec ADMIN_TCP vide" fw check
fw set ADMIN_TCP "22,443" >/dev/null; fw set OPEN_TCP "" >/dev/null; fw set OPEN_UDP "" >/dev/null
check_fail "apply refusé en mode hors-ligne (DDI_ROOT)" env DDI_ROOT="$T_TMP/x" "$FW" apply

echo "== Espaces de noms réseau =="
if ! ip netns add "$SRV" 2>/dev/null; then
  ko "création des espaces de noms réseau" "ip netns indisponible sur ce banc : les tests réseau n'ont pas pu être exécutés"
  finish; exit
fi
ip netns add "$CLI"
ip link add vsrv type veth peer name vcli
ip link set vsrv netns "$SRV"; ip link set vcli netns "$CLI"
ip -n "$SRV" addr add "$SRV_IP/24" dev vsrv; ip -n "$SRV" link set vsrv up; ip -n "$SRV" link set lo up
ip -n "$CLI" addr add "$ADMIN_IP/24" dev vcli; ip -n "$CLI" addr add "$OTHER_IP/24" dev vcli
ip -n "$CLI" link set vcli up; ip -n "$CLI" link set lo up
ip netns exec "$SRV" python3 "$PROBE" listen 22 443 8080 9000 53 5353 >/dev/null 2>&1 &
echo $! > "$T_TMP/listener.pid"
sleep 1
# Autre table nftables préexistante : doit survivre à toutes les opérations
ip netns exec "$SRV" nft add table ip autre
ip netns exec "$SRV" nft add chain ip autre c '{ type filter hook input priority 10; policy accept; }'

echo "== Référence : sans pare-feu, tout est joignable (valide la sonde) =="
expect_eq "sans règle : TCP 22 joignable" open "$(probe tcp 22 "$ADMIN_IP")"
expect_eq "sans règle : TCP 8080 joignable" open "$(probe tcp 8080 "$ADMIN_IP")"
expect_eq "sans règle : port fermé -> closed (RST)" closed "$(probe tcp 7777 "$ADMIN_IP")"
expect_eq "sans règle : UDP 53 joignable" open "$(probe udp 53 "$ADMIN_IP")"

echo "== Pare-feu appliqué : administration limitée au réseau d'administration =="
fw set ADMIN_NETS "$ADMIN_NET" >/dev/null
fw_srv apply >/dev/null 2>"$T_TMP/apply.err"; rc=$?
expect_eq "apply : code retour 0" 0 "$rc"
expect_eq "admin : TCP 22 joignable" open "$(probe tcp 22 "$ADMIN_IP")"
expect_eq "admin : TCP 443 joignable" open "$(probe tcp 443 "$ADMIN_IP")"
expect_eq "admin : TCP 8080 refusé (non ouvert)" filtered "$(probe tcp 8080 "$ADMIN_IP")"
expect_eq "admin : UDP 53 refusé (non ouvert)" filtered "$(probe udp 53 "$ADMIN_IP")"
expect_eq "hors réseau d'admin : TCP 22 refusé" filtered "$(probe tcp 22 "$OTHER_IP")"
expect_eq "hors réseau d'admin : TCP 443 refusé" filtered "$(probe tcp 443 "$OTHER_IP")"
expect_eq "ICMP echo répondu depuis le réseau d'admin" open "$(probe icmp 0 "$ADMIN_IP")"
expect_eq "ICMP echo répondu depuis un autre poste (diagnostic réseau)" open "$(probe icmp 0 "$OTHER_IP")"
expect_eq "autre table nftables préservée après apply" 1 "$(ip netns exec "$SRV" nft list tables | grep -c 'table ip autre')"
fw_srv status > "$T_TMP/status"
expect_eq "une seule règle d'administration IPv4 active" 1 "$(grep -c '@admin4 tcp dport' "$T_TMP/status")"
fw_srv apply >/dev/null 2>&1
fw_srv status > "$T_TMP/status2"
expect_eq "après deux apply : toujours une seule règle (remplacement atomique)" 1 "$(grep -c '@admin4 tcp dport' "$T_TMP/status2")"
expect_eq "après deux apply : toujours une seule table dédiée" 1 "$(ip netns exec "$SRV" nft list tables | grep -c 'table inet ddibuntu')"

echo "== Ports ouverts à tous =="
fw set OPEN_TCP "8080" >/dev/null; fw set OPEN_UDP "53" >/dev/null
fw_srv apply >/dev/null 2>&1
expect_eq "TCP 8080 ouvert : joignable depuis l'admin" open "$(probe tcp 8080 "$ADMIN_IP")"
expect_eq "TCP 8080 ouvert : joignable hors réseau d'admin" open "$(probe tcp 8080 "$OTHER_IP")"
expect_eq "UDP 53 ouvert : joignable hors réseau d'admin" open "$(probe udp 53 "$OTHER_IP")"
expect_eq "TCP 9000 non ouvert : refusé" filtered "$(probe tcp 9000 "$OTHER_IP")"
expect_eq "TCP 22 reste réservé à l'administration" filtered "$(probe tcp 22 "$OTHER_IP")"
fw set OPEN_TCP "" >/dev/null; fw set OPEN_UDP "" >/dev/null

echo "== Anti-verrouillage : retour arrière automatique =="
fw_srv apply >/dev/null 2>&1
expect_eq "avant : admin joignable" open "$(probe tcp 22 "$ADMIN_IP")"
cp "$DDI_NFT_FILE" "$T_TMP/nft.before"
fw set ADMIN_NETS "10.99.0.64/29" >/dev/null          # n'inclut plus le poste d'administration
fw_srv apply --confirm 3 >/dev/null 2>&1
expect_eq "nouvelles règles actives : l'admin est coupé" filtered "$(probe tcp 22 "$ADMIN_IP")"
sleep 5
expect_eq "sans confirmation : retour arrière, admin de nouveau joignable" open "$(probe tcp 22 "$ADMIN_IP")"
check "fichier persistant restauré (un redémarrage ne reverrouille pas)" cmp "$DDI_NFT_FILE" "$T_TMP/nft.before"
expect_eq "autre table nftables préservée après le retour arrière" 1 "$(ip netns exec "$SRV" nft list tables | grep -c 'table ip autre')"

echo "== Anti-verrouillage : confirmation =="
fw set ADMIN_NETS "$ADMIN_NET, 10.99.0.64/29" >/dev/null   # change légitime : l'admin reste joignable
fw_srv apply --confirm 3 >/dev/null 2>&1
fw_srv confirm >"$T_TMP/confirm.out" 2>&1
expect_grep "confirm : règles conservées" 'Règles conservées' "$T_TMP/confirm.out"
sleep 5
expect_eq "après confirmation et délai : règles toujours actives" open "$(probe tcp 22 "$ADMIN_IP")"
expect_grep "après confirmation : le nouveau réseau est actif" '10\.99\.0\.64/29' <(fw_srv status)
fw_srv confirm >"$T_TMP/confirm2.out" 2>&1
expect_grep "confirm sans application en attente : message clair" 'Aucune application en attente' "$T_TMP/confirm2.out"

echo "== Retour arrière manuel =="
fw set ADMIN_NETS "10.99.0.64/29" >/dev/null
fw_srv apply >/dev/null 2>&1
expect_eq "règle restrictive appliquée : admin coupé" filtered "$(probe tcp 22 "$ADMIN_IP")"
fw_srv rollback >/dev/null 2>&1
expect_eq "rollback : règles précédentes rétablies, admin joignable" open "$(probe tcp 22 "$ADMIN_IP")"

echo "== Règles invalides : rien n'est appliqué =="
fw_srv status > "$T_TMP/avant"
fw set ADMIN_NETS "bogus" >/dev/null 2>&1; rc=$?
expect_eq "valeur invalide refusée (code 2)" 2 "$rc"
fw_srv status > "$T_TMP/apres"
check "règles actives inchangées après un refus" cmp "$T_TMP/avant" "$T_TMP/apres"

echo "== Premier démarrage : table absente puis retour arrière =="
ip netns exec "$SRV" nft delete table inet ddibuntu
fw set ADMIN_NETS "$ADMIN_NET" >/dev/null
fw_srv apply >/dev/null 2>&1
fw_srv rollback >/dev/null 2>&1
expect_eq "rollback sans règles précédentes : la table dédiée est retirée" 0 "$(ip netns exec "$SRV" nft list tables | grep -c 'table inet ddibuntu')"
expect_eq "autre table toujours présente" 1 "$(ip netns exec "$SRV" nft list tables | grep -c 'table ip autre')"

if [ ! -e /proc/net/if_inet6 ]; then note "noyau du banc sans IPv6 : règles IPv6 vérifiées par nft -c seulement, pas par trafic réel"; fi

finish
