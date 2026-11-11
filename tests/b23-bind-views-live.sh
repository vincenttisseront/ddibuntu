#!/usr/bin/env bash
# Batterie 23 (réel) — vues DNS (0.9.8) sur deux vrais « named » (127.0.3.1 = primaire, 127.0.3.2 = secondaire) configurés par ddibuntu-reload :
# réponses distinctes selon le client, une clé de transfert par vue (dérivée), RPZ par vue, NOTIFY par vue, promotion, retour à une configuration sans vue.
# Seuls les chemins (pid, clés de contrôle) sont adaptés au banc. Demande root, named, dig, nsupdate.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
RELOAD="$RFS/usr/local/sbin/ddibuntu-reload"
for t in named named-checkconf dig nsupdate tsig-keygen rndc openssl python3 ip; do command -v "$t" >/dev/null 2>&1 || { note "batterie BIND réelle non exécutable ici (outil absent : $t)"; finish; exit; }; done
[ "$(id -u)" -eq 0 ] || { ko "à lancer en root"; finish; exit; }
getent passwd bind >/dev/null || { note "compte « bind » absent : batterie non exécutable"; finish; exit; }

W="$(mktemp -d /srv/ddibind.XXXXXX)"; chmod 755 "$W"
IP1=127.0.3.1; IP2=127.0.3.2; CLI_INT=127.0.3.11; CLI_EXT=127.0.3.12   # deux « clients » : le premier est dans la vue interne
PIDS=""
DDNS_CREATED=0
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null; done; sleep 1; for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
  for a in $IP1 $IP2 $CLI_INT $CLI_EXT; do ip addr del $a/32 dev lo 2>/dev/null; done
  [ "$DDNS_CREATED" = 1 ] && rm -f /etc/bind/ddi-ddns.key
  rm -rf "$W" "$T_TMP"
}
trap cleanup EXIT
for a in $IP1 $IP2 $CLI_INT $CLI_EXT; do ip addr add $a/32 dev lo 2>/dev/null; done
if [ ! -f /etc/bind/ddi-ddns.key ]; then mkdir -p /etc/bind; tsig-keygen -a hmac-sha256 ddi-ddns > /etc/bind/ddi-ddns.key; DDNS_CREATED=1; fi
tsig-keygen -a hmac-sha256 ddi-xfr > "$W/xfr.key"
XSECRET="$(sed -n 's/.*secret "\(.*\)";/\1/p' "$W/xfr.key")"
# PKI minimale (la partie Kea de ddibuntu-reload l'exige dès que deux nœuds de données existent)
openssl ecparam -name prime256v1 -genkey -noout -out "$W/ca.key" 2>/dev/null
openssl req -x509 -new -key "$W/ca.key" -subj /CN=test-ca -days 2 -out "$W/ca.crt" 2>/dev/null

nodes_dir() { echo "$W/n$1"; }
setup_node() { # setup_node N IP
  local n="$1" ip="$2" d; d="$(nodes_dir "$1")"
  mkdir -p "$d"/{gen,bind,kea,state,zones,cache,run,cl/pki}
  cp "$W/ca.crt" "$d/cl/pki/ca.crt"
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/cl/pki/node.key" 2>/dev/null
  openssl req -new -key "$d/cl/pki/node.key" -subj "/CN=n$n" -out "$d/n.csr" 2>/dev/null
  openssl x509 -req -in "$d/n.csr" -CA "$W/ca.crt" -CAkey "$W/ca.key" -CAcreateserial -days 2 -out "$d/cl/pki/node.crt" 2>/dev/null
  printf 'CLUSTER_NAME=lab\nNODE_NAME=n%s\nNODE_ROLE=data\nNODE_IP=%s\nREPL_NET=127.0.3.0/24\nPEERS=n1=%s:data n2=%s:data\nCA_NODE=0\n' "$n" "$ip" "$IP1" "$IP2" > "$d/cl/cluster.conf"
  install -m 0640 -o root -g bind "$W/xfr.key" "$d/bind/ddi-xfr.key"
  chown -R bind:bind "$d/zones" "$d/cache" "$d/run"
  printf 'include "%s/named.conf.options";\ninclude "%s/named.conf.local";\nkey "rndc-key" { algorithm hmac-sha256; secret "cm5kY2tleXJuZGNrZXlybmRja2V5cm5kY2tleTEyMzQ="; };\ncontrols { inet 127.0.0.1 port 953%s allow { 127.0.0.1; } keys { "rndc-key"; }; };\n' "$d/bind" "$d/bind" "$n" > "$d/bind/named.conf"
  # (« localhost » couvrirait TOUTES les adresses du serveur, dont celle du faux client externe : le banc liste les adresses)
  # ces zones sont celles de la console : mêmes formats que render.ts
  cat > "$d/gen/named.conf.options" <<CONF
// Généré par DDI-Buntu — ne pas modifier à la main.
include "/etc/bind/ddi-ddns.key";
options {
  directory "/var/cache/bind";
  listen-on { $ip; };
  listen-on-v6 { none; };
  recursion yes;
  allow-recursion { 127.0.0.0/8; };
  allow-query { any; };
  allow-transfer { none; };
  dnssec-validation no;
  check-names primary warn;
  querylog no;
  response-policy { zone "rpz.ddibuntu.local" policy given; } qname-wait-recurse no;
};
CONF
  cat > "$d/gen/named.conf.zones" <<CONF
// Généré par DDI-Buntu — ne pas modifier à la main.
view "interne" {
  match-clients { $CLI_INT; 127.0.0.1; };
  recursion yes;
zone "corp.test" { type primary; file "$d/zones/db.interne.corp.test"; notify yes; };
zone "rpz.ddibuntu.local" { type primary; file "$d/zones/db.rpz-interne"; allow-query { none; }; };
};
view "externe" {
  match-clients { any; };
  recursion no;
  allow-recursion { none; };
zone "corp.test" { type primary; file "$d/zones/db.externe.corp.test"; notify yes; };
zone "rpz.ddibuntu.local" { type primary; file "$d/zones/db.rpz-externe"; allow-query { none; }; };
};
CONF
  printf '{"Dhcp4":{"interfaces-config":{"interfaces":["lo"]},"control-socket":{"socket-type":"unix","socket-name":"/run/kea/kea4-ctrl-socket"},"lease-database":{"type":"memfile","persist":false},"subnet4":[]}}' > "$d/gen/kea-dhcp4.conf"
}
write_zones() { # write_zones SERIAL "enreg. interne" "enreg. externe" "règles RPZ"
  local d; d="$(nodes_dir 1)"; mkdir -p "$d/gen/zones"
  printf '$ORIGIN corp.test.
$TTL 300
@ IN SOA ns1.corp.test. root.corp.test. ( %s 3600 600 86400 300 )
@ IN NS ns1.corp.test.
ns1 IN A 127.0.3.1
www IN A 10.20.0.10
%s
' "$1" "$2" > "$d/gen/zones/db.interne.corp.test"
  printf '$ORIGIN corp.test.
$TTL 300
@ IN SOA ns1.corp.test. root.corp.test. ( %s 3600 600 86400 300 )
@ IN NS ns1.corp.test.
ns1 IN A 127.0.3.1
www IN A 203.0.113.10
%s
' "$1" "$3" > "$d/gen/zones/db.externe.corp.test"
  for v in interne externe; do
    printf '$ORIGIN rpz.ddibuntu.local.
$TTL 300
@ IN SOA localhost. root.localhost. ( %s 3600 600 86400 300 )
@ IN NS localhost.
%s
' "$1" "$4" > "$d/gen/zones/db.rpz-$v"
  done
}
rl() { # rl N [option]
  local d; d="$(nodes_dir "$1")"; shift
  env DDI_GENERATED_DIR="$d/gen" DDI_BIND_ETC="$d/bind" DDI_ZONES_RUNTIME_DIR="$d/zones" DDI_KEA_ETC="$d/kea" DDI_STATE_DIR="$d/state" DDI_CLUSTER_DIR="$d/cl" \
      DDI_RELOAD_NOSERVICES=1 DDI_LOCK_FILE="$d/reload.lock" bash "$RELOAD" "$@"
}
adapt() { # adaptation au banc : un named par nœud (pid, session, cache) — rien d'autre
  local d; d="$(nodes_dir "$1")"
  sed -i "s|directory \"/var/cache/bind\";|directory \"$d/cache\"; pid-file \"$d/run/named.pid\"; session-keyfile \"$d/run/session.key\";|" "$d/bind/named.conf.options"
}
rndc_n() { local n="$1"; shift; rndc -s 127.0.0.1 -p "953$n" -y rndc-key -c /dev/null "$@" 2>&1; }
start_named() {
  local d; d="$(nodes_dir "$1")"
  named -u bind -c "$d/bind/named.conf" -g >>"$d/named.log" 2>&1 &
  PIDS="$PIDS $!"; eval "NPID$1=$!"
}
reload_named() { kill -HUP "$(eval echo \$NPID"$1")"; }
q() { dig +short +tries=1 +time=3 "$@" 2>&1; }
wait_cond() { local s="$1" d="$2" e="$3" i=0; while [ "$i" -lt "$s" ]; do if eval "$e" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }


vkey() { # vkey VUE -> secret dérivé (HMAC-SHA256 du secret du cluster, « ddibuntu-view:<vue> »), comme ddibuntu-reload
  python3 - "$XSECRET" "$1" <<'PY'
import base64, hashlib, hmac, sys
print(base64.b64encode(hmac.new(base64.b64decode(sys.argv[1]), b"ddibuntu-view:" + sys.argv[2].encode(), hashlib.sha256).digest()).decode())
PY
}
qi() { q -b $CLI_INT "$@"; }   # question posée depuis la vue interne
qe() { q -b $CLI_EXT "$@"; }   # …depuis la vue externe
axfr() { # axfr VUE IP ZONE
  dig +tries=1 +time=3 -y "hmac-sha256:ddi-xfr-$1:$(vkey "$1")" @"$2" "$3" AXFR 2>&1
}

echo "== Configuration par ddibuntu-reload (deux vues) =="
setup_node 1 $IP1; setup_node 2 $IP2
write_zones 100 "" "" "bad.example CNAME ."
check "n1 : ddibuntu-reload complet (primaire)" rl 1
check "n2 : ddibuntu-reload --replica (secondaire)" rl 2 --replica
adapt 1; adapt 2
for n in 1 2; do
  check "n$n : named-checkconf" named-checkconf "$(nodes_dir $n)/bind/named.conf"
  check "n$n : clés de transfert par vue installées" test -s "$(nodes_dir $n)/bind/ddi-xfr-views.key"
  expect_eq "n$n : clés de vues en 0640 root:bind" "640 root bind" "$(stat -c '%a %U %G' "$(nodes_dir $n)/bind/ddi-xfr-views.key")"
  expect_grep "n$n : une clé pour chaque vue" 'key "ddi-xfr-interne"' "$(nodes_dir $n)/bind/ddi-xfr-views.key"
  expect_grep "n$n : …et pour l'autre" 'key "ddi-xfr-externe"' "$(nodes_dir $n)/bind/ddi-xfr-views.key"
done
expect_eq "les deux nœuds dérivent les mêmes secrets" "$(grep -c secret "$(nodes_dir 1)/bind/ddi-xfr-views.key")" "$(grep -c secret "$(nodes_dir 2)/bind/ddi-xfr-views.key")"
expect_eq "n1 et n2 : mêmes clés de vues (rien de nouveau à distribuer)" "$(sha256sum < "$(nodes_dir 1)/bind/ddi-xfr-views.key")" "$(sha256sum < "$(nodes_dir 2)/bind/ddi-xfr-views.key")"
expect_eq "la clé dérivée est celle que le banc recalcule" "1" "$(grep -c "$(vkey interne)" "$(nodes_dir 1)/bind/ddi-xfr-views.key")"
expect_grep "n1 : la vue interne n'accepte que son propre transfert signé (et exclut la clé de l'autre vue)" 'key "ddi-xfr-interne"; !key "ddi-xfr-externe";' "$(nodes_dir 1)/bind/named.conf.local"
expect_grep "n1 : NOTIFY vers le secondaire avec la clé de la vue" 'also-notify \{ 127\.0\.3\.2 key "ddi-xfr-interne"; \}' "$(nodes_dir 1)/bind/named.conf.local"
expect_grep "n2 : le secondaire s'adresse au primaire avec la clé de chaque vue" 'server 127\.0\.3\.1 \{ keys "ddi-xfr-externe"; \}' "$(nodes_dir 2)/bind/named.conf.local"
expect_eq "n2 : aucun fichier de zone copié par la console" "0" "$(ls "$(nodes_dir 2)/zones" | wc -l | tr -d ' ')"

echo "== Démarrage : chaque vue reçoit SA zone =="
start_named 1; start_named 2
wait_cond 40 "n1 répond (vue interne)" '[ "$(qi @$IP1 www.corp.test A)" = 10.20.0.10 ]'
expect_eq "n1 : le client interne voit les adresses privées" "10.20.0.10" "$(qi @$IP1 www.corp.test A)"
expect_eq "n1 : le client externe voit les adresses publiques" "203.0.113.10" "$(qe @$IP1 www.corp.test A)"
expect_eq "n1 : le serveur se résout lui-même (127.0.0.1 → vue interne)" "10.20.0.10" "$(q -b 127.0.0.1 @$IP1 www.corp.test A)"
wait_cond 40 "n2 reçoit la zone de la vue interne" '[ "$(qi @$IP2 www.corp.test A)" = 10.20.0.10 ]'
wait_cond 40 "n2 reçoit la zone de la vue externe" '[ "$(qe @$IP2 www.corp.test A)" = 203.0.113.10 ]'
expect_eq "n2 : interne ≠ externe, comme sur le primaire" "10.20.0.10 203.0.113.10" "$(qi @$IP2 www.corp.test A) $(qe @$IP2 www.corp.test A)"
check "n2 : un fichier de zone par vue sur disque" bash -c "test -s '$(nodes_dir 2)/zones/db.interne.corp.test' && test -s '$(nodes_dir 2)/zones/db.externe.corp.test'"
wait_cond 20 "n2 a reçu les deux zones RPZ" 'test -s "$(nodes_dir 2)/zones/db.rpz-interne" && test -s "$(nodes_dir 2)/zones/db.rpz-externe"'
expect_eq "n2 : récursion non offerte au client externe (REFUSED pour un nom hors zone)" "1" "$(dig +tries=1 +time=3 -b $CLI_EXT @$IP2 example.invalid A | grep -c 'status: REFUSED')"

echo "== RPZ dans chaque vue =="
wait_cond 20 "n1 applique la RPZ (vue interne)" 'dig +tries=1 +time=3 -b $CLI_INT @$IP1 bad.example A | grep -q "status: NXDOMAIN"'
wait_cond 20 "n2 applique la RPZ reçue (vue interne)" 'dig +tries=1 +time=3 -b $CLI_INT @$IP2 bad.example A | grep -q "status: NXDOMAIN"'
wait_cond 20 "n2 applique la RPZ reçue (vue externe, zone locale seulement : la récursion y est coupée)" 'dig +tries=1 +time=3 -b $CLI_EXT @$IP2 bad.example A | grep -qE "status: (NXDOMAIN|REFUSED)"'

echo "== Transferts : une clé par vue =="
check "AXFR de la vue interne avec sa clé : accepté, données internes" bash -c "$(declare -f axfr vkey); XSECRET='$XSECRET'; axfr interne $IP1 corp.test | grep -q 10.20.0.10"
check_fail "…et jamais les données externes" bash -c "$(declare -f axfr vkey); XSECRET='$XSECRET'; axfr interne $IP1 corp.test | grep -q 203.0.113.10"
check "AXFR de la vue externe avec sa clé : accepté, données externes" bash -c "$(declare -f axfr vkey); XSECRET='$XSECRET'; axfr externe $IP1 corp.test | grep -q 203.0.113.10"
check_fail "…et jamais les données internes" bash -c "$(declare -f axfr vkey); XSECRET='$XSECRET'; axfr externe $IP1 corp.test | grep -q 10.20.0.10"
check_fail "AXFR sans clé depuis le client interne : refusé" bash -c "dig +tries=1 +time=3 -b $CLI_INT @$IP1 corp.test AXFR | grep -q 'www.corp.test'"
check_fail "AXFR avec la clé générale (non dérivée) du cluster : refusé" bash -c "dig +tries=1 +time=3 -y hmac-sha256:ddi-xfr:$XSECRET @$IP1 corp.test AXFR | grep -q 'www.corp.test'"
check_fail "AXFR depuis le secondaire, même avec la bonne clé de vue : refusé (pas de transfert en chaîne)" bash -c "$(declare -f axfr vkey); XSECRET='$XSECRET'; axfr interne $IP2 corp.test | grep -q 10.20.0.10"

echo "== Nouveau déploiement : NOTIFY par vue =="
write_zones 200 "api IN A 10.20.0.20" "api IN A 203.0.113.20" "bad.example CNAME .
evil.example CNAME ."
check "n1 : ddibuntu-reload complet (nouveau déploiement)" rl 1
adapt 1; reload_named 1
wait_cond 30 "n2 : nouvel enregistrement dans la vue interne" '[ "$(qi @$IP2 api.corp.test A)" = 10.20.0.20 ]'
wait_cond 30 "n2 : nouvel enregistrement dans la vue externe" '[ "$(qe @$IP2 api.corp.test A)" = 203.0.113.20 ]'
expect_eq "n2 : l'enregistrement interne n'a pas fuité vers l'externe" "" "$(qe @$IP2 api.corp.test A | grep -v 203.0.113.20)"
wait_cond 30 "n2 applique la nouvelle règle RPZ" 'dig +tries=1 +time=3 -b $CLI_INT @$IP2 evil.example A | grep -q "status: NXDOMAIN"'

echo "== Refus motivé : configuration à vues invalide =="
cp "$(nodes_dir 1)/gen/named.conf.zones" "$W/zones.ok"
BEFORE="$(sha256sum "$(nodes_dir 1)/bind/named.conf.local" | cut -d' ' -f1)"; KBEFORE="$(sha256sum "$(nodes_dir 1)/bind/ddi-xfr-views.key" | cut -d' ' -f1)"
sed -i 's|^view "externe" {|view "externe" {\n  match-clients { any; };|' "$(nodes_dir 1)/gen/named.conf.zones"   # directive en double : named-checkconf la refuse
check_fail "n1 : une configuration refusée par named-checkconf n'est pas appliquée" rl 1
expect_eq "…la configuration BIND d'avant est intacte" "$BEFORE" "$(sha256sum "$(nodes_dir 1)/bind/named.conf.local" | cut -d' ' -f1)"
expect_eq "…ainsi que les clés de vues" "$KBEFORE" "$(sha256sum "$(nodes_dir 1)/bind/ddi-xfr-views.key" | cut -d' ' -f1)"
cp "$W/zones.ok" "$(nodes_dir 1)/gen/named.conf.zones"
check "n1 : la configuration saine est de nouveau appliquée" rl 1

echo "== Promotion : n1 tombe, n2 devient primaire avec les zones transférées de chaque vue =="
kill "$NPID1"; wait "$NPID1" 2>/dev/null; sleep 1
mkdir -p "$(nodes_dir 2)/gen"
for f in named.conf.options named.conf.zones; do sed "s|$(nodes_dir 1)/|$(nodes_dir 2)/|g" "$(nodes_dir 1)/gen/$f" > "$(nodes_dir 2)/gen/$f"; done
cp "$(nodes_dir 2)/zones/db.externe.corp.test" "$W/ext.keep"; printf 'ceci n est pas une zone\n' > "$(nodes_dir 2)/zones/db.externe.corp.test"
BEFORE="$(sha256sum "$(nodes_dir 2)/bind/named.conf.local" | cut -d' ' -f1)"
check_fail "promotion refusée si la zone transférée d'UNE vue est invalide" rl 2 --promote
expect_eq "…rien n'a été modifié (toujours secondaire)" "$BEFORE" "$(sha256sum "$(nodes_dir 2)/bind/named.conf.local" | cut -d' ' -f1)"
cp "$W/ext.keep" "$(nodes_dir 2)/zones/db.externe.corp.test"; chown bind:bind "$(nodes_dir 2)/zones/db.externe.corp.test"
check "n2 : ddibuntu-reload --promote" rl 2 --promote
expect_eq "n2 : rôle BIND mémorisé = primary" "primary" "$(cat "$(nodes_dir 2)/state/bind-role")"
expect_grep "n2 : zones de la vue interne déclarées primaires" 'zone "corp.test" \{ type primary; file "[^"]*db\.interne\.corp\.test"' "$(nodes_dir 2)/bind/named.conf.local"
expect_grep "n2 : zones de la vue externe déclarées primaires" 'zone "corp.test" \{ type primary; file "[^"]*db\.externe\.corp\.test"' "$(nodes_dir 2)/bind/named.conf.local"
adapt 2; reload_named 2
wait_cond 20 "n2 sert la vue interne en tant que primaire" '[ "$(qi @$IP2 api.corp.test A)" = 10.20.0.20 ]'
expect_eq "n2 : …et la vue externe" "203.0.113.20" "$(qe @$IP2 api.corp.test A)"
check "AXFR signé de la vue interne depuis le nouveau primaire" bash -c "$(declare -f axfr vkey); XSECRET='$XSECRET'; axfr interne $IP2 corp.test | grep -q api.corp.test"

echo "== Retour à une configuration sans vue =="
kill "$NPID2"; wait "$NPID2" 2>/dev/null; sleep 1
d1="$(nodes_dir 1)"
printf '// Généré par DDI-Buntu — ne pas modifier à la main.\nzone "corp.test" { type primary; file "%s/zones/db.corp.test"; notify yes; };\n' "$d1" > "$d1/gen/named.conf.zones"
rm -f "$d1/gen/zones/db."*
printf '$ORIGIN corp.test.\n$TTL 300\n@ IN SOA ns1.corp.test. root.corp.test. ( 300 3600 600 86400 300 )\n@ IN NS ns1.corp.test.\nns1 IN A 127.0.3.1\nwww IN A 10.20.0.10\n' > "$d1/gen/zones/db.corp.test"
sed -i '/response-policy/d' "$d1/gen/named.conf.options"
check "n1 : ddibuntu-reload sans vue" rl 1
adapt 1
check_fail "n1 : plus de bloc « view » dans la configuration BIND" grep -q '^view ' "$d1/bind/named.conf.local"
check_fail "n1 : clés de vues retirées" test -e "$d1/bind/ddi-xfr-views.key"
check_fail "n1 : plus d'inclusion des clés de vues" grep -q 'ddi-xfr-views' "$d1/bind/named.conf.options"
check "n1 : named-checkconf" named-checkconf "$d1/bind/named.conf"
start_named 1
wait_cond 20 "n1 sert la zone sans vue" '[ "$(qe @$IP1 www.corp.test A)" = 10.20.0.10 ]'
expect_eq "n1 : tous les clients voient la même réponse" "10.20.0.10 10.20.0.10" "$(qi @$IP1 www.corp.test A) $(qe @$IP1 www.corp.test A)"

note "non couvert : mises à jour dynamiques (Kea DDNS) dans une vue précise (elles vont à la vue qui correspond à l'expéditeur), match-destinations sur plusieurs adresses du serveur, coupure réseau réelle entre machines"
if [ "$T_FAIL" -gt 0 ]; then
  for n in 1 2; do echo "--- journal de named n$n ---"; grep -iE "corp.test|notify|transfer|view|error|refused|loaded|running" "$(nodes_dir $n)/named.log" | tail -60 | cut -c1-240; done
fi
finish
