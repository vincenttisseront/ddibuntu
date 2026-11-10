#!/usr/bin/env bash
# Batterie 12 (réel) — deux vrais « named » (127.0.3.1 = primaire, 127.0.3.2 = secondaire) configurés par ddibuntu-reload (modes complet et --replica) :
# transfert de zone signé TSIG, NOTIFY, IXFR après mise à jour dynamique (DDNS), distribution de la RPZ, refus des transferts non signés.
# Seuls les chemins (pid, clés de contrôle) sont adaptés au banc. Demande root, named, dig, nsupdate.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
RELOAD="$RFS/usr/local/sbin/ddibuntu-reload"
for t in named named-checkconf dig nsupdate tsig-keygen rndc openssl python3 ip; do command -v "$t" >/dev/null 2>&1 || { note "batterie BIND réelle non exécutable ici (outil absent : $t)"; finish; exit; }; done
[ "$(id -u)" -eq 0 ] || { ko "à lancer en root"; finish; exit; }
getent passwd bind >/dev/null || { note "compte « bind » absent : batterie non exécutable"; finish; exit; }

W="$(mktemp -d /srv/ddibind.XXXXXX)"; chmod 755 "$W"
IP1=127.0.3.1; IP2=127.0.3.2
PIDS=""
DDNS_CREATED=0
cleanup() {
  for p in $PIDS; do kill "$p" 2>/dev/null; done; sleep 1; for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
  ip addr del $IP1/32 dev lo 2>/dev/null; ip addr del $IP2/32 dev lo 2>/dev/null
  [ "$DDNS_CREATED" = 1 ] && rm -f /etc/bind/ddi-ddns.key
  rm -rf "$W" "$T_TMP"
}
trap cleanup EXIT
ip addr add $IP1/32 dev lo 2>/dev/null; ip addr add $IP2/32 dev lo 2>/dev/null
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
zone "corp.test" { type primary; file "$d/zones/db.corp.test"; notify yes; allow-update { key "ddi-ddns"; }; };
zone "static.test" { type primary; file "$d/zones/db.static.test"; notify yes; allow-transfer { 127.0.0.2; }; };
zone "rpz.ddibuntu.local" { type primary; file "$d/zones/db.rpz"; allow-query { none; }; };
CONF
  printf '{"Dhcp4":{"interfaces-config":{"interfaces":["lo"]},"control-socket":{"socket-type":"unix","socket-name":"/run/kea/kea4-ctrl-socket"},"lease-database":{"type":"memfile","persist":false},"subnet4":[]}}' > "$d/gen/kea-dhcp4.conf"
}
write_zones() { # write_zones SERIAL "enregistrements supplémentaires" "règles RPZ"
  local d; d="$(nodes_dir 1)"; mkdir -p "$d/gen/zones"
  printf '$ORIGIN corp.test.\n$TTL 300\n@ IN SOA ns1.corp.test. root.corp.test. ( %s 3600 600 86400 300 )\n@ IN NS ns1.corp.test.\nns1 IN A 127.0.3.1\nwww IN A 10.20.0.10\n%s\n' "$1" "$2" > "$d/gen/zones/db.corp.test"
  printf '$ORIGIN static.test.\n$TTL 300\n@ IN SOA ns1.static.test. root.static.test. ( %s 3600 600 86400 300 )\n@ IN NS ns1.static.test.\nns1 IN A 127.0.3.1\nwww IN A 10.30.0.10\n%s\n' "$1" "$2" > "$d/gen/zones/db.static.test"
  printf '$ORIGIN rpz.ddibuntu.local.\n$TTL 300\n@ IN SOA localhost. root.localhost. ( %s 3600 600 86400 300 )\n@ IN NS localhost.\n%s\n' "$1" "$3" > "$d/gen/zones/db.rpz"
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
  named -u bind -c "$d/bind/named.conf" -g >"$d/named.log" 2>&1 &
  PIDS="$PIDS $!"; eval "NPID$1=$!"
}
reload_named() { kill -HUP "$(eval echo \$NPID"$1")"; }
q() { dig +short +tries=1 +time=3 "$@" 2>&1; }
wait_cond() { local s="$1" d="$2" e="$3" i=0; while [ "$i" -lt "$s" ]; do if eval "$e" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }

echo "== Configuration par ddibuntu-reload =="
setup_node 1 $IP1; setup_node 2 $IP2
write_zones 100 "" "bad.example CNAME ."
check "n1 : ddibuntu-reload complet (primaire)" rl 1
check "n2 : ddibuntu-reload --replica (secondaire)" rl 2 --replica
adapt 1; adapt 2
check "n1 : named-checkconf" named-checkconf "$(nodes_dir 1)/bind/named.conf"
check "n2 : named-checkconf" named-checkconf "$(nodes_dir 2)/bind/named.conf"
expect_eq "n2 : aucun fichier de zone copié par la console (reçus par transfert)" "0" "$(ls "$(nodes_dir 2)/zones" | wc -l | tr -d ' ')"

echo "== Démarrage et transfert initial =="
start_named 1; start_named 2
wait_cond 20 "n1 répond" '[ -n "$(q @$IP1 www.corp.test A)" ]'
expect_eq "n1 : enregistrement servi" "10.20.0.10" "$(q @$IP1 www.corp.test A)"
wait_cond 30 "n2 reçoit la zone par transfert signé" '[ "$(q @$IP2 www.corp.test A)" = 10.20.0.10 ]'
expect_eq "n2 : SOA = celui du primaire (série 100)" "100" "$(q @$IP2 corp.test SOA | awk '{print $3}')"
check "n2 a écrit la zone transférée sur disque" test -s "$(nodes_dir 2)/zones/db.corp.test"
wait_cond 15 "n2 a reçu la zone RPZ" 'test -s "$(nodes_dir 2)/zones/db.rpz"'

echo "== RPZ distribuée =="
wait_cond 20 "n1 applique la RPZ (NXDOMAIN)" 'dig +tries=1 +time=3 @$IP1 bad.example A | grep -q "status: NXDOMAIN"'
wait_cond 20 "n2 applique la RPZ reçue par transfert (NXDOMAIN)" 'dig +tries=1 +time=3 @$IP2 bad.example A | grep -q "status: NXDOMAIN"'
check_fail "la zone RPZ n'est pas interrogeable (allow-query none)" bash -c "dig +tries=1 +time=3 @$IP2 rpz.ddibuntu.local SOA | grep -q 'status: NOERROR' && dig +short @$IP2 rpz.ddibuntu.local SOA | grep -q ."

echo "== Transferts de zone : seule la clé du cluster =="
check_fail "AXFR sans clé depuis le primaire : refusé" bash -c "dig +tries=1 +time=3 @$IP1 corp.test AXFR | grep -q 'www.corp.test'"
check_fail "AXFR sans clé depuis le secondaire : refusé" bash -c "dig +tries=1 +time=3 @$IP2 corp.test AXFR | grep -q 'www.corp.test'"
check "AXFR avec la clé du cluster depuis le primaire : accepté" bash -c "dig +tries=1 +time=3 -y hmac-sha256:ddi-xfr:$XSECRET @$IP1 corp.test AXFR | grep -q 'www.corp.test'"
check_fail "AXFR avec une mauvaise clé : refusé" bash -c "dig +tries=1 +time=3 -y hmac-sha256:ddi-xfr:cm5kY2tleXJuZGNrZXlybmRja2V5cm5kY2tleTEyMzQ= @$IP1 corp.test AXFR | grep -q 'www.corp.test'"
check_fail "AXFR avec la clé mais depuis le secondaire : refusé (transfert en chaîne interdit)" bash -c "dig +tries=1 +time=3 -y hmac-sha256:ddi-xfr:$XSECRET @$IP2 corp.test AXFR | grep -q 'www.corp.test'"

echo "== Mise à jour dynamique (DDNS) sur le primaire → IXFR vers le secondaire =="
cat > "$W/upd" <<UPD
server $IP1
zone corp.test
update add dyn.corp.test 300 A 10.20.0.99
send
UPD
check "nsupdate signé ddi-ddns sur le primaire" nsupdate -k /etc/bind/ddi-ddns.key "$W/upd"
expect_eq "primaire : enregistrement dynamique servi" "10.20.0.99" "$(q @$IP1 dyn.corp.test A)"
wait_cond 20 "secondaire : enregistrement dynamique reçu (NOTIFY + IXFR)" '[ "$(q @$IP2 dyn.corp.test A)" = 10.20.0.99 ]'
cat > "$W/upd2" <<UPD
server $IP2
zone corp.test
update add refuse.corp.test 300 A 10.20.0.98
send
UPD
check_fail "mise à jour dynamique vers le secondaire : refusée" nsupdate -k /etc/bind/ddi-ddns.key "$W/upd2"

echo "== Nouveau déploiement de la console (zones et RPZ modifiées) =="
write_zones 200 "api IN A 10.20.0.20" "bad.example CNAME .
evil.example CNAME ."
check "n1 : ddibuntu-reload complet (nouveau déploiement)" rl 1
adapt 1; reload_named 1
wait_cond 30 "n2 reçoit la nouvelle zone statique (série 200)" '[ "$(q @$IP2 static.test SOA | awk "{print \$3}")" = 200 ]'
expect_eq "n2 : nouvel enregistrement" "10.20.0.20" "$(q @$IP2 api.static.test A)"
expect_eq "n2 : liste de transfert propre à la zone conservée + clé du cluster (AXFR signé accepté)" "1" "$(dig +tries=1 +time=3 -y hmac-sha256:ddi-xfr:$XSECRET @$IP1 static.test AXFR | grep -c 'api.static.test')"
wait_cond 30 "n2 applique la nouvelle règle RPZ" 'dig +tries=1 +time=3 @$IP2 evil.example A | grep -q "status: NXDOMAIN"'

echo "== Secondaire redémarré : repart de sa copie, rattrape le primaire =="
kill "$NPID2"; wait "$NPID2" 2>/dev/null; sleep 1
write_zones 300 "api IN A 10.20.0.20
late IN A 10.20.0.30" "bad.example CNAME ."
rl 1 >/dev/null 2>&1; adapt 1; reload_named 1
start_named 2
wait_cond 40 "n2 rattrape la série 300 après redémarrage" '[ "$(q @$IP2 static.test SOA | awk "{print \$3}")" = 300 ]'
expect_eq "n2 : enregistrement ajouté pendant son absence" "10.20.0.30" "$(q @$IP2 late.static.test A)"

echo "== Promotion : n1 tombe, n2 devient primaire avec les zones transférées (ddibuntu-reload --promote) =="
# n2 possède une copie transférée ; le DDNS reçu avant la panne (dyn.corp.test) doit survivre à la promotion (il n'existe que dans les zones, pas dans la console)
kill "$NPID1"; wait "$NPID1" 2>/dev/null; sleep 1
mkdir -p "$(nodes_dir 2)/gen"
# copies répliquées par la base (follow). Sur l'appliance le chemin des zones est le même sur les deux nœuds ; sur le banc chaque nœud a le sien : on le transpose
for f in named.conf.options named.conf.zones; do sed "s|$(nodes_dir 1)/|$(nodes_dir 2)/|g" "$(nodes_dir 1)/gen/$f" > "$(nodes_dir 2)/gen/$f"; done
# zone transférée corrompue : la promotion est refusée et le nœud reste secondaire
cp "$(nodes_dir 2)/zones/db.static.test" "$W/static.keep"; printf 'ceci n est pas une zone\n' > "$(nodes_dir 2)/zones/db.static.test"
BEFORE="$(sha256sum "$(nodes_dir 2)/bind/named.conf.local" | cut -d' ' -f1)"
check_fail "promotion refusée si une zone transférée est invalide" rl 2 --promote
expect_eq "…rien n'a été modifié (toujours secondaire)" "$BEFORE" "$(sha256sum "$(nodes_dir 2)/bind/named.conf.local" | cut -d' ' -f1)"
cp "$W/static.keep" "$(nodes_dir 2)/zones/db.static.test"; chown bind:bind "$(nodes_dir 2)/zones/db.static.test"
check "n2 : ddibuntu-reload --promote" rl 2 --promote
expect_eq "n2 : rôle BIND mémorisé = primary" "primary" "$(cat "$(nodes_dir 2)/state/bind-role")"
expect_grep "n2 : zone déclarée primaire avec transfert signé" 'zone "corp.test" \{ type primary; file "[^"]+"; notify yes; allow-transfer \{ key "ddi-xfr"; \}' "$(nodes_dir 2)/bind/named.conf.local"
expect_grep "n2 : NOTIFY vers n1" 'also-notify \{ 127\.0\.3\.1 key "ddi-xfr"; \}' "$(nodes_dir 2)/bind/named.conf.options"
adapt 2; reload_named 2
wait_cond 20 "n2 sert la zone en tant que primaire (série transférée, mise à jour dynamique comprise)" '[ "$(q @$IP2 corp.test SOA | awk "{print \$3}")" -gt 100 ]'
expect_eq "n2 : enregistrement dynamique reçu avant la panne conservé" "10.20.0.99" "$(q @$IP2 dyn.corp.test A)"
expect_eq "n2 : zone statique à la dernière série transférée" "300" "$(q @$IP2 static.test SOA | awk '{print $3}')"
cat > "$W/upd3" <<UPD
server $IP2
zone corp.test
update add apres.corp.test 300 A 10.20.0.77
send
UPD
check "n2 accepte maintenant la mise à jour dynamique (primaire)" nsupdate -k /etc/bind/ddi-ddns.key "$W/upd3"
expect_eq "n2 : la mise à jour est servie" "10.20.0.77" "$(q @$IP2 apres.corp.test A)"
check "AXFR signé depuis le nouveau primaire : accepté" bash -c "dig +tries=1 +time=3 -y hmac-sha256:ddi-xfr:$XSECRET @$IP2 corp.test AXFR | grep -q 'apres.corp.test'"
wait_cond 20 "n2 applique toujours la RPZ" 'dig +tries=1 +time=3 @$IP2 bad.example A | grep -q "status: NXDOMAIN"'

echo "== Réintégration : n1 revient comme secondaire de n2 (série plus récente chez n1) =="
# n1 avait un enregistrement dynamique que n2 n'a jamais reçu : sa copie est « plus récente » ; sans purge elle ne serait jamais remplacée
echo primary > "$(nodes_dir 1)/state/bind-role"
printf 'server %s\nzone corp.test\nupdate add perdu.corp.test 300 A 10.20.0.55\nsend\n' "$IP1" > "$W/upd4"
start_named 1; wait_cond 20 "n1 redémarré (ancienne configuration primaire)" '[ -n "$(q @$IP1 www.corp.test A)" ]'
check "mise à jour dynamique sur l'ancien primaire (jamais transférée à n2)" nsupdate -k /etc/bind/ddi-ddns.key "$W/upd4"
kill "$NPID1"; wait "$NPID1" 2>/dev/null; sleep 1
for f in named.conf.options named.conf.zones; do sed "s|$(nodes_dir 2)/|$(nodes_dir 1)/|g" "$(nodes_dir 2)/gen/$f" > "$(nodes_dir 1)/gen/$f"; done
rm -rf "$(nodes_dir 1)/gen/zones"
check "n1 : ddibuntu-reload --replica (ancien primaire)" rl 1 --replica
expect_eq "n1 : fichiers de zone retirés pour repartir d'un transfert complet" "0" "$(ls "$(nodes_dir 1)/zones" | wc -l | tr -d ' ')"
expect_eq "n1 : rôle mémorisé = secondary" "secondary" "$(cat "$(nodes_dir 1)/state/bind-role")"
adapt 1; start_named 1
wait_cond 40 "n1 reçoit la zone du nouveau primaire" '[ "$(q @$IP1 apres.corp.test A)" = 10.20.0.77 ]'
expect_eq "n1 : l'enregistrement perdu n'est PAS revenu (le nouveau primaire fait foi)" "" "$(q @$IP1 perdu.corp.test A)"

note "constaté (existant, hors cluster) : « rndc reload » n'applique PAS le fichier d'une zone dynamique (allow-update) ; seul freeze/thaw le fait, au prix des noms enregistrés dynamiquement. Voir docs/ROADMAP.md"
note "non couvert : coupure réseau réelle entre deux machines, grandes zones (IXFR volumineux), DNSSEC, bascule déclenchée par un vrai changement de leader Patroni (voir b10-cluster-live)"
if [ "$T_FAIL" -gt 0 ]; then
  for n in 1 2; do echo "--- journal de named n$n (corp.test, notify, transfer, journal, error) ---"; grep -iE "corp.test|notify|transfer|journal|error|refused" "$(nodes_dir $n)/named.log" | tail -25 | cut -c1-240; done
fi
finish
