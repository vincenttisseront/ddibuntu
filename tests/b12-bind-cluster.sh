#!/usr/bin/env bash
# Batterie 12 — BIND en cluster (sans démon) : transformation faite par root dans ddibuntu-reload (primaire / secondaire), vrai « named-checkconf ».
# Les zones ne sont jamais copiées en base : le secondaire les reçoit par transfert signé TSIG (essai réel : b12-bind-cluster-live.sh).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
RELOAD="$RFS/usr/local/sbin/ddibuntu-reload"
for t in named-checkconf tsig-keygen python3 openssl; do command -v "$t" >/dev/null 2>&1 || { ko "outil requis absent : $t"; finish; exit; }; done
[ "$(id -u)" -eq 0 ] || { ko "à lancer en root"; finish; exit; }

W="$T_TMP/w"; GEN="$W/gen"; BE="$W/bind"; KE="$W/kea"; ST="$W/state"; CD="$W/cl"; ZN="$W/zones"
mkdir -p "$GEN/zones" "$BE" "$KE" "$ST" "$CD" "$ZN"
printf 'include "%s/named.conf.options";\ninclude "%s/named.conf.local";\n' "$BE" "$BE" > "$BE/named.conf"
tsig-keygen -a hmac-sha256 ddi-xfr > "$BE/ddi-xfr.key"
KEYSRC="$BE/ddi-xfr.key"
DDNS_CREATED=0
if [ ! -f /etc/bind/ddi-ddns.key ]; then mkdir -p /etc/bind; tsig-keygen -a hmac-sha256 ddi-ddns > /etc/bind/ddi-ddns.key; DDNS_CREATED=1; fi
trap '[ "$DDNS_CREATED" = 1 ] && rm -f /etc/bind/ddi-ddns.key; rm -rf "$T_TMP"' EXIT

# Sorties « telles que la console les produit » (mêmes formats que webui/server/utils/render.ts ; contrôlé aussi par unit-render.test.ts)
cat > "$GEN/named.conf.options" <<'CONF'
// Généré par DDI-Buntu — ne pas modifier à la main.
include "/etc/bind/ddi-ddns.key";
options {
  directory "/var/cache/bind";
  listen-on { any; };
  listen-on-v6 { any; };
  recursion yes;
  allow-recursion { 127.0.0.0/8; };
  allow-query { any; };
  allow-transfer { none; };
  dnssec-validation auto;
  response-policy { zone "rpz.ddibuntu.local" policy given; } qname-wait-recurse no;
};
CONF
cat > "$GEN/named.conf.zones" <<CONF
// Généré par DDI-Buntu — ne pas modifier à la main.
zone "corp.test" { type primary; file "$ZN/db.corp.test"; notify yes; allow-update { key "ddi-ddns"; }; };
zone "ext.test" { type primary; file "$ZN/db.ext.test"; notify yes; allow-transfer { 10.77.0.0/16; }; };
zone "rpz.ddibuntu.local" { type primary; file "$ZN/db.rpz"; allow-query { none; }; };
zone "autre.test" { type secondary; primaries { 192.0.2.9; }; file "$ZN/db.autre.test"; };
zone "fwd.test" { type forward; forward only; forwarders { 192.0.2.53; }; };
CONF
for z in corp.test ext.test; do printf '$ORIGIN %s.\n$TTL 300\n@ IN SOA ns.%s. root.%s. ( 1 3600 600 86400 300 )\n@ IN NS ns.%s.\nns IN A 10.0.0.1\n' "$z" "$z" "$z" "$z" > "$GEN/zones/db.$z"; done
printf '$ORIGIN rpz.ddibuntu.local.\n$TTL 300\n@ IN SOA localhost. root.localhost. ( 1 3600 600 86400 300 )\n@ IN NS localhost.\n' > "$GEN/zones/db.rpz"
printf '{"Dhcp4":{"interfaces-config":{"interfaces":["lo"]},"control-socket":{"socket-type":"unix","socket-name":"/run/kea/kea4-ctrl-socket"},"lease-database":{"type":"memfile","persist":false},"subnet4":[]}}' > "$GEN/kea-dhcp4.conf"

# matériel TLS du cluster : exigé par la partie Kea de ddibuntu-reload dès que deux nœuds de données existent
mkdir -p "$CD/pki"
openssl ecparam -name prime256v1 -genkey -noout -out "$CD/ca.key" 2>/dev/null
openssl req -x509 -new -key "$CD/ca.key" -subj /CN=test-ca -days 2 -out "$CD/pki/ca.crt" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$CD/pki/node.key" 2>/dev/null
openssl req -new -key "$CD/pki/node.key" -subj /CN=n -out "$CD/n.csr" 2>/dev/null
openssl x509 -req -in "$CD/n.csr" -CA "$CD/pki/ca.crt" -CAkey "$CD/ca.key" -CAcreateserial -days 2 -out "$CD/pki/node.crt" 2>/dev/null
conf() { printf 'CLUSTER_NAME=lab\nNODE_NAME=%s\nNODE_ROLE=%s\nNODE_IP=%s\nREPL_NET=10.9.0.0/24\nPEERS=%s\nCA_NODE=0\n' "$1" "$2" "$3" "$4" > "$CD/cluster.conf"; }
rl() { env DDI_GENERATED_DIR="$GEN" DDI_BIND_ETC="$BE" DDI_ZONES_RUNTIME_DIR="$ZN" DDI_KEA_ETC="$KE" DDI_STATE_DIR="$ST" DDI_CLUSTER_DIR="$CD" DDI_RELOAD_NOSERVICES=1 bash "$RELOAD" "$@"; }
OPT="$BE/named.conf.options"; LOC="$BE/named.conf.local"
PEERS3="n1=10.9.0.1:data n2=10.9.0.2:data n3=10.9.0.3:witness"

echo "== Sans cluster : copie fidèle =="
rm -f "$CD/cluster.conf"
check "reload complet sans cluster" rl
check "options copiées telles quelles" cmp "$GEN/named.conf.options" "$OPT"
check "zones copiées telles quelles" cmp "$GEN/named.conf.zones" "$LOC"
expect_nogrep "aucune clé de cluster sans cluster" 'ddi-xfr' "$LOC"
expect_grep "transfert de zone refusé par défaut (BIND l'autorise à tous sinon)" 'allow-transfer \{ none; \};' "$OPT"
conf n1 data 10.9.0.1 "n1=10.9.0.1:data"
check "un seul nœud de données : reload complet" rl
check "…toujours copie fidèle" cmp "$GEN/named.conf.zones" "$LOC"
conf n3 witness 10.9.0.3 "$PEERS3"
check "arbitre : reload complet" rl
check "…jamais de transformation sur un arbitre" cmp "$GEN/named.conf.zones" "$LOC"

echo "== Deux nœuds de données, clé absente : BIND reste simple, avec avertissement =="
conf n1 data 10.9.0.1 "$PEERS3"
mv "$BE/ddi-xfr.key" "$BE/ddi-xfr.key.away"
rl >"$T_TMP/nokey.log" 2>&1; expect_eq "reload complet sans clé TSIG : succès" 0 "$?"
expect_grep "…avec un avertissement" 'AVERTISSEMENT.*TSIG' "$T_TMP/nokey.log"
check "…zones non transformées" cmp "$GEN/named.conf.zones" "$LOC"
check_fail "--replica sans clé TSIG : refusé" rl --replica
mv "$BE/ddi-xfr.key.away" "$BE/ddi-xfr.key"

echo "== Primaire (n1) =="
check "reload complet sur n1" rl
check "named-checkconf accepte" named-checkconf "$BE/named.conf"
expect_grep "options : clé TSIG incluse" "^include \"$BE/ddi-xfr.key\";" "$OPT"
expect_grep "options : écoute sur l'adresse du réseau dédié" 'listen-on \{ 10\.9\.0\.1; \};' "$OPT"
expect_grep "options : NOTIFY signé vers le pair" 'also-notify \{ 10\.9\.0\.2 key "ddi-xfr"; \};' "$OPT"
expect_grep "options : transfert réservé à la clé" '^  allow-transfer \{ key "ddi-xfr"; \};' "$OPT"
expect_nogrep "options : plus de allow-transfer { none; } global" 'allow-transfer \{ none; \}' "$OPT"
expect_grep "zone DDNS : transfert par clé + mise à jour dynamique conservée" 'zone "corp.test" \{ type primary; file "[^"]+"; notify yes; allow-transfer \{ key "ddi-xfr"; \}; allow-update \{ key "ddi-ddns"; \}; \};' "$LOC"
expect_grep "zone avec liste explicite : liste conservée + clé" 'zone "ext.test" .*allow-transfer \{ 10\.77\.0\.0/16; key "ddi-xfr"; \};' "$LOC"
expect_grep "zone RPZ : transférée comme les autres, interrogation interdite conservée" 'zone "rpz.ddibuntu.local" \{ type primary; file "[^"]+db\.rpz"; notify yes; allow-transfer \{ key "ddi-xfr"; \}; allow-query \{ none; \}; \};' "$LOC"
expect_grep "zone secondaire externe inchangée" 'zone "autre.test" \{ type secondary; primaries \{ 192\.0\.2\.9; \};' "$LOC"
expect_grep "zone de redirection inchangée" 'zone "fwd.test" \{ type forward;' "$LOC"
expect_grep "server : requêtes vers le pair signées" '^server 10\.9\.0\.2 \{ keys "ddi-xfr"; \};' "$LOC"
check "fichiers de zone installés sur le primaire" test -f "$ZN/db.corp.test" -a -f "$ZN/db.rpz"
S1="$(sha256sum "$LOC" "$OPT" | sha256sum)"; rl >/dev/null 2>&1; expect_eq "idempotent" "$S1" "$(sha256sum "$LOC" "$OPT" | sha256sum)"

echo "== Secondaire (n2, --replica) =="
conf n2 data 10.9.0.2 "$PEERS3"
rm -f "$ZN"/db.*; printf 'ancien-contenu\n' > "$ZN/db.corp.test"
rm -rf "$GEN/zones"   # le secondaire n'a PAS les fichiers de zone de la console
check "reload --replica sur n2 sans fichiers de zone" rl --replica
check "named-checkconf accepte" named-checkconf "$BE/named.conf"
expect_grep "zone primaire → secondaire, primaire = n1, signé" 'zone "corp.test" \{ type secondary; primaries \{ 10\.9\.0\.1 key "ddi-xfr"; \}; file "[^"]+db\.corp\.test"; \};' "$LOC"
expect_grep "RPZ aussi (interrogation interdite conservée)" 'zone "rpz.ddibuntu.local" \{ type secondary; primaries \{ 10\.9\.0\.1 key "ddi-xfr"; \}; file "[^"]+db\.rpz"; allow-query \{ none; \}; \};' "$LOC"
expect_nogrep "aucune mise à jour dynamique sur le secondaire" 'allow-update' "$LOC"
expect_nogrep "inclusion de la clé DDNS retirée" 'ddi-ddns\.key' "$OPT"
expect_grep "secondaire : pas de NOTIFY" '^  notify no;' "$OPT"
expect_grep "secondaire : écoute sur sa propre adresse du réseau dédié" 'listen-on \{ 10\.9\.0\.2; \};' "$OPT"
expect_grep "secondaire : transfert refusé à tous (réservé au primaire)" '^  allow-transfer \{ none; \};' "$OPT"
expect_nogrep "secondaire : pas de also-notify" 'also-notify' "$OPT"
expect_grep "zone secondaire externe inchangée" 'zone "autre.test" \{ type secondary; primaries \{ 192\.0\.2\.9; \};' "$LOC"
expect_grep "server : vers n1" '^server 10\.9\.0\.1 \{ keys "ddi-xfr"; \};' "$LOC"
expect_eq "fichiers de zone existants (transférés) non touchés" "ancien-contenu" "$(cat "$ZN/db.corp.test")"
expect_grep "statut : réplica" '^ok=1' "$ST/reload-status"

echo "== Entrées hostiles ou inattendues : refus, rien ne change =="
GOOD="$(sha256sum "$LOC" "$OPT" | sha256sum)"
unchanged() { [ "$(sha256sum "$LOC" "$OPT" | sha256sum)" = "$GOOD" ]; }
cp "$GEN/named.conf.zones" "$T_TMP/zones.ok"; cp "$GEN/named.conf.options" "$T_TMP/options.ok"
sed -i 's/notify yes; allow-update/notify yes; also-notify { 6.6.6.6; }; allow-update/' "$GEN/named.conf.zones"
check_fail "propriété de zone inconnue refusée" rl --replica
check "…configuration en place intacte" unchanged
cp "$T_TMP/zones.ok" "$GEN/named.conf.zones"
echo 'zone "x.test" { type primary; file "/etc/passwd"; };' >> "$GEN/named.conf.zones"
check_fail "chemin de zone hors dossier refusé (frontière existante)" rl --replica
cp "$T_TMP/zones.ok" "$GEN/named.conf.zones"
echo 'acl "x" { 1.1.1.1; };' >> "$GEN/named.conf.zones"
check_fail "ligne de zone inattendue refusée" rl --replica
cp "$T_TMP/zones.ok" "$GEN/named.conf.zones"
sed -i '/allow-transfer { none; };/d' "$GEN/named.conf.options"
check_fail "options sans allow-transfer global : refus (pas d'injection à l'aveugle)" rl --replica
cp "$T_TMP/options.ok" "$GEN/named.conf.options"
check "…état de départ rétabli : accepté de nouveau" rl --replica
GOOD="$(sha256sum "$LOC" "$OPT" | sha256sum)"
conf n3 witness 10.9.0.3 "$PEERS3"; check_fail "--replica sur un arbitre refusé" rl --replica
conf n2 data 10.9.0.2 "n2=10.9.0.2:data"; check_fail "--replica avec un seul nœud de données refusé" rl --replica
conf n2 data 10.9.0.2 "n1=10.9.0.1:data n2=999.9.0.2:data"; check_fail "adresse de pair invalide refusée" rl --replica
check "…rien n'a changé" unchanged
conf n2 data 10.9.0.2 "$PEERS3"

echo "== Retour arrière si named-checkconf refuse =="
cp "$KEYSRC" "$T_TMP/key.ok"; echo 'garbage {' > "$BE/ddi-xfr.key"
check_fail "clé TSIG illisible : named-checkconf refuse" rl --replica
check "…configuration précédente restaurée" unchanged
expect_grep "…statut : échec avec retour arrière" '^ok=0' "$ST/reload-status"
cp "$T_TMP/key.ok" "$BE/ddi-xfr.key"
check "reprise après correction" rl --replica

finish
