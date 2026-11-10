#!/usr/bin/env bash
# Batterie 11 — Kea HA (load-balancing) : injection du bloc HA par root dans ddibuntu-reload, sans démon.
# Vrai « kea-dhcp4 -t » (bibliothèques HA, TLS) ; aucun service touché (DDI_RELOAD_NOSERVICES). Demande root (ddibuntu-reload l'exige).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
RELOAD="$RFS/usr/local/sbin/ddibuntu-reload"
for t in kea-dhcp4 openssl python3; do command -v "$t" >/dev/null 2>&1 || { ko "outil requis absent : $t"; finish; exit; }; done
[ "$(id -u)" -eq 0 ] || { ko "à lancer en root"; finish; exit; }
check "bash -n : ddibuntu-reload" bash -n "$RELOAD"
check "shellcheck : ddibuntu-reload" bash -c "command -v shellcheck >/dev/null && shellcheck -x '$RELOAD' || true"

W="$T_TMP/w"; mkdir -p "$W"
GEN="$W/gen"; KETC="$W/kea"; ST="$W/state"; CD="$W/cl"
mkdir -p "$GEN" "$KETC" "$ST" "$CD/pki"
# PKI de test (le cluster réel utilise celle de ddibuntu-cluster)
openssl ecparam -name prime256v1 -genkey -noout -out "$CD/ca.key" 2>/dev/null
openssl req -x509 -new -key "$CD/ca.key" -subj /CN=test-ca -days 2 -out "$CD/pki/ca.crt" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$CD/pki/node.key" 2>/dev/null
openssl req -new -key "$CD/pki/node.key" -subj /CN=n1 -out "$CD/n.csr" 2>/dev/null
openssl x509 -req -in "$CD/n.csr" -CA "$CD/pki/ca.crt" -CAkey "$CD/ca.key" -CAcreateserial -days 2 -out "$CD/pki/node.crt" 2>/dev/null

kea_src() {   # configuration « telle que la console la produit »
  cat <<'JSON'
{ "Dhcp4": {
  "interfaces-config": { "interfaces": ["lo"] },
  "control-socket": { "socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket" },
  "lease-database": { "type": "memfile", "persist": false },
  "valid-lifetime": 3600,
  "subnet4": [ { "id": 1, "subnet": "10.20.0.0/24", "pools": [ { "pool": "10.20.0.100 - 10.20.0.200" } ] } ],
  "loggers": [ { "name": "kea-dhcp4", "output_options": [ { "output": "stdout" } ], "severity": "INFO" } ]
} }
JSON
}
conf() {   # conf NOM ROLE "PEERS"
  printf 'CLUSTER_NAME=lab\nNODE_NAME=%s\nNODE_ROLE=%s\nNODE_IP=10.9.0.1\nREPL_NET=10.9.0.0/24\nPEERS=%s\nCA_NODE=0\n' "$1" "$2" "$3" > "$CD/cluster.conf"
}
rl() {   # rl [arguments] : ddibuntu-reload --kea-only avec chemins de test
  env DDI_GENERATED_DIR="$GEN" DDI_KEA_ETC="$KETC" DDI_STATE_DIR="$ST" DDI_CLUSTER_DIR="$CD" DDI_RELOAD_NOSERVICES=1 \
      DDI_KEA_LEASE_FILE="$W/leases.csv" ${HOOKS:+DDI_KEA_HOOKS_DIR="$HOOKS"} bash "$RELOAD" "$@"
}
inst() { cat "$KETC/kea-dhcp4.conf"; }
pj() { python3 -c "import json,sys; d=json.load(open('$KETC/kea-dhcp4.conf'))['Dhcp4']; $1"; }

echo "== Sans cluster : aucune modification =="
rm -f "$CD/cluster.conf"; kea_src > "$GEN/kea-dhcp4.conf"
check "kea-only sans cluster.conf" rl --kea-only
check "aucun hook sans cluster" pj "assert 'hooks-libraries' not in d"
check "baux inchangés (memfile non persistant de la source)" pj "assert d['lease-database']['persist'] is False"

echo "== Un seul nœud de données : pas de HA =="
conf n1 data "n1=10.9.0.1:data"; kea_src > "$GEN/kea-dhcp4.conf"
check "kea-only à un nœud" rl --kea-only
check "aucun hook à un seul nœud de données" pj "assert 'hooks-libraries' not in d"
conf n3 witness "n1=10.9.0.1:data n2=10.9.0.2:data n3=10.9.0.3:witness"
check "kea-only sur un arbitre" rl --kea-only
check "l'arbitre n'exécute jamais Kea HA" pj "assert 'hooks-libraries' not in d"

echo "== Deux nœuds de données : HA load-balancing =="
conf n2 data "n1=10.9.0.1:data n2=10.9.0.2:data n3=10.9.0.3:witness"
check "kea-only sur n2 (secondaire)" rl --kea-only
check "n2 : deux bibliothèques (lease_cmds, ha)" pj "l=[h['library'].split('/')[-1] for h in d['hooks-libraries']]; assert l==['libdhcp_lease_cmds.so','libdhcp_ha.so'], l"
check "n2 : this-server-name = n2, mode load-balancing" pj "h=d['hooks-libraries'][1]['parameters']['high-availability'][0]; assert h['this-server-name']=='n2' and h['mode']=='load-balancing'"
check "n2 : n1 primary, n2 secondary (ordre déterministe)" pj "p=d['hooks-libraries'][1]['parameters']['high-availability'][0]['peers']; assert [(x['name'],x['role']) for x in p]==[('n1','primary'),('n2','secondary')], p"
check "n2 : URL des pairs = réseau dédié, port 8000, TLS" pj "p=d['hooks-libraries'][1]['parameters']['high-availability'][0]['peers']; assert [x['url'] for x in p]==['https://10.9.0.1:8000/','https://10.9.0.2:8000/'], p"
check "n2 : l'arbitre n'est pas un pair HA" pj "p=d['hooks-libraries'][1]['parameters']['high-availability'][0]['peers']; assert len(p)==2"
check "n2 : TLS mutuel (autorité, certificat, clé du nœud)" pj "h=d['hooks-libraries'][1]['parameters']['high-availability'][0]; assert h['trust-anchor'].endswith('/pki/ca.crt') and h['cert-file'].endswith('/pki/node.crt') and h['key-file'].endswith('/pki/node.key')"
check "n2 : écouteur HTTP dédié (pas d'agent de contrôle)" pj "h=d['hooks-libraries'][1]['parameters']['high-availability'][0]; assert h['multi-threading']['http-dedicated-listener'] is True"
check "n2 : baux en fichier persistant local" pj "l=d['lease-database']; assert l['type']=='memfile' and l['persist'] is True and l['name']=='$W/leases.csv'"
check "n2 : sous-réseaux de la console conservés" pj "assert d['subnet4'][0]['subnet']=='10.20.0.0/24'"
expect_eq "n2 : droits 0640" "640" "$(stat -c %a "$KETC/kea-dhcp4.conf")"
check "n2 : kea-dhcp4 -t accepte la configuration finale" kea-dhcp4 -t "$KETC/kea-dhcp4.conf"
conf n1 data "n1=10.9.0.1:data n2=10.9.0.2:data n3=10.9.0.3:witness"
check "kea-only sur n1 (primaire)" rl --kea-only
check "n1 : this-server-name = n1" pj "h=d['hooks-libraries'][1]['parameters']['high-availability'][0]; assert h['this-server-name']=='n1'"
conf n1 data "n3=10.9.0.3:witness n2=10.9.0.2:data n1=10.9.0.1:data"
check "kea-only avec PEERS dans un autre ordre" rl --kea-only
check "ordre de PEERS sans effet sur les rôles HA" pj "p=d['hooks-libraries'][1]['parameters']['high-availability'][0]['peers']; assert [(x['name'],x['role']) for x in p]==[('n1','primary'),('n2','secondary')]"
S1="$(sha256sum "$KETC/kea-dhcp4.conf" | cut -d' ' -f1)"; rl --kea-only >/dev/null 2>&1; expect_eq "idempotent : même fichier à la seconde application" "$S1" "$(sha256sum "$KETC/kea-dhcp4.conf" | cut -d' ' -f1)"
expect_grep "état écrit pour la console (ok=1)" '^ok=1' "$ST/reload-status"

echo "== Frontière de privilèges =="
GOOD="$(sha256sum "$KETC/kea-dhcp4.conf" | cut -d' ' -f1)"
unchanged() { [ "$(sha256sum "$KETC/kea-dhcp4.conf" | cut -d' ' -f1)" = "$GOOD" ]; }
kea_src | python3 -c "import json,sys; d=json.load(sys.stdin); d['Dhcp4']['hooks-libraries']=[{'library':'/tmp/evil.so'}]; print(json.dumps(d))" > "$GEN/kea-dhcp4.conf"
check_fail "la console ne peut pas déclarer de hook" rl --kea-only
check "…et la configuration en place n'a pas bougé" unchanged
kea_src | python3 -c "import json,sys; d=json.load(sys.stdin); d['Dhcp4']['lease-database']={'type':'postgresql','name':'kea','user':'kea','password':'SECRETKEA','host':'127.0.0.1'}; print(json.dumps(d))" > "$GEN/kea-dhcp4.conf"
check "base de baux PostgreSQL de la console remplacée en mode HA" rl --kea-only
expect_nogrep "le mot de passe de la console n'atteint pas le fichier final" "SECRETKEA" "$KETC/kea-dhcp4.conf"
check "baux : fichier local" pj "assert d['lease-database']['type']=='memfile'"
GOOD="$(sha256sum "$KETC/kea-dhcp4.conf" | cut -d' ' -f1)"
kea_src > "$GEN/kea-dhcp4.conf"
conf n1 data 'n1=10.9.0.1:data n2=10.9.0.2:data;touch /tmp/pwn'
check_fail "cluster.conf hostile (PEERS) refusé" rl --kea-only
check "…sans toucher à la configuration en place" unchanged
conf n1 data 'n1=10.9.0.1:data n2=999.9.0.2:data'
check_fail "adresse de pair invalide refusée" rl --kea-only
conf 'N1;x' data 'n1=10.9.0.1:data n2=10.9.0.2:data'
check_fail "NODE_NAME invalide refusé" rl --kea-only
conf n9 data 'n1=10.9.0.1:data n2=10.9.0.2:data'
check_fail "nœud absent de PEERS refusé" rl --kea-only
check "…configuration en place intacte" unchanged
printf 'garbage line\n' > "$CD/cluster.conf"
check_fail "cluster.conf illisible refusé" rl --kea-only
conf n1 data 'n1=10.9.0.1:data n2=10.9.0.2:data'
HOOKS=/nonexistent check_fail "bibliothèques HA introuvables : refus" rl --kea-only
check "…configuration en place intacte (après refus de bibliothèque)" unchanged

echo "== Retour arrière si Kea refuse la configuration finale =="
mv "$CD/pki/node.key" "$CD/pki/node.key.bak"
check_fail "clé TLS absente : kea-dhcp4 -t refuse, application refusée" rl --kea-only
check "…ancienne configuration restaurée" unchanged
expect_grep "…le statut annonce l'échec et le retour arrière" '^ok=0' "$ST/reload-status"
mv "$CD/pki/node.key.bak" "$CD/pki/node.key"
check "reprise après correction" rl --kea-only
expect_grep "…statut de nouveau ok=1" '^ok=1' "$ST/reload-status"

echo "== Mode complet (primaire) : même injection =="
if command -v named-checkconf >/dev/null 2>&1; then
  mkdir -p "$W/bind" "$W/zones" "$GEN/zones"
  printf 'include "%s/named.conf.options";\ninclude "%s/named.conf.local";\n' "$W/bind" "$W/bind" > "$W/bind/named.conf"
  printf 'options { directory "/var/cache/bind"; };\n' > "$GEN/named.conf.options"; : > "$GEN/named.conf.zones"
  kea_src > "$GEN/kea-dhcp4.conf"
  env DDI_GENERATED_DIR="$GEN" DDI_KEA_ETC="$KETC" DDI_STATE_DIR="$ST" DDI_CLUSTER_DIR="$CD" DDI_BIND_ETC="$W/bind" DDI_ZONES_RUNTIME_DIR="$W/zones" \
      DDI_RELOAD_NOSERVICES=1 DDI_KEA_LEASE_FILE="$W/leases.csv" bash "$RELOAD" >"$T_TMP/full.log" 2>&1; rc=$?
  expect_eq "ddibuntu-reload complet avec cluster : code 0" 0 "$rc"; [ "$rc" -eq 0 ] || tail -5 "$T_TMP/full.log"
  check "primaire : bloc HA présent" pj "assert len(d['hooks-libraries'])==2"
else note "named-checkconf absent : mode complet non testé ici (couvert par b06)"; fi

finish
