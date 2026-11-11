#!/usr/bin/env bash
# Batterie 17 — assistants de la console (création du cluster, lot d'enrôlement, rattachement) avec de VRAIS etcd : nœuds simulés sur 127.0.1.1-2.
# Les demandes passent par les fichiers JSON que la console dépose (.cluster-setup hors cluster, .cluster-action dans le cluster) :
# validation stricte, confirmations, fichiers hostiles, phrase de passe jamais écrite dans les résultats ni les journaux.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

CL="$RFS/usr/local/sbin/ddibuntu-cluster"
PY=python3.12
PGBIN=/usr/lib/postgresql/16/bin
missing=""
[ "$(id -u)" -eq 0 ] || missing="$missing root"
for t in etcd etcdctl openssl gpg runuser python3 patroni patronictl curl; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
command -v "$PY" >/dev/null 2>&1 || PY=python3
getent passwd etcd >/dev/null && getent passwd postgres >/dev/null || missing="$missing comptes-etcd/postgres"
[ -x "$PGBIN/initdb" ] || missing="$missing postgresql-16"
if [ -n "$missing" ]; then note "batterie cluster réel (exploitation) non exécutable ici (manque :$missing)"; finish; exit; fi

B="$(mktemp -d /srv/ddilive.XXXXXX)"; chmod 755 "$B"
cleanup() { pkill -u etcd -f "$B/" 2>/dev/null; pkill -9 -u postgres -f "$B/n" 2>/dev/null
  for _ in $(seq 1 20); do pgrep -u etcd -f "$B/" >/dev/null 2>&1 || break; sleep 0.5; done
  sleep 1; rm -rf "$B"; rm -rf "$T_TMP"; }
trap cleanup EXIT

ip() { echo "127.0.1.$1"; }
R() { echo "$B/n$1"; }
mkwrap() {
  local n="$1" r; r="$(R "$n")"
  printf '#!/bin/sh\nexec env DDI_ROOT=%s DDI_TEST=1 DDI_PY=%s DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN= DDI_PG_CONFIG_DIR= DDI_NO_ACTIVATE=1 DDI_ETCD_CMD=%s/etcdcmd%s.sh bash %s "$@"\n' "$r" "$PY" "$B" "$n" "$CL" > "$B/cl$n.sh"
  printf '#!/bin/sh\ncase "$1" in\n  stop) pkill -u etcd -f %s/ 2>/dev/null; sleep 1 ;;\n  start) ( cd / && runuser -u etcd -- /usr/bin/etcd --config-file %s/etc/ddibuntu-cluster/etcd.yml >%s/etcd%s.log 2>&1 & ) ;;\nesac\n' "$r" "$r" "$B" "$n" > "$B/etcdcmd$n.sh"
  chmod 755 "$B/cl$n.sh" "$B/etcdcmd$n.sh"
}
cl() { local n="$1"; shift; "$B/cl$n.sh" "$@"; }
clp() { local pw="$1" n="$2"; shift 2; DDI_BUNDLE_PASS="$pw" "$B/cl$n.sh" "$@"; }
mknode() { local r; r="$(R "$1")"; mkdir -p "$r/usr/lib" "$r/run/pg" "$r/var/lib/postgresql/16" "$r/var/lib/etcd" "$r/etc/ddibuntu" "$r/etc/bind" "$r/var/lib/ddibuntu/generated"
  ln -s /usr/lib/postgresql "$r/usr/lib/postgresql"
  chown -R postgres:postgres "$r/run/pg" "$r/var/lib/postgresql"; chmod 755 "$r" "$r/run" "$r/var" "$r/var/lib" "$r/etc"; mkwrap "$1"; }
initdb_local() { runuser -u postgres -- "$PGBIN/initdb" -D "$(R "$1")/var/lib/postgresql/16/main" -E UTF8 --data-checksums >/dev/null 2>&1; }
start_etcd() { "$B/etcdcmd$1.sh" start; }
stop_etcd() { "$B/etcdcmd$1.sh" stop; }
ectl() { local n="$1"; shift; local p; p="$(R "$n")/etc/ddibuntu-cluster/pki"; ETCDCTL_API=3 etcdctl --endpoints "https://$(ip "$n"):2379" --command-timeout=5s --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "$@"; }
wait_for() { local s="$1" d="$2"; shift 2; local i=0; while [ "$i" -lt "$s" ]; do if "$@" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }
# qj N EXPRESSION : évalue une expression Python sur le bloc « etcd.quorum » de l'état publié par le nœud N
qj() { cl "$1" status 2>/dev/null | python3 -c 'import json,sys; q=json.load(sys.stdin)["etcd"]["quorum"]; print(eval(sys.argv[1]))' "$2"; }
st() { cl "$1" status 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2"; }
G() { echo "$(R "$1")/var/lib/ddibuntu/generated"; }
peers() { grep '^PEERS=' "$(R "$1")/etc/ddibuntu-cluster/cluster.conf" | cut -d= -f2-; }
newnode() {   # newnode NOM N IP RÔLE ORIGINE : lot depuis le nœud ORIGINE, installation et démarrage du nœud N
  local name="$1" n="$2" addr="$3" role="$4" from="$5" pw
  pw="$(cl "$from" bundle --name "$name" --ip "$addr" --role "$role" --out "$B/$name.bundle" 2>"$B/bundle-$name.err")"
  [ -n "$pw" ] && ok "lot $name ($role) créé sur n$from" || { ko "lot $name créé" "$(cat "$B/bundle-$name.err")"; return 1; }
  mknode "$n"; [ "$role" != data ] || initdb_local "$n"
  local a=(--no-activate); [ "$role" != data ] || a+=(--wipe-local-db)
  check "join $name" clp "$pw" "$n" join "$B/$name.bundle" "${a[@]}"
  start_etcd "$n"; wait_for 30 "etcd $name répond" ectl "$n" endpoint status
  check "activate $name" cl "$n" activate
  local k; for k in 1 2 3 4; do [ -x "$B/cl$k.sh" ] && [ "$k" != "$n" ] && cl "$k" sync >/dev/null 2>&1; done; cl "$n" sync >/dev/null 2>&1; true
}


G() { echo "$(R "$1")/var/lib/ddibuntu/generated"; }
res() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$(R "$1")/run/ddibuntu/cluster-result.json" "$2"; }
# setup N JSON : dépose .cluster-setup et lance le service ; capture TOUTE la sortie (journal) dans $B/out
setup() { printf '%s' "$2" > "$(G "$1")/.cluster-setup"; cl "$1" setup-request >"$B/out" 2>&1; }
act() { printf '%s' "$2" > "$(G "$1")/.cluster-action"; cl "$1" request >"$B/out" 2>&1; }
PASS="Abcdefghijklmnop0123456789XY"
HN="$(hostname -s)"

echo "== 1. Création du cluster depuis la console (nœud encore hors cluster) =="
mknode 1; initdb_local 1
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -o "-c listen_addresses='' -c unix_socket_directories=$(R 1)/run/pg -c port=5432" -l "$(R 1)/run/pg/init.log" -w start >/dev/null 2>&1
for bad in 'pas du json' '[]' '{"action":"init"}' '{"action":"remove-node","node":"n1","confirm":"n1"}' \
  '{"action":"init","cluster":"lab","node":"n1","ip":"127.0.1.1","confirm":"autre"}' \
  '{"action":"init","cluster":"lab","node":"n1","ip":"999.0.1.1","confirm":"n1"}' \
  '{"action":"init","cluster":"Lab","node":"n1","ip":"127.0.1.1","confirm":"n1"}' \
  '{"action":"init","cluster":"lab","node":"n1;x","ip":"127.0.1.1","confirm":"n1;x"}' \
  '{"action":"init","cluster":"lab","node":"n1","ip":"127.0.1.1","confirm":"n1","extra":1}' \
  '{"action":"init","cluster":"lab","node":"n1","ip":"127.0.1.1","vip":"127.0.1.9","confirm":"n1"}' \
  '{"action":"init","cluster":"lab","node":"n1","ip":"127.0.1.1","vipIface":"eth0","confirm":"n1"}' \
  '{"action":"init","cluster":"lab","node":"n1","ip":"127.0.1.1","vip":"127.0.1.9","vipIface":"eth0;x","confirm":"n1"}' \
  '{"action":"init","cluster":"lab","node":"n1","ip":"127.0.1.1","vip":"127.0.1.9","vipIface":"eth0","vrid":0,"confirm":"n1"}' \
  '{"action":"init","cluster":"lab","node":"n1","ip":"127.0.1.1","vip":"127.0.1.9","vipIface":"eth0","vrid":"5","confirm":"n1"}' \
  '{"action":"init","cluster":"lab","node":"n1","ip":"127.0.1.1","net":"10.0.0.0/33","confirm":"n1"}' \
  '{"action":"init","cluster":"lab","node":"n1","ip":"127.0.1.1","net":"$(id)/8","confirm":"n1"}' \
  '{"action":"join","pass":"court","confirm":"'"$HN"'"}' '{"action":"join","pass":"'"$PASS"'","confirm":"mauvais"}' '{"action":"join","pass":"'"$PASS"'$(id)","confirm":"'"$HN"'"}'; do
  setup 1 "$bad"; expect_eq "refusée : ${bad:0:60}" "False demande invalide" "$(res 1 '"%s %s" % (d["ok"], d["message"])')"
done
expect_eq "…aucune configuration de cluster n'a été créée" "no" "$([ -e "$(R 1)/etc/ddibuntu-cluster/cluster.conf" ] && echo yes || echo no)"
expect_eq "…le fichier de demande est consommé" "no" "$([ -e "$(G 1)/.cluster-setup" ] && echo yes || echo no)"
printf '{"action":"init"}' > "$(G 1)/.cluster-setup.real"; ln -sf "$(G 1)/.cluster-setup.real" "$(G 1)/.cluster-setup"; cl 1 setup-request >/dev/null 2>&1
expect_eq "lien symbolique refusé" "demande invalide" "$(res 1 'd["message"]')"
head -c 5000 /dev/zero | tr '\0' 'a' > "$(G 1)/.cluster-setup"; cl 1 setup-request >/dev/null 2>&1
expect_eq "fichier démesuré refusé" "demande invalide" "$(res 1 'd["message"]')"
setup 1 '{"action":"init","cluster":"lab","node":"n1","ip":"127.0.1.1","net":"127.0.0.0/8","confirm":"n1"}'
expect_eq "création acceptée" "init True" "$(res 1 '"%s %s" % (d["action"], d["ok"])')"
expect_eq "…le cluster porte le nom demandé" "CLUSTER_NAME=lab" "$(grep '^CLUSTER_NAME=' "$(R 1)/etc/ddibuntu-cluster/cluster.conf")"
expect_eq "…ce nœud porte l'autorité" "CA_NODE=1" "$(grep '^CA_NODE=' "$(R 1)/etc/ddibuntu-cluster/cluster.conf")"
expect_eq "…réseau dédié enregistré" "REPL_NET=127.0.0.0/8" "$(grep '^REPL_NET=' "$(R 1)/etc/ddibuntu-cluster/cluster.conf")"
setup 1 '{"action":"init","cluster":"autre","node":"n1","ip":"127.0.1.1","confirm":"n1"}'
expect_eq "seconde création refusée (déjà dans un cluster)" "False ce nœud appartient déjà à un cluster" "$(res 1 '"%s %s" % (d["ok"], d["message"])')"
expect_eq "…le nom du cluster n'a pas changé" "CLUSTER_NAME=lab" "$(grep '^CLUSTER_NAME=' "$(R 1)/etc/ddibuntu-cluster/cluster.conf")"
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -m fast -w stop >/dev/null 2>&1
start_etcd 1; wait_for 20 "etcd n1 sain" ectl 1 endpoint health
check "activate n1" cl 1 activate
check "sync n1" cl 1 sync

echo "== 2. Lot d'enrôlement demandé par la console (phrase imposée par la console) =="
B1='"action":"bundle","node":"n2","ip":"127.0.1.2","role":"data","pass":"'"$PASS"'","confirm":"n2"'
for bad in "{${B1/\"pass\":\"$PASS\"/\"pass\":\"court\"}}" "{${B1/\"role\":\"data\"/\"role\":\"autre\"}}" "{${B1/127.0.1.2/300.0.0.1}}" "{${B1/\"confirm\":\"n2\"/\"confirm\":\"n3\"}}" "{${B1},\"extra\":1}" \
  '{"action":"refresh","pass":"'"$PASS"'"}' '{"action":"refresh","ip":"127.0.1.2"}' "{${B1/\"node\":\"n2\"/\"node\":\"N2\"}}" "{${B1/$PASS/${PASS}\$(id)}}"; do
  act 1 "$bad"; expect_eq "refusée : ${bad:0:70}" "False demande invalide" "$(res 1 '"%s %s" % (d["ok"], d["message"])')"
done
expect_eq "…aucun lot n'a été créé" "0" "$(ls "$(G 1)"/cluster-bundle-* 2>/dev/null | wc -l)"
act 1 "{${B1/\"node\":\"n2\"/\"node\":\"n1\"}}"; expect_eq "nom déjà pris : refusé par la commande" "False" "$(res 1 'd["ok"]')"
act 1 "{${B1/127.0.1.2/127.0.1.1}}"; expect_eq "adresse déjà prise : refusée par la commande" "False" "$(res 1 'd["ok"]')"
act 1 "{$B1}"
expect_eq "lot n2 créé" "bundle True" "$(res 1 '"%s %s" % (d["action"], d["ok"])')"
expect_eq "…fichier en 0640" "640" "$(stat -c %a "$(G 1)/cluster-bundle-n2.bundle")"
expect_eq "…la phrase de passe n'est PAS dans le résultat publié" "0" "$(grep -c "$PASS" "$(R 1)/run/ddibuntu/cluster-result.json")"
expect_eq "…ni dans le journal de la commande" "0" "$(grep -c "$PASS" "$B/out")"
expect_eq "…ni dans le lot en clair (chiffré)" "0" "$(grep -c 'BEGIN' "$(G 1)/cluster-bundle-n2.bundle")"
expect_eq "…la demande est consommée" "no" "$([ -e "$(G 1)/.cluster-action" ] && echo yes || echo no)"
expect_eq "…n2 est inscrit dans les pairs de n1" "True" "$(grep -q 'n2=127.0.1.2:data' "$(R 1)/etc/ddibuntu-cluster/cluster.conf" && echo True)"
act 1 "{$B1}"; expect_eq "même lot redemandé : refusé" "False" "$(res 1 'd["ok"]')"

echo "== 3. Rattachement demandé par la console sur le nouveau nœud =="
mknode 2; initdb_local 2
J="$(G 2)/cluster-join.bundle"
cp "$(G 1)/cluster-bundle-n2.bundle" "$J"
setup 2 '{"action":"join","pass":"'"$PASS"'","confirm":"mauvais"}'; expect_eq "mauvaise confirmation : refusé" "False demande invalide" "$(res 2 '"%s %s" % (d["ok"], d["message"])')"
expect_eq "…le lot déposé est détruit" "no" "$([ -e "$J" ] && echo yes || echo no)"
cp "$(G 1)/cluster-bundle-n2.bundle" "$J"
setup 2 '{"action":"join","pass":"Zzzzzzzzzzzzzzzzzzzzzzzz9999","confirm":"'"$HN"'"}'
expect_eq "mauvaise phrase de passe : échec" "join False" "$(res 2 '"%s %s" % (d["action"], d["ok"])')"
expect_eq "…message lisible" "True" "$(res 2 '"illisible" in d["message"]')"
expect_eq "…le nœud n'a pas rejoint (pas de configuration)" "no" "$([ -e "$(R 2)/etc/ddibuntu-cluster/cluster.conf" ] && echo yes || echo no)"
expect_eq "…sa base locale est intacte" "yes" "$([ -e "$(R 2)/var/lib/postgresql/16/main/PG_VERSION" ] && echo yes || echo no)"
expect_eq "…la phrase fausse n'apparaît pas dans le résultat" "0" "$(grep -c 'Zzzzzzzz' "$(R 2)/run/ddibuntu/cluster-result.json")"
setup 2 '{"action":"join","pass":"'"$PASS"'","confirm":"'"$HN"'"}'
expect_eq "lot absent : refusé" "False lot d'enrôlement absent ou invalide" "$(res 2 '"%s %s" % (d["ok"], d["message"])')"
cp "$(G 1)/cluster-bundle-n2.bundle" "$J"
setup 2 '{"action":"join","pass":"'"$PASS"'","confirm":"'"$HN"'"}'
expect_eq "rattachement accepté" "join True" "$(res 2 '"%s %s" % (d["action"], d["ok"])')"
expect_eq "…ce nœud est « n2 » du cluster « lab »" "NODE_NAME=n2 CLUSTER_NAME=lab" "$(grep '^NODE_NAME=' "$(R 2)/etc/ddibuntu-cluster/cluster.conf") $(grep '^CLUSTER_NAME=' "$(R 2)/etc/ddibuntu-cluster/cluster.conf")"
expect_eq "…le lot est supprimé des deux endroits" "no no" "$([ -e "$J" ] && echo yes || echo no) $([ -e "$(R 2)/var/lib/ddibuntu/cluster/join.bundle" ] && echo yes || echo no)"
expect_eq "…la base locale a été effacée (reprise par Patroni)" "no" "$([ -e "$(R 2)/var/lib/postgresql/16/main/PG_VERSION" ] && echo yes || echo no)"
expect_eq "…aucune phrase de passe dans le résultat ni le journal" "0" "$(grep -c "$PASS" "$(R 2)/run/ddibuntu/cluster-result.json" "$B/out" | awk -F: '{s+=$2} END{print s}')"
setup 2 '{"action":"join","pass":"'"$PASS"'","confirm":"'"$HN"'"}'
expect_eq "second rattachement refusé" "False ce nœud appartient déjà à un cluster" "$(res 2 '"%s %s" % (d["ok"], d["message"])')"
start_etcd 2; wait_for 30 "etcd n2 répond" ectl 2 endpoint status
check "activate n2" cl 2 activate
wait_for 60 "etcd : les deux membres sont sains" ectl 1 endpoint health --cluster
check "sync n1" cl 1 sync
expect_eq "le quorum voit 2 voix saines" "2 2 2" "$(cl 1 status | python3 -c 'import json,sys; q=json.load(sys.stdin)["etcd"]["quorum"]; print(q["voters"], q["needed"], q["healthy"])')"

echo "== 4. Hygiène des lots oubliés =="
touch "$(G 1)/cluster-bundle-vieux.bundle" "$(G 1)/cluster-bundle-recent.bundle"; touch -d '2 hours ago' "$(G 1)/cluster-bundle-vieux.bundle"
act 1 '{"action":"refresh"}'
expect_eq "lot de plus d'une heure détruit" "no" "$([ -e "$(G 1)/cluster-bundle-vieux.bundle" ] && echo yes || echo no)"
expect_eq "lot récent conservé" "yes" "$([ -e "$(G 1)/cluster-bundle-recent.bundle" ] && echo yes || echo no)"
expect_eq "…le lot de n2 aussi (créé il y a moins d'une heure)" "yes" "$([ -e "$(G 1)/cluster-bundle-n2.bundle" ] && echo yes || echo no)"

finish
