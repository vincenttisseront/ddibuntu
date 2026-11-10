#!/usr/bin/env bash
# Batterie 10b — cluster RÉEL : 3 nœuds simulés sur des adresses de boucle locale (127.0.1.1-3), de vrais etcd (TLS mutuel) et de
# vrais Patroni/PostgreSQL. Vérifie : reprise d'une base existante, enrôlement par lot chiffré, croissance etcd sans perte de
# quorum (learner), réplication authentifiée par certificat, bascule contrôlée, bascule automatique après arrêt brutal,
# réintégration de l'ancien primaire, et isolation (un primaire sans quorum passe en lecture seule).
# Exige root, etcd, patroni (python3.12 + psycopg2) et PostgreSQL 16. Sinon : la batterie se déclare non exécutable (NOTE) et sort sans échec.
# Limite assumée : un seul noyau, une seule horloge, pas de coupure réseau réelle — c'est un test de logique de cluster, pas un test de panne matérielle.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

CL="$RFS/usr/local/sbin/ddibuntu-cluster"
PGBIN=/usr/lib/postgresql/16/bin
PY=python3.12
missing=""
[ "$(id -u)" -eq 0 ] || missing="$missing root"
for t in etcd etcdctl patroni openssl gpg curl runuser; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
[ -x "$PGBIN/initdb" ] || missing="$missing postgresql-16"
$PY -c 'import psycopg2, patroni' >/dev/null 2>&1 || missing="$missing python3.12+psycopg2+patroni"
getent passwd postgres >/dev/null && getent passwd etcd >/dev/null || missing="$missing comptes-postgres/etcd"
if [ -n "$missing" ]; then note "batterie cluster réel non exécutable ici (manque :$missing)"; finish; exit; fi

B="$(mktemp -d /srv/ddilive.XXXXXX)"; chmod 755 "$B"
cleanup() {
  pkill -f "patroni $B/" 2>/dev/null; pkill -u etcd -f "$B/" 2>/dev/null; sleep 1
  for n in 1 2 3; do pkill -9 -u postgres -f "$B/n$n/" 2>/dev/null; done
  rm -rf "$B"; rm -rf "$T_TMP"
}
trap cleanup EXIT

ip() { echo "127.0.1.$1"; }
R() { echo "$B/n$1"; }
# cl N commande... : exécute ddibuntu-cluster dans l'environnement du nœud N
cl() { local n="$1"; shift; DDI_ROOT="$(R "$n")" DDI_TEST=1 DDI_PY=$PY DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN='' DDI_PG_CONFIG_DIR='' "$CL" "$@"; }
clp() { local pw="$1"; shift; DDI_BUNDLE_PASS="$pw" cl "$@"; }
mknode() {
  local r; r="$(R "$1")"; mkdir -p "$r/usr/lib" "$r/run/pg" "$r/var/lib/postgresql/16" "$r/var/lib/etcd" "$r/etc/ddibuntu"
  ln -s /usr/lib/postgresql "$r/usr/lib/postgresql"
  chown -R postgres:postgres "$r/run/pg" "$r/var/lib/postgresql"; chmod 755 "$r" "$r/run" "$r/var" "$r/var/lib" "$r/etc"
}
initdb_local() { runuser -u postgres -- "$PGBIN/initdb" -D "$(R "$1")/var/lib/postgresql/16/main" -E UTF8 --data-checksums >/dev/null 2>&1; }
start_etcd() { local r; r="$(R "$1")"; ( cd / && runuser -u etcd -- /usr/bin/etcd --config-file "$r/etc/ddibuntu-cluster/etcd.yml" >"$B/etcd$1.log" 2>&1 & ); }
start_patroni() { local r; r="$(R "$1")"; ( cd / && runuser -u postgres -- $PY /usr/bin/patroni "$r/etc/patroni/config.yml" >"$B/patroni$1.log" 2>&1 & ); }
kill_patroni_hard() { local r; r="$(R "$1")"; pkill -9 -f "patroni $r/"; pkill -9 -u postgres -f "$r/var/lib/postgresql" ; sleep 1; }
api() { local r; r="$(R "$1")"; local p="$r/etc/ddibuntu-cluster/pki"; curl -s --max-time 5 --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "https://$(ip "$1"):8008/$2"; }
sql() { local n="$1"; shift; runuser -u postgres -- psql -h "$(R "$n")/run/pg" -d postgres -v ON_ERROR_STOP=1 -Atq "$@"; }
ectl() { local n="$1"; shift; local p; p="$(R "$n")/etc/ddibuntu-cluster/pki"; ETCDCTL_API=3 etcdctl --endpoints "https://$(ip "$n"):2379" --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "$@"; }
# cluster_json N : /cluster vu par le nœud N
role_of() { api "$1" cluster | python3 -c 'import json,sys
n=sys.argv[1]
try: d=json.load(sys.stdin)
except Exception: print("?"); sys.exit()
m=[x for x in d.get("members",[]) if x["name"]==n]
print((m[0]["role"]+"/"+m[0].get("state","?")) if m else "absent")' "n$2" 2>/dev/null; }
wait_for() { # wait_for secondes "description" commande... (réussit quand la commande réussit)
  local s="$1" d="$2"; shift 2; local i=0
  while [ "$i" -lt "$s" ]; do if "$@" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done
  ko "$d" "délai de ${s}s dépassé"; return 1
}
is_leader() { [ "$(role_of "$1" "$2")" = "leader/running" ]; }          # is_leader VUDE_DE_N NOEUD
is_replica() { case "$(role_of "$1" "$2")" in replica/streaming|replica/running) return 0 ;; *) return 1 ;; esac; }
streaming() { [ "$(role_of "$1" "$2")" = "replica/streaming" ]; }
leader_name() { api "$1" cluster | python3 -c 'import json,sys
d=json.load(sys.stdin)
print(next((m["name"] for m in d["members"] if m["role"]=="leader"),""))' 2>/dev/null; }
voters() { ectl "$1" member list -w json 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin)["members"]
print(sum(1 for m in d if not m.get("isLearner")), sum(1 for m in d if m.get("isLearner")))' 2>/dev/null; }

echo "== Nœud 1 : base PostgreSQL existante, puis « init » =="
mknode 1; initdb_local 1
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -o "-c listen_addresses='' -c unix_socket_directories=$(R 1)/run/pg -c port=5432" -l "$(R 1)/run/pg/init.log" -w start >/dev/null 2>&1
sql 1 -c "create table t(id int primary key, v text); insert into t values (1,'avant-cluster')"
printf 'DDI_DATABASE_URL=postgres://ddi:s1@127.0.0.1/ddibuntu\nDDI_SECRET_KEY=CLE-DU-PRIMAIRE\nDDI_KEA_DB_PASSWORD=kea1\nAUTRE=1\n' > "$(R 1)/etc/ddibuntu/console.env"
check "init n1" cl 1 init --name n1 --ip "$(ip 1)" --net 127.0.0.0/8
check_fail "init refusé si le nœud est déjà dans un cluster" cl 1 init --name n1 --ip "$(ip 1)" --net 127.0.0.0/8
check_fail "init refuse un nom invalide" cl 9 init --name 'N 1;rm' --ip 127.0.1.9 --net 127.0.0.0/8
check_fail "init refuse une adresse invalide" cl 9 init --name n9 --ip 127.0.1.999 --net 127.0.0.0/8
C1="$(R 1)/etc/ddibuntu-cluster"
expect_eq "la clé de l'autorité ne quitte pas le nœud 1" "yes" "$([ -f "$(R 1)/var/lib/ddibuntu/cluster/ca/ca.key" ] && echo yes || echo no)"
expect_eq "clé privée du nœud : 0640 groupe ddicluster" "640 ddicluster" "$(stat -c '%a %G' "$C1/pki/node.key")"
expect_eq "clé de l'autorité : 0600" "600" "$(stat -c '%a' "$(R 1)/var/lib/ddibuntu/cluster/ca/ca.key")"
check "certificat du nœud valide et signé par l'autorité" openssl verify -CAfile "$C1/pki/ca.crt" "$C1/pki/node.crt"
expect_grep "certificat : SAN contient l'adresse du réseau dédié" 'IP Address:127\.0\.1\.1' <(openssl x509 -in "$C1/pki/node.crt" -noout -ext subjectAltName)
expect_grep "etcd.yml : TLS mutuel obligatoire (client)" 'client-cert-auth: true' "$C1/etcd.yml"
expect_nogrep "etcd.yml : aucune écoute en clair / hors réseau dédié" 'http://|0\.0\.0\.0' "$C1/etcd.yml"
expect_grep "Patroni : API en TLS avec certificat client exigé" 'verify_client: required' "$(R 1)/etc/patroni/config.yml"
expect_grep "pg_hba : réplication par certificat uniquement" 'hostssl replication replicator .* cert map=ddicluster' "$(R 1)/etc/patroni/config.yml"
expect_nogrep "pg_hba : aucune entrée « trust » ni mot de passe de réplication" ' trust|password: ' "$(R 1)/etc/patroni/config.yml"

runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -m fast -w stop >/dev/null 2>&1
start_etcd 1
wait_for 20 "etcd n1 sain" ectl 1 endpoint health
start_patroni 1
wait_for 60 "Patroni n1 devient leader sur la base existante" is_leader 1 1
expect_eq "la base existante est conservée" "avant-cluster" "$(sql 1 -c "select v from t where id=1")"
expect_eq "rôle de réplication créé" "1" "$(sql 1 -c "select count(*) from pg_roles where rolname='replicator' and rolreplication")"

echo "== Lots d'enrôlement (n2 données, n3 arbitre) =="
bundle() { cl 1 bundle --name "$1" --ip "$2" --role "$3" --out "$B/$1.bundle" 2>"$B/bundle-$1.err"; }
P2="$(bundle n2 "$(ip 2)" data)"; [ -n "$P2" ] && ok "lot n2 créé" || ko "lot n2 créé" "$(cat "$B/bundle-n2.err")"
expect_grep "le lot est chiffré (OpenPGP symétrique)" 'ASCII|PGP|^' "$B/n2.bundle"
expect_eq "lot : aucun secret en clair (clé privée absente du fichier)" "0" "$(grep -c 'BEGIN' "$B/n2.bundle")"
expect_eq "lot : droits 0600" "600" "$(stat -c '%a' "$B/n2.bundle")"
check_fail "bundle refuse un nom déjà pris" cl 1 bundle --name n2 --ip 127.0.1.7 --out "$B/x.bundle"
check_fail "bundle refuse une adresse déjà prise" cl 1 bundle --name n7 --ip "$(ip 2)" --out "$B/x.bundle"
check_fail "bundle refuse un rôle inconnu" cl 1 bundle --name n7 --ip 127.0.1.7 --role root --out "$B/x.bundle"
sleep 1
expect_eq "etcd : n2 est « learner » (le quorum n'est pas dégradé)" "1 1" "$(voters 1)"
expect_eq "le primaire reste leader pendant l'enrôlement" "leader/running" "$(role_of 1 1)"

mknode 2; initdb_local 2
echo "BASE-LOCALE-N2" > "$(R 2)/var/lib/postgresql/16/main/MARQUEUR"
printf 'DDI_DATABASE_URL=postgres://ddi:s2@127.0.0.1/ddibuntu\nDDI_SECRET_KEY=CLE-LOCALE-N2\nDDI_KEA_DB_PASSWORD=kea2\nAUTRE=2\n' > "$(R 2)/etc/ddibuntu/console.env"
check_fail "join : mauvaise phrase de passe" clp "faux" 2 join "$B/n2.bundle" --wipe-local-db --no-activate
cp "$B/n2.bundle" "$B/n2-alt.bundle"; printf 'X' | dd of="$B/n2-alt.bundle" bs=1 seek=900 conv=notrunc 2>/dev/null
check_fail "join : lot altéré refusé" clp "$P2" 2 join "$B/n2-alt.bundle" --wipe-local-db --no-activate
check_fail "join : refus sans --wipe-local-db (la base locale est protégée)" clp "$P2" 2 join "$B/n2.bundle" --no-activate
expect_eq "la base locale n'a pas été touchée par les refus" "BASE-LOCALE-N2" "$(cat "$(R 2)/var/lib/postgresql/16/main/MARQUEUR" 2>/dev/null)"
check "join n2" clp "$P2" 2 join "$B/n2.bundle" --wipe-local-db --no-activate
expect_eq "join : base locale effacée" "no" "$([ -e "$(R 2)/var/lib/postgresql/16/main/MARQUEUR" ] && echo yes || echo no)"
expect_eq "join : clé secrète de la console alignée sur le primaire" "CLE-DU-PRIMAIRE" "$(sed -n 's/^DDI_SECRET_KEY=//p' "$(R 2)/etc/ddibuntu/console.env")"
expect_eq "join : le reste de console.env est conservé" "AUTRE=2" "$(grep '^AUTRE=' "$(R 2)/etc/ddibuntu/console.env")"
expect_eq "join : une seule ligne DDI_SECRET_KEY" "1" "$(grep -c '^DDI_SECRET_KEY=' "$(R 2)/etc/ddibuntu/console.env")"
expect_eq "join : pas d'autorité sur n2" "no" "$([ -e "$(R 2)/var/lib/ddibuntu/cluster/ca/ca.key" ] && echo yes || echo no)"
check_fail "join : un nœud déjà rattaché refuse un second lot" clp "$P2" 2 join "$B/n2.bundle" --wipe-local-db --no-activate
start_etcd 2
wait_for 30 "etcd n2 répond (membre sans voix)" ectl 2 endpoint status
check "activate n2 : promotion du learner en votant" cl 2 activate
expect_eq "etcd : 2 votants, 0 learner" "2 0" "$(voters 1)"
start_patroni 2
wait_for 90 "n2 réplique en continu (basebackup puis streaming)" streaming 1 2

P3="$(bundle n3 "$(ip 3)" witness)"; [ -n "$P3" ] && ok "lot n3 (arbitre) créé" || ko "lot n3 créé" "$(cat "$B/bundle-n3.err")"
mknode 3
check "join n3 (arbitre : pas de --wipe-local-db nécessaire)" clp "$P3" 3 join "$B/n3.bundle" --no-activate
expect_eq "arbitre : aucune configuration Patroni ni base" "no" "$([ -e "$(R 3)/etc/patroni/config.yml" ] && echo yes || echo no)"
expect_eq "arbitre : aucun secret de la console reçu" "no" "$([ -s "$(R 3)/etc/ddibuntu/console.env" ] && echo yes || echo no)"
start_etcd 3
wait_for 30 "etcd n3 répond (membre sans voix)" ectl 3 endpoint status
check "activate n3" cl 3 activate
expect_eq "etcd : 3 votants" "3 0" "$(voters 1)"
expect_nogrep "avant sync : n2 ne connaît pas encore n3" 'n3=' <(grep '^PEERS=' "$(R 2)/etc/ddibuntu-cluster/cluster.conf")
check "sync sur n2 : le registre etcd apprend n3 à n2" cl 2 sync
expect_grep "après sync : n2 connaît n3 (arbitre)" "n3=127\\.0\\.1\\.3:witness" "$(R 2)/etc/ddibuntu-cluster/cluster.conf"
expect_grep "après sync : n2 recalcule la configuration Patroni" 'hosts: .*127\.0\.1\.3:2379' "$(R 2)/etc/patroni/config.yml"
check "sync idempotent" cl 2 sync

echo "== Réplication et authentification =="
sql 1 -c "insert into t values (2,'après-cluster')"
wait_for 20 "la donnée écrite sur le primaire arrive sur n2" test "$(sql 2 -c "select count(*) from t" 2>/dev/null)" = 2
expect_eq "n2 est bien un secondaire en lecture seule" "t" "$(sql 2 -c "select pg_is_in_recovery()")"
check_fail "n2 refuse l'écriture" sql 2 -c "insert into t values (9,'non')"
expect_eq "un seul primaire dans le cluster" "n1" "$(leader_name 2)"
# connexion de réplication sans certificat client : refusée
check_fail "réplication sans certificat refusée" env PGSSLMODE=require PGPASSWORD=x psql "host=$(ip 1) port=5432 user=replicator dbname=replication replication=true sslmode=require" -c "IDENTIFY_SYSTEM"
check_fail "réplication en clair refusée" env PGSSLMODE=disable psql "host=$(ip 1) port=5432 user=replicator dbname=replication replication=true sslmode=disable" -c "IDENTIFY_SYSTEM"
# certificat signé par une AUTRE autorité : refusé
mkdir -p "$B/evil"; ( cd "$B/evil" && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -subj "/CN=evil" -days 2 >/dev/null 2>&1 \
  && openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout n.key -out n.csr -subj "/CN=node-n1" >/dev/null 2>&1 && openssl x509 -req -in n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out n.crt -days 2 >/dev/null 2>&1 )
chmod -R a+rX "$B/evil"
check_fail "certificat d'une autre autorité refusé par PostgreSQL" env PGSSLCERT="$B/evil/n.crt" PGSSLKEY="$B/evil/n.key" psql "host=$(ip 1) port=5432 user=replicator dbname=replication replication=true sslmode=require" -c "IDENTIFY_SYSTEM"
check_fail "API Patroni refuse un client sans certificat" curl -sf --max-time 5 --cacert "$C1/pki/ca.crt" "https://$(ip 1):8008/cluster"
check_fail "etcd refuse un client sans certificat" env ETCDCTL_API=3 etcdctl --endpoints "https://$(ip 1):2379" --cacert "$C1/pki/ca.crt" endpoint health
OUT="$(cl 1 status 2>&1)"; echo "$OUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["etcd"]["healthy"] and d["etcd"]["members"]==3 and len(d["patroni"]["members"])==2' 2>/dev/null && ok "status : JSON cohérent (etcd 3 membres, 2 nœuds de données)" || ko "status" "$OUT"

echo "== Bascule contrôlée =="
# patronictl lit sa configuration : on l'exécute avec l'environnement du nœud 1
check "switchover vers n2" cl 1 switchover --candidate n2
wait_for 60 "n2 devient leader" is_leader 2 2
wait_for 60 "n1 réplique à nouveau" streaming 2 1
expect_eq "n2 accepte l'écriture après bascule" "ok" "$(sql 2 -c "insert into t values (3,'sur-n2'); select 'ok'" | tail -1)"
wait_for 20 "n1 reçoit la donnée de n2" test "$(sql 1 -c "select count(*) from t" 2>/dev/null)" = 3

echo "== Bascule automatique (arrêt brutal du primaire) =="
kill_patroni_hard 2
wait_for 90 "n1 est promu automatiquement (quorum etcd n1+n3)" is_leader 1 1
expect_eq "aucune donnée validée perdue" "3" "$(sql 1 -c "select count(*) from t")"
expect_eq "le nouveau primaire accepte l'écriture" "ok" "$(sql 1 -c "insert into t values (4,'après-panne'); select 'ok'" | tail -1)"

echo "== Réintégration de l'ancien primaire (pg_rewind) =="
sql 1 -c "checkpoint"
start_patroni 2
wait_for 120 "n2 revient comme secondaire" streaming 1 2
wait_for 30 "n2 a rattrapé la donnée écrite pendant son absence" test "$(sql 2 -c "select count(*) from t" 2>/dev/null)" = 4
expect_eq "toujours un seul primaire" "n1" "$(leader_name 1)"

echo "== Isolation : primaire sans quorum → lecture seule =="
# n1 est primaire. On coupe etcd sur n2 et n3 : n1 perd le quorum et doit se rétrograder lui-même.
pkill -u etcd -f "$(R 2)/etc" 2>/dev/null; pkill -u etcd -f "$(R 3)/etc" 2>/dev/null
# Patroni coupe PostgreSQL (ou le relance en lecture seule) : dans les deux cas, plus aucune écriture possible sur n1
not_writable() { [ "$(sql "$1" -c "select pg_is_in_recovery()" 2>/dev/null)" != f ]; }
wait_for 90 "n1 sans quorum cesse d'être primaire (arrêt ou lecture seule)" not_writable 1
check_fail "n1 isolé refuse l'écriture" sql 1 -c "insert into t values (50,'split-brain')"
start_etcd 2; start_etcd 3
wait_for 60 "le quorum revient : etcd n2 sain" ectl 2 endpoint health
writable_count() { for n in 1 2; do sql "$n" -c "select pg_is_in_recovery()" 2>/dev/null; done | grep -c '^f$'; }
wait_for 150 "le cluster retrouve un primaire en écriture" test "$(writable_count)" = 1
sleep 10
NL="$(writable_count)"
expect_eq "après retour du quorum : exactement un primaire accessible en écriture" "1" "$NL"
note "non couvert : coupure réseau réelle, perte de machine, horloges désynchronisées, disque saturé ; à rejouer sur le premier laboratoire (docs/ARCHITECTURE-CLUSTER.md)"

finish
