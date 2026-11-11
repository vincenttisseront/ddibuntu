#!/usr/bin/env bash
# Batterie 19 — sauvegarde / restauration (PITR) DANS UN CLUSTER RÉEL : 2 nœuds de données (vrais Patroni/PostgreSQL) + 1 arbitre, vrais etcd.
# Vérifie : réglages partagés par etcd, archivage sur le primaire, secondaires qui ne sauvegardent pas, restauration à une heure précise
# sur le primaire avec Patroni mis en pause (le primaire reste primaire), recréation du secondaire, reprise de la réplication,
# archivage rétabli sur un secondaire (mise à jour), nouvelle sauvegarde de référence après une bascule.
# Exige root, etcd, patroni (python3.12 + psycopg2) et PostgreSQL 16. Sinon : NOTE, sans échec.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

CL="$RFS/usr/local/sbin/ddibuntu-cluster"
BK="$RFS/usr/local/sbin/ddibuntu-backup"
WAL="$RFS/usr/local/lib/ddibuntu/wal-archive.sh"
PGBIN=/usr/lib/postgresql/16/bin
PY=python3.12
missing=""
[ "$(id -u)" -eq 0 ] || missing="$missing root"
for t in etcd etcdctl patroni patronictl openssl gpg curl runuser; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
[ -x "$PGBIN/initdb" ] || missing="$missing postgresql-16"
$PY -c 'import psycopg2, patroni' >/dev/null 2>&1 || missing="$missing python3.12+psycopg2+patroni"
getent passwd postgres >/dev/null && getent passwd etcd >/dev/null || missing="$missing comptes-postgres/etcd"
if [ -n "$missing" ]; then note "batterie sauvegarde en cluster réel non exécutable ici (manque :$missing)"; finish; exit; fi

B="$(mktemp -d /srv/ddilive.XXXXXX)"; chmod 755 "$B"
cleanup() {
  pkill -f "patroni $B/" 2>/dev/null; pkill -u etcd -f "$B/" 2>/dev/null; sleep 1
  for n in 1 2 3; do pkill -9 -u postgres -f "$B/n$n/" 2>/dev/null; done
  for _ in $(seq 1 40); do pgrep -u etcd -f "$B/" >/dev/null 2>&1 || break; sleep 0.5; done   # l'arrêt d'etcd n'est pas instantané : la batterie suivante réutilise ses ports
  pkill -9 -u etcd -f "$B/" 2>/dev/null
  sleep 1; if [ -n "${KEEP:-}" ]; then echo "conservé : $B"; else rm -rf "$B"; fi; rm -rf "$T_TMP"
}
trap cleanup EXIT
mkdir -p "$B/lib"; install -m 755 "$WAL" "$B/lib/wal-archive.sh"; chmod 755 "$B"

ip() { echo "127.0.1.$1"; }
R() { echo "$B/n$1"; }
cl() { local n="$1"; shift; DDI_ROOT="$(R "$n")" DDI_TEST=1 DDI_PY=$PY DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN='' DDI_PG_CONFIG_DIR='' DDI_LIBDIR="$B/lib" "$CL" "$@"; }
clp() { local pw="$1"; shift; DDI_BUNDLE_PASS="$pw" cl "$@"; }
mknode() {
  local r; r="$(R "$1")"; mkdir -p "$r/usr/lib" "$r/run/pg" "$r/var/lib/postgresql/16" "$r/var/lib/etcd" "$r/etc/ddibuntu" "$r/var/lib/ddibuntu/generated" "$r/etc/bind"
  ln -s /usr/lib/postgresql "$r/usr/lib/postgresql"
  chown -R postgres:postgres "$r/run/pg" "$r/var/lib/postgresql"; chmod 755 "$r" "$r/run" "$r/var" "$r/var/lib" "$r/etc"
  cp "$RFS/etc/ddibuntu/backup.conf" "$r/etc/ddibuntu/backup.conf"
  printf '#!/bin/sh\nexec env DDI_ROOT=%s DDI_TEST=1 DDI_PY=%s DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN= DDI_PG_CONFIG_DIR= DDI_LIBDIR=%s bash %s "$@"\n' "$r" "$PY" "$B/lib" "$CL" > "$B/clw$1.sh"; chmod 755 "$B/clw$1.sh"
}
initdb_local() { runuser -u postgres -- "$PGBIN/initdb" -D "$(R "$1")/var/lib/postgresql/16/main" -E UTF8 --data-checksums >/dev/null 2>&1; }
start_etcd() { local r; r="$(R "$1")"; ( cd / && runuser -u etcd -- /usr/bin/etcd --config-file "$r/etc/ddibuntu-cluster/etcd.yml" >"$B/etcd$1.log" 2>&1 & ); }
start_patroni() { local r; r="$(R "$1")"; ( cd / && runuser -u postgres -- $PY /usr/bin/patroni "$r/etc/patroni/config.yml" >"$B/patroni$1.log" 2>&1 9>&- & ); }
api() { local r; r="$(R "$1")"; local p="$r/etc/ddibuntu-cluster/pki"; curl -s --max-time 5 --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "https://$(ip "$1"):8008/$2"; }
sql() { local n="$1"; shift; runuser -u postgres -- psql -h "$(R "$n")/run/pg" -d postgres -v ON_ERROR_STOP=1 -Atq "$@"; }
sqlq() { sql "$@" 2>/dev/null; }
ectl() { local n="$1"; shift; local p; p="$(R "$n")/etc/ddibuntu-cluster/pki"; ETCDCTL_API=3 etcdctl --endpoints "https://$(ip "$n"):2379" --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "$@"; }
role_of() { api "$1" cluster | python3 -c 'import json,sys
n=sys.argv[1]
try: d=json.load(sys.stdin)
except Exception: print("?"); sys.exit()
m=[x for x in d.get("members",[]) if x["name"]==n]
print((m[0]["role"]+"/"+m[0].get("state","?")) if m else "absent")' "n$2" 2>/dev/null; }
wait_cond() { local s="$1" d="$2" e="$3" i=0; while [ "$i" -lt "$s" ]; do if eval "$e" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }
wait_for() { local s="$1" d="$2"; shift 2; local i=0; while [ "$i" -lt "$s" ]; do if "$@" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }
is_leader() { [ "$(role_of "$1" "$2")" = "leader/running" ]; }
streaming() { [ "$(role_of "$1" "$2")" = "replica/streaming" ]; }
leader_name() { api "$1" cluster | python3 -c 'import json,sys
d=json.load(sys.stdin)
print(next((m["name"] for m in d["members"] if m["role"]=="leader"),""))' 2>/dev/null; }
paused() { api "$1" config | python3 -c 'import json,sys; print(json.load(sys.stdin).get("pause", False))' 2>/dev/null; }
bkn() { local n="$1"; shift; env DDI_ROOT="$(R "$n")" DDI_TEST=1 DDI_PY=$PY DDI_LIBDIR="$B/lib" DDI_RESTORE_WAIT=150 DDI_CLUSTER_CMD="$B/clw$n.sh" bash "$BK" "$@"; }
bst() { local n="$1"; shift; bkn "$n" status 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
REPO1="$(R 1)/var/lib/ddibuntu/backup"
flush_wal() { local f i; f="$(sqlq 1 -c "select pg_walfile_name(pg_switch_wal())")"; for i in $(seq 40); do [ -f "$REPO1/wal/$f.gz" ] && return 0; sleep 0.5; done; return 1; }
stamp() { sqlq 1 -c "select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD HH24:MI:SS')"; }

echo "== Cluster : n1 (données, primaire) + n2 (données) + n3 (arbitre) =="
mknode 1; initdb_local 1
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -o "-c listen_addresses='' -c unix_socket_directories=$(R 1)/run/pg -c port=5432" -l "$(R 1)/run/pg/init.log" -w start >/dev/null 2>&1
sql 1 -c "create table t(id serial primary key, lot text)" >/dev/null
check "init n1" cl 1 init --name n1 --ip "$(ip 1)" --net 127.0.0.0/8 --no-activate
expect_grep "Patroni : archive_mode actif dès l'installation" "archive_mode: \"on\"" "$(R 1)/etc/patroni/config.yml"
expect_grep "Patroni : archive_command = script ddibuntu" "archive_command: '.*wal-archive.sh %p %f'" "$(R 1)/etc/patroni/config.yml"
expect_grep "pg_hba : sauvegarde locale par pg_basebackup (peer)" 'local replication postgres peer' "$(R 1)/etc/patroni/config.yml"
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -m fast -w stop >/dev/null 2>&1
start_etcd 1; wait_for 20 "etcd n1 sain" ectl 1 endpoint health
check "activate n1" cl 1 activate
start_patroni 1; wait_for 60 "n1 devient leader" is_leader 1 1
bundle() { cl 1 bundle --name "$1" --ip "$2" --role "$3" --out "$B/$1.bundle" 2>"$B/bundle-$1.err"; }
P2="$(bundle n2 "$(ip 2)" data)"; [ -n "$P2" ] && ok "lot n2" || ko "lot n2" "$(cat "$B/bundle-n2.err")"
mknode 2; initdb_local 2
check "join n2" clp "$P2" 2 join "$B/n2.bundle" --wipe-local-db --no-activate
start_etcd 2; wait_for 30 "etcd n2" ectl 2 endpoint status
check "activate n2" cl 2 activate
start_patroni 2; wait_for 120 "n2 réplique en continu" streaming 1 2
P3="$(bundle n3 "$(ip 3)" witness)"; [ -n "$P3" ] && ok "lot n3" || ko "lot n3" "$(cat "$B/bundle-n3.err")"
mknode 3; check "join n3" clp "$P3" 3 join "$B/n3.bundle" --no-activate
start_etcd 3; wait_for 30 "etcd n3" ectl 3 endpoint status
check "activate n3" cl 3 activate
for k in 1 2; do cl "$k" sync >/dev/null 2>&1; done

echo "== Activation sur le primaire : réglages partagés par etcd =="
expect_eq "n1 : archive_mode déjà actif (aucun redémarrage nécessaire)" "on" "$(sqlq 1 -c 'show archive_mode')"
out="$(bkn 1 enable 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "enable sur le primaire" || ko "enable sur le primaire" "$(printf '%s' "$out" | tail -n 4 | tr '\n' ' ')"
expect_eq "n1 : une sauvegarde complète" "1" "$(bst 1 'len(d["backups"])')"
expect_eq "n1 : primaire" "primary" "$(bst 1 'd["role"]')"
expect_eq "n1 : cluster détecté" "ddi" "$(bst 1 'd["cluster"]' | sed 's/.*/ddi/')"
check "réglages publiés dans etcd" bash -c "'$B/clw1.sh' backup-conf get | grep -q '^ENABLED=1$'"
check "n2 voit les réglages d'etcd" bash -c "'$B/clw2.sh' backup-conf get | grep -q '^ENABLED=1$'"
expect_eq "n2 : encore désactivé localement avant le minuteur" "False" "$(bst 2 'd["enabled"]')"
bkn 2 auto >/dev/null 2>&1
expect_eq "n2 : réglages repris d'etcd par le minuteur" "True" "$(bst 2 'd["enabled"]')"
expect_eq "n2 : secondaire" "standby" "$(bst 2 'd["role"]')"
expect_eq "n2 : ne sauvegarde pas (secondaire)" "0" "$(bst 2 'len(d["backups"])')"
check_fail "n2 : « run » refusé sur un secondaire" bkn 2 run
check_fail "n2 : restauration refusée sur un secondaire" bkn 2 restore --latest --yes
expect_eq "n3 (arbitre) : aucune base à sauvegarder" "witness" "$(bst 3 'd["role"]')"
check_fail "n3 : enable refusé" bkn 3 enable
bkn 1 configure KEEP_FULL=4 INTERVAL_HOURS=12 START_HOUR=3 MIRROR_DIR= >/dev/null 2>&1
bkn 2 auto >/dev/null 2>&1
expect_eq "un réglage changé sur n1 arrive sur n2" "12" "$(bst 2 'd["intervalHours"]')"
printf 'ENABLED=1\nDIR=/var/lib/ddibuntu/backup\nKEEP_FULL=3\n$(touch /tmp/pwn-b19)\n' | "$B/clw1.sh" backup-conf put >/dev/null 2>&1
bkn 2 auto >/dev/null 2>&1
check_fail "(réglages piégés d'etcd non appliqués ni exécutés)" test -e /tmp/pwn-b19
expect_eq "n2 : réglages sains conservés" "12" "$(bst 2 'd["intervalHours"]')"
bkn 1 configure KEEP_FULL=4 INTERVAL_HOURS=12 START_HOUR=3 MIRROR_DIR= >/dev/null 2>&1

echo "== Données horodatées et deuxième sauvegarde =="
sql 1 -c "insert into t(lot) select 'A' from generate_series(1,100)" >/dev/null
sleep 1; T_A="$(stamp)"; sleep 2
sql 1 -c "insert into t(lot) select 'B' from generate_series(1,100)" >/dev/null
sleep 1; T_B="$(stamp)"; : "$T_B"; sleep 2
B2="$(bkn 1 run 2>/dev/null | tail -n1)"
[[ "$B2" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] && ok "sauvegarde complète 2 ($B2)" || ko "sauvegarde complète 2" "$B2"
sleep 1
sql 1 -c "insert into t(lot) select 'C' from generate_series(1,100)" >/dev/null
sleep 1; T_C="$(stamp)"; sleep 2
sql 1 -c "create table z_marker(i int)" >/dev/null
check "journaux vidés vers l'archive" flush_wal
wait_cond 30 "n2 a reçu les 300 lignes" '[ "$(sqlq 2 -c "select count(*) from t")" = 300 ]'
expect_eq "archiveur de n1 : aucun échec" "0" "$(bst 1 'd["archiver"]["failed_count"]')"
check "verify (n1)" bkn 1 verify

echo "== Restauration sur le primaire à T_A (Patroni en pause pendant l'opération) =="
LEAD0="$(leader_name 1)"
out="$(bkn 1 restore --at "$T_A+00" --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "restauration du cluster à $T_A" || { ko "restauration du cluster à $T_A" "$(printf '%s' "$out" | tail -n 6 | tr '\n' ' ')"; tail -n 20 "$B/patroni1.log" | cut -c1-200; }
wait_for 90 "n1 est de nouveau leader en service" is_leader 1 1
expect_eq "le primaire n'a pas changé" "$LEAD0" "$(leader_name 1)"
expect_eq "n1 : 100 lignes (lot A)" "100" "$(sqlq 1 -c 'select count(*) from t')"
expect_eq "Patroni n'est plus en pause" "False" "$(paused 1)"
check "ancienne base conservée à côté" bash -c "compgen -G '$(R 1)/var/lib/postgresql/16/main.pre-restore.*' >/dev/null"
expect_eq "réglages de récupération retirés" "" "$(sqlq 1 -c 'show restore_command')"
expect_eq "n1 : une nouvelle timeline" "True" "$([ "$(sqlq 1 -c 'select timeline_id from pg_control_checkpoint()')" -ge 2 ] && echo True || echo False)"
wait_for 180 "n2 recréé par Patroni, de nouveau en réplication continue" streaming 1 2
wait_cond 30 "n2 : 100 lignes (la même base que le primaire)" '[ "$(sqlq 2 -c "select count(*) from t")" = 100 ]'
expect_eq "n2 n'a jamais pris la place du primaire" "0" "$(grep -c 'promoted self to leader' "$B/patroni2.log")"
sql 1 -c "insert into t(lot) select 'D' from generate_series(1,25)" >/dev/null
wait_cond 30 "une écriture après la restauration se réplique" '[ "$(sqlq 2 -c "select count(*) from t")" = 125 ]'
expect_eq "sauvegarde de référence prise après la restauration" "True" "$([ "$(bst 1 'len(d["backups"])')" -ge 3 ] && echo True || echo False)"
expect_eq "…sur la nouvelle timeline" "True" "$([ "$(bst 1 'd["backups"][-1]["timeline"]')" -ge 2 ] && echo True || echo False)"
check "journaux archivés sur la nouvelle timeline" flush_wal

echo "== Retour à T_C malgré la restauration précédente (branche de l'ancienne timeline) =="
out="$(bkn 1 restore --at "$T_C+00" --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "restauration du cluster à $T_C" || { ko "restauration du cluster à $T_C" "$(printf '%s' "$out" | tail -n 6 | tr '\n' ' ')"; }
wait_for 90 "n1 leader" is_leader 1 1
expect_eq "n1 : 300 lignes" "300" "$(sqlq 1 -c 'select count(*) from t')"
wait_for 180 "n2 de nouveau en réplication" streaming 1 2
wait_cond 30 "n2 : 300 lignes" '[ "$(sqlq 2 -c "select count(*) from t")" = 300 ]'

echo "== Échec de restauration dans le cluster : retour à la base précédente, Patroni reprend =="
sql 1 -c "insert into t(lot) select 'G' from generate_series(1,10)" >/dev/null; flush_wal
sleep 1; T_G="$(stamp)"; sleep 2
sql 1 -c "insert into t(lot) select 'H' from generate_series(1,10)" >/dev/null; flush_wal
LASTWAL="$(find "$REPO1/wal" -maxdepth 1 -regextype posix-extended -regex '.*/[0-9A-F]{24}\.gz' -printf '%f\n' | sort | tail -n 2 | head -n 1)"
mkdir -p "$B/walsave"; cp -a "$REPO1/wal/." "$B/walsave/"
rm -f "$REPO1/wal/$LASTWAL"
# shellcheck disable=SC2034  # lu par wait_cond (eval)
before="$(sqlq 1 -c 'select count(*) from t')"
out="$(bkn 1 restore --at "$T_G+00" --yes 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && ok "restauration impossible refusée (journal $LASTWAL manquant)" || ko "restauration impossible aurait dû échouer" "$(printf '%s' "$out" | tail -n 3 | tr '\n' ' ')"
wait_cond 120 "n1 de nouveau en service avec ses données intactes après l'échec" '[ "$(sqlq 1 -c "select count(*) from t")" = "$before" ]'
wait_for 90 "n1 leader" is_leader 1 1
expect_eq "Patroni n'est plus en pause" "False" "$(paused 1)"
wait_for 60 "n2 toujours en réplication" streaming 1 2
cp -a "$B/walsave/." "$REPO1/wal/"

echo "== Mise à jour : un secondaire sans archivage est remis en état par le minuteur =="
# état d'un appareil installé avant cette version : Patroni démarré sans paramètres d'archivage
sed -i '/archive_mode:/d;/archive_command:/d' "$(R 2)/etc/patroni/config.yml"
pkill -f "patroni $(R 2)/" 2>/dev/null; sleep 6; pkill -9 -u postgres -f "$(R 2)/var/lib/postgresql" 2>/dev/null; sleep 2
start_patroni 2
wait_cond 120 "n2 : de nouveau en réplication, sans archivage (appareil non mis à jour)" '[ "$(sqlq 2 -c "show archive_mode")" = off ] && [ "$(role_of 1 2)" = "replica/streaming" ]'
check "n2 : dépôt présent et propriété de postgres (créé par le minuteur dès l'activation)" bash -c "bkn() { :; }; env DDI_ROOT='$(R 2)' DDI_TEST=1 DDI_PY=$PY DDI_LIBDIR='$B/lib' DDI_CLUSTER_CMD='$B/clw2.sh' bash '$BK' auto >/dev/null 2>&1; [ \"\$(stat -c %U '$(R 2)/var/lib/ddibuntu/backup/wal')\" = postgres ]"
wait_cond 120 "n2 : archive_mode rétabli par le minuteur (régénération Patroni + redémarrage de ce nœud)" '[ "$(sqlq 2 -c "show archive_mode")" = on ]'
expect_grep "n2 : configuration Patroni re-générée" "archive_mode: \"on\"" "$(R 2)/etc/patroni/config.yml"
wait_for 120 "n2 toujours en réplication" streaming 1 2

echo "== Bascule : le nouveau primaire prend sa propre sauvegarde de référence =="
check "bascule contrôlée vers n2" cl 1 switchover --candidate n2
wait_for 90 "n2 devient leader" is_leader 2 2
bkn 2 auto >/dev/null 2>&1
expect_eq "n2 : une sauvegarde complète prise par le nouveau primaire" "1" "$(bst 2 'len(d["backups"])')"
expect_eq "n2 : primaire" "primary" "$(bst 2 'd["role"]')"
check "n2 : sauvegarde intègre" bkn 2 verify
expect_eq "n1 (ancien primaire) : ne sauvegarde plus" "standby" "$(bst 1 'd["role"]')"
n_before="$(bst 1 'len(d["backups"])')"; bkn 1 auto >/dev/null 2>&1
expect_eq "n1 : minuteur sans effet sur un secondaire" "$n_before" "$(bst 1 'len(d["backups"])')"

finish
