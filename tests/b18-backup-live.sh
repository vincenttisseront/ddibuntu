#!/usr/bin/env bash
# Batterie 18 — sauvegarde et restauration à un instant donné (PITR) avec un VRAI PostgreSQL 16 :
# archivage des journaux (archive_command), sauvegarde complète (pg_basebackup), restauration à une heure précise, à la dernière
# sauvegarde et à une sauvegarde donnée, restaurations successives (branches de timelines), détection de corruption,
# échec de restauration avec retour à la base précédente, rétention, copie externe, planification et demandes JSON hostiles.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

BK="$RFS/usr/local/sbin/ddibuntu-backup"
WAL="$RFS/usr/local/lib/ddibuntu/wal-archive.sh"
PGBIN=/usr/lib/postgresql/16/bin
missing=""
[ "$(id -u)" -eq 0 ] || missing="$missing root"
for t in runuser python3 gzip sha256sum flock; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
getent passwd postgres >/dev/null || missing="$missing compte-postgres"
[ -x "$PGBIN/initdb" ] && [ -x "$PGBIN/pg_basebackup" ] || missing="$missing postgresql-16"
if [ -n "$missing" ]; then note "batterie sauvegarde réelle non exécutable ici (manque :$missing)"; finish; exit; fi

B="$(mktemp -d /srv/ddilive.XXXXXX)"; chmod 755 "$B"
cleanup() {
  runuser -u postgres -- "$PGBIN/pg_ctl" -D "$B/var/lib/postgresql/16/main" -m immediate stop >/dev/null 2>&1
  pkill -9 -u postgres -f "$B/" 2>/dev/null; sleep 1; if [ -n "${KEEP:-}" ]; then echo "conservé : $B"; else rm -rf "$B"; fi; rm -rf "$T_TMP"
}
trap cleanup EXIT

DATA="$B/var/lib/postgresql/16/main"
REPO="$B/var/lib/ddibuntu/backup"
CONF="$B/etc/ddibuntu/backup.conf"
GEN="$B/var/lib/ddibuntu/generated"
RUN="$B/run/ddibuntu"
SOCK="$B/run/pg"
PORT=55432

mkdir -p "$B/etc/ddibuntu" "$SOCK" "$B/var/lib/postgresql/16" "$GEN" "$B/etc/postgresql/16/main/conf.d" "$B/lib" "$B/mirror" "$B/run/ddibuntu"
cp "$RFS/etc/ddibuntu/backup.conf" "$CONF"
install -m 755 "$WAL" "$B/lib/wal-archive.sh"
chown -R postgres:postgres "$SOCK" "$B/var/lib/postgresql"; chmod 755 "$B" "$B/etc" "$B/etc/postgresql" "$B/etc/postgresql/16" "$B/etc/postgresql/16/main" "$B/etc/postgresql/16/main/conf.d" \
  "$B/lib" "$B/etc/ddibuntu" "$B/var" "$B/var/lib" "$B/run"

cat > "$B/pgctl.sh" <<EOF
#!/bin/sh
P="runuser -u postgres -- $PGBIN/pg_ctl -D $DATA"
case "\$1" in
  start) \$P -l $SOCK/pg.log -w -t 60 start >/dev/null 2>&1 ;;
  stop) \$P -m fast -w stop >/dev/null 2>&1 ;;
  restart) \$P -m fast -l $SOCK/pg.log -w -t 60 restart >/dev/null 2>&1 ;;
esac
EOF
chmod 755 "$B/pgctl.sh"

bk() { env DDI_ROOT="$B" DDI_TEST=1 DDI_PG_PORT=$PORT DDI_PG_SOCKET_DIR="$SOCK" DDI_PG_CMD="$B/pgctl.sh" DDI_LIBDIR="$B/lib" DDI_RESTORE_WAIT=90 DDI_PG_LOG="$SOCK/pg.log" bash "$BK" "$@"; }
sql() { runuser -u postgres -- "$PGBIN/psql" -h "$SOCK" -p $PORT -d postgres -Atq -X -v ON_ERROR_STOP=1 -c "$1"; }
sqlq() { sql "$1" 2>/dev/null; }
js() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
st() { bk status 2>/dev/null | js "$1"; }
nbk() { st 'len(d["backups"])'; }
wait_for() { local s="$1" d="$2"; shift 2; local i=0; while [ "$i" -lt "$s" ]; do if "$@" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }
# flush_wal : ferme le segment courant et attend son archivage
LAST_SEG=""
flush_wal() { local f i; f="$(sqlq "select pg_walfile_name(pg_switch_wal())")"; LAST_SEG="$f"; for i in $(seq 40); do [ -f "$REPO/wal/$f.gz" ] && return 0; sleep 0.5; done; return 1; }
count() { sqlq "select count(*) from t"; }

echo "== Base PostgreSQL 16 réelle (hors cluster), archivage non encore activé =="
runuser -u postgres -- "$PGBIN/initdb" -D "$DATA" -E UTF8 --data-checksums >/dev/null 2>&1 && ok "initdb" || ko "initdb"
cat >> "$DATA/postgresql.conf" <<EOF
port = $PORT
listen_addresses = ''
unix_socket_directories = '$SOCK'
include_dir = '$B/etc/postgresql/16/main/conf.d'
max_wal_senders = 5
EOF
check "PostgreSQL démarre" "$B/pgctl.sh" start
wait_for 20 "PostgreSQL répond" sql "select 1"
expect_eq "archive_mode désactivé au départ" "off" "$(sqlq 'show archive_mode')"

expect_eq "état : sauvegardes désactivées" "False" "$(st 'd["enabled"]')"
expect_eq "état : primaire" "primary" "$(st 'd["role"]')"
expect_eq "état : aucune sauvegarde" "0" "$(nbk)"
check "état publié dans /run/ddibuntu" test -s "$RUN/backup-status.json"
check_fail "sauvegarde refusée tant que c'est désactivé" bk run
check_fail "restauration refusée sans --yes" bk restore --latest

echo "== Script d'archivage (archive_command) =="
f="$T_TMP/wal-src"; head -c 4096 /dev/urandom > "$f"; chmod 644 "$f"
good=000000010000000000000007
sa() { runuser -u postgres -- env DDI_ROOT="$B" DDI_BACKUP_CONF="$CONF" bash "$B/lib/wal-archive.sh" "$@"; }
cp "$f" "$B/wal-src"; chmod 644 "$B/wal-src"
check "désactivé : le journal est écarté sans erreur" sa "$B/wal-src" $good
check_fail "désactivé : rien n'est écrit" test -e "$REPO/wal/$good.gz"

echo "== Activation (redémarrage de PostgreSQL pour archive_mode) et première sauvegarde =="
# l'activation bascule ENABLED=1 puis crée le dépôt
out="$(bk enable 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "enable réussi" || ko "enable réussi" "$(printf '%s' "$out" | tail -n 5 | tr '\n' ' ')"
expect_grep "configuration enregistrée" '^ENABLED=1$' "$CONF"
expect_eq "archive_mode actif après redémarrage" "on" "$(sqlq 'show archive_mode')"
check "réglage conf.d écrit" test -s "$B/etc/postgresql/16/main/conf.d/ddibuntu-archive.conf"
expect_eq "une sauvegarde complète existe" "1" "$(nbk)"
B1="$(st 'd["backups"][0]["id"]')"
check "métadonnées : timeline 1" test "$(st 'd["backups"][0]["timeline"]')" = 1
expect_eq "journal de fin de sauvegarde archivé" "True" "$(st 'd["backups"][0]["walArchived"]')"
check "dépôt propriété de postgres" test "$(stat -c %U "$REPO")" = postgres
check "fichiers de la sauvegarde" bash -c "cd '$REPO/base/$B1' && test -s base.tar.gz && test -s pg_wal.tar.gz && test -s backup_manifest && test -s SHA256SUMS"
check "verify : sauvegarde intègre" bk verify
sa "$B/wal-src" $good && ok "activé : journal archivé" || ko "activé : journal archivé"
check "journal compressé et lisible" gzip -t "$REPO/wal/$good.gz"
check "archivage idempotent (même contenu)" sa "$B/wal-src" $good
head -c 4096 /dev/urandom > "$B/wal-other"; chmod 644 "$B/wal-other"
check_fail "écrasement par un contenu différent refusé" sa "$B/wal-other" $good
check_fail "nom de journal hostile refusé" sa "$B/wal-src" '../../etc/passwd'
check_fail "nom de journal inconnu refusé" sa "$B/wal-src" 'pg_hba.conf'
check_fail "chemin source inexistant refusé" sa "$B/absent" 000000010000000000000008
rm -f "$REPO/wal/$good.gz" "$B/wal-src" "$B/wal-other"

echo "== Jeu de données horodaté : A (100 lignes), B (+100), sauvegarde 2, C (+100) =="
sql "create table t(id serial primary key, lot text, at timestamptz default clock_timestamp())" >/dev/null && ok "table créée"
sql "insert into t(lot) select 'A' from generate_series(1,100)" >/dev/null
sleep 1; T_A="$(sqlq "select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD HH24:MI:SS')")"; sleep 2
sql "insert into t(lot) select 'B' from generate_series(1,100)" >/dev/null
sleep 1; T_B="$(sqlq "select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD HH24:MI:SS')")"; sleep 2
B2="$(bk run 2>/dev/null | tail -n1)"
[[ "$B2" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] && ok "sauvegarde complète 2 ($B2)" || ko "sauvegarde complète 2" "sortie : $B2"
sleep 1
sql "insert into t(lot) select 'C' from generate_series(1,100)" >/dev/null
sleep 1; T_C="$(sqlq "select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD HH24:MI:SS')")"; sleep 2
sql "create table z_marker(i int)" >/dev/null   # une transaction postérieure à T_C : PostgreSQL exige un enregistrement au-delà de la cible
check "journaux vidés vers l'archive" flush_wal
expect_eq "avant restauration : 300 lignes" "300" "$(count)"
expect_eq "deux sauvegardes au catalogue" "2" "$(nbk)"
expect_eq "archiveur : aucun échec" "0" "$(st 'd["archiver"]["failed_count"]')"
check "archiveur : des journaux envoyés" test "$(st 'd["archiver"]["archived_count"]')" -ge 3
check "fenêtre de restauration annoncée (pitrFrom)" test "$(st 'd["pitrFrom"]')" != None

echo "== Validation des paramètres =="
for kv in KEEP_FULL=0 KEEP_FULL=99 KEEP_FULL=abc INTERVAL_HOURS=0 INTERVAL_HOURS=500 START_HOUR=24 'MIRROR_DIR=../etc' 'MIRROR_DIR=relatif' 'MIRROR_DIR=/a b' 'FOO=1' 'ENABLED=0'; do
  check_fail "paramètre refusé : $kv" bk configure "$kv"
done
expect_grep "configuration inchangée après refus" '^KEEP_FULL=3$' "$CONF"
printf 'ENABLED=1\nDIR=/var/lib/ddibuntu/backup\nKEEP_FULL=3\nINTERVAL_HOURS=24\nSTART_HOUR=2\nMIRROR_DIR=\n$(touch /tmp/pwn)\n' > "$T_TMP/evil.conf"
cp "$CONF" "$T_TMP/good.conf"; cp "$T_TMP/evil.conf" "$CONF"
check_fail "fichier de configuration piégé refusé" bk status
check_fail "(le piège n'a pas été exécuté)" test -e /tmp/pwn
cp "$T_TMP/good.conf" "$CONF"
check "configuration saine relue" bk status

echo "== Corruption : détectée, restauration refusée, suppression possible =="
sleep 1; B3="$(bk run 2>/dev/null | tail -n1)"
check "sauvegarde 3 ($B3)" test -d "$REPO/base/$B3"
cp "$REPO/base/$B3/base.tar.gz" "$T_TMP/b3.good"
printf 'X' | dd of="$REPO/base/$B3/base.tar.gz" bs=1 seek=200 conv=notrunc status=none
check_fail "verify : corruption détectée (tout)" bk verify
check_fail "verify : corruption détectée (cet identifiant)" bk verify "$B3"
check "verify d'une autre sauvegarde intègre" bk verify "$B1"
check_fail "restauration d'une sauvegarde corrompue refusée" bk restore --id "$B3" --yes
expect_eq "la base n'a pas été touchée par le refus" "300" "$(count)"
check_fail "suppression : identifiant hostile refusé" bk delete '../base'
check "suppression de la sauvegarde corrompue" bk delete "$B3"
check_fail "(elle a disparu)" test -d "$REPO/base/$B3"
check "verify de nouveau propre" bk verify

echo "== Restauration à une heure précise (T_A → seules les lignes A) =="
out="$(bk restore --at "$T_A+00" --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "restauration à $T_A réussie" || ko "restauration à $T_A" "$(printf '%s' "$out" | tail -n 4 | tr '\n' ' ')"
expect_eq "après restauration à T_A : 100 lignes" "100" "$(count)"
expect_eq "lot A uniquement" "A" "$(sqlq 'select string_agg(distinct lot, $$,$$) from t')"
check "ancienne base conservée à côté" bash -c "compgen -G '$DATA.pre-restore.*' >/dev/null"
expect_eq "nouvelle timeline (2)" "2" "$(sqlq 'select timeline_id from pg_control_checkpoint()')"
expect_eq "réglages de récupération retirés" "" "$(sqlq 'show restore_command')"
expect_eq "PostgreSQL de nouveau en lecture-écriture" "f" "$(sqlq 'select pg_is_in_recovery()')"
expect_eq "sauvegarde de référence prise après la restauration" "3" "$(nbk)"
expect_eq "(sur la nouvelle timeline)" "2" "$(st 'd["backups"][-1]["timeline"]')"
sql "insert into t(lot) select 'D' from generate_series(1,50)" >/dev/null
check "journaux archivés sur la timeline 2" flush_wal
check "état de restauration publié" bash -c "grep -q '\"phase\": *\"done\"' '$RUN/backup-restore.json' || grep -q 'done' '$RUN/backup-restore.json'"

echo "== Retour vers T_B, puis vers T_C (branches successives) =="
out="$(bk restore --at "$T_B+00" --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "restauration à $T_B réussie" || ko "restauration à $T_B" "$(printf '%s' "$out" | tail -n 4 | tr '\n' ' ')"
expect_eq "après restauration à T_B : 200 lignes (A+B)" "200" "$(count)"
expect_eq "timeline 3" "3" "$(sqlq 'select timeline_id from pg_control_checkpoint()')"
sql "insert into t(lot) select 'E' from generate_series(1,25)" >/dev/null
check "journaux archivés sur la timeline 3" flush_wal
out="$(bk restore --at "$T_C+00" --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "restauration à $T_C réussie" || ko "restauration à $T_C" "$(printf '%s' "$out" | tail -n 4 | tr '\n' ' ')"
expect_eq "après restauration à T_C : 300 lignes (A+B+C)" "300" "$(count)"
expect_eq "lots A, B, C" "A,B,C" "$(sqlq 'select string_agg(distinct lot, $$,$$ order by lot) from t')"

echo "== Dernière sauvegarde + rejeu complet (--latest) et sauvegarde choisie (--id) =="
sql "insert into t(lot) select 'F' from generate_series(1,40)" >/dev/null
check "journaux archivés avant --latest" flush_wal
out="$(bk restore --latest --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "restauration --latest réussie" || ko "restauration --latest" "$(printf '%s' "$out" | tail -n 4 | tr '\n' ' ')"
expect_eq "--latest rejoue tous les journaux : 340 lignes" "340" "$(count)"
out="$(bk restore --id "$B1" --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "restauration à la sauvegarde 1 réussie" || ko "restauration à la sauvegarde 1" "$(printf '%s' "$out" | tail -n 4 | tr '\n' ' ')"
expect_eq "sauvegarde 1 : la table n'existe pas encore" "" "$(sqlq "select to_regclass('public.t')")"
out="$(bk restore --at "$T_C+00" --yes 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "retour à T_C après plusieurs restaurations" || ko "retour à T_C" "$(printf '%s' "$out" | tail -n 4 | tr '\n' ' ')"
expect_eq "300 lignes retrouvées" "300" "$(count)"

echo "== Demandes impossibles =="
check_fail "avant la première sauvegarde" bk restore --at '2000-01-01 00:00:00+00' --yes
check_fail "dans le futur" bk restore --at '2999-01-01 00:00:00+00' --yes
check_fail "date sans fuseau" bk restore --at '2026-01-01 00:00:00' --yes
check_fail "date piégée" bk restore --at "2026-01-01 00:00:00+00'; drop table t; --" --yes
check_fail "identifiant piégé" bk restore --id '../../x' --yes
check_fail "option inconnue" bk restore --force --yes
expect_eq "toujours 300 lignes" "300" "$(count)"

echo "== Échec de restauration : retour automatique à la base précédente =="
# journal manquant entre la sauvegarde et l'heure visée : la récupération ne peut pas atteindre la cible
sql "insert into t(lot) select 'G' from generate_series(1,10)" >/dev/null; flush_wal; SEG_G="$LAST_SEG"
sleep 1; T_G="$(sqlq "select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD HH24:MI:SS')")"; sleep 1
sql "insert into t(lot) select 'H' from generate_series(1,10)" >/dev/null; flush_wal
mkdir -p "$T_TMP/walsave"; cp -a "$REPO/wal/." "$T_TMP/walsave/"
rm -f "$REPO/wal/$SEG_G.gz"   # le journal de G manque : la récupération s'arrête avant la cible
before="$(count)"; npre="$(find "$B/var/lib/postgresql/16" -maxdepth 1 -name 'main.pre-restore.*' | wc -l)"
out="$(bk restore --at "$T_G+00" --yes 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && ok "restauration impossible refusée (journal $SEG_G manquant)" || ko "restauration impossible aurait dû échouer" "$(printf '%s' "$out" | tail -n 3 | tr '\n' ' ')"
case "$out" in *"--latest"*) ok "message d'échec : indice pour revenir au plus récent" ;; *) ko "message d'échec : indice" "$(printf '%s' "$out" | tail -n 2 | tr '\n' ' ')" ;; esac
wait_for 60 "la base précédente est de nouveau en service" sql "select 1"
expect_eq "données intactes après l'échec" "$before" "$(count)"
expect_eq "aucune base orpheline laissée par l'échec" "$npre" "$(find "$B/var/lib/postgresql/16" -maxdepth 1 -name 'main.pre-restore.*' | wc -l)"
check "état d'échec publié" bash -c "grep -q 'failed' '$RUN/backup-restore.json'"
cp -a "$T_TMP/walsave/." "$REPO/wal/"

echo "== Rétention =="
sleep 1; bk run >/dev/null 2>&1; sleep 1; bk run >/dev/null 2>&1
n0="$(nbk)"; check "plus de 2 sauvegardes avant rétention" test "$n0" -gt 2
check "rétention à 2 sauvegardes" bk configure KEEP_FULL=2 INTERVAL_HOURS=24 START_HOUR=0 MIRROR_DIR=
check "prune" bk prune
expect_eq "il ne reste que 2 sauvegardes" "2" "$(nbk)"
check "journaux antérieurs supprimés mais ceux utiles conservés" bk verify
FIRST="$(st 'd["backups"][0]["startSegment"]')"
oldest="$(find "$REPO/wal" -maxdepth 1 -regextype posix-extended -regex '.*/[0-9A-F]{24}.*' -printf '%f\n' | sort | head -n1)"
check "aucun journal avant la plus ancienne sauvegarde conservée" bash -c "[ '${oldest:0:24}' = '$FIRST' ] || [ '${oldest:0:24}' \> '$FIRST' ]"
first_id() { find "$REPO/base" -mindepth 1 -maxdepth 1 -name '2*' -printf '%f\n' | sort | head -n1; }
check "suppression de la plus ancienne (il en reste une)" bk delete "$(first_id)"
expect_eq "une seule sauvegarde" "1" "$(nbk)"
check_fail "la dernière sauvegarde ne peut pas être supprimée" bk delete "$(first_id)"
expect_eq "(elle est restée)" "1" "$(nbk)"
sleep 1; bk run >/dev/null 2>&1; bk run >/dev/null 2>&1; bk prune >/dev/null 2>&1

echo "== Planification (minuteur) =="
n1="$(nbk)"
bk auto >/dev/null 2>&1
expect_eq "auto : rien à faire juste après une sauvegarde" "$n1" "$(nbk)"
DDI_NOW=$(( $(date +%s) + 90000 )) bk auto >/dev/null 2>&1
check "auto : sauvegarde déclenchée après l'intervalle (25 h simulées)" test "$(nbk)" -ge "$n1"
check "auto : état publié" test -s "$RUN/backup-status.json"

echo "== Copie externe =="
bk configure KEEP_FULL=2 INTERVAL_HOURS=24 START_HOUR=0 MIRROR_DIR=/mirror >/dev/null 2>&1
bk auto >/dev/null 2>&1
check "copie externe : sauvegardes" bash -c "compgen -G '$B/mirror/base/*' >/dev/null"
check "copie externe : journaux" bash -c "compgen -G '$B/mirror/wal/*' >/dev/null"
check "copie externe : horodatage" test -s "$B/mirror/.ddibuntu-last-sync"
bk configure KEEP_FULL=2 INTERVAL_HOURS=24 START_HOUR=0 MIRROR_DIR= >/dev/null 2>&1

echo "== Demandes JSON de la console (revalidées par root) =="
req() { printf '%s' "$1" > "$GEN/.backup-request"; chmod 640 "$GEN/.backup-request"; bk request >/dev/null 2>&1; }
res() { js "$1" < "$RUN/backup-result.json"; }
HOST="$(hostname -s)"; CNT_BEFORE_REQ="$(count)"
req '{"action":"refresh"}';                               expect_eq "refresh accepté" "True" "$(res 'd["ok"]')"
check_fail "(demande consommée)" test -e "$GEN/.backup-request"
req '{"action":"run"}';                                   expect_eq "run accepté" "True" "$(res 'd["ok"]')"
[[ "$(res 'd["id"]')" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] && ok "run : identifiant renvoyé" || ko "run : identifiant renvoyé"
check "run : une sauvegarde de plus (ou rétention)" test "$(nbk)" -ge 1
req '{"action":"verify"}';                                expect_eq "verify accepté" "True" "$(res 'd["ok"]')"
req '{"action":"configure","keepFull":3,"intervalHours":12,"startHour":1,"mirrorDir":""}'; expect_eq "configure accepté" "True" "$(res 'd["ok"]')"
expect_grep "configure : écrit" '^INTERVAL_HOURS=12$' "$CONF"
req '{"action":"prune"}';                                 expect_eq "prune accepté" "True" "$(res 'd["ok"]')"
for bad in 'pas du json' '[]' '{"action":"format-disk"}' '{"action":"run","x":1}' '{"action":"delete","id":"../../etc"}' '{"action":"delete","id":"20260101T000000Z","extra":1}' \
           '{"action":"verify","id":"$(id)"}' '{"action":"configure","keepFull":0,"intervalHours":12,"startHour":1,"mirrorDir":""}' \
           '{"action":"configure","keepFull":3,"intervalHours":12,"startHour":1,"mirrorDir":"../../etc"}' \
           '{"action":"configure","keepFull":3,"intervalHours":12,"startHour":1}' \
           '{"action":"restore","mode":"latest"}' '{"action":"restore","mode":"latest","confirm":"autre-nom"}' \
           '{"action":"restore","mode":"at","at":"2026-01-01 00:00:00","confirm":"'"$HOST"'"}' '{"action":"restore","mode":"id","id":"x","confirm":"'"$HOST"'"}' \
           '{"action":"restore","mode":"latest","id":"20260101T000000Z","confirm":"'"$HOST"'"}'; do
  req "$bad"; r="$(res 'd["ok"]')"; [ "$r" = False ] && ok "demande refusée : ${bad:0:60}" || ko "demande hostile acceptée : ${bad:0:60}"
done
printf '%0700d' 0 > "$GEN/.backup-request"; bk request >/dev/null 2>&1; expect_eq "demande trop longue refusée" "False" "$(res 'd["ok"]')"
rm -f "$GEN/.backup-request"; ln -s /etc/passwd "$GEN/.backup-request"; bk request >/dev/null 2>&1
expect_eq "lien symbolique refusé" "False" "$(res 'd["ok"]')"; check_fail "(lien supprimé)" test -e "$GEN/.backup-request"
expect_eq "aucune restauration déclenchée par les demandes hostiles" "$CNT_BEFORE_REQ" "$(count)"
req '{"action":"restore","mode":"latest","confirm":"'"$HOST"'"}'
expect_eq "restauration demandée avec la bonne confirmation" "True" "$(res 'd["ok"]')"
wait_for 30 "base en service après la restauration par la console" sql "select 1"
CNT_K="$(count)"; sleep 1
T_K="$(sqlq "select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD HH24:MI:SS')")"; sleep 2
sql "insert into t(lot) select 'L' from generate_series(1,3)" >/dev/null; sql "create table if not exists z_marker2(i int)" >/dev/null; flush_wal
req '{"action":"restore","mode":"at","at":"'"${T_K/ /T}"'Z","confirm":"'"$HOST"'"}'
expect_eq "restauration à l'heure demandée par la console" "True" "$(res 'd["ok"]')"
expect_eq "les 3 lignes postérieures à l'heure visée ont disparu" "$CNT_K" "$(count)"

echo "== Désactivation =="
check "disable" bk disable
expect_eq "état : désactivé" "False" "$(st 'd["enabled"]')"
expect_eq "les sauvegardes existantes sont conservées" "True" "$([ "$(nbk)" -ge 1 ] && echo True || echo False)"
good2=000000010000000000000009; cp "$f" "$B/wal-src2"; chmod 644 "$B/wal-src2"
check "journaux écartés une fois désactivé" sa "$B/wal-src2" $good2
check_fail "(et non archivés)" test -e "$REPO/wal/$good2.gz"
check_fail "run refusé" bk run

echo "== Nœud arbitre (witness) : aucune base à sauvegarder =="
W="$B/w"; mkdir -p "$W/etc/ddibuntu" "$W/etc/ddibuntu-cluster" "$W/run"
cp "$RFS/etc/ddibuntu/backup.conf" "$W/etc/ddibuntu/backup.conf"
printf 'CLUSTER_NAME=ddi\nNODE_NAME=arbitre\nNODE_ROLE=witness\n' > "$W/etc/ddibuntu-cluster/cluster.conf"
wk() { env DDI_ROOT="$W" DDI_TEST=1 bash "$BK" "$@"; }
check_fail "enable refusé sur l'arbitre" wk enable
expect_eq "état : arbitre" "witness" "$(wk status 2>/dev/null | js 'd["role"]')"

finish
