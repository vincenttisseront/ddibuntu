#!/usr/bin/env bash
# Batterie 22 — test de bascule guidé (« drill ») DANS UN CLUSTER RÉEL : 2 nœuds de données (vrais Patroni/PostgreSQL) + 1 arbitre, vrais etcd.
# Vérifie : pré-contrôles (refus motivés), bascule mesurée (fenêtre sans primaire, promotion, réintégration de l'ancien primaire, rattrapage),
# retour au primaire d'origine, rapport conservé dans etcd et publié pour la console, demandes de la console (frontière de privilèges),
# refus pendant qu'un test est en cours, nettoyage après échec.
# Exige root, etcd, patroni (python3.12 + psycopg2) et PostgreSQL 16. Sinon : NOTE, sans échec.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

CL="$RFS/usr/local/sbin/ddibuntu-cluster"
PGBIN=/usr/lib/postgresql/16/bin
PY=python3.12
missing=""
[ "$(id -u)" -eq 0 ] || missing="$missing root"
for t in etcd etcdctl patroni patronictl openssl gpg curl runuser; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
[ -x "$PGBIN/initdb" ] || missing="$missing postgresql-16"
$PY -c 'import psycopg2, patroni' >/dev/null 2>&1 || missing="$missing python3.12+psycopg2+patroni"
getent passwd postgres >/dev/null && getent passwd etcd >/dev/null || missing="$missing comptes-postgres/etcd"
if [ -n "$missing" ]; then note "batterie test de bascule en cluster réel non exécutable ici (manque :$missing)"; finish; exit; fi

B="$(mktemp -d /srv/ddilive.XXXXXX)"; chmod 755 "$B"
cleanup() {
  if [ -n "${HOLD:-}" ]; then echo "cluster conservé (HOLD) : $B"; return; fi
  pkill -f "cluster-drill.py" 2>/dev/null
  pkill -f "patroni $B/" 2>/dev/null; pkill -u etcd -f "$B/" 2>/dev/null; sleep 1
  for n in 1 2 3; do pkill -9 -u postgres -f "$B/n$n/" 2>/dev/null; done
  for _ in $(seq 1 40); do pgrep -u etcd -f "$B/" >/dev/null 2>&1 || break; sleep 0.5; done   # l'arrêt d'etcd n'est pas instantané : la batterie suivante réutilise ses ports
  pkill -9 -u etcd -f "$B/" 2>/dev/null
  sleep 1; if [ -n "${KEEP:-}" ]; then echo "conservé : $B"; else rm -rf "$B"; fi; rm -rf "$T_TMP"
}
trap cleanup EXIT

ip() { echo "127.0.1.$1"; }
R() { echo "$B/n$1"; }
cl() { local n="$1"; shift; DDI_ROOT="$(R "$n")" DDI_TEST=1 DDI_PY=$PY DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN='' DDI_PG_CONFIG_DIR='' DDI_GENERATED_DIR="$(R "$n")/var/lib/ddibuntu/generated" DDI_LIBDIR="${LIBDIR:-$RFS/usr/local/lib/ddibuntu}" "$CL" "$@"; }
wrap() { printf '#!/bin/bash\nexport DDI_ROOT=%s DDI_TEST=1 DDI_PY=%s DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN="" DDI_PG_CONFIG_DIR="" DDI_GENERATED_DIR=%s/var/lib/ddibuntu/generated DDI_LIBDIR=%s\nexec %s "$@"\n' "$(R "$1")" "$PY" "$(R "$1")" "$RFS/usr/local/lib/ddibuntu" "$CL" > "$B/cl$1.sh"; chmod +x "$B/cl$1.sh"; }
clp() { local pw="$1"; shift; DDI_BUNDLE_PASS="$pw" cl "$@"; }
mknode() {
  local r; r="$(R "$1")"; mkdir -p "$r/usr/lib" "$r/run/pg" "$r/var/lib/postgresql/16" "$r/var/lib/etcd" "$r/etc/ddibuntu" "$r/var/lib/ddibuntu/generated" "$r/etc/bind"
  ln -s /usr/lib/postgresql "$r/usr/lib/postgresql"
  chown -R postgres:postgres "$r/run/pg" "$r/var/lib/postgresql"; chmod 755 "$r" "$r/run" "$r/var" "$r/var/lib" "$r/etc"
}
initdb_local() { runuser -u postgres -- "$PGBIN/initdb" -D "$(R "$1")/var/lib/postgresql/16/main" -E UTF8 --data-checksums >/dev/null 2>&1; }
start_etcd() { local r; r="$(R "$1")"; ( cd / && runuser -u etcd -- /usr/bin/etcd --config-file "$r/etc/ddibuntu-cluster/etcd.yml" >"$B/etcd$1.log" 2>&1 & ); }
start_patroni() { local r; r="$(R "$1")"; ( cd / && runuser -u postgres -- $PY /usr/bin/patroni "$r/etc/patroni/config.yml" >"$B/patroni$1.log" 2>&1 9>&- 8>&- & ); }
api() { local r; r="$(R "$1")"; local p="$r/etc/ddibuntu-cluster/pki"; curl -s --max-time 5 --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "https://$(ip "$1"):8008/$2"; }
sql() { local n="$1"; shift; runuser -u postgres -- psql -h "$(R "$n")/run/pg" -d postgres -v ON_ERROR_STOP=1 -Atq "$@"; }
sqlq() { sql "$@" 2>/dev/null; }
ectl() { local n="$1"; shift; local p; p="$(R "$n")/etc/ddibuntu-cluster/pki"; ETCDCTL_API=3 etcdctl --endpoints "https://$(ip "$n"):2379" --command-timeout=5s --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "$@"; }
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
rep() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }   # rep EXPR < JSON

echo "== Cluster : n1 (données, primaire) + n2 (données) + n3 (arbitre) =="
mknode 1; initdb_local 1
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -o "-c listen_addresses='' -c unix_socket_directories=$(R 1)/run/pg -c port=5432" -l "$(R 1)/run/pg/init.log" -w start >/dev/null 2>&1
sql 1 -c "create table t(id serial primary key, lot text)" >/dev/null
check "init n1" cl 1 init --name n1 --ip "$(ip 1)" --net 127.0.0.0/8 --no-activate
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
expect_eq "primaire initial : n1" "n1" "$(leader_name 1)"

if [ -n "${HOLD:-}" ]; then echo "DEV: B=$B"; finish; exit; fi

wrap 1; wrap 2
CN="$(grep '^CLUSTER_NAME=' "$(R 1)/etc/ddibuntu-cluster/cluster.conf" | cut -d= -f2-)"
ET() { ectl 1 "$@"; }
DRL=/ddibuntu-cluster/drills/; ACTKEY=/ddibuntu-cluster/drill/active
nrep() { ET get --prefix "$DRL" --keys-only | grep -cE '/[0-9]{8}T[0-9]{6}Z$'; }
newer() { ET get --prefix "$DRL" --keys-only | grep -E '/[0-9]{8}T[0-9]{6}Z$' | sed 's#.*/##' | awk -v b="$1" '$0 > b' | wc -l; }   # rapports plus récents que BASE (insensible au plafond de 20)
lastid() { ET get --prefix "$DRL" --keys-only | grep -E '/[0-9]{8}T[0-9]{6}Z$' | sort | tail -1 | sed 's#.*/##'; }
report() { ET get "$DRL$1" --print-value-only; }
active_id() { ET get "$ACTKEY" --print-value-only 2>/dev/null | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("id", ""))
except Exception: print("")'; }
LIVE() { echo "$(R "$1")/run/ddibuntu/cluster-drill-live.json"; }
GEN() { echo "$(R "$1")/var/lib/ddibuntu/generated/.cluster-action"; }
drop() { printf '%s' "$2" > "$(GEN "$1")"; chmod 640 "$(GEN "$1")"; cl "$1" request >/dev/null 2>&1; }   # drop N JSON : dépose la demande puis laisse root la traiter
res() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$(R "$1")/run/ddibuntu/cluster-result.json" "$2"; }
PCTL() { runuser -u postgres -- $PY /usr/bin/patronictl -c "$(R 1)/etc/patroni/config.yml" "$@"; }
count_on() { sqlq "$1" -c 'select count(*) from t'; }
chk_status() { rep '" ".join(c["id"] + "=" + c["status"] for c in d["checks"] if c["id"] == sys.argv[0])'; }
stable() { local l o; l="$(leader_name 1)"; [ -n "$l" ] || return 1; if [ "$l" = n1 ]; then o=2; else o=1; fi; [ "$(role_of 1 "$o")" = "replica/streaming" ]; }
wait_stable() { wait_for 150 "$1" stable; }
back_to_n1() { if [ "$(leader_name 1)" != n1 ]; then cl 2 switchover --candidate n1 >/dev/null 2>&1; fi; wait_for 90 "n1 est de nouveau le primaire" is_leader 1 1; wait_stable "cluster stable"; }

echo "== 1. Pré-contrôles (lecture seule) =="
CK="$(cl 1 drill-check)"; RC=$?
expect_eq "cluster sain : code 0, primaire n1, candidat n2, prêt" "0 n1 n2 True" "$RC $(printf '%s' "$CK" | rep 'd["leader"] + " " + d["candidate"] + " " + str(d["ok"])')"
expect_eq "…aucun contrôle en écart (topologie, Patroni actif, candidat, retard, secondaires, quorum, autre test)" "" "$(printf '%s' "$CK" | rep '" ".join(c["id"] for c in d["checks"] if c["status"] == "fail")')"
expect_eq "…les contrôles attendus sont tous présents" "active candidate lag pause pending quorum replicas topology" "$(printf '%s' "$CK" | rep '" ".join(sorted(c["id"] for c in d["checks"] if c["id"] in ("topology","pause","candidate","lag","replicas","pending","quorum","active")))')"
CK="$(cl 1 drill-check --candidate n1)"; RC=$?
expect_eq "candidat = primaire actuel : refusé (code 1)" "1 False fail" "$RC $(printf '%s' "$CK" | rep 'str(d["ok"]) + " " + next(c["status"] for c in d["checks"] if c["id"] == "candidate")')"
CK="$(cl 1 drill-check --candidate n3)"; RC=$?
expect_eq "candidat = arbitre : refusé" "1 False" "$RC $(printf '%s' "$CK" | rep 'str(d["ok"])')"
OUT="$(cl 1 drill-check --candidate 'N 1' 2>&1)"; RC=$?
expect_eq "nom de candidat invalide : refusé net, rien exécuté" "1 yes" "$RC $(echo "$OUT" | grep -q 'candidate invalide' && echo yes || echo no)"
OUT="$(cl 3 drill-check 2>&1)"; RC=$?
expect_eq "sur l'arbitre : refusé (nœud de données requis)" "1 yes" "$RC $(echo "$OUT" | grep -q 'nœud de données' && echo yes || echo no)"
N0="$(nrep)"
OUT="$(cl 1 drill 2>&1)"; RC=$?
expect_eq "drill sans --yes : refusé, aucun rapport, aucune marque" "1 $N0 " "$RC $(nrep) $(active_id)"
OUT="$(cl 1 drill --yes --by pirate 2>&1)"; RC=$?
expect_eq "--by inconnu : refusé" "1 $N0" "$RC $(nrep)"
OUT="$(cl 1 drill --yes --bidon 2>&1)"; RC=$?
expect_eq "option inconnue : refusée" "1 $N0" "$RC $(nrep)"

echo "== 2. Pré-contrôles non satisfaits : refus motivé, rien n'est modifié =="
PCTL pause "$CN" --wait >/dev/null 2>&1
CK="$(cl 1 drill-check)"; RC=$?
expect_eq "Patroni en pause : contrôle « pause » en écart" "1 pause=fail" "$RC $(printf '%s' "$CK" | rep '" ".join(c["id"] + "=" + c["status"] for c in d["checks"] if c["id"] == "pause")')"
# l'historique est borné à 20 rapports : 22 anciens rapports (de faux, ignorés à la lecture) + une clé étrangère qui ne doit jamais être supprimée
for i in $(seq 10 31); do ET put "${DRL}20250101T0000${i}Z" '{}' >/dev/null; done
ET put "${DRL}zz-etranger" 'a conserver' >/dev/null
OUT="$(cl 1 drill --yes --json 2>/dev/null)"; RC=$?
expect_eq "…le test est refusé (code 1), sans bascule : n1 reste primaire" "1 refused n1" "$RC $(printf '%s' "$OUT" | rep 'd["outcome"]') $(leader_name 1)"
RID="$(lastid)"
expect_eq "…le refus est conservé comme rapport dans etcd" "refused" "$(report "$RID" | rep 'd["outcome"]')"
expect_eq "…l'historique est ramené à 20 rapports ; la clé étrangère est intacte" "20 a conserver" "$(nrep) $(ET get "${DRL}zz-etranger" --print-value-only)"
expect_eq "…aucune marque « en cours » ni avancement résiduel" " no" "$(active_id) $([ -e "$(LIVE 1)" ] && echo yes || echo no)"
ET del "${DRL}zz-etranger" >/dev/null
PCTL resume "$CN" --wait >/dev/null 2>&1
wait_cond 20 "Patroni repris : plus de pause" '[ "$(cl 1 drill-check | rep "[c[\"status\"] for c in d[\"checks\"] if c[\"id\"] == \"pause\"][0]")" = ok ]'

echo "-- secondaire arrêté : le candidat n'est plus joignable"
pkill -f "patroni $(R 2)/" 2>/dev/null
wait_cond 30 "API Patroni de n2 éteinte" '! api 2 patroni | grep -q role'
CK="$(cl 1 drill-check)"; RC=$?
expect_eq "n2 hors service : prêt = False, code 1" "1 False" "$RC $(printf '%s' "$CK" | rep 'str(d["ok"])')"
expect_eq "…aucune bascule tentée sur ce constat (n1 reste primaire)" "n1" "$(leader_name 1)"
start_patroni 2
wait_for 120 "n2 réplique de nouveau" streaming 1 2
wait_cond 30 "pré-contrôles de nouveau au vert" '[ "$(cl 1 drill-check | rep "str(d[\"ok\"])")" = True ]'

echo "== 3. Bascule réelle mesurée (sans retour) =="
sql 1 -c "insert into t(lot) values ('avant-drill')" >/dev/null
# shellcheck disable=SC2034  # lu dans les chaînes évaluées par wait_cond
CNT0="$(count_on 1)"
wait_cond 30 "n2 a reçu l'écriture" '[ "$(count_on 2)" = "$CNT0" ]'
OUT="$(cl 1 drill --yes --json 2>"$B/drill3.err")"; RC=$?
expect_eq "code 0 ; résultat « success » ; n1 → n2, une seule phase, lancé en ligne de commande" "0 success n1 n2 1 cli" "$RC $(printf '%s' "$OUT" | rep 'd["outcome"] + " " + d["from"] + " " + d["to"] + " " + str(len(d["phases"])) + " " + d["by"]')"
expect_eq "n2 est le nouveau primaire" "n2" "$(leader_name 1)"
wait_for 60 "n1 le suit en réplication continue (vue /cluster de Patroni, rafraîchie à chaque boucle)" streaming 1 1
M="$(printf '%s' "$OUT" | rep 'json.dumps(d["phases"][0]["metrics"])' 2>/dev/null)"
[ -n "$M" ] || M="$(printf '%s' "$OUT" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["phases"][0]["metrics"]))')"
expect_eq "mesures : ligne de temps +1, aucune perte de position WAL" "True True" "$(printf '%s' "$M" | rep 'str(d["timeline"][1] == d["timeline"][0] + 1) + " " + str(d["lsnContinuity"])')"
expect_eq "…fenêtre sans primaire, promotion, réintégration, rattrapage mesurés (nombres positifs) et dans les seuils" "True" "$(printf '%s' "$M" | rep 'str(all(isinstance(d[k], (int, float)) and 0 <= d[k] for k in ("noPrimaryMs","promotionMs","rejoinMs","catchUpMs")) and d["noPrimaryMs"] < 15000 and d["promotionMs"] < 30000 and d["rejoinMs"] < 90000)')"
expect_eq "…tous les verdicts de la phase sont conformes" "noPrimary=ok promotion=ok rejoin=ok catchUp=ok timeline=ok lsn=ok" "$(printf '%s' "$OUT" | rep '" ".join(k + "=" + v for k, v in d["phases"][0]["verdicts"].items())')"
expect_eq "…contrôles après bascule : primaire, secondaires, quorum" "leader=ok replicas=ok quorum=ok" "$(printf '%s' "$OUT" | rep '" ".join(c["id"] + "=" + c["status"] for c in d["phases"][0]["post"])')"
expect_eq "…événements horodatés enregistrés (commande, plus de primaire, promotion)" "True" "$(printf '%s' "$OUT" | rep 'str({"step","leader"} <= {e["kind"] for e in d["events"]} and all(isinstance(e["t"], int) for e in d["events"]))')"
RID="$(lastid)"
expect_eq "rapport conservé dans etcd, identique à celui affiché" "$RID" "$(printf '%s' "$OUT" | rep 'd["id"]')"
expect_eq "…liste de l'autre nœud : même rapport en tête" "$RID" "$(cl 2 drills | rep 'd["reports"][0]["id"]')"
expect_eq "…publié pour la console sur le nœud d'origine" "$RID" "$(rep 'd["reports"][0]["id"]' < "$(R 1)/run/ddibuntu/cluster-drills.json")"
expect_eq "…aucune marque, aucun fichier d'avancement, verrou libre" " no free" "$(active_id) $([ -e "$(LIVE 1)" ] && echo yes || echo no) $( (exec 9>>"$(R 1)/var/lib/ddibuntu/cluster/drill.lock"; flock -n 9 && echo free || echo held) )"
sql 2 -c "insert into t(lot) values ('apres-drill')" >/dev/null
wait_cond 30 "aucune donnée perdue : n1 reçoit les écritures du nouveau primaire (avant ET après)" '[ "$(count_on 1)" = "$((CNT0 + 1))" ]'

echo "== 4. Bascule et retour au primaire d'origine, lancés depuis le primaire courant =="
OUT="$(cl 2 drill --yes --back --json 2>/dev/null)"; RC=$?
expect_eq "code 0 ; success ; n2 → n1 puis n1 → n2" "0 success switch:n2>n1 back:n1>n2 True" "$RC $(printf '%s' "$OUT" | rep 'd["outcome"] + " " + " ".join(p["name"] + ":" + p["from"] + ">" + p["to"] for p in d["phases"]) + " " + str(d["back"])')"
expect_eq "…les deux phases mesurées : ligne de temps +1 chacune, continues l'une après l'autre" "True" "$(printf '%s' "$OUT" | rep 'str(all(p["metrics"]["timeline"][1] == p["metrics"]["timeline"][0] + 1 for p in d["phases"]) and d["phases"][1]["metrics"]["timeline"][0] == d["phases"][0]["metrics"]["timeline"][1])')"
expect_eq "…n2 est redevenu primaire" "n2" "$(leader_name 1)"
wait_for 60 "…n1 le suit en réplication continue" streaming 1 1
expect_eq "…rapport suivant conservé (par ordre des identifiants)" "True" "$([ "$(lastid)" = "$(printf '%s' "$OUT" | rep 'd["id"]')" ] && echo True || echo False)"
check "retour manuel vers n1 (aucun test en cours : la bascule ordinaire reste possible)" cl 2 switchover --candidate n1
wait_for 90 "n1 est le primaire" is_leader 1 1
wait_stable "cluster stable"

echo "== 5. Pendant un test, la topologie ne bouge pas =="
L5="$(lastid)"
cl 1 drill --yes --back --json > "$B/drill5.json" 2> "$B/drill5.err" &
DP=$!
wait_cond 40 "marque « test en cours » posée dans etcd" '[ -n "$(active_id)" ]'
AID="$(active_id)"
wait_cond 30 "avancement publié par le moniteur" '[ -s "$(LIVE 1)" ]'
expect_eq "…avancement du même test" "$AID live" "$(rep 'd["id"] + " " + d["type"]' < "$(LIVE 1)")"
refus() { local OUT RC; OUT="$("$@" 2>&1)"; RC=$?; [ "$RC" -ne 0 ] && echo "$OUT" | grep -q 'test de bascule est en cours' && echo refused || echo "NON ($RC) $(echo "$OUT" | tail -1)"; }
expect_eq "change-ip refusé" "refused" "$(refus cl 1 change-ip --ip 127.0.5.5 --yes)"
expect_eq "set-net refusé" "refused" "$(refus cl 1 set-net 127.0.0.0/8)"
expect_eq "remove-node refusé" "refused" "$(refus cl 1 remove-node n3)"
expect_eq "take-ca refusé" "refused" "$(refus cl 2 take-ca --yes)"
expect_eq "bascule manuelle refusée" "refused" "$(refus cl 1 switchover --candidate n2)"
expect_eq "un second test est refusé tout de suite" "refused" "$(refus cl 2 drill --yes)"
expect_eq "…sans toucher à la marque du premier" "$AID" "$(active_id)"
drop 2 '{"action":"change-ip","ip":"127.0.5.6","confirm":"n2"}'
expect_eq "demande de la console (change-ip) refusée de même" "False yes" "$(res 2 'd["ok"]') $(res 2 '"test de bascule" in d["message"] and "yes" or "no"')"
drop 2 "{\"action\":\"drill\",\"confirm\":\"$CN\"}"
expect_eq "demande de la console (second test) refusée de même, marque intacte" "False yes $AID" "$(res 2 'd["ok"]') $(res 2 '"test de bascule" in d["message"] and "yes" or "no"') $(active_id)"
OUT="$(cl 2 drill-check)"
expect_eq "les pré-contrôles restent permis (et signalent le test en cours)" "False active=fail" "$(printf '%s' "$OUT" | rep 'str(d["ok"]) + " " + " ".join(c["id"] + "=" + c["status"] for c in d["checks"] if c["id"] == "active")')"
wait "$DP"; RC=$?
OUT="$(cat "$B/drill5.json")"
expect_eq "le premier test va à son terme : success, n1 → n2 → n1" "0 success n1 n2 True" "$RC $(printf '%s' "$OUT" | rep 'd["outcome"] + " " + d["from"] + " " + d["to"] + " " + str(len(d["phases"]) == 2)')"
expect_eq "…un seul nouveau rapport (les refus n'en créent pas), marque et avancement retirés" "1 no" "$(newer "$L5") $([ -e "$(LIVE 1)" ] && echo yes || echo no)$(active_id)"
wait_stable "cluster stable"
expect_eq "…n1 est de nouveau le primaire" "n1" "$(leader_name 1)"

echo "== 6. Demandes de la console (frontière de privilèges) =="
drop 1 '{"action":"drill-check"}'
expect_eq "drill-check : accepté, résultat publié" "True drill-check" "$(res 1 'str(d["ok"]) + " " + d["action"]')"
expect_eq "…pré-contrôles publiés pour la console (prêt)" "True n1 n2" "$(rep 'str(d["ok"]) + " " + d["leader"] + " " + d["candidate"]' < "$(R 1)/run/ddibuntu/cluster-drill-check.json")"
drop 1 '{"action":"drill-check","node":"n2"}'
expect_eq "drill-check avec candidat : accepté" "True" "$(res 1 'd["ok"]')"
refused_drill() {   # refused_drill LIBELLÉ N JSON : demande invalide, aucun test lancé, rien modifié
  local n0 l0; n0="$(lastid)"; l0="$(leader_name 1)"
  drop "$2" "$3"
  expect_eq "$1" "False demande invalide 0 $l0" "$([ -e "$(GEN "$2")" ] && echo True || echo False) $(res "$2" '(str(d["ok"]) == "False") and d["message"] or "OK ?!"') $(newer "$n0") $(leader_name 1)"
}
refused_drill "mauvaise confirmation" 1 '{"action":"drill","confirm":"autre"}'
refused_drill "clé supplémentaire" 1 "{\"action\":\"drill\",\"confirm\":\"$CN\",\"x\":1}"
refused_drill "retour non booléen" 1 "{\"action\":\"drill\",\"confirm\":\"$CN\",\"back\":\"true\"}"
refused_drill "candidat piégé" 1 "{\"action\":\"drill\",\"confirm\":\"$CN\",\"node\":\"n2; reboot\"}"
refused_drill "drill-check avec confirmation" 1 "{\"action\":\"drill-check\",\"confirm\":\"$CN\"}"
refused_drill "drill-check avec retour" 1 '{"action":"drill-check","back":true}'
refused_drill "demande surdimensionnée (plus de 1 Kio)" 1 "{\"action\":\"drill\",\"confirm\":\"$CN\",\"node\":\"$(printf 'n%.0s' $(seq 1 1100))\"}"
ln -sf /etc/hostname "$(GEN 1)"; cl 1 request >/dev/null 2>&1
expect_eq "lien symbolique à la place de la demande : ignoré (demande invalide)" "False demande invalide" "$(res 1 'd["ok"]') $(res 1 'd["message"]')"
rm -f "$(GEN 1)"
L6="$(lastid)"
drop 1 "{\"action\":\"drill\",\"confirm\":\"$CN\",\"back\":true}"
expect_eq "drill par la console : succès, action « drill »" "True drill" "$(res 1 'str(d["ok"]) + " " + d["action"]')"
RID="$(lastid)"
expect_eq "…un nouveau rapport, lancé par la console, avec retour, conforme" "1 console True success" "$(newer "$L6") $(report "$RID" | rep 'd["by"] + " " + str(d["back"]) + " " + d["outcome"]')"
expect_eq "…le message publié pour la console ne contient que nos propres mots" "True" "$(res 1 'str(d["message"].startswith("test de bascule ") and d["message"].endswith(": success"))')"
wait_stable "cluster stable"
expect_eq "…n1 est de nouveau le primaire (retour mesuré)" "n1" "$(leader_name 1)"

echo "== 7. Arrêts anormaux : rien ne reste bloqué =="
mkdir -p "$B/stublib"; printf '#!/usr/bin/env python3\nimport sys\nsys.exit(3)\n' > "$B/stublib/cluster-drill.py"
L7="$(lastid)"
OUT="$(LIBDIR="$B/stublib" cl 1 drill --yes 2>&1)"; RC=$?
expect_eq "assistant en panne (sans rapport) : échec net, pas de bascule, pas de rapport" "1 yes n1 0" "$RC $(echo "$OUT" | grep -q 'sans rapport' && echo yes || echo no) $(leader_name 1) $(newer "$L7")"
expect_eq "…marque retirée, avancement retiré, verrou libre" " no free" "$(active_id) $([ -e "$(LIVE 1)" ] && echo yes || echo no) $( (exec 9>>"$(R 1)/var/lib/ddibuntu/cluster/drill.lock"; flock -n 9 && echo free || echo held) )"
NOW="$(date +%s)"
ET put $ACTKEY "{\"id\":\"20260101T000000Z\",\"node\":\"n2\",\"at\":$((NOW - 1300)),\"phase\":\"switch\"}" >/dev/null
expect_eq "marque vieille de plus de 20 minutes (nœud mort en plein test) : ignorée" "True" "$(cl 1 drill-check | rep 'str(d["ok"])')"
ET put $ACTKEY "{\"id\":\"20260101T000000Z\",\"node\":\"n2\",\"at\":$NOW,\"phase\":\"switch\"}" >/dev/null
OUT="$(cl 1 drill --yes 2>&1)"; RC=$?
expect_eq "marque récente d'un autre nœud : un nouveau test est refusé" "1 yes" "$RC $(echo "$OUT" | grep -q 'test de bascule est en cours' && echo yes || echo no)"
OUT="$(cl 1 drill-clear 2>&1)"; RC=$?
expect_eq "drill-clear sans --yes : refusé, marque intacte" "1 20260101T000000Z" "$RC $(active_id)"
check "drill-clear --yes retire la marque abandonnée" cl 1 drill-clear --yes
expect_eq "…marque retirée, pré-contrôles de nouveau verts" " True" "$(active_id) $(cl 1 drill-check | rep 'str(d["ok"])')"

echo "-- arrêt du test en pleine bascule (SIGTERM sur tout le groupe, comme systemd à l'expiration du délai)"
setsid "$B/cl1.sh" drill --yes --back > "$B/drill7.out" 2>&1 &
TP=$!
wait_cond 40 "bascule en cours (avancement « switch »)" 'grep -q "\"phase\":\"switch\"" "$(LIVE 1)"'
kill -TERM -- "-$TP" 2>/dev/null; wait "$TP" 2>/dev/null
wait_cond 20 "marque « en cours » retirée par le piège de sortie" '[ -z "$(active_id)" ]'
expect_eq "…avancement retiré, verrou libre" "no free" "$([ -e "$(LIVE 1)" ] && echo yes || echo no) $( (exec 9>>"$(R 1)/var/lib/ddibuntu/cluster/drill.lock"; flock -n 9 && echo free || echo held) )"
wait_stable "le cluster retrouve seul un primaire et un secondaire en réplication"
back_to_n1
expect_eq "un nouveau test peut être lancé aussitôt : pré-contrôles verts" "True" "$(cl 1 drill-check | rep 'str(d["ok"])')"

finish
