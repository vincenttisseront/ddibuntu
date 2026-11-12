#!/usr/bin/env bash
# Batterie 26 — MISE À JOUR DU CLUSTER NŒUD PAR NŒUD (0.9.13), dans un cluster réel : vrais etcd (3 membres) et vrais Patroni/PostgreSQL.
# L'installation (ddibuntu-selfupdate) est simulée : la batterie joue le rôle de root sur chaque nœud (« tick » = ce que fait « follow » chaque minute) et
# vérifie l'ORDRE : arbitre, secondaire, primaire en dernier ; un seul nœud à la fois ; un échec arrête la file ; annulation ; reprise ; ordre soldé.
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
quorum() { cl "$1" _quorum 2>/dev/null; }
qv() { quorum "$1" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2" 2>/dev/null; }
# lecture/écriture « quorum » : l'écriture n'est validée qu'avec la majorité ; la lecture est linéarisable (consistency=l)
wq() { ectl "$1" put "$2" "$3" >/dev/null 2>&1; }
rq() { ectl "$1" get "$2" --consistency=l --print-value-only 2>/dev/null; }
statuses() { for n in "$@"; do ectl "$n" endpoint status -w json 2>/dev/null; done | python3 -c 'import json,sys
rows=[]
dec=json.JSONDecoder(); s=sys.stdin.read(); i=0
while i<len(s):
    while i<len(s) and s[i] in " \n\r\t": i+=1
    if i>=len(s): break
    o,j=dec.raw_decode(s,i); i=j; rows+=o
print(json.dumps([{"id":r["Status"]["header"]["member_id"],"leader":r["Status"]["leader"],"term":r["Status"]["raftTerm"],"learner":bool(r["Status"].get("isLearner"))} for r in rows]))'; }
rep() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }   # rep EXPR < JSON


stage() { # stage ÉTAPE VOTANTS_ATTENDUS NŒUDS... : état du quorum etcd à cette étape de la création
  local label="$1" want="$2"; shift 2
  local q; q="$(quorum "$1")"
  expect_eq "$label : $want votant(s), tous sains" "$want $want" "$(echo "$q" | rep 'str(d["voters"])+" "+str(d["healthy"])' 2>/dev/null)"
  expect_eq "$label : quorum présent, majorité requise = $((want / 2 + 1))" "True $((want / 2 + 1))" "$(echo "$q" | rep 'str(d["hasQuorum"])+" "+str(d["needed"])')"
  expect_eq "$label : un chef raft élu" "1" "$(echo "$q" | rep '1 if d["leader"] else 0')"
  local st; st="$(statuses "$@")"
  expect_eq "$label : tous les membres reconnaissent le MÊME chef" "1" "$(echo "$st" | rep 'len({r["leader"] for r in d})' 2>/dev/null || echo "$st" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len({r["leader"] for r in d}))')"
  expect_eq "$label : un seul terme raft sur l'ensemble des membres" "1" "$(echo "$st" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len({r["term"] for r in d}))')"
  local v="vq-$label-$RANDOM"
  check "$label : écriture validée par la majorité" wq "$1" "/b24/probe" "$v"
  local n r=1; for n in "$@"; do [ "$(rq "$n" /b24/probe)" = "$v" ] || r=0; done
  expect_eq "$label : lecture linéarisable identique depuis chaque membre" "1" "$r"
}

echo "== Cluster : n1 (données, primaire) + n2 (données) + n3 (arbitre) =="
mknode 1; initdb_local 1
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -o "-c listen_addresses='' -c unix_socket_directories=$(R 1)/run/pg -c port=5432" -l "$(R 1)/run/pg/init.log" -w start >/dev/null 2>&1
sql 1 -c "create table t(id serial primary key, lot text)" >/dev/null
check "init n1" cl 1 init --name n1 --ip "$(ip 1)" --net 127.0.0.0/8 --no-activate
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -m fast -w stop >/dev/null 2>&1
start_etcd 1; wait_for 20 "etcd n1 sain" ectl 1 endpoint health
check "activate n1" cl 1 activate
start_patroni 1; wait_for 60 "n1 devient leader" is_leader 1 1
stage "création (n1 seul)" 1 1
lease_holder() { local k; k="$(ectl 1 get --prefix /ddibuntu/ --keys-only 2>/dev/null | grep '/leader$' | head -1)"; [ -n "$k" ] && ectl 1 get "$k" --print-value-only 2>/dev/null; }
expect_eq "bail de chef Patroni tenu dans etcd par n1 (une seule clé de chef)" "n1 1" "$(lease_holder) $(ectl 1 get --prefix /ddibuntu/ --keys-only 2>/dev/null | grep -c '/leader$')"
bundle() { cl 1 bundle --name "$1" --ip "$2" --role "$3" --out "$B/$1.bundle" 2>"$B/bundle-$1.err"; }
P2="$(bundle n2 "$(ip 2)" data)"; [ -n "$P2" ] && ok "lot n2" || ko "lot n2" "$(cat "$B/bundle-n2.err")"
mknode 2; initdb_local 2
check "join n2" clp "$P2" 2 join "$B/n2.bundle" --wipe-local-db --no-activate
start_etcd 2; wait_for 30 "etcd n2" ectl 2 endpoint status
check "activate n2" cl 2 activate
start_patroni 2; wait_for 120 "n2 réplique en continu" streaming 1 2
stage "jonction de n2" 2 1 2
P3="$(bundle n3 "$(ip 3)" witness)"; [ -n "$P3" ] && ok "lot n3" || ko "lot n3" "$(cat "$B/bundle-n3.err")"
mknode 3; check "join n3" clp "$P3" 3 join "$B/n3.bundle" --no-activate
start_etcd 3; wait_for 30 "etcd n3" ectl 3 endpoint status
check "activate n3" cl 3 activate
for k in 1 2; do cl "$k" sync >/dev/null 2>&1; done
expect_eq "primaire initial : n1" "n1" "$(leader_name 1)"
stage "jonction de n3 (arbitre)" 3 1 2 3
expect_eq "marge de tolérance : 1 membre peut tomber" "1" "$(qv 1 'd["tolerance"]')"
expect_eq "le chef Patroni est le primaire PostgreSQL (une seule écriture possible)" "n1" "$(lease_holder)"

kill_etcd() { pkill -u etcd -f "$B/n$1/" 2>/dev/null; local i=0; while pgrep -u etcd -f "$B/n$1/" >/dev/null 2>&1 && [ "$i" -lt 40 ]; do sleep 0.5; i=$((i + 1)); done; }
has_leader() { [ "$(qv "$1" 'd["hasQuorum"] and d["leader"] is not None')" = "True" ]; }
one_primary() { local c=0 n; for n in 1 2; do [ "$(role_of "$1" "$n")" = "leader/running" ] && c=$((c + 1)); done; [ "$c" = 1 ]; }


tick() { cl "$1" _putver "$(cat "$(R "$1")/usr/local/lib/ddibuntu/VERSION")" >/dev/null 2>&1; cl "$1" update-step >/dev/null 2>&1; }
ticks() { local n; for n in "$@"; do tick "$n"; done; }
reqf() { echo "$(R "$1")/var/lib/ddibuntu/generated/.update-request"; }
has_req() { [ -e "$(reqf "$1")" ] && echo yes || echo no; }
ver() { cat "$(R "$1")/usr/local/lib/ddibuntu/VERSION"; }
ust() { cl "$1" update 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2"; }
# sim N : simule ddibuntu-selfupdate sur N — consomme la demande déposée et « installe » la version
sim() { local f; f="$(reqf "$1")"; [ -e "$f" ] || return 1; python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$f" > "$(R "$1")/usr/local/lib/ddibuntu/VERSION"; rm -f "$f"; tick "$1"; }
G() { echo "$(R "$1")/var/lib/ddibuntu/generated"; }
for n in 1 2 3; do mkdir -p "$(R $n)/usr/local/lib/ddibuntu" "$(R $n)/var/lib/ddibuntu"; echo 0.9.12 > "$(R $n)/usr/local/lib/ddibuntu/VERSION"; done
wait_for 90 "cluster stable : n1 primaire, n2 en réplication" is_leader 1 1
wait_for 90 "n2 réplique" streaming 1 2
CLN="$(cl 1 status 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["cluster"])')"

echo "== 1. Versions publiées, aucun ordre =="
ticks 1 2 3
expect_eq "les trois versions sont publiées (0.9.12)" "0.9.12 0.9.12 0.9.12" "$(ust 1 'd["versions"].get("n1")') $(ust 1 'd["versions"].get("n2")') $(ust 1 'd["versions"].get("n3")')"
expect_eq "aucun ordre" "None" "$(ust 1 'd["order"]')"
check_fail "annulation sans ordre : refusée" cl 1 update-cancel

echo "== 2. Refus de démarrage =="
check_fail "déjà à la version cible" cl 1 update-start 0.9.12
check_fail "version plus ancienne que celle d'un nœud" cl 1 update-start 0.9.10
check_fail "version invalide" cl 1 update-start latest
check_fail "version invalide (injection)" cl 1 update-start '0.9.13; rm -rf /'
check_fail "depuis l'arbitre : réservé aux nœuds de données" cl 3 update-start 0.9.13
expect_eq "aucun ordre n'a été publié" "" "$(rq 1 /ddibuntu-cluster/update)"

echo "== 3. Ordre donné, vu des trois nœuds =="
check "update-start 0.9.13 (depuis n1)" cl 1 update-start 0.9.13
for n in 1 2 3; do expect_eq "nœud $n voit l'ordre" "0.9.13 n1" "$(ust $n 'd["order"]["target"] + " " + d["order"]["by"]')"; done
check_fail "un second ordre est refusé tant que le premier court" cl 2 update-start 0.9.13
expect_eq "jeu de clés strict de l'ordre" "at by target" "$(rq 1 /ddibuntu-cluster/update | python3 -c 'import json,sys; print(" ".join(sorted(json.load(sys.stdin))))')"

echo "== 4. Ordre de passage : arbitre, puis secondaire, puis primaire =="
ticks 1 2
expect_eq "primaire et secondaire attendent : aucune demande déposée" "no no" "$(has_req 1) $(has_req 2)"
expect_eq "n1 attend l'arbitre n3 (le premier de la file)" "waiting" "$(ust 1 'd["states"]["n1"]["state"]')"
tick 3
expect_eq "l'arbitre n3 dépose sa demande d'installation (version cible)" "yes 0.9.13" "$(has_req 3) $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$(reqf 3)")"
ticks 3 1 2
expect_eq "…une seule demande à la fois (n1 et n2 attendent toujours)" "yes no no" "$(has_req 3) $(has_req 1) $(has_req 2)"
expect_eq "la demande est répétée sans doublon et n3 reste « demande déposée »" "requested" "$(ust 1 'd["states"]["n3"]["state"]')"
sim 3
tick 3
expect_eq "n3 installé : version 0.9.13 publiée, état « done »" "0.9.13 done" "$(ust 1 'd["versions"]["n3"]') $(ust 1 'd["states"]["n3"]["state"]')"
expect_eq "l'ordre n'est pas soldé : n1 et n2 ne sont pas à jour" "0.9.13" "$(ust 1 'd["order"]["target"]')"
ticks 1 2
expect_eq "c'est le tour du secondaire n2 ; le primaire n1 attend encore" "yes no" "$(has_req 2) $(has_req 1)"

echo "== 5. Échec sur un nœud : la file s'ARRÊTE =="
rm -f "$(reqf 2)"
ORD_AT="$(rq 1 /ddibuntu-cluster/update | python3 -c 'import json,sys; print(json.load(sys.stdin)["at"])')"
printf '{"state":"failed","target":"0.9.13","updated_at":%s,"message":"x","error":"disque plein"}' "$((ORD_AT + 5))" > "$(R 2)/var/lib/ddibuntu/update-status.json"
ticks 2 1
expect_eq "n2 signale l'échec et ne redemande rien" "failed no" "$(ust 1 'd["states"]["n2"]["state"]') $(has_req 2)"
expect_eq "la ligne de n2 donne la cause réelle de l'échec" "yes" "$(ust 1 '"yes" if "disque plein" in d["states"]["n2"]["msg"] else "no"')"
expect_eq "le primaire n1 reste en attente (aucune version qui s'éloigne)" "no waiting" "$(has_req 1) $(ust 1 'd["states"]["n1"]["state"]')"
expect_eq "versions : n1/n2 inchangés, n3 à jour" "0.9.12 0.9.12 0.9.13" "$(ver 1) $(ver 2) $(ver 3)"

echo "== 6. Annulation, puis reprise =="
check "update-cancel" cl 1 update-cancel
expect_eq "l'ordre a disparu" "None" "$(ust 1 'd["order"]')"
expect_eq "…et les états aussi" "{}" "$(ust 1 'd["states"]')"
ticks 1 2 3
expect_eq "sans ordre, aucun nœud ne dépose de demande" "no no no" "$(has_req 1) $(has_req 2) $(has_req 3)"
sleep 2
check "nouvel ordre (n3 est déjà à jour)" cl 1 update-start 0.9.13
ticks 3 1 2
expect_eq "l'ancien échec ne bloque plus (antérieur au nouvel ordre) : n2 redemande" "yes no" "$(has_req 2) $(has_req 1)"
expect_eq "n3 (déjà à jour) ne redemande rien" "no" "$(has_req 3)"
sim 2; tick 2
expect_eq "n2 installé" "0.9.13" "$(ust 1 'd["versions"]["n2"]')"

echo "== 7. Le primaire passe en dernier ; ordre soldé =="
tick 1
expect_eq "n1 (primaire) dépose enfin sa demande" "yes" "$(has_req 1)"
expect_eq "n1 est toujours le primaire PostgreSQL pendant l'installation" "n1" "$(leader_name 1)"
sim 1; ticks 1 2 3
expect_eq "les trois nœuds sont à la même version" "0.9.13 0.9.13 0.9.13" "$(ust 1 'd["versions"]["n1"]') $(ust 1 'd["versions"]["n2"]') $(ust 1 'd["versions"]["n3"]')"
expect_eq "l'ordre est soldé (clé supprimée)" "" "$(rq 1 /ddibuntu-cluster/update)"
check_fail "plus rien à faire vers 0.9.13" cl 1 update-start 0.9.13

echo "== 7b. Cible dépassée par une release plus récente : ordre annulé, rien d'installé =="
check "ordre 0.9.14" cl 1 update-start 0.9.14
ORD_AT="$(rq 1 /ddibuntu-cluster/update | python3 -c 'import json,sys; print(json.load(sys.stdin)["at"])')"
ticks 1 2 3; rm -f "$(reqf 1)" "$(reqf 2)" "$(reqf 3)"
for k in 1 2 3; do printf '{"state":"failed","target":"0.9.14","updated_at":%s,"error":"la version demandée (0.9.14) n'"'"'est plus la dernière release (0.9.15) : relancer la recherche"}' "$((ORD_AT + 5))" > "$(R $k)/var/lib/ddibuntu/update-status.json"; done
ticks 1 2 3
expect_eq "l'ordre dépassé est annulé tout seul" "None" "$(ust 1 'd["order"]')"
rm -f "$(R 1)/var/lib/ddibuntu/update-status.json" "$(R 2)/var/lib/ddibuntu/update-status.json" "$(R 3)/var/lib/ddibuntu/update-status.json"

echo "== 8. Valeurs piégées dans etcd : aucun effet =="
for bad in 'pas du json' '[]' '{"target":"latest","at":1,"by":"n1"}' '{"target":"0.9.14","at":1,"by":"n1","x":1}' '{"target":"0.9.14","at":"1","by":"n1"}' '{"target":"0.9.14","at":1,"by":"N1"}'; do
  wq 1 /ddibuntu-cluster/update "$bad"; ticks 1 2 3
  expect_eq "ordre ignoré : ${bad:0:44}" "None no no no" "$(ust 1 'd["order"]') $(has_req 1) $(has_req 2) $(has_req 3)"
done
ectl 1 del /ddibuntu-cluster/update >/dev/null 2>&1

echo "== 9. Demandes JSON de la console =="
req() { printf '%s' "$2" > "$(G "$1")/.cluster-action"; cl "$1" request >/dev/null 2>&1; }
res() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$(R "$1")/run/ddibuntu/cluster-result.json" "$2"; }
for bad in '{"action":"update-start","version":"0.9.14"}' "{\"action\":\"update-start\",\"version\":\"0.9.14\",\"confirm\":\"autre\"}" "{\"action\":\"update-start\",\"version\":\"latest\",\"confirm\":\"$CLN\"}" "{\"action\":\"update-start\",\"version\":\"0.9.14\",\"confirm\":\"$CLN\",\"x\":1}" '{"action":"update-cancel"}'; do
  req 1 "$bad"; expect_eq "refusée : ${bad:0:70}" "False" "$(res 1 'd["ok"]')"
done
expect_eq "…aucun ordre publié" "" "$(rq 1 /ddibuntu-cluster/update)"
req 1 "{\"action\":\"update-start\",\"version\":\"0.9.14\",\"confirm\":\"$CLN\"}"
expect_eq "update-start accepté" "update-start True" "$(res 1 'd["action"] + " " + str(d["ok"])')"
expect_eq "…ordre vu par l'arbitre" "0.9.14" "$(ust 3 'd["order"]["target"]')"
req 1 "{\"action\":\"update-cancel\",\"confirm\":\"$CLN\"}"
expect_eq "update-cancel accepté, ordre supprimé" "True " "$(res 1 'd["ok"]') $(rq 1 /ddibuntu-cluster/update)"

echo "== 10. Quorum perdu : ni ordre ni annulation =="
check "ordre 0.9.14" cl 1 update-start 0.9.14
kill_etcd 2; kill_etcd 3
wait_cond 30 "n1 constate la perte du quorum" '[ "$(qv 1 "d[\"hasQuorum\"]")" = "False" ]'
check_fail "annulation refusée sans quorum" cl 1 update-cancel
check_fail "nouvel ordre refusé sans quorum" cl 1 update-start 0.9.15
start_etcd 2; start_etcd 3
wait_cond 60 "le quorum revient" 'has_leader 1'
expect_eq "l'ordre a survécu à la perte du quorum" "0.9.14" "$(ust 1 'd["order"]["target"]')"
check "annulation de nettoyage" cl 1 update-cancel

finish
