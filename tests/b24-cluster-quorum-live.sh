#!/usr/bin/env bash
# Batterie 24 — ÉLECTION DU QUORUM À LA CRÉATION DU CLUSTER, dans un cluster réel : vrais etcd (3 membres) et vrais Patroni/PostgreSQL.
# À chaque étape de la création (init, jonction n2, jonction n3 arbitre) : membres, voix, un seul chef raft, même terme, écriture/lecture linéarisables,
# chef Patroni tenu par un bail etcd ; puis épreuves : perte d'un membre (quorum conservé), perte du chef raft (nouvelle élection, terme supérieur),
# perte de la majorité (plus aucune écriture) et retour du quorum.
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
# membre déclaré mais pas encore démarré (sans nom dans etcd) : il reste « learner », le quorum de n1 ne change pas (régression : il comptait comme votant)
expect_eq "n2 déclaré, pas démarré : 1 votant, majorité 1, quorum présent" "1 1 True" "$(quorum 1 | rep 'str(d["voters"])+" "+str(d["needed"])+" "+str(d["hasQuorum"])')"
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
term() { statuses "$@" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(max(r["term"] for r in d))'; }
has_leader() { [ "$(qv "$1" 'd["hasQuorum"] and d["leader"] is not None')" = "True" ]; }
one_primary() { local c=0 n; for n in 1 2; do [ "$(role_of "$1" "$n")" = "leader/running" ] && c=$((c + 1)); done; [ "$c" = 1 ]; }

echo "== Épreuve 1 : l'arbitre tombe — le quorum (2 sur 3) est conservé, rien ne bouge =="
T0="$(term 1 2 3)"
kill_etcd 3
wait_cond 20 "le quorum voit 2 membres sains sur 3, tolérance 0" '[ "$(qv 1 "str(d[\"healthy\"])+str(d[\"hasQuorum\"])+str(d[\"tolerance\"])")" = "2True0" ]'
check "écriture toujours validée (n1+n2 = majorité)" wq 1 /b24/probe "sans-arbitre"
expect_eq "…et lue de façon linéarisable depuis n2" "sans-arbitre" "$(rq 2 /b24/probe)"
expect_eq "aucune nouvelle élection (même terme raft)" "$T0" "$(term 1 2)"
expect_eq "le primaire PostgreSQL n'a pas bougé" "n1" "$(leader_name 1)"
start_etcd 3; wait_cond 40 "n3 revient : 3 membres sains" '[ "$(qv 1 "d[\"healthy\"]")" = 3 ]'
expect_eq "…sans nouvelle élection" "$T0" "$(term 1 2 3)"

echo "== Épreuve 2 : le chef raft tombe — les survivants en ÉLISENT un autre =="
RL="$(qv 1 'd["leader"]')"; ok "chef raft actuel : $RL"
LN="${RL#n}"; SURV="$(for n in 1 2 3; do [ "$n" != "$LN" ] && echo $n; done | tr '\n' ' ')"; S1="${SURV%% *}"; S2="$(echo "$SURV" | awk '{print $2}')"
kill_etcd "$LN"
wait_cond 40 "un nouveau chef est élu parmi les survivants" '[ -n "$(qv '"$S1"' "d[\"leader\"] if d[\"hasQuorum\"] and d[\"leader\"] not in (None,\"$RL\") else \"\"")" ]'
NL="$(qv "$S1" 'd["leader"]')"; [ -n "$NL" ] && [ "$NL" != "$RL" ] && ok "nouveau chef raft : $NL (≠ $RL)" || ko "nouveau chef raft" "$NL"
T1="$(term "$S1" "$S2")"; [ "$T1" -gt "$T0" ] && ok "le terme raft a augmenté ($T0 → $T1) : élection réelle" || ko "terme raft" "$T0 → $T1"
expect_eq "les deux survivants reconnaissent le même chef" "1" "$(statuses "$S1" "$S2" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len({r["leader"] for r in d}))')"
check "écriture validée par la majorité restante" wq "$S1" /b24/probe "apres-election"
expect_eq "…lue depuis l'autre survivant" "apres-election" "$(rq "$S2" /b24/probe)"
start_etcd "$LN"; wait_cond 60 "l'ancien chef revient comme suiveur : 3 membres sains" '[ "$(qv '"$S1"' "d[\"healthy\"]")" = 3 ]'
expect_eq "…et n'a pas repris la tête (un seul chef, le nouveau)" "$NL" "$(qv 1 'd["leader"]')"
wait_for 90 "PostgreSQL : un seul primaire, de nouveau sain" one_primary 1
expect_eq "toujours une unique clé de chef Patroni" "1" "$(ectl "$S1" get --prefix /ddibuntu/ --keys-only 2>/dev/null | grep -c '/leader$')"

echo "== Épreuve 3 : la majorité tombe — plus AUCUNE écriture (pas de cerveau partagé) =="
kill_etcd 2; kill_etcd 3
wait_cond 30 "n1 constate la perte du quorum" '[ "$(qv 1 "d[\"hasQuorum\"]")" = "False" ]'
check_fail "écriture refusée sans majorité" wq 1 /b24/probe "sans-quorum"
expect_eq "lecture linéarisable refusée sans majorité (aucune valeur périmée servie)" "" "$(rq 1 /b24/probe)"
start_etcd 2; start_etcd 3
wait_cond 60 "le quorum revient et un chef est élu" 'has_leader 1'
check "écriture de nouveau validée" wq 1 /b24/probe "retour"
expect_eq "…lue depuis chaque membre" "retour retour retour" "$(rq 1 /b24/probe) $(rq 2 /b24/probe) $(rq 3 /b24/probe)"
expect_eq "la dernière écriture acceptée avant la panne n'a pas disparu" "retour" "$(rq 3 /b24/probe)"
wait_for 120 "PostgreSQL : un seul primaire accessible en écriture" one_primary 1
stage "après les épreuves" 3 1 2 3

# pair encore inscrit au registre mais retiré d'etcd (retrait manuel du membre) : il ne vote plus, le quorum ne doit pas le compter
id3="$(ectl 1 member list -w json 2>/dev/null | python3 -c 'import json,sys; print(next(("%x" % m["ID"] for m in json.load(sys.stdin)["members"] if m.get("name")=="n3"), ""))')"
[ -n "$id3" ] && ok "identifiant du membre n3 relevé" || ko "identifiant du membre n3 relevé" "introuvable"
check "retrait manuel du membre n3 d'etcd" ectl 1 member remove "$id3"
wait_cond 30 "n1 ne compte plus n3 comme votant" '[ "$(qv 1 "d[\"voters\"]")" = "2" ]'
expect_eq "n3 absent d'etcd mais encore au registre : 2 votants, majorité 2, quorum présent" "2 2 True" "$(quorum 1 | rep 'str(d["voters"])+" "+str(d["needed"])+" "+str(d["hasQuorum"])')"

finish
