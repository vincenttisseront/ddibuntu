#!/usr/bin/env bash
# Batterie 25 — NŒUD PRÉFÉRÉ DU PRIMAIRE (0.9.11), dans un cluster réel : vrais etcd (3 membres) et vrais Patroni/PostgreSQL.
# Consigne publiée dans etcd et vue par les TROIS nœuds ; refus (arbitre, nom invalide, valeurs piégées, quorum perdu) ; demandes JSON de la console ;
# écart avec le primaire réel puis bascule contrôlée vers le nœud préféré et retour ; nettoyage de la consigne au retrait du nœud.
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

echo "== 1. État initial : aucune consigne =="
pref() { cl "$1" preferred 2>/dev/null; }
sj() { cl "$1" status 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2"; }
CLN="$(sj 1 'd["cluster"]')"; [ -n "$CLN" ] && ok "nom du cluster : $CLN" || ko "nom du cluster" "vide"
expect_eq "aucune consigne : « preferred » vaut null" "null" "$(pref 1)"
expect_eq "…et l'état publié porte preferred = null" "None" "$(sj 1 'd["preferred"]')"
check_fail "retrait sans consigne : refusé" cl 1 clear-preferred

echo "== 2. Publication, vue des trois nœuds =="
check "set-preferred n2 (depuis n1)" cl 1 set-preferred n2
expect_eq "clé etcd : nœud n2, auteur n1" "n2 n1" "$(rq 1 /ddibuntu-cluster/preferred | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["node"], d["by"])')"
for n in 1 2 3; do expect_eq "nœud $n voit la consigne (n2)" "n2" "$(pref $n | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"])')"; done
expect_eq "état publié du nœud 2 : preferred = n2" "n2" "$(sj 2 'd["preferred"]["node"]')"
expect_eq "état publié de l'arbitre : preferred = n2" "n2" "$(sj 3 'd["preferred"]["node"]')"
expect_eq "aucun écart de format : seules les clés node/at/by" "at by node" "$(rq 1 /ddibuntu-cluster/preferred | python3 -c 'import json,sys; print(" ".join(sorted(json.load(sys.stdin))))')"
check "le changement de consigne est possible (n1)" cl 2 set-preferred n1
expect_eq "…vue par tous : n1" "n1 n1 n1" "$(for n in 1 2 3; do pref $n | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"])'; done | tr '\n' ' ' | sed 's/ $//')"
check "retour à n2" cl 1 set-preferred n2

echo "== 3. Refus =="
check_fail "l'arbitre ne peut pas être préféré" cl 1 set-preferred n3
check_fail "nœud inconnu" cl 1 set-preferred n9
check_fail "nom invalide (majuscule)" cl 1 set-preferred N2
check_fail "nom invalide (injection)" cl 1 set-preferred 'n2; rm -rf /'
check_fail "depuis l'arbitre : réservé aux nœuds de données" cl 3 set-preferred n1
check_fail "depuis l'arbitre : le retrait aussi" cl 3 clear-preferred
expect_eq "la consigne n'a pas bougé" "n2" "$(pref 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"])')"

echo "== 4. Valeurs piégées écrites directement dans etcd : ignorées, l'état reste publiable =="
for bad in '{"node":"n3","at":1,"by":"n1"}' '{"node":"n2","at":1,"by":"n1","x":1}' 'pas du json' '[]' '{"node":"N2"}' '{"node":["n2"]}'; do
  wq 1 /ddibuntu-cluster/preferred "$bad"
  expect_eq "valeur ignorée : ${bad:0:40}" "null" "$(pref 1)"
  expect_eq "…l'état se construit toujours (clé preferred nulle)" "None" "$(sj 1 'd["preferred"]')"
done
check "remise de la consigne n2" cl 1 set-preferred n2

echo "== 5. Demandes JSON de la console (fichier .cluster-action, relues par root) =="
G1="$(R 1)/var/lib/ddibuntu/generated/.cluster-action"
req() { printf '%s' "$2" > "$(R "$1")/var/lib/ddibuntu/generated/.cluster-action"; cl "$1" request >/dev/null 2>&1; }
res() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$(R "$1")/run/ddibuntu/cluster-result.json" "$2"; }
for bad in "{\"action\":\"set-preferred\",\"node\":\"n1\"}" "{\"action\":\"set-preferred\",\"node\":\"n1\",\"confirm\":\"autre\"}" "{\"action\":\"set-preferred\",\"node\":\"n1\",\"confirm\":\"$CLN\",\"x\":1}" \
  "{\"action\":\"set-preferred\",\"node\":\"../x\",\"confirm\":\"$CLN\"}" "{\"action\":\"set-preferred\",\"node\":\"n3\",\"confirm\":\"$CLN\"}" "{\"action\":\"clear-preferred\"}" "{\"action\":\"clear-preferred\",\"confirm\":\"autre\"}"; do
  req 1 "$bad"; expect_eq "refusée : ${bad:0:70}" "False" "$(res 1 'd["ok"]')"
done
expect_eq "…la consigne n'a pas bougé" "n2" "$(pref 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"])')"
req 1 "{\"action\":\"set-preferred\",\"node\":\"n1\",\"confirm\":\"$CLN\"}"
expect_eq "set-preferred n1 : accepté" "set-preferred True" "$(res 1 'd["action"] + " " + str(d["ok"])')"
expect_eq "…publié pour tous" "n1" "$(pref 3 | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"])')"
expect_eq "…le fichier de demande est consommé" "no" "$([ -e "$G1" ] && echo yes || echo no)"
req 2 "{\"action\":\"set-preferred\",\"node\":\"n2\",\"confirm\":\"$CLN\"}"
expect_eq "set-preferred n2 depuis n2 : accepté" "True" "$(res 2 'd["ok"]')"
req 1 "{\"action\":\"clear-preferred\",\"confirm\":\"$CLN\"}"
expect_eq "clear-preferred : accepté" "True null" "$(res 1 'str(d["ok"])') $(pref 2)"
check_fail "…un second retrait est refusé (rien à retirer)" cl 1 clear-preferred

echo "== 6. Quorum perdu : ni écriture ni retrait de la consigne =="
check "consigne n2 posée" cl 1 set-preferred n2
kill_etcd 2; kill_etcd 3
wait_cond 30 "n1 constate la perte du quorum" '[ "$(qv 1 "d[\"hasQuorum\"]")" = "False" ]'
check_fail "set-preferred refusé sans quorum" cl 1 set-preferred n1
check_fail "clear-preferred refusé sans quorum" cl 1 clear-preferred
req 1 "{\"action\":\"set-preferred\",\"node\":\"n1\",\"confirm\":\"$CLN\"}"; expect_eq "demande de la console refusée sans quorum" "False" "$(res 1 'd["ok"]')"
start_etcd 2; start_etcd 3
wait_cond 60 "le quorum revient" 'has_leader 1'
wait_for 120 "PostgreSQL : un seul primaire" one_primary 1
expect_eq "la consigne a survécu à la perte du quorum" "n2" "$(pref 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"])')"

echo "== 7. Écart avec le primaire réel, puis bascule contrôlée vers le nœud préféré =="
stable() { local l o; l="$(leader_name 1)"; [ -n "$l" ] || return 1; if [ "$l" = n1 ]; then o=2; else o=1; fi; [ "$(role_of 1 "$o")" = "replica/streaming" ]; }
wait_for 150 "cluster stable" stable
expect_eq "primaire n1, préféré n2 : l'écart est visible dans l'état publié" "n1 n2" "$(sj 1 'd["patroni"]["members"][0]["name"] if d["patroni"]["members"][0]["role"]=="leader" else d["patroni"]["members"][1]["name"]') $(sj 1 'd["preferred"]["node"]')"
check "bascule contrôlée vers le nœud préféré (n2)" cl 1 switchover --candidate n2
wait_for 90 "n2 est le primaire" is_leader 1 2
wait_for 150 "cluster stable après la bascule" stable
expect_eq "la consigne n'a pas été touchée par la bascule" "n2" "$(pref 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"])')"
expect_eq "…ni appliquée toute seule : n2 reste le primaire après 20 s" "n2" "$(sleep 20; leader_name 1)"
check "consigne n1 ; le primaire (n2) s'en écarte" cl 2 set-preferred n1
check "retour contrôlé sur n1" cl 2 switchover --candidate n1
wait_for 90 "n1 est de nouveau le primaire" is_leader 1 1
wait_for 150 "cluster stable" stable

echo "== 8. Retrait d'un nœud : la consigne ne reste pas orpheline =="
check "consigne n2" cl 1 set-preferred n2
check "retrait de n2 (secondaire, quorum conservé avec n1+n3)" cl 1 remove-node n2
expect_eq "la consigne a disparu avec le nœud" "" "$(rq 1 /ddibuntu-cluster/preferred)"
expect_eq "…et l'état publié n'en porte plus" "None" "$(sj 1 'd["preferred"]')"

finish
