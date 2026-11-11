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
  pkill -f "$B/console/" 2>/dev/null; pkill -f "patroni $B/" 2>/dev/null; pkill -u etcd -f "$B/" 2>/dev/null; sleep 1
  for n in 1 2 3; do pkill -9 -u postgres -f "$B/n$n/" 2>/dev/null; done
  for _ in $(seq 1 40); do pgrep -u etcd -f "$B/" >/dev/null 2>&1 || break; sleep 0.5; done   # l'arrêt d'etcd n'est pas instantané : la batterie suivante réutilise ses ports
  pkill -9 -u etcd -f "$B/" 2>/dev/null
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
wait_cond() { # wait_cond secondes "description" 'expression shell' : l'expression est ÉVALUÉE À CHAQUE ESSAI (pas une seule fois)
  local s="$1" d="$2" e="$3" i=0
  while [ "$i" -lt "$s" ]; do if eval "$e" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done
  ko "$d" "délai de ${s}s dépassé"; return 1
}
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
check "init n1" cl 1 init --name n1 --ip "$(ip 1)" --net 127.0.0.0/8 --no-activate
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
check "activate n1 : inscription au registre" cl 1 activate
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
wait_cond 20 "la donnée écrite sur le primaire arrive sur n2" '[ "$(sql 2 -c "select count(*) from t")" = 2 ]'
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

echo "== Configuration Kea : « follow » (primaire = fichiers de la console, secondaire = copie répliquée en base) =="
kea_json() { printf '{"Dhcp4":{"interfaces-config":{"interfaces":["lo"]},"control-socket":{"socket-type":"unix","socket-name":"/run/kea/kea4-ctrl-socket"},"lease-database":{"type":"memfile","persist":false},"subnet4":[{"id":1,"subnet":"%s","pools":[{"pool":"%s"}]}]}}' "$1" "$2"; }
mkdir -p "$B/zones"; chown bind:bind "$B/zones" 2>/dev/null || true   # même chemin de zones sur les deux nœuds : c'est le chemin écrit par la console
for n in 1 2; do
  mkdir -p "$(R $n)/gen" "$(R $n)/kea" "$(R $n)/kstate" "$(R $n)/etc/bind"
  printf 'include "%s/etc/bind/named.conf.options";\ninclude "%s/etc/bind/named.conf.local";\n' "$(R $n)" "$(R $n)" > "$(R $n)/etc/bind/named.conf"
  : > "$(R $n)/etc/bind/named.conf.options"; : > "$(R $n)/etc/bind/named.conf.local"
  printf '#!/bin/bash\necho run >> %s/reload-calls\nexec env DDI_KEA_ETC=%s DDI_BIND_ETC=%s/etc/bind DDI_ZONES_RUNTIME_DIR=%s DDI_LOCK_FILE=%s/reload.lock DDI_STATE_DIR=%s DDI_CLUSTER_DIR=%s DDI_RELOAD_NOSERVICES=1 DDI_KEA_LEASE_FILE=%s/leases.csv bash %s/usr/local/sbin/ddibuntu-reload "$@"\n' \
    "$(R $n)" "$(R $n)/kea" "$(R $n)" "$B/zones" "$(R $n)" "$(R $n)/kstate" "$(R $n)/etc/ddibuntu-cluster" "$(R $n)" "$RFS" > "$(R $n)/reload.sh"; chmod 755 "$(R $n)/reload.sh"
done
fol() { local n="$1"; shift; DDI_GENERATED_DIR="$(R "$n")/gen" DDI_RELOAD_CMD="$(R "$n")/reload.sh" DDI_DB_NAME=postgres cl "$n" follow "$@"; }
calls() { local f; f="$(R "$1")/reload-calls"; [ -f "$f" ] && wc -l < "$f" | tr -d ' ' || echo 0; }
store() { # store GEN SUBNET POOL [EMPREINTE_FORCÉE] : écrit la ligne sur le primaire (n1)
  local f="$B/kea-row.json"; kea_json "$2" "$3" > "$f"
  local sha="${4:-$(sha256sum "$f" | cut -d' ' -f1)}"
  sql 1 -c "insert into rendered_configs (name, content, generation, sha256) values ('kea-dhcp4.conf', \$\$$(cat "$f")\$\$, $1, '$sha') on conflict (name) do update set content = excluded.content, generation = excluded.generation, sha256 = excluded.sha256" >/dev/null
}
sql 1 -c "create table rendered_configs (name text primary key, content text not null, generation bigint not null, sha256 text not null, deployed_at timestamptz not null default now())" >/dev/null
expect_eq "follow sur le secondaire sans rien déployé : rien à faire" "00" "$(fol 2 >/dev/null 2>&1; echo $?)$(calls 2)"
store 1 10.50.0.0/24 "10.50.0.10 - 10.50.0.200"
wait_cond 20 "la configuration Kea arrive sur n2 par la réplication PostgreSQL" '[ "$(sql 2 -c "select count(*) from rendered_configs")" = 1 ]'
check "follow sur n2 (secondaire)" fol 2
expect_eq "n2 : copie de la console écrite dans son dossier généré" "10.50.0.0/24" "$(python3 -c "import json; print(json.load(open('$(R 2)/gen/kea-dhcp4.conf'))['Dhcp4']['subnet4'][0]['subnet'])")"
expect_eq "n2 : ddibuntu-reload --kea-only appelé une fois" "1" "$(calls 2)"
expect_eq "n2 : HA injecté par root (this-server-name = n2)" "n2" "$(python3 -c "import json; d=json.load(open('$(R 2)/kea/kea-dhcp4.conf'))['Dhcp4']; print(d['hooks-libraries'][1]['parameters']['high-availability'][0]['this-server-name'])")"
expect_eq "n2 : les deux nœuds de données sont pairs HA, l'arbitre non" "2" "$(python3 -c "import json; d=json.load(open('$(R 2)/kea/kea-dhcp4.conf'))['Dhcp4']; print(len(d['hooks-libraries'][1]['parameters']['high-availability'][0]['peers']))")"
check "follow idempotent : second passage sans rechargement" fol 2
expect_eq "n2 : toujours un seul appel" "1" "$(calls 2)"
GOOD2="$(sha256sum "$(R 2)/kea/kea-dhcp4.conf" | cut -d' ' -f1)"
store 2 10.50.0.0/24 "10.50.0.10 - 10.50.0.200" "$(printf '0%.0s' $(seq 64))"
wait_cond 20 "empreinte altérée répliquée sur n2" '[ "$(sql 2 -c "select sha256 from rendered_configs")" = "$(printf "0%.0s" $(seq 64))" ]'
fol 2 >"$B/fol-bad.out" 2>&1
expect_grep "empreinte non conforme : refus signalé" 'empreinte' "$B/fol-bad.out"
expect_eq "…aucun rechargement" "1" "$(calls 2)"
expect_eq "…configuration en place intacte" "$GOOD2" "$(sha256sum "$(R 2)/kea/kea-dhcp4.conf" | cut -d' ' -f1)"
store 3 10.60.0.0/24 "10.60.0.10 - 10.60.0.200"
wait_cond 20 "nouvelle génération répliquée" '[ "$(sql 2 -c "select generation from rendered_configs")" = 3 ]'
check "follow applique la nouvelle génération" fol 2
expect_eq "n2 : nouveau sous-réseau en service" "10.60.0.0/24" "$(python3 -c "import json; print(json.load(open('$(R 2)/kea/kea-dhcp4.conf'))['Dhcp4']['subnet4'][0]['subnet'])")"
# une base compromise ne doit pas permettre d'exécuter du code : même avec une empreinte « correcte », le hook est refusé par root
GOOD2="$(sha256sum "$(R 2)/kea/kea-dhcp4.conf" | cut -d' ' -f1)"
printf '%s' '{"Dhcp4":{"interfaces-config":{"interfaces":["lo"]},"control-socket":{"socket-type":"unix","socket-name":"/run/kea/kea4-ctrl-socket"},"lease-database":{"type":"memfile","persist":false},"hooks-libraries":[{"library":"/tmp/evil.so"}],"subnet4":[]}}' > "$B/evil.json"
sql 1 -c "update rendered_configs set content = \$\$$(cat "$B/evil.json")\$\$, sha256 = '$(sha256sum "$B/evil.json" | cut -d' ' -f1)', generation = 4" >/dev/null
wait_cond 20 "ligne piégée répliquée sur n2" '[ "$(sql 2 -c "select generation from rendered_configs")" = 4 ]'
check_fail "base compromise : hook refusé par ddibuntu-reload" fol 2
expect_eq "…configuration Kea en place intacte" "$GOOD2" "$(sha256sum "$(R 2)/kea/kea-dhcp4.conf" | cut -d' ' -f1)"
store 5 10.60.0.0/24 "10.60.0.10 - 10.60.0.200"
echo "-- primaire (n1) : lit les fichiers de la console --"
kea_json 10.70.0.0/24 "10.70.0.10 - 10.70.0.20" > "$(R 1)/gen/kea-dhcp4.conf"
check "follow sur n1 (primaire)" fol 1
expect_eq "n1 : HA injecté (this-server-name = n1)" "n1" "$(python3 -c "import json; d=json.load(open('$(R 1)/kea/kea-dhcp4.conf'))['Dhcp4']; print(d['hooks-libraries'][1]['parameters']['high-availability'][0]['this-server-name'])")"
expect_eq "n1 : sous-réseau de la console" "10.70.0.0/24" "$(python3 -c "import json; print(json.load(open('$(R 1)/kea/kea-dhcp4.conf'))['Dhcp4']['subnet4'][0]['subnet'])")"
expect_eq "status : l'état Kea est présent (null si Kea ne tourne pas)" "True" "$(cl 1 status | python3 -c 'import json,sys; print("kea" in json.load(sys.stdin))')"

echo "== BIND : clé TSIG du cluster et « follow » (secondaire = zones transférées, primaire = NOTIFY vers le pair) =="
check "clé de transfert identique sur n1 et n2 (propagée par le lot d'enrôlement)" cmp "$(R 1)/etc/bind/ddi-xfr.key" "$(R 2)/etc/bind/ddi-xfr.key"
expect_eq "clé de transfert : droits 0640" "640" "$(stat -c %a "$(R 2)/etc/bind/ddi-xfr.key")"
BOPT="$B/named-options.conf"; BZON="$B/named-zones.conf"
cat > "$BOPT" <<CONF
// Généré par DDI-Buntu — ne pas modifier à la main.
options {
  directory "/var/cache/bind";
  listen-on { 127.0.1.1; };
  listen-on-v6 { none; };
  recursion yes;
  allow-recursion { 127.0.0.0/8; };
  allow-query { any; };
  allow-transfer { none; };
  dnssec-validation no;
  check-names primary warn;
  querylog no;
};
CONF
cat > "$BZON" <<CONF
// Généré par DDI-Buntu — ne pas modifier à la main.
zone "lab.test" { type primary; file "$B/zones/db.lab.test"; notify yes; };
CONF
printf '%s' "$(cat "$BOPT")" > "$BOPT.n" && mv "$BOPT.n" "$BOPT"; printf '%s' "$(cat "$BZON")" > "$BZON.n" && mv "$BZON.n" "$BZON"   # contenu sans retour final : octet pour octet ce que la base renvoie
store_named() { # store_named GEN : écrit les deux lignes BIND sur le primaire (n1)
  local nm f
  for nm in named.conf.options named.conf.zones; do
    if [ "$nm" = named.conf.options ]; then f="$BOPT"; else f="$BZON"; fi
    sql 1 -c "insert into rendered_configs (name, content, generation, sha256) values ('$nm', \$\$$(cat "$f")\$\$, $1, '$(printf '%s' "$(cat "$f")" | sha256sum | cut -d' ' -f1)') on conflict (name) do update set content = excluded.content, generation = excluded.generation, sha256 = excluded.sha256" >/dev/null
  done
}
store_named 6
wait_cond 20 "les fichiers BIND de la console arrivent sur n2 par la réplication" '[ "$(sql 2 -c "select count(*) from rendered_configs")" = 3 ]'
mkdir -p "$(R 2)/gen/zones"; echo "périmé" > "$(R 2)/gen/zones/db.lab.test"       # une copie locale périmée ne doit jamais écraser la zone transférée
C0="$(calls 2)"
check "follow sur n2 (secondaire) : Kea + BIND" fol 2
expect_eq "n2 : ddibuntu-reload --replica appelé une fois" "$((C0 + 1))" "$(calls 2)"
check "n2 : zone périmée supprimée du dossier généré" test ! -e "$(R 2)/gen/zones"
expect_grep "n2 : la zone est secondaire, transférée depuis n1 avec la clé TSIG" "zone \"lab.test\" \\{ type secondary; primaries \\{ 127.0.1.1 key \"ddi-xfr\"; \\}" "$(R 2)/etc/bind/named.conf.local"
expect_grep "n2 : écoute sur son adresse du réseau dédié" "listen-on \\{ 127.0.1.2; \\}" "$(R 2)/etc/bind/named.conf.options"
expect_grep "n2 : ne notifie personne" "notify no;" "$(R 2)/etc/bind/named.conf.options"
expect_grep "n2 : transferts refusés par défaut" "allow-transfer \\{ none; \\}" "$(R 2)/etc/bind/named.conf.options"
check "n2 : aucun fichier de zone local écrit par root" test -z "$(ls "$B/zones" 2>/dev/null)"
check "follow n2 idempotent (BIND)" fol 2
expect_eq "n2 : aucun appel de plus" "$((C0 + 1))" "$(calls 2)"
echo "-- primaire (n1) : zones de la console, NOTIFY et transferts signés vers n2 --"
cp "$BOPT" "$(R 1)/gen/named.conf.options"; cp "$BZON" "$(R 1)/gen/named.conf.zones"
mkdir -p "$(R 1)/gen/zones"
printf '$ORIGIN lab.test.\n$TTL 300\n@ IN SOA ns1.lab.test. root.lab.test. ( 1 3600 600 86400 300 )\n@ IN NS ns1.lab.test.\nns1 IN A 127.0.1.1\nwww IN A 10.20.0.10\n' > "$(R 1)/gen/zones/db.lab.test"
check "follow sur n1 (primaire) : rechargement complet" fol 1
expect_grep "n1 : transfert signé par la clé TSIG du cluster" "allow-transfer \\{ key \"ddi-xfr\"; \\}" "$(R 1)/etc/bind/named.conf.options"
expect_grep "n1 : NOTIFY vers n2 sur le réseau dédié" "also-notify \\{ 127.0.1.2 key \"ddi-xfr\"; \\}" "$(R 1)/etc/bind/named.conf.options"
expect_grep "n1 : zone primaire avec transfert signé" "zone \"lab.test\" \\{ type primary; file \"$B/zones/db.lab.test\"; notify yes; allow-transfer \\{ key \"ddi-xfr\"; \\}" "$(R 1)/etc/bind/named.conf.local"
check "n1 : fichier de zone installé" test -f "$B/zones/db.lab.test"
check "follow n1 idempotent (BIND)" fol 1
check "named-checkconf accepte la configuration de n1" named-checkconf "$(R 1)/etc/bind/named.conf"
check "named-checkconf accepte la configuration de n2" named-checkconf "$(R 2)/etc/bind/named.conf"

echo "== Bascule contrôlée =="
# patronictl lit sa configuration : on l'exécute avec l'environnement du nœud 1
# la console dépose une demande (fichier d'une ligne) ; root la valide puis lance la bascule. Les demandes invalides ne font rien.
req() { # req CONTENU : dépose la demande sur n1 puis la fait traiter
  printf '%s' "$1" > "$(R 1)/gen/.cluster-switchover"
  DDI_GENERATED_DIR="$(R 1)/gen" cl 1 request >"$B/req.out" 2>&1; echo $?
}
rmsg() { python3 -c "import json; print(json.load(open('$(R 1)/run/ddibuntu/cluster-result.json'))['message'])"; }
expect_eq "demande vide : refusée" "demande invalide" "$(req '' >/dev/null; rmsg)"
expect_eq "demande piégée (injection) : refusée" "demande invalide" "$(req $'n2; touch /tmp/pwn' >/dev/null; rmsg)"
expect_eq "…rien exécuté" "no" "$([ -e /tmp/pwn ] && echo yes || echo no)"
expect_eq "arbitre candidat : refusé" "nœud candidat inconnu ou sans base de données" "$(req n3 >/dev/null; rmsg)"
expect_eq "nœud inconnu : refusé" "nœud candidat inconnu ou sans base de données" "$(req n9 >/dev/null; rmsg)"
expect_eq "le leader candidat : refusé" "le candidat est déjà le leader" "$(req n1 >/dev/null; rmsg)"
ln -sf /etc/hostname "$(R 1)/gen/.cluster-switchover"; DDI_GENERATED_DIR="$(R 1)/gen" cl 1 request >/dev/null 2>&1
expect_eq "lien symbolique : refusé et supprimé" "demande invalide/no" "$(rmsg)/$([ -e "$(R 1)/gen/.cluster-switchover" ] || [ -L "$(R 1)/gen/.cluster-switchover" ] && echo yes || echo no)"
check "la demande valide déclenche la bascule vers n2" test "$(req n2)" = 0
expect_eq "résultat publié pour la console" "bascule effectuée" "$(rmsg)"
wait_for 60 "n2 devient leader" is_leader 2 2
wait_for 60 "n1 réplique à nouveau" streaming 2 1
expect_eq "n2 accepte l'écriture après bascule" "ok" "$(sql 2 -c "insert into t values (3,'sur-n2'); select 'ok'" | tail -1)"
wait_cond 20 "n1 reçoit la donnée de n2" '[ "$(sql 1 -c "select count(*) from t")" = 3 ]'
# le suiveur suit le changement de leader : n2 (devenu leader) promeut son BIND, n1 (devenu secondaire) redevient secondaire
bindrole() { cat "$(R "$1")/kstate/bind-role" 2>/dev/null || echo -; }
expect_eq "avant : n1 primaire BIND, n2 secondaire" "primary/secondary" "$(bindrole 1)/$(bindrole 2)"
C2="$(calls 2)"; C1="$(calls 1)"
check "follow sur n2 (nouveau leader) : promotion BIND" fol 2
expect_eq "n2 : un appel à ddibuntu-reload" "$((C2 + 1))" "$(calls 2)"
expect_eq "n2 : BIND primaire" "primary" "$(bindrole 2)"
expect_grep "n2 : zone primaire, transfert signé" 'zone "lab.test" \{ type primary;.*allow-transfer \{ key "ddi-xfr"; \}' "$(R 2)/etc/bind/named.conf.local"
expect_grep "n2 : NOTIFY vers n1" 'also-notify \{ 127\.0\.1\.1 key "ddi-xfr"; \}' "$(R 2)/etc/bind/named.conf.options"
check "follow sur n2 idempotent après promotion" fol 2
check "follow sur n1 (devenu secondaire) : retour en secondaire" fol 1
expect_eq "n1 : un appel à ddibuntu-reload" "$((C1 + 1))" "$(calls 1)"
expect_eq "n1 : BIND secondaire" "secondary" "$(bindrole 1)"
expect_grep "n1 : zone secondaire du nouveau leader" 'zone "lab.test" \{ type secondary; primaries \{ 127\.0\.1\.2 key "ddi-xfr"; \}' "$(R 1)/etc/bind/named.conf.local"
expect_grep "n1 : plus de also-notify" 'notify no;' "$(R 1)/etc/bind/named.conf.options"

echo "== Mise à jour progressive : le leader attend que les secondaires soient à jour =="
for n in 1 2; do mkdir -p "$(R $n)/usr/local/lib/ddibuntu"; echo 0.5.4 > "$(R $n)/usr/local/lib/ddibuntu/VERSION"; done
fol 1 >/dev/null 2>&1; fol 2 >/dev/null 2>&1       # chaque nœud publie sa version dans etcd
expect_eq "versions partagées dans etcd" "0.5.4/0.5.4" "$(ectl 1 get /ddibuntu-cluster/versions/n1 --print-value-only)/$(ectl 1 get /ddibuntu-cluster/versions/n2 --print-value-only)"
expect_eq "n2 est leader" "n2" "$(leader_name 1)"
cl 2 rolling-check 0.5.5 >"$B/rc.out" 2>&1; RC=$?
expect_eq "leader : mise à jour refusée tant que le secondaire n'est pas à jour (code 3)" "3" "$RC"
expect_grep "…message : mettre d'abord à jour n1" "mettez d'abord à jour n1" "$B/rc.out"
check "secondaire : mise à jour autorisée en premier" cl 1 rolling-check 0.5.5
check_fail "version visée invalide refusée" cl 2 rolling-check "0.5; reboot"
echo 0.5.5 > "$(R 1)/usr/local/lib/ddibuntu/VERSION"; fol 1 >/dev/null 2>&1
check "leader : autorisé une fois le secondaire à jour" cl 2 rolling-check 0.5.5

echo "== Bascule automatique (arrêt brutal du primaire) =="
kill_patroni_hard 2
wait_for 90 "n1 est promu automatiquement (quorum etcd n1+n3)" is_leader 1 1
expect_eq "aucune donnée validée perdue" "3" "$(sql 1 -c "select count(*) from t")"
expect_eq "le nouveau primaire accepte l'écriture" "ok" "$(sql 1 -c "insert into t values (4,'après-panne'); select 'ok'" | tail -1)"
C1="$(calls 1)"
check "follow sur n1 (promu par Patroni, n2 injoignable) : promotion BIND" fol 1
expect_eq "n1 : un appel à ddibuntu-reload" "$((C1 + 1))" "$(calls 1)"
expect_eq "n1 : BIND de nouveau primaire" "primary" "$(bindrole 1)"

echo "== Réintégration de l'ancien primaire (pg_rewind) =="
sql 1 -c "checkpoint"
start_patroni 2
wait_for 120 "n2 revient comme secondaire" streaming 1 2
wait_cond 30 "n2 a rattrapé la donnée écrite pendant son absence" '[ "$(sql 2 -c "select count(*) from t")" = 4 ]'
expect_eq "toujours un seul primaire" "n1" "$(leader_name 1)"
C2="$(calls 2)"
check "follow sur n2 (ancien primaire revenu) : retour en secondaire" fol 2
expect_eq "n2 : un appel à ddibuntu-reload" "$((C2 + 1))" "$(calls 2)"
expect_eq "n2 : BIND secondaire" "secondary" "$(bindrole 2)"

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
wait_cond 200 "le cluster retrouve un primaire en écriture" '[ "$(writable_count)" = 1 ]'
sleep 10
NL="$(writable_count)"
expect_eq "après retour du quorum : exactement un primaire accessible en écriture" "1" "$NL"
echo "== Console réelle : le leader écrit, le secondaire est en lecture seule, la bascule demandée par la console déplace l'écriture =="
if [ ! -f "$ROOT/webui/.output/server/index.mjs" ] || ! command -v node >/dev/null 2>&1; then
  note "console non construite (webui/.output) ou node absent : section console non exécutée"
else
  NODE_BIN="$(command -v node)"; CON="$B/console"; mkdir -p "$CON"; cp -r "$ROOT/webui/.output" "$CON/.output"; chmod -R a+rX "$CON"
  find_leader() { for n in 1 2; do [ "$(sql "$n" -c "select pg_is_in_recovery()" 2>/dev/null)" = f ] && { echo "$n"; return; }; done; }
  LN="$(find_leader)"; RN=$((3 - LN))
  sql "$LN" -c "drop table if exists rendered_configs" >/dev/null     # la migration 6 de la console recrée la table (créée à la main plus haut pour les essais de « follow »)
  start_console() { # start_console N PORT
    mkdir -p "$B/congen$1"; chown postgres:postgres "$B/congen$1"
    ( cd "$CON" && runuser -u postgres -- env NODE_ENV=production PORT="$2" NITRO_HOST=127.0.0.1 DDI_TEST_MODE=1 DDI_COOKIE_SECURE=false DDI_SECRET_KEY=cle-secrete-de-test-0123456789abcdefghij \
      DDI_SETUP_TOKEN=jeton-test DDI_PBKDF2_ITERATIONS=2000 DDI_GENERATED_DIR="$B/congen$1" DDI_CLUSTER_STATUS="$(R "$1")/run/ddibuntu/cluster-status.json" \
      DDI_QUERY_LOG=/nonexistent DDI_RELOAD_STATUS="$B/congen$1/reload-status" \
      DDI_DATABASE_URL="postgresql://postgres@/postgres?host=$(R "$1")/run/pg" "$NODE_BIN" "$CON/.output/server/index.mjs" >"$B/console$1.log" 2>&1 & )
  }
  hc() { # hc PORT METHODE CHEMIN [JSON] : code HTTP ; corps dans $B/hc.out
    local port="$1" m="$2" pth="$3" d="${4:-}"
    if [ -n "$d" ]; then curl -s -o "$B/hc.out" -w '%{http_code}' -X "$m" -b "$B/jar" -c "$B/jar" -H "x-csrf-token: ${CSRF:-}" -H 'content-type: application/json' -d "$d" "http://127.0.0.1:$port$pth"
    else curl -s -o "$B/hc.out" -w '%{http_code}' -X "$m" -b "$B/jar" -c "$B/jar" -H "x-csrf-token: ${CSRF:-}" "http://127.0.0.1:$port$pth"; fi
  }
  hcode() { python3 -c "import json; d=json.load(open('$B/hc.out')); print(d.get('data',{}).get('code') or d.get('statusMessage',''))" 2>/dev/null; }
  PL=3101; PR=3102; PW='Zq7!vK2m-Lw9#pR4t'
  start_console "$LN" $PL
  wait_cond 60 "la console du leader (n$LN) démarre et migre le schéma" '[ "$(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:$PL/api/health)" = 200 ]'
  LAST_MIG="$(grep -oE 'version: [0-9]+, sql: SCHEMA_[0-9]+' "$ROOT/webui/server/utils/db.ts" | grep -oE '^version: [0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1)"
  wait_cond 30 "le schéma de la console arrive sur le secondaire (n$RN) par la réplication" '[ "$(sql $RN -c "select coalesce(max(version),0) from schema_migrations")" = '"$LAST_MIG"' ]'
  start_console "$RN" $PR
  wait_cond 60 "la console du secondaire (n$RN) démarre sans écrire (schéma déjà au niveau)" '[ "$(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:$PR/api/health)" = 200 ]'
  expect_eq "leader : /cluster/role → pas de secondaire" "false" "$(curl -s http://127.0.0.1:$PL/api/cluster/role | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["replica"]).lower())')"
  expect_eq "secondaire : /cluster/role → secondaire" "true" "$(curl -s http://127.0.0.1:$PR/api/cluster/role | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["replica"]).lower())')"
  expect_eq "leader : création du premier administrateur" "200" "$(hc $PL POST /api/setup/admin "{\"token\":\"jeton-test\",\"username\":\"admin\",\"password\":\"$PW\"}")"
  expect_eq "leader : connexion" "200" "$(hc $PL POST /api/auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}")"
  CSRF="$(python3 -c "import json; print(json.load(open('$B/hc.out'))['csrf'])")"
  expect_eq "leader : écriture acceptée (nouvel utilisateur)" "200" "$(hc $PL POST /api/users "{\"username\":\"lect\",\"role\":\"viewer\",\"password\":\"$PW\"}")"
  wait_cond 20 "la session et l'utilisateur sont répliqués sur le secondaire" '[ "$(sql $RN -c "select count(*) from users")" = 2 ]'
  expect_eq "secondaire : connexion refusée (lecture seule)" "503/replica" "$(hc $PR POST /api/auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}")/$(hcode)"
  expect_eq "secondaire : la session ouverte sur le leader reste lisible" "200" "$(hc $PR GET /api/users)"
  expect_eq "secondaire : écriture refusée proprement (503)" "503/replica" "$(hc $PR POST /api/users "{\"username\":\"intrus\",\"role\":\"viewer\",\"password\":\"$PW\"}")/$(hcode)"
  expect_eq "secondaire : déploiement refusé et aucun fichier écrit" "503/0" "$(hc $PR POST /api/system/apply '{"deploy":true}')/$([ -e "$B/congen$RN/.deployed" ] && echo 1 || echo 0)"
  expect_eq "secondaire : l'utilisateur refusé n'existe pas" "0" "$(sql $RN -c "select count(*) from users where username = 'intrus'")"
  # états publiés par root (follow) lus par les deux consoles
  fol "$LN" >/dev/null 2>&1; fol "$RN" >/dev/null 2>&1
  expect_eq "leader : état du cluster visible, rôle local = leader" "true/leader/n$LN" "$(hc $PL GET /api/cluster/status >/dev/null; python3 -c "import json; d=json.load(open('$B/hc.out')); print(str(d['clustered']).lower()+'/'+d['state']['localRole']+'/'+d['state']['leader'])")"
  expect_eq "secondaire : même cluster vu en lecture seule, rôle local = replica" "true/replica/true" "$(hc $PR GET /api/cluster/status >/dev/null; python3 -c "import json; d=json.load(open('$B/hc.out')); print(str(d['clustered']).lower()+'/'+d['state']['localRole']+'/'+str(d['replica']).lower())")"
  expect_eq "leader : le secondaire est le seul candidat à la bascule" "n$RN" "$(hc $PL GET /api/cluster/status >/dev/null; python3 -c "import json; print(','.join(json.load(open('$B/hc.out'))['candidates']))")"
  expect_eq "leader : demande de bascule vers le secondaire acceptée" "200" "$(hc $PL POST /api/cluster/switchover "{\"candidate\":\"n$RN\"}")"
  expect_eq "…la demande est un simple fichier d'une ligne" "n$RN" "$(cat "$B/congen$LN/.cluster-switchover")"
  # le fichier est déposé par le processus « postgres » du banc (la console) ; root le relit et exécute (unité .path en production)
  DDI_GENERATED_DIR="$B/congen$LN" cl "$LN" request >"$B/req2.out" 2>&1; RQ=$?
  expect_eq "root : demande validée et bascule exécutée" "0" "$RQ"
  wait_for 90 "le secondaire devient leader" is_leader "$RN" "$RN"
  wait_cond 30 "la console de n$RN (nouveau leader) accepte maintenant les écritures" '[ "$(hc $PR POST /api/users "{\"username\":\"apres\",\"role\":\"viewer\",\"password\":\"$PW\"}")" = 200 ]'
  wait_cond 30 "la console de n$LN (ancien leader) refuse maintenant les écritures (503)" '[ "$(hc $PL POST /api/users "{\"username\":\"refuse\",\"role\":\"viewer\",\"password\":\"$PW\"}")" = 503 ]'
  wait_cond 30 "la même session fonctionne sur le nouveau leader et l'utilisateur écrit est répliqué sur l'ancien" '[ "$(sql $LN -c "select count(*) from users where username = '"'"'apres'"'"'")" = 1 ]'
  pkill -f "$CON/.output/server/index.mjs" 2>/dev/null
fi
note "non couvert : coupure réseau réelle, perte de machine, horloges désynchronisées, disque saturé ; à rejouer sur le premier laboratoire (docs/ARCHITECTURE-CLUSTER.md)"

finish
