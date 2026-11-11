#!/usr/bin/env bash
# Batterie 16 — exploitation du cluster avec de VRAIS etcd (TLS mutuel) : 3 nœuds simulés sur 127.0.1.1-4.
# Quorum en direct (sondes de chaque membre), clé de l'autorité publiée chiffrée et reprise, perte du nœud autorité (le « master »),
# retrait d'un nœud perdu, enrôlement du remplaçant, refus de retraits dangereux, perte du quorum et reconstruction (force-new-cluster),
# demandes JSON de la console (validation stricte, confirmations, fichiers hostiles).
# Patroni/PostgreSQL ne sont pas nécessaires (etcd seul) ; initdb sert seulement aux nœuds « données » qui rejoignent.
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
  printf '#!/bin/sh\nexec env DDI_ROOT=%s DDI_TEST=1 DDI_PY=%s DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN= DDI_PG_CONFIG_DIR= DDI_ETCD_CMD=%s/etcdcmd%s.sh bash %s "$@"\n' "$r" "$PY" "$B" "$n" "$CL" > "$B/cl$n.sh"
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

echo "== Cluster : 3 etcd réels (n1 autorité + n2 données, n3 arbitre) =="
mknode 1; initdb_local 1
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -o "-c listen_addresses='' -c unix_socket_directories=$(R 1)/run/pg -c port=5432" -l "$(R 1)/run/pg/init.log" -w start >/dev/null 2>&1
check "init n1" cl 1 init --name n1 --ip "$(ip 1)" --net 127.0.0.0/8 --no-activate
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -m fast -w stop >/dev/null 2>&1
start_etcd 1; wait_for 20 "etcd n1 sain" ectl 1 endpoint health
check "activate n1" cl 1 activate
newnode n2 2 "$(ip 2)" data 1
wait_for 60 "etcd : les deux membres sont sains" ectl 1 endpoint health --cluster
sleep 8   # etcd n'ajoute un membre que si tous les autres sont connectés depuis plus de 5 s
newnode n3 3 "$(ip 3)" witness 1
wait_for 60 "etcd : trois membres sains" ectl 1 endpoint health --cluster

echo "== 1. Quorum en direct : sonde de chaque membre =="
expect_eq "3 voix, majorité 2, 3 saines" "3 2 3" "$(qj 1 '"%d %d %d" % (q["voters"], q["needed"], q["healthy"])')"
expect_eq "quorum présent, tolérance d'une panne" "True 1" "$(qj 1 '"%s %d" % (q["hasQuorum"], q["tolerance"])')"
expect_eq "les trois membres sont joignables et sains" "3" "$(qj 1 'sum(1 for m in q["members"] if m["reachable"] and m["healthy"])')"
expect_eq "un seul leader etcd, connu par son nom" "1" "$(qj 1 'sum(1 for m in q["members"] if m["isLeader"])')"
expect_eq "le leader désigné porte le nom du membre" "True" "$(qj 1 'q["leader"] in ("n1","n2","n3")')"
expect_eq "chaque membre expose latence, index raft et version" "True" "$(qj 1 'all(m["latencyMs"] is not None and m["raftIndex"] and m["version"] for m in q["members"])')"
expect_eq "aucun membre en « learner »" "0" "$(qj 1 'sum(1 for m in q["members"] if m["learner"])')"
expect_eq "même vue depuis l'arbitre" "3 2 3" "$(qj 3 '"%d %d %d" % (q["voters"], q["needed"], q["healthy"])')"
expect_eq "aucun secret dans l'état (pas de clé ni certificat)" "0" "$(cl 1 status | grep -ciE 'BEGIN|PRIVATE|secret')"

echo "== 2. Clé de l'autorité : publiée chiffrée, reprise par un nœud de données =="
expect_eq "n1 porte l'autorité (état)" "True" "$(st 1 'd["ca"]["node"]')"
check "ca-sync n1 (publication)" cl 1 ca-sync
V="$(ectl 1 get /ddibuntu-cluster/ca/escrow --print-value-only)"
expect_eq "valeur publiée : v1 + empreinte" "1 64" "$(printf '%s' "$V" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["v"], len(d["sha"]))')"
expect_eq "la clé privée n'apparaît pas en clair" "0" "$(printf '%s' "$V" | base64 -d 2>/dev/null | grep -c 'PRIVATE KEY')"
expect_eq "porteur enregistré" "n1" "$(ectl 1 get /ddibuntu-cluster/ca/owner --print-value-only)"
expect_eq "l'arbitre lit la même valeur chiffrée" "$V" "$(ectl 3 get /ddibuntu-cluster/ca/escrow --print-value-only)"
REV="$(ectl 1 get /ddibuntu-cluster/ca/escrow -w json | python3 -c 'import json,sys; print(json.load(sys.stdin)["kvs"][0]["mod_revision"])')"
check "ca-sync n1 (idempotent)" cl 1 ca-sync
expect_eq "…rien n'est republié" "$REV" "$(ectl 1 get /ddibuntu-cluster/ca/escrow -w json | python3 -c 'import json,sys; print(json.load(sys.stdin)["kvs"][0]["mod_revision"])')"
expect_eq "n2 : l'état annonce la clé publiée et son porteur" "True n1" "$(st 2 '"%s %s" % (d["ca"]["escrow"], d["ca"]["owner"])')"
check_fail "take-ca n2 refusé tant que n1 est en ligne" cl 2 take-ca --yes
check_fail "take-ca refusé sur l'arbitre (pas de clé d'enveloppe)" cl 3 take-ca --yes
check_fail "take-ca sans --yes refusé" cl 2 take-ca
expect_eq "n2 ne porte pas l'autorité" "no" "$([ -e "$(R 2)/var/lib/ddibuntu/cluster/ca/ca.key" ] && echo yes || echo no)"
CAKEY_SHA="$(sha256sum < "$(R 1)/var/lib/ddibuntu/cluster/ca/ca.key" | cut -d' ' -f1)"
ectl 1 put /canary alive >/dev/null

echo "== 3. Le master (n1, autorité) est perdu pour de bon =="
stop_etcd 1
wait_for 20 "n2 voit n1 injoignable" bash -c "[ \"\$($B/cl2.sh status 2>/dev/null | python3 -c 'import json,sys; q=json.load(sys.stdin)[\"etcd\"][\"quorum\"]; print(sum(1 for m in q[\"members\"] if not m[\"reachable\"]))')\" = 1 ]"
wait_for 30 "n2 : nouvelle élection etcd terminée" bash -c "[ \"\$($B/cl2.sh status 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"etcd\"][\"quorum\"][\"hasQuorum\"])')\" = True ]"
expect_eq "n2 : quorum conservé (2 voix sur 3), plus aucune marge" "True 0 2" "$(qj 2 '"%s %d %d" % (q["hasQuorum"], q["tolerance"], q["healthy"])')"
expect_eq "n1 est marqué injoignable, ni sain ni leader" "False False False" "$(qj 2 '[ "%s %s %s" % (m["reachable"], m["healthy"], m["isLeader"]) for m in q["members"] if m["name"]=="n1"][0]')"
expect_eq "le canari est lisible (le cluster continue)" "alive" "$(ectl 2 get /canary --print-value-only)"
check_fail "bundle impossible sur n2 tant qu'il n'a pas l'autorité" cl 2 bundle --name n4 --ip "$(ip 4)" --role data
check "take-ca sur n2 (n1 perdu)" cl 2 take-ca --yes
expect_eq "n2 porte l'autorité" "yes" "$([ -e "$(R 2)/var/lib/ddibuntu/cluster/ca/ca.key" ] && echo yes || echo no)"
expect_eq "…avec la MÊME clé que n1" "$CAKEY_SHA" "$(sha256sum < "$(R 2)/var/lib/ddibuntu/cluster/ca/ca.key" | cut -d' ' -f1)"
expect_eq "…le certificat de l'autorité n'a pas changé" "$(sha256sum < "$(R 1)/var/lib/ddibuntu/cluster/ca/ca.crt" | cut -d' ' -f1)" "$(sha256sum < "$(R 2)/var/lib/ddibuntu/cluster/ca/ca.crt" | cut -d' ' -f1)"
expect_eq "…la clé est en 0600" "600" "$(stat -c %a "$(R 2)/var/lib/ddibuntu/cluster/ca/ca.key")"
expect_eq "…porteur mis à jour dans etcd" "n2" "$(ectl 2 get /ddibuntu-cluster/ca/owner --print-value-only)"
check_fail "take-ca refusé quand on porte déjà l'autorité" cl 2 take-ca --yes

echo "== 4. Retrait du nœud perdu =="
check_fail "remove-node : soi-même refusé" cl 2 remove-node n2
check_fail "remove-node : nom inconnu refusé" cl 2 remove-node n9
check_fail "remove-node : nom hostile refusé" cl 2 remove-node '../../etc/passwd'
check_fail "remove-node : nom vide refusé" cl 2 remove-node ''
check "remove-node n1" cl 2 remove-node n1
expect_eq "n1 n'est plus membre etcd" "" "$(ectl 2 member list -w json | python3 -c 'import json,sys; print(" ".join(m["name"] for m in json.load(sys.stdin)["members"] if m["name"]=="n1"))')"
expect_eq "n2 : pairs = n2 + n3" "n2=$(ip 2):data n3=$(ip 3):witness" "$(peers 2)"
expect_eq "registre : n1 effacé" "" "$(ectl 2 get /ddibuntu-cluster/nodes/n1 --print-value-only)"
expect_eq "marque de retrait écrite" "$(ip 1)" "$(ectl 2 get /ddibuntu-cluster/removed/n1 --print-value-only)"
check "sync n3 : l'arbitre oublie n1" cl 3 sync
expect_eq "n3 : pairs = n2 + n3" "n2=$(ip 2):data n3=$(ip 3):witness" "$(peers 3)"
expect_eq "quorum à 2 voix sur 2 requises, sans marge" "2 2 2 0" "$(qj 2 '"%d %d %d %d" % (q["voters"], q["needed"], q["healthy"], q["tolerance"])')"
check_fail "retrait répété de n1 refusé (nœud inconnu)" cl 2 remove-node n1

echo "== 5. Enrôlement du remplaçant (lot signé par la nouvelle autorité n2) =="
wait_for 60 "etcd : n2 et n3 sains" ectl 2 endpoint health --cluster
sleep 8
newnode n4 4 "$(ip 4)" data 2
wait_for 60 "etcd : trois membres sains" ectl 2 endpoint health --cluster
expect_eq "3 voix, tolérance d'une panne retrouvée" "3 2 3 1" "$(qj 2 '"%d %d %d %d" % (q["voters"], q["needed"], q["healthy"], q["tolerance"])')"
expect_eq "le certificat de n4 est signé par la même autorité" "OK" "$(openssl verify -CAfile "$(R 1)/var/lib/ddibuntu/cluster/ca/ca.crt" "$(R 4)/etc/ddibuntu-cluster/pki/node.crt" 2>&1 | grep -q ': OK' && echo OK)"
check "sync n3 : l'arbitre apprend n4" cl 3 sync
expect_eq "n3 : pairs = n2 + n3 + n4" "n2=$(ip 2):data n3=$(ip 3):witness n4=$(ip 4):data" "$(peers 3)"

echo "== 6. Retraits dangereux refusés =="
stop_etcd 4
wait_for 20 "n2 voit n4 injoignable" bash -c "[ \"\$($B/cl2.sh status 2>/dev/null | python3 -c 'import json,sys; q=json.load(sys.stdin)[\"etcd\"][\"quorum\"]; print(sum(1 for m in q[\"members\"] if not m[\"reachable\"]))')\" = 1 ]"
check_fail "retirer n3 alors que n4 est HS casserait le quorum : refusé" cl 2 remove-node n3
expect_eq "…n3 est toujours membre" "n3" "$(ectl 2 member list -w json | python3 -c 'import json,sys; print(" ".join(m["name"] for m in json.load(sys.stdin)["members"] if m["name"]=="n3"))')"
check_fail "recover refusé : etcd a encore son quorum" cl 2 recover --yes
start_etcd 4; wait_for 30 "n4 revient" ectl 4 endpoint health

echo "== 8. Demandes JSON de la console (fichier .cluster-action) =="
G2="$(G 2)"
req() { printf '%s' "$1" > "$G2/.cluster-action"; cl 2 request >/dev/null 2>&1; }
res() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$(R 2)/run/ddibuntu/cluster-result.json" "$1"; }
req '{"action":"refresh"}'; expect_eq "refresh : accepté" "refresh True" "$(res '"%s %s" % (d["action"], d["ok"])')"
expect_eq "…l'état publié est frais" "True" "$(python3 -c 'import json,sys,time; print(time.time()-json.load(open(sys.argv[1]))["at"] < 30)' "$(R 2)/run/ddibuntu/cluster-status.json")"
expect_eq "…le fichier de demande est consommé" "no" "$([ -e "$G2/.cluster-action" ] && echo yes || echo no)"
for bad in 'pas du json' '[]' '{"action":"format-disk"}' '{"action":"refresh","extra":1}' '{"action":"remove-node","node":"n3"}' '{"action":"remove-node","node":"n3","confirm":"n4"}' '{"action":"remove-node","node":"../x","confirm":"../x"}' '{"action":"recover","confirm":"autre"}' '{"action":"take-ca","confirm":"n9"}' '{"action":"refresh","node":"n3"}' '{"action":"remove-node","node":["n3"],"confirm":["n3"]}'; do
  req "$bad"; expect_eq "demande refusée : ${bad:0:44}" "False" "$(res 'd["ok"]')"
done
expect_eq "message fixe pour une demande invalide" "demande invalide" "$(res 'd["message"]')"
printf '{"action":"refresh"}' > "$G2/.cluster-action.real"; ln -sf "$G2/.cluster-action.real" "$G2/.cluster-action"; cl 2 request >/dev/null 2>&1
expect_eq "lien symbolique refusé" "demande invalide" "$(res 'd["message"]')"
head -c 5000 /dev/zero | tr '\0' 'a' > "$G2/.cluster-action"; cl 2 request >/dev/null 2>&1
expect_eq "fichier démesuré refusé" "demande invalide" "$(res 'd["message"]')"
wait_for 30 "n4 sain avant son retrait" ectl 2 endpoint health --cluster; sleep 8
req '{"action":"remove-node","node":"n4","confirm":"n4"}'
expect_eq "remove-node n4 via la console : accepté" "remove-node True" "$(res '"%s %s" % (d["action"], d["ok"])')"
[ "$(res 'd["ok"]')" = True ] || echo "   message: $(res 'd["message"]')"
stop_etcd 4
req '{"action":"remove-node","node":"n4","confirm":"n4"}'
expect_eq "…répété : refusé (nœud inconnu), message de la commande" "False" "$(res 'd["ok"]')"
expect_eq "…message lisible et sans caractère de contrôle" "True" "$(res 'len(d["message"])>0 and all(c.isprintable() for c in d["message"])')"

echo "== 7. Perte du quorum (n3 perdu, n2 seul sur 2 voix) : reconstruction depuis n2 =="
ectl 2 put /canary2 survivant >/dev/null
stop_etcd 3
wait_for 30 "etcd de n2 n'a plus de quorum" bash -c "! $B/cl2.sh status >/dev/null 2>&1 || [ \"\$($B/cl2.sh status 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"etcd\"][\"quorum\"][\"hasQuorum\"])')\" = False ]"
expect_eq "état : quorum perdu (aucune voix saine : sans leader, même n2 échoue à la sonde)" "False 0 2" "$(qj 2 '"%s %d %d" % (q["hasQuorum"], q["healthy"], q["needed"])')"
check_fail "remove-node impossible sans quorum" cl 2 remove-node n3
check_fail "recover sans --yes refusé" cl 2 recover
check "recover --yes sur n2" cl 2 recover --yes
wait_for 30 "etcd n2 sain seul" ectl 2 endpoint health
expect_eq "un seul membre etcd" "1" "$(ectl 2 member list -w json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["members"]))')"
expect_eq "les données sont conservées (canari 1)" "alive" "$(ectl 2 get /canary --print-value-only)"
expect_eq "les données sont conservées (canari 2)" "survivant" "$(ectl 2 get /canary2 --print-value-only)"
expect_eq "pairs = n2 seul" "n2=$(ip 2):data" "$(peers 2)"
expect_eq "marques de retrait : n1, n3, n4" "n1 n3 n4" "$(ectl 2 get --prefix /ddibuntu-cluster/removed/ --keys-only | sed 's#.*/##' | grep . | sort | tr '\n' ' ' | sed 's/ $//')"
expect_eq "la configuration etcd ne garde PAS force-new-cluster" "0" "$(grep -c 'force-new-cluster' "$(R 2)/etc/ddibuntu-cluster/etcd.yml")"
expect_eq "sauvegarde du répertoire etcd conservée" "1" "$(ls -d "$(R 2)"/var/lib/etcd/ddibuntu.pre-recover.* 2>/dev/null | wc -l)"
expect_eq "état : 1 voix, majorité 1, quorum" "1 1 True" "$(qj 2 '"%d %d %s" % (q["voters"], q["needed"], q["hasQuorum"])')"
check_fail "recover refusé : le quorum est revenu" cl 2 recover --yes

finish
