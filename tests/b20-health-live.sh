#!/usr/bin/env bash
# Batterie 20 — santé des nœuds (ddibuntu-health) : services attendus / absents, disques, certificats, heure, valeurs hostiles assainies ;
# puis, avec un VRAI etcd en TLS mutuel, partage de la santé de chaque nœud dans le cluster (une clé par nœud), refus des écritures
# invalides et relecture assainie dans l'état publié (valeurs piégées, démesurées ou mal nommées ignorées).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

HC="$RFS/usr/local/sbin/ddibuntu-health"
CL="$RFS/usr/local/sbin/ddibuntu-cluster"
PY=python3.12; command -v "$PY" >/dev/null 2>&1 || PY=python3
PGBIN=/usr/lib/postgresql/16/bin
B="$(mktemp -d /srv/ddilive.XXXXXX)"; chmod 755 "$B"
STUB="$B/units"; mkdir -p "$STUB"
cleanup() { pkill -u etcd -f "$B/" 2>/dev/null; for _ in $(seq 1 20); do pgrep -u etcd -f "$B/" >/dev/null 2>&1 || break; sleep 0.5; done
  pkill -9 -u postgres -f "$B/" 2>/dev/null; sleep 1; rm -rf "$B"; rm -rf "$T_TMP"; }
trap cleanup EXIT

# faux systemctl : un fichier par unité (ligne 1 = état actif, ligne 2 = « enabled »/« disabled »)
cat > "$B/systemctl" <<EOF
#!/bin/sh
cmd=\$1; shift; unit=""; for a in "\$@"; do unit=\$a; done
f="$STUB/\$unit"
case "\$cmd" in
  show) [ -f "\$f" ] && echo loaded || echo not-found ;;
  is-active) [ -f "\$f" ] && sed -n 1p "\$f" || echo inactive ;;
  is-enabled) [ -f "\$f" ] && sed -n 2p "\$f" || echo disabled ;;
esac
EOF
# faux df : un système de fichiers distinct pour /var/lib/postgresql, le reste sur /
cat > "$B/df" <<'EOF'
#!/bin/sh
for a in "$@"; do p=$a; done
echo "Filesystem 1-blocks Used Available Capacity Mounted on"
case "$p" in
  */var/lib/postgresql) echo "/dev/vdb1 200000000000 150000000000 50000000000 75% /var/lib/postgresql" ;;
  *) echo "/dev/vda1 100000000000 40000000000 60000000000 40% /" ;;
esac
EOF
chmod 755 "$B/systemctl" "$B/df"
unit() { printf '%s\n%s\n' "$2" "${3:-enabled}" > "$STUB/$1"; }

hc() { env DDI_ROOT="$B/s" DDI_TEST=1 DDI_SYSTEMCTL="$B/systemctl" DDI_DF="$B/df" DDI_TLS_DIR="$B/s/tls" DDI_PGBIN=/nonexistent bash "$HC" "$@"; }
hj() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2"; }
HJ="$B/s/run/ddibuntu/health.json"
mkdir -p "$B/s/tls" "$B/s/run"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$B/s/tls/k.pem" -out "$B/s/tls/console.crt" -subj /CN=test -days 40 >/dev/null 2>&1

echo "== Hors cluster : services, disques, certificat =="
unit ddibuntu-console.service active; unit named.service active; unit "postgresql@16-main.service" active; unit nftables.service active
unit kea-dhcp4-server.service inactive disabled      # présent mais désactivé : pas attendu
unit chrony.service active
check "ddibuntu-health run" hc run
[ -f "$HJ" ] && ok "health.json publié" || ko "health.json publié"
expect_eq "mode du fichier 0644" "644" "$(stat -c %a "$HJ")"
expect_eq "rôle standalone, pas de cluster" "standalone None" "$(hj "$HJ" 'd["role"] + " " + str(d["cluster"])')"
expect_eq "services attendus et actifs" "True" "$(hj "$HJ" 'all(s["state"] == "active" and s["expected"] for s in d["services"] if s["name"] in ("console","dns","postgresql","firewall","time"))')"
expect_eq "PostgreSQL attendu hors cluster" "True" "$(hj "$HJ" 'any(s["name"] == "postgresql" and s["expected"] for s in d["services"])')"
expect_eq "etcd et Patroni absents hors cluster" "False" "$(hj "$HJ" 'any(s["name"] in ("etcd","patroni") for s in d["services"])')"
expect_eq "Kea désactivé : signalé comme non attendu" "True" "$(hj "$HJ" 'any(s["name"] == "dhcp" and not s["expected"] for s in d["services"])')"
expect_eq "unité inconnue (keepalived) : ignorée" "False" "$(hj "$HJ" 'any(s["name"] == "keepalived" for s in d["services"])')"
expect_eq "deux systèmes de fichiers (/ et /var/lib/postgresql)" "/ /var/lib/postgresql" "$(hj "$HJ" '" ".join(sorted(x["mount"] for x in d["disks"]))')"
expect_eq "taille et espace libre du disque racine" "100000000000 60000000000" "$(hj "$HJ" '" ".join(str(v) for x in d["disks"] if x["mount"] == "/" for v in (x["sizeBytes"], x["availBytes"]))')"
expect_eq "certificat de la console : échéance dans ~40 jours" "True" "$(hj "$HJ" 'any(c["name"] == "console" and 39*86400 < c["notAfter"] - d["at"] < 41*86400 for c in d["certs"])')"
expect_eq "heure : booléen ou inconnu" "True" "$(hj "$HJ" 'd["timeSynced"] in (True, False, None)')"
expect_eq "charge, mémoire, durée de fonctionnement lues" "True" "$(hj "$HJ" 'd["memory"]["totalKb"] > 0 and d["uptimeSeconds"] > 0 and d["load1"] >= 0')"
expect_eq "PostgreSQL non sondé quand pg_isready est absent" "None" "$(hj "$HJ" 'd["postgres"]')"
expect_eq "aucun secret (clé, mot de passe) dans la santé" "0" "$(grep -ciE 'PRIVATE|password|secret|BEGIN' "$HJ")"
expect_eq "JSON compact sur une ligne" "1" "$(wc -l < "$HJ" | tr -d ' ')"

echo "== Panne : service attendu arrêté / en échec =="
unit named.service failed
hc run; expect_eq "named en échec" "failed True" "$(hj "$HJ" '" ".join(str(v) for s in d["services"] if s["name"] == "dns" for v in (s["state"], s["expected"]))')"
unit named.service inactive
hc run; expect_eq "named arrêté" "inactive" "$(hj "$HJ" '[s["state"] for s in d["services"] if s["name"] == "dns"][0]')"

echo "== Valeurs hostiles : assainies =="
printf 'active; rm -rf /\nenabled\n' > "$STUB/named.service"
hc run; expect_eq "état piégé remplacé par « unknown »" "unknown" "$(hj "$HJ" '[s["state"] for s in d["services"] if s["name"] == "dns"][0]')"
printf '%s\nenabled\n' "$(printf 'a%.0s' $(seq 1 300))" > "$STUB/named.service"
hc run; expect_eq "état démesuré remplacé par « unknown »" "unknown" "$(hj "$HJ" '[s["state"] for s in d["services"] if s["name"] == "dns"][0]')"
unit named.service active
cat > "$B/df" <<'EOF'
#!/bin/sh
echo "Filesystem 1-blocks Used Available Capacity Mounted on"
echo "/dev/x abc def ghi 40% /; touch /tmp/pwned"
echo "/dev/y 0 0 0 0% /y"
EOF
hc run; expect_eq "disque aux valeurs non numériques ou taille nulle : ignoré" "0" "$(hj "$HJ" 'len(d["disks"])')"
[ ! -e /tmp/pwned ] && ok "(rien n'a été exécuté)" || { ko "commande injectée exécutée"; rm -f /tmp/pwned; }
printf 'garbage' > "$B/s/tls/console.crt"
hc run; expect_eq "certificat illisible : ignoré sans erreur" "0" "$(hj "$HJ" 'len(d["certs"])')"
check "show n'écrit rien" bash -c "rm -f '$HJ'; env DDI_ROOT='$B/s' DDI_TEST=1 DDI_SYSTEMCTL='$B/systemctl' DDI_DF='$B/df' bash '$HC' show | python3 -c 'import json,sys; json.load(sys.stdin)'; [ ! -e '$HJ' ]"
check_fail "sous-commande inconnue refusée" hc nimportequoi

echo "== Arbitre (faux fichier de cluster) : pas de base, etcd seul =="
mkdir -p "$B/s/etc/ddibuntu-cluster"
printf 'CLUSTER_NAME=lab\nNODE_NAME=n3\nNODE_ROLE=witness\n' > "$B/s/etc/ddibuntu-cluster/cluster.conf"
unit etcd.service active; unit patroni.service inactive disabled
hc run
expect_eq "nom du nœud, rôle et cluster" "n3 witness lab" "$(hj "$HJ" '" ".join((d["node"], d["role"], d["cluster"]))')"
expect_eq "etcd attendu, PostgreSQL et Patroni non attendus" "True" "$(hj "$HJ" 'any(s["name"] == "etcd" and s["expected"] for s in d["services"]) and not any(s["name"] in ("postgresql","patroni") and s["expected"] for s in d["services"])')"
expect_eq "aucune sonde PostgreSQL sur un arbitre" "None" "$(hj "$HJ" 'd["postgres"]')"
printf 'CLUSTER_NAME=lab\nNODE_NAME=n1\nNODE_ROLE=data\n' > "$B/s/etc/ddibuntu-cluster/cluster.conf"
unit patroni.service active
hc run
expect_eq "nœud de données : Patroni attendu, pas postgresql@" "True" "$(hj "$HJ" 'any(s["name"] == "patroni" and s["expected"] for s in d["services"]) and not any(s["name"] == "postgresql" for s in d["services"])')"
printf 'CLUSTER_NAME=Pa$(id)\nNODE_NAME=n1;x\nNODE_ROLE=data\n' > "$B/s/etc/ddibuntu-cluster/cluster.conf"
hc run; expect_eq "nom de nœud piégé ignoré (nom de machine à la place)" "True" "$(hj "$HJ" 'd["node"] != "n1;x" and d["cluster"] is None')"

echo "== Cluster réel : etcd en TLS mutuel =="
missing=""
[ "$(id -u)" -eq 0 ] || missing="$missing root"
for t in etcd etcdctl openssl gpg runuser python3 patroni curl; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
getent passwd etcd >/dev/null && getent passwd postgres >/dev/null || missing="$missing comptes-etcd/postgres"
[ -x "$PGBIN/initdb" ] || missing="$missing postgresql-16"
if [ -n "$missing" ]; then note "partie cluster réel non exécutable ici (manque :$missing)"; finish; exit; fi

R="$B/n1"
mkdir -p "$R/usr/lib" "$R/run/pg" "$R/var/lib/postgresql/16" "$R/var/lib/etcd" "$R/etc/ddibuntu" "$R/etc/bind" "$R/var/lib/ddibuntu/generated"
ln -s /usr/lib/postgresql "$R/usr/lib/postgresql"; chown -R postgres:postgres "$R/run/pg" "$R/var/lib/postgresql"; chmod 755 "$R" "$R/run" "$R/var" "$R/var/lib" "$R/etc"
printf '#!/bin/sh\nexec env DDI_ROOT=%s DDI_TEST=1 DDI_PY=%s DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN= DDI_PG_CONFIG_DIR= DDI_ETCD_CMD=%s/etcdcmd.sh bash %s "$@"\n' "$R" "$PY" "$B" "$CL" > "$B/cl.sh"
printf '#!/bin/sh\ncase "$1" in\n  stop) pkill -u etcd -f %s/ 2>/dev/null; sleep 1 ;;\n  start) ( cd / && runuser -u etcd -- /usr/bin/etcd --config-file %s/etc/ddibuntu-cluster/etcd.yml >%s/etcd.log 2>&1 & ) ;;\nesac\n' "$R" "$R" "$B" > "$B/etcdcmd.sh"
chmod 755 "$B/cl.sh" "$B/etcdcmd.sh"
cl() { "$B/cl.sh" "$@"; }
ectl() { local p="$R/etc/ddibuntu-cluster/pki"; ETCDCTL_API=3 etcdctl --endpoints "https://127.0.1.1:2379" --command-timeout=5s --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "$@"; }
wait_for() { local s="$1" d="$2"; shift 2; local i=0; while [ "$i" -lt "$s" ]; do if "$@" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }
runuser -u postgres -- "$PGBIN/initdb" -D "$R/var/lib/postgresql/16/main" -E UTF8 --data-checksums >/dev/null 2>&1
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$R/var/lib/postgresql/16/main" -o "-c listen_addresses='' -c unix_socket_directories=$R/run/pg -c port=5432" -l "$R/run/pg/init.log" -w start >/dev/null 2>&1
check "init n1" cl init --name n1 --ip 127.0.1.1 --net 127.0.0.0/8 --no-activate
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$R/var/lib/postgresql/16/main" -m fast -w stop >/dev/null 2>&1
# la batterie précédente (b19) peut encore être en train d'arrêter ses etcd : on attend que 127.0.1.1:2379 et :2380 soient libres
for _ in $(seq 1 60); do ss -ltn 2>/dev/null | grep -qE '127\.0\.1\.1:(2379|2380) ' || break; sleep 0.5; done
"$B/etcdcmd.sh" start; wait_for 20 "etcd n1 sain" ectl endpoint health
check "activate n1" cl activate

# santé de n1, publiée par le vrai script (dans le cluster il partage aussi par etcd)
mkdir -p "$R/run/ddibuntu" "$R/tls"
cp "$B/s/tls/console.crt" "$R/tls/" 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$R/tls/k.pem" -out "$R/tls/console.crt" -subj /CN=t -days 90 >/dev/null 2>&1
unit etcd.service active; unit patroni.service active; unit named.service active
cat > "$B/df" <<'EOF'
#!/bin/sh
echo "Filesystem 1-blocks Used Available Capacity Mounted on"
echo "/dev/vda1 100000000000 40000000000 60000000000 40% /"
EOF
hcl() { env DDI_ROOT="$R" DDI_TEST=1 DDI_SYSTEMCTL="$B/systemctl" DDI_DF="$B/df" DDI_TLS_DIR="$R/tls" DDI_PGBIN=/nonexistent DDI_CLUSTER_CMD="$B/cl.sh" bash "$HC" "$@"; }
check "ddibuntu-health run dans le cluster" hcl run
expect_eq "clé de santé de n1 présente dans etcd" "/ddibuntu-cluster/health/n1" "$(ectl get /ddibuntu-cluster/health/n1 --keys-only | head -1)"
expect_eq "la valeur d'etcd est la santé publiée (même nœud, même instant)" "True" "$(ectl get /ddibuntu-cluster/health/n1 --print-value-only | python3 -c 'import json,sys; e=json.load(sys.stdin); l=json.load(open(sys.argv[1])); print(e["node"] == "n1" and e["at"] == l["at"] and e["role"] == "data")' "$R/run/ddibuntu/health.json")"
sth() { cl status 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
expect_eq "l'état du cluster relaie la santé de n1" "True" "$(sth '"n1" in d["health"] and d["health"]["n1"]["role"] == "data"')"
expect_eq "certificat de n1 (console et cluster) relayés" "True" "$(sth 'sorted(c["name"] for c in d["health"]["n1"]["certs"]) == ["cluster-ca", "cluster-node", "console"]')"

echo "== health-put : écritures invalides refusées =="
check_fail "JSON invalide refusé" bash -c "printf 'pas du json' | '$B/cl.sh' health-put"
check_fail "tableau JSON refusé" bash -c "printf '[1,2]' | '$B/cl.sh' health-put"
check_fail "santé d'un AUTRE nœud refusée" bash -c "printf '{\"node\":\"n2\",\"at\":1}' | '$B/cl.sh' health-put"
check_fail "santé sans nom refusée" bash -c "printf '{\"at\":1}' | '$B/cl.sh' health-put"
check_fail "valeur de plus de 4 Kio refusée" bash -c "python3 -c 'import json; print(json.dumps({\"node\":\"n1\",\"x\":\"a\"*5000}))' | '$B/cl.sh' health-put"
check_fail "entrée vide refusée" bash -c "printf '' | '$B/cl.sh' health-put"
expect_eq "n1 n'a pas été modifié par les refus" "True" "$(ectl get /ddibuntu-cluster/health/n1 --print-value-only | python3 -c 'import json,sys; print(json.load(sys.stdin)["role"] == "data")')"

echo "== Valeurs piégées dans etcd : ignorées à la relecture =="
printf '{"node":"n9","at":1,"services":[]}' | ectl put /ddibuntu-cluster/health/n9 >/dev/null          # valide (nœud connu seulement par sa clé)
printf '{"node":"n8","at":1}' | ectl put /ddibuntu-cluster/health/n7 >/dev/null                          # nom différent de la clé
printf 'pas du json' | ectl put /ddibuntu-cluster/health/n6 >/dev/null
python3 -c 'import json; print(json.dumps({"node":"n5","pad":"x"*6000}))' | ectl put /ddibuntu-cluster/health/n5 >/dev/null   # démesurée
printf '{"node":"N4"}' | ectl put /ddibuntu-cluster/health/N4 >/dev/null                                # nom invalide (majuscule)
printf '[1]' | ectl put /ddibuntu-cluster/health/n3 >/dev/null
expect_eq "seules les santés valides sont relayées (n1, n9)" "n1 n9" "$(sth '" ".join(sorted(d["health"]))')"
expect_eq "aucune valeur démesurée relayée" "True" "$(cl status | python3 -c 'import sys; print(len(sys.stdin.read()) < 20000)')"
# la publication d'état complète (follow) place la santé dans cluster-status.json
check "follow publie l'état du cluster" cl follow
expect_eq "cluster-status.json contient la santé des nœuds" "True" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sorted(d["health"]) == ["n1","n9"])' "$R/run/ddibuntu/cluster-status.json")"

[ -n "${KEEP:-}" ] && { trap - EXIT; echo "gardé : $B"; }
finish
