#!/usr/bin/env bash
# Batterie 40 — la PKI (EJBCA) dans le cluster, avec de VRAIS etcd (TLS mutuel) : 3 nœuds simulés sur 127.0.1.1-3 (deux de données, un arbitre).
# Vérifie : installation sur le leader seul, état chiffré dans etcd (l'arbitre ne lit rien), application sur le secondaire (secrets, instance, autorités, volume),
# unité Quadlet SANS démarrage automatique, image tirée en veille, garde-fous (seul le leader écrit), bascule (le secondaire promu démarre, l'ancien leader s'arrête),
# consigne d'arrêt répliquée, marque « mise à jour interrompue » (posée, refusée par un autre nœud, retirée seulement après vérification), retrait et remise à zéro
# propagés, valeurs hostiles dans etcd, secondaire qui ne publie jamais, conflit de deux PKI, etcd injoignable, verrou occupé, absence de secret résiduel.
# Podman, systemctl, psql, curl et ddibuntu-fw sont des bouchons (un jeu par nœud) ; Patroni est remplacé par un fichier de rôle (DDI_TEST_PATRONI_ROLE_FILE).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

CL="$RFS/usr/local/sbin/ddibuntu-cluster"
PKI="$RFS/usr/local/sbin/ddibuntu-pki"
PY=python3.12
PGBIN=/usr/lib/postgresql/16/bin
missing=""
[[ "$(id -u)" -eq 0 ]] || missing="$missing root"
for t in etcd etcdctl openssl gpg runuser python3 curl flock; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
command -v "$PY" >/dev/null 2>&1 || PY=python3
getent passwd etcd >/dev/null && getent passwd postgres >/dev/null || missing="$missing comptes-etcd/postgres"
[[ -x "$PGBIN/initdb" ]] || missing="$missing postgresql-16"
if [[ -n "$missing" ]]; then note "batterie PKI en cluster réel non exécutable ici (manque :$missing)"; finish; exit; fi

B="$(mktemp -d /srv/ddilive.XXXXXX)"; chmod 755 "$B"
cleanup() { pkill -u etcd -f "$B/" 2>/dev/null; pkill -9 -u postgres -f "$B/n" 2>/dev/null
  for _ in $(seq 1 20); do pgrep -u etcd -f "$B/" >/dev/null 2>&1 || break; sleep 0.5; done
  sleep 1; rm -rf "$B"; rm -rf "$T_TMP"; }
trap cleanup EXIT

ip() { echo "127.0.1.$1"; }
R() { echo "$B/n$1"; }
IMG=docker.io/keyfactor/ejbca-ce:9.6.3
HOST=pki.lab.test
KEY=/ddibuntu-cluster/pki/state
MARK=/ddibuntu-cluster/pki/updating

# Enrobages par nœud : cl N … (ddibuntu-cluster) et pki N … (ddibuntu-pki), chacun dans l'environnement du nœud et appelant l'autre par son propre enrobage
mkpki() {
  local n="$1" r d; r="$(R "$n")"; d="$B/d$n"
  mkdir -p "$d" "$r/etc/ddibuntu/pki" "$r/var/lib/ddibuntu/pki" "$r/etc/containers/systemd" "$r/var/lib/ddibuntu/generated/pki-in" "$r/run/ddibuntu"
  cat > "$d/podman" <<EOF
#!/bin/bash
echo "podman \$*" >> "$d/calls.log"
case "\$1 \$2" in
  "image exists") [ -f "$d/image.present" ] ;;
  "image inspect") echo "sha256:$(printf 'a%.0s' $(seq 64))" ;;
  *) [ "\$1" = pull ] && touch "$d/image.present"; exit 0 ;;
esac
EOF
  cat > "$d/systemctl" <<EOF
#!/bin/bash
echo "systemctl \$*" >> "$d/calls.log"
case "\$1" in
  is-active) [ -f "$d/active" ] ;;
  show) date -u -d "-20 seconds" '+%a %Y-%m-%d %H:%M:%S UTC' ;;
  start|restart) touch "$d/active" ;;
  stop) rm -f "$d/active" ;;
esac
EOF
  printf '#!/bin/bash\n{ echo "psql $*"; cat; } >> "%s/psql.log"\n' "$d" > "$d/psql"
  printf '#!/bin/bash\nif [ -f "%s/healthy" ]; then printf ALLOK; exit 0; fi\nexit 22\n' "$d" > "$d/curl"
  printf '#!/bin/bash\necho "fw $*" >> "%s/calls.log"\n' "$d" > "$d/fw"
  printf '#!/bin/bash\necho "systemd-run $*" >> "%s/sdrun.log"\n' "$d" > "$d/systemd-run"
  chmod 755 "$d"/*
  printf '#!/bin/sh\nexec env DDI_PKI_ALLOW_USER=1 DDI_LIBDIR=%s DDI_RUN_DIR=%s/run/ddibuntu DDI_GENERATED_DIR=%s/var/lib/ddibuntu/generated DDI_PKI_ETC=%s/etc/ddibuntu/pki DDI_PKI_DATA=%s/var/lib/ddibuntu/pki DDI_PKI_QUADLET_DIR=%s/etc/containers/systemd DDI_PKI_PODMAN=%s/podman DDI_PKI_SYSTEMCTL=%s/systemctl DDI_PKI_CURL=%s/curl DDI_FW_BIN=%s/fw DDI_PKI_PSQL=%s/psql DDI_PKI_LOCK=%s/lock DDI_PKI_PULL_LOCK=%s/pull.lock DDI_PKI_SYSTEMD_RUN=%s/systemd-run DDI_PKI_UID=%s DDI_PKI_NO_UPDATE_CHECK=1 DDI_CLUSTER_CONF=%s/etc/ddibuntu-cluster/cluster.conf DDI_CLUSTER_CMD=%s/cl%s.sh DDI_PKI_CLUSTER_LOCK_WAIT=${DDI_PKI_CLUSTER_LOCK_WAIT:-8} bash %s "$@"\n' \
    "$RFS/usr/local/lib/ddibuntu" "$r" "$r" "$r" "$r" "$r" "$d" "$d" "$d" "$d" "$d" "$d" "$d" "$d" "$(id -u)" "$r" "$B" "$n" "$PKI" > "$B/pki$n.sh"
  chmod 755 "$B/pki$n.sh"
}
mkwrap() {
  local n="$1" r; r="$(R "$n")"
  printf '#!/bin/sh\nexec env DDI_ROOT=%s DDI_TEST=1 DDI_PY=%s DDI_PG_SOCKET_DIR=/run/pg DDI_PG_LOCAL_LISTEN= DDI_PG_CONFIG_DIR= DDI_PKI_CMD=%s/pki%s.sh DDI_TEST_PATRONI_ROLE_FILE=%s/role%s bash %s "$@"\n' "$r" "$PY" "$B" "$n" "$B" "$n" "$CL" > "$B/cl$n.sh"
  chmod 755 "$B/cl$n.sh"
}
cl() { local n="$1"; shift; "$B/cl$n.sh" "$@"; }
clp() { local pw="$1" n="$2"; shift 2; DDI_BUNDLE_PASS="$pw" "$B/cl$n.sh" "$@"; }
pki() { local n="$1"; shift; "$B/pki$n.sh" "$@"; }
role() { printf '%s\n' "$2" > "$B/role$1"; }
mknode() { local r; r="$(R "$1")"; mkdir -p "$r/usr/lib" "$r/run/pg" "$r/var/lib/postgresql/16" "$r/var/lib/etcd" "$r/etc/ddibuntu" "$r/etc/bind" "$r/var/lib/ddibuntu/generated"
  ln -s /usr/lib/postgresql "$r/usr/lib/postgresql"
  chown -R postgres:postgres "$r/run/pg" "$r/var/lib/postgresql"; chmod 755 "$r" "$r/run" "$r/var" "$r/var/lib" "$r/etc"; mkwrap "$1"; mkpki "$1"; }
initdb_local() { runuser -u postgres -- "$PGBIN/initdb" -D "$(R "$1")/var/lib/postgresql/16/main" -E UTF8 --data-checksums >/dev/null 2>&1; }
start_etcd() { local r; r="$(R "$1")"; ( cd / && runuser -u etcd -- /usr/bin/etcd --config-file "$r/etc/ddibuntu-cluster/etcd.yml" >"$B/etcd$1.log" 2>&1 & ); }
stop_etcd() { pkill -u etcd -f "$(R "$1")/" 2>/dev/null; sleep 1; }
ectl() { local n="$1"; shift; local p; p="$(R "$n")/etc/ddibuntu-cluster/pki"; ETCDCTL_API=3 etcdctl --endpoints "https://$(ip "$n"):2379" --cacert "$p/ca.crt" --cert "$p/node.crt" --key "$p/node.key" "$@"; }
wait_for() { local s="$1" d="$2"; shift 2; local i=0; while [[ "$i" -lt "$s" ]]; do if "$@" >/dev/null 2>&1; then ok "$d (${i}s)"; return 0; fi; sleep 1; i=$((i + 1)); done; ko "$d" "délai de ${s}s dépassé"; return 1; }

ETC() { echo "$(R "$1")/etc/ddibuntu/pki"; }
DAT() { echo "$(R "$1")/var/lib/ddibuntu/pki"; }
QU() { echo "$(R "$1")/etc/containers/systemd/ddibuntu-ejbca.container"; }
RUNJ() { echo "$(R "$1")/run/ddibuntu"; }
active() { [[ -f "$B/d$1/active" ]] && echo yes || echo no; }
jget() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    d = d.get(k) if isinstance(d, dict) else None
print("" if d is None else d)' "$1" "$2" 2>/dev/null; }
cj() { jget "$(RUNJ "$1")/pki-cluster.json" "$2"; }       # pki-cluster.json publié par « align »
sj() { jget "$(RUNJ "$1")/pki-sync.json" "$2"; }          # pki-sync.json publié par « pki-sync »
res() { jget "$(RUNJ "$1")/pki-result.json" "$2"; }
req() { local n="$1"; printf '%s' "$2" > "$(R "$n")/var/lib/ddibuntu/generated/.pki-request"; pki "$n" request >/dev/null 2>&1; }
shaof() { sha256sum < "$1" | cut -d' ' -f1; }
synced() { cat "$(R "$1")/var/lib/ddibuntu/cluster/pki-synced" 2>/dev/null; }
tree() { ( cd "$1" 2>/dev/null && find . -name work -prune -o -type f -print0 | sort -z | xargs -0 sha256sum 2>/dev/null ); }
unit_of() { sed "s#$(R "$1")##g" "$(QU "$1")" | sha256sum | cut -d' ' -f1; }   # l'unité, sans le préfixe propre à chaque nœud simulé

echo "== Cluster : 3 etcd réels (n1 autorité + n2 données, n3 arbitre) =="
mknode 1; initdb_local 1
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -o "-c listen_addresses='' -c unix_socket_directories=$(R 1)/run/pg -c port=5432" -l "$(R 1)/run/pg/init.log" -w start >/dev/null 2>&1
check "init n1" cl 1 init --name n1 --ip "$(ip 1)" --net 127.0.0.0/8 --no-activate
runuser -u postgres -- "$PGBIN/pg_ctl" -D "$(R 1)/var/lib/postgresql/16/main" -m fast -w stop >/dev/null 2>&1
start_etcd 1; wait_for 20 "etcd n1 sain" ectl 1 endpoint health
check "activate n1" cl 1 activate
bundle() { cl 1 bundle --name "$1" --ip "$2" --role "$3" --out "$B/$1.bundle" 2>"$B/bundle-$1.err"; }
P2="$(bundle n2 "$(ip 2)" data)"; [[ -n "$P2" ]] && ok "lot n2 (données) créé" || ko "lot n2 créé" "$(cat "$B/bundle-n2.err")"; mknode 2; initdb_local 2
check "join n2 (données)" clp "$P2" 2 join "$B/n2.bundle" --wipe-local-db --no-activate
start_etcd 2; wait_for 30 "etcd n2 répond" ectl 2 endpoint status
check "activate n2" cl 2 activate
wait_for 60 "etcd : les deux membres sont sains" ectl 1 endpoint health --cluster
sleep 8
P3="$(bundle n3 "$(ip 3)" witness)"; [[ -n "$P3" ]] && ok "lot n3 (arbitre) créé" || ko "lot n3 (arbitre) créé" "$(cat "$B/bundle-n3.err")"; mknode 3
check "join n3 (arbitre)" clp "$P3" 3 join "$B/n3.bundle" --no-activate
start_etcd 3; wait_for 30 "etcd n3 répond" ectl 3 endpoint status
check "activate n3" cl 3 activate
role 1 leader; role 2 replica
expect_eq "n1 : rôle local = leader" "leader" "$(cl 1 role)"
expect_eq "n2 : rôle local = replica" "replica" "$(cl 2 role)"
expect_eq "n3 (arbitre) : rôle local = witness" "witness" "$(cl 3 role)"

echo "== Rien d'installé : synchronisation et alignement sans effet =="
check "pki-sync n1 sans PKI" cl 1 pki-sync
expect_eq "…aucune valeur publiée" "" "$(ectl 1 get "$KEY" --print-value-only)"
expect_eq "…état « à jour »" "synced" "$(sj 1 state)"
check "align n2 sans PKI" pki 2 align replica
expect_eq "…aucune unité écrite" "no" "$([[ -e "$(QU 2)" ]] && echo yes || echo no)"
expect_eq "…rien n'est installé (publié)" "False" "$(cj 2 installed)"
check "pki-sync n3 (arbitre) : sans effet" cl 3 pki-sync
expect_eq "…l'arbitre ne publie rien" "no" "$([[ -e "$(RUNJ 3)/pki-sync.json" ]] && echo yes || echo no)"

echo "== Garde-fous : seul le leader écrit =="
check_fail "n2 (secondaire) : installation refusée" pki 2 apply "$IMG" "$HOST" ""
expect_grep "…le message nomme le secondaire" "secondaire" /dev/stdin <<< "$(pki 2 apply "$IMG" "$HOST" "" 2>&1)"
check_fail "n3 (arbitre) : installation refusée" pki 3 apply "$IMG" "$HOST" ""
expect_grep "…le message nomme l'arbitre" "arbitre" /dev/stdin <<< "$(pki 3 apply "$IMG" "$HOST" "" 2>&1)"
check_fail "n2 : « start » refusé" pki 2 start
check_fail "n2 : remise à zéro refusée" pki 2 reset
req 2 '{"action":"apply","image":"'"$IMG"'","hostname":"'"$HOST"'","nets":[]}'
expect_eq "n2 : demande de la console refusée" "False" "$(res 2 ok)"
expect_grep "…avec une explication" "secondaire" "$(RUNJ 2)/pki-result.json"
req 2 '{"action":"status"}'
expect_eq "n2 : la demande « status » reste permise" "True" "$(res 2 ok)"
expect_eq "n2 : toujours rien d'installé" "no" "$([[ -e "$(ETC 2)/ejbca.env" ]] && echo yes || echo no)"

echo "== Installation sur le leader (n1) =="
req 1 '{"action":"apply","image":"'"$IMG"'","hostname":"'"$HOST"'","nets":["10.7.0.0/24"]}'
expect_eq "n1 : installation acceptée" "True" "$(res 1 ok)"
expect_eq "n1 : conteneur démarré" "yes" "$(active 1)"
expect_nogrep "n1 : l'unité n'a PAS de section [Install] (jamais démarrée par systemd au démarrage)" "^\[Install\]" "$(QU 1)"
expect_grep "n1 : l'unité tourne sur l'image épinglée" "^Image=docker.io/keyfactor/ejbca-ce@sha256:a{64}$" "$(QU 1)"
# fabrication de ce qu'EJBCA écrirait dans le volume et dans les métadonnées (clés TLS, copies de demandes)
mkdir -p "$(DAT 1)/persistent/secrets/tls" "$(DAT 1)/ca/RootDDI"
head -c 3000 /dev/urandom > "$(DAT 1)/persistent/secrets/tls/server.jks"; echo storepw > "$(DAT 1)/persistent/secrets/tls/server.storepasswd"
printf 'metadonnees\n' > "$(DAT 1)/ca/RootDDI/info.json"; chmod 600 "$(DAT 1)/persistent/secrets/tls/server.jks"
mkdir -p "$(DAT 1)/persistent/work"; echo transitoire > "$(DAT 1)/persistent/work/x"
pki 1 state-export "$B/x.state" > "$B/x.sha"
expect_eq "n1 : l'export d'état donne une empreinte de 64 caractères" "64" "$(wc -c < "$B/x.sha" | tr -d ' ')"
expect_eq "n1 : l'état exporté a la permission 0600" "600" "$(stat -c %a "$B/x.state")"
expect_eq "…le dossier d'échange (work) n'est jamais exporté" "0" "$(grep -c 'persistent/work' "$B/x.state")"
expect_eq "…l'état exporté encode les fichiers : le mot de passe de base n'y apparaît pas tel quel" "0" "$(grep -c "$(sed -n 's/^DATABASE_PASSWORD=//p' "$(ETC 1)/ejbca.env")" "$B/x.state")"
pki 1 state-export "$B/y.state" > "$B/y.sha"
expect_eq "n1 : l'export est déterministe (deux exports, même empreinte)" "$(cat "$B/x.sha")" "$(cat "$B/y.sha")"
touch -d '2001-01-01' "$(DAT 1)/ca/RootDDI/info.json"; pki 1 state-export "$B/z.state" > "$B/z.sha"
expect_eq "…indépendant des dates de fichiers" "$(cat "$B/x.sha")" "$(cat "$B/z.sha")"

echo "== Publication chiffrée dans etcd =="
check "n1 : pki-sync publie" cl 1 pki-sync
V="$(ectl 1 get "$KEY" --print-value-only)"
expect_eq "etcd : valeur v1 avec empreinte de 64 caractères" "1 64" "$(printf '%s' "$V" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["v"], len(d["sha"]))')"
expect_eq "etcd : l'empreinte est celle de l'état de n1" "$(cat "$B/x.sha")" "$(printf '%s' "$V" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')"
expect_eq "etcd : publié par n1" "n1" "$(printf '%s' "$V" | python3 -c 'import json,sys; print(json.load(sys.stdin)["by"])')"
expect_eq "etcd : le nom public n'apparaît pas en clair" "0" "$(printf '%s' "$V" | grep -c "$HOST")"
expect_eq "etcd : le mot de passe de base n'apparaît pas en clair" "0" "$(printf '%s' "$V" | grep -c "$(sed -n 's/^DATABASE_PASSWORD=//p' "$(ETC 1)/ejbca.env")")"
expect_eq "etcd : l'arbitre lit la même valeur chiffrée (et ne peut rien en faire)" "$V" "$(ectl 3 get "$KEY" --print-value-only)"
expect_eq "n1 : état synchronisé = état local" "$(cat "$B/x.sha")" "$(synced 1)"
expect_eq "n1 : état « publié »" "published" "$(sj 1 state)"
check "n1 : pki-sync idempotent" cl 1 pki-sync
expect_eq "n1 : à jour" "synced" "$(sj 1 state)"

echo "== Application sur le secondaire (n2) =="
check "n2 : pki-sync applique" cl 2 pki-sync
expect_eq "n2 : état appliqué" "applied" "$(sj 2 state)"
for f in ejbca.env instance.json; do expect_eq "n2 : $f identique octet pour octet" "$(shaof "$(ETC 1)/$f")" "$(shaof "$(ETC 2)/$f")"; done
expect_eq "n2 : ejbca.env en 0600" "600" "$(stat -c %a "$(ETC 2)/ejbca.env")"
expect_eq "n2 : métadonnées des autorités identiques" "$(tree "$(DAT 1)/ca")" "$(tree "$(DAT 2)/ca")"
expect_eq "n2 : volume identique (clés TLS d'EJBCA)" "$(tree "$(DAT 1)/persistent")" "$(tree "$(DAT 2)/persistent")"
expect_eq "n2 : clé TLS en 0600" "600" "$(stat -c %a "$(DAT 2)/persistent/secrets/tls/server.jks")"
expect_eq "n2 : le conteneur n'est pas démarré par la synchronisation" "no" "$(active 2)"
expect_eq "n2 : état synchronisé" "$(cat "$B/x.sha")" "$(synced 2)"
check "n2 : pki-sync idempotent" cl 2 pki-sync
expect_eq "n2 : à jour" "synced" "$(sj 2 state)"

echo "== n2 se prépare en veille : unité écrite, image tirée en arrière-plan, pare-feu prêt, conteneur arrêté =="
check "n2 : align replica" pki 2 align replica
expect_eq "n2 : unité Quadlet écrite" "yes" "$([[ -e "$(QU 2)" ]] && echo yes || echo no)"
expect_nogrep "n2 : …sans section [Install]" "^\[Install\]" "$(QU 2)"
expect_eq "n2 : unité identique à celle de n1 (au préfixe du nœud près)" "$(unit_of 1)" "$(unit_of 2)"
expect_eq "n2 : conteneur arrêté" "no" "$(active 2)"
expect_eq "n2 : image absente → tirage lancé en arrière-plan" "pulling" "$(cj 2 image)"
expect_grep "n2 : …par systemd-run, jamais sous le verrou général" "pull-image" "$B/d2/sdrun.log"
expect_eq "n2 : rôle publié" "replica" "$(cj 2 role)"
expect_grep "n2 : pare-feu préparé pour les réseaux de la PKI" "fw set PKI_NETS 10.7.0.0/24" "$B/d2/calls.log"
check "n2 : le tirage (pull-image) se fait sans le verrou général" pki 2 pull-image
expect_eq "n2 : l'image est présente" "yes" "$([[ -f "$B/d2/image.present" ]] && echo yes || echo no)"
check "n2 : align replica (image prête)" pki 2 align replica
expect_eq "n2 : image prête" "ready" "$(cj 2 image)"
expect_eq "n2 : toujours arrêté" "no" "$(active 2)"
expect_eq "n2 : unité inactive publiée" "inactive" "$(cj 2 unit)"

echo "== Préparation de chaque nœud, publiée dans etcd (visible dans « status ») =="
check "n1 : align leader (déjà en marche)" pki 1 align leader
check "n1 : follow (pki-sync + alignement + préparation)" cl 1 follow
check "n2 : follow (pki-sync + alignement + préparation)" cl 2 follow
ST="$(cl 1 status 2>/dev/null)"
expect_eq "status : la PKI du cluster est « activée »" "True" "$(printf '%s' "$ST" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ejbca"]["enabled"])')"
expect_eq "status : n1 prêt (leader, unité active)" "leader active" "$(printf '%s' "$ST" | python3 -c 'import json,sys; n=json.load(sys.stdin)["ejbca"]["nodes"]["n1"]; print(n["role"], n["unit"])')"
expect_eq "status : n2 prêt à reprendre (secondaire, image prête, état synchronisé)" "replica inactive ready $(cut -c1-12 "$B/x.sha")" "$(printf '%s' "$ST" | python3 -c 'import json,sys; n=json.load(sys.stdin)["ejbca"]["nodes"]["n2"]; print(n["role"], n["unit"], n["image"], n["synced"])')"
expect_eq "status : l'état d'etcd est désigné (12 caractères)" "$(cut -c1-12 "$B/x.sha")" "$(printf '%s' "$ST" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ejbca"]["state"]["sha"])')"
expect_eq "status : aucune marque de mise à jour" "None" "$(printf '%s' "$ST" | python3 -c 'import json,sys; print(json.load(sys.stdin)["ejbca"]["mark"])')"
expect_eq "status : le contenu chiffré n'est jamais publié" "0" "$(printf '%s' "$ST" | grep -c '"blob"')"
expect_eq "status (arbitre) : pas de bloc PKI" "None" "$(cl 3 status 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["ejbca"])')"

echo "== Bascule : n2 devient leader, n1 secondaire =="
role 1 replica; role 2 leader
check "n1 (ancien leader) : follow" cl 1 follow
expect_eq "n1 : le conteneur est arrêté (la PKI ne tourne que sur le leader)" "no" "$(active 1)"
expect_eq "n1 : rôle publié = replica" "replica" "$(cj 1 role)"
expect_eq "n1 : ses secrets et ses données sont conservés (reprise possible)" "yes" "$([[ -e "$(ETC 1)/ejbca.env" ]] && [[ -e "$(DAT 1)/persistent/secrets/tls/server.jks" ]] && echo yes || echo no)"
check "n2 (promu) : follow" cl 2 follow
expect_eq "n2 : le conteneur démarre" "yes" "$(active 2)"
expect_grep "n2 : la base « ejbca » est vérifiée avant le démarrage" "create role ejbca" "$B/d2/psql.log"
expect_eq "n2 : rôle publié = leader" "leader" "$(cj 2 role)"
check "n2 : follow suivant : rien ne change (pas de redémarrage)" cl 2 follow
expect_eq "n2 : un seul démarrage au total" "1" "$(grep -c '^systemctl start' "$B/d2/calls.log")"
check "n1 : pki-sync (l'état n'a pas changé)" cl 1 pki-sync
expect_eq "n1 : à jour" "synced" "$(sj 1 state)"

echo "== Le leader peut agir ; une action est publiée sans attendre la minute suivante =="
check "n2 : pki-sync (leader, état inchangé)" cl 2 pki-sync
req 2 '{"action":"stop"}'
expect_eq "n2 : arrêt demandé par l'administrateur accepté" "True" "$(res 2 ok)"
expect_eq "n2 : conteneur arrêté" "no" "$(active 2)"
expect_eq "n2 : consigne d'arrêt écrite" "stopped" "$(tr -d '\n' < "$(ETC 2)/desired")"
expect_grep "n2 : la console déclenche aussitôt la synchronisation (systemd-run … pki-sync)" "pki-sync" "$B/d2/sdrun.log"
check "n2 : follow ne redémarre pas une PKI arrêtée volontairement" cl 2 follow
expect_eq "n2 : toujours arrêté" "no" "$(active 2)"
expect_eq "n2 : publié avec la consigne d'arrêt" "stopped" "$(cj 2 desired)"
expect_eq "etcd : la consigne d'arrêt a été publiée (nouvelle empreinte)" "$(synced 2)" "$(ectl 2 get "$KEY" --print-value-only | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')"
check "n1 : pki-sync reçoit la consigne" cl 1 pki-sync
expect_eq "n1 : consigne d'arrêt répliquée" "stopped" "$(tr -d '\n' < "$(ETC 1)/desired")"

echo "== L'arrêt volontaire survit à une bascule =="
role 1 leader; role 2 replica
check "n2 : follow (devient secondaire)" cl 2 follow
check "n1 : follow (devient leader)" cl 1 follow
expect_eq "n1 : leader mais la PKI reste arrêtée (consigne de l'administrateur)" "no" "$(active 1)"
expect_eq "n1 : consigne publiée" "stopped" "$(cj 1 desired)"
req 1 '{"action":"start"}'
expect_eq "n1 : démarrage demandé accepté" "True" "$(res 1 ok)"
expect_eq "n1 : conteneur démarré" "yes" "$(active 1)"
expect_eq "n1 : consigne d'arrêt levée" "no" "$([[ -e "$(ETC 1)/desired" ]] && echo yes || echo no)"
check "n1 : publie la levée de la consigne" cl 1 pki-sync
check "n2 : la reçoit" cl 2 pki-sync
expect_eq "n2 : consigne levée aussi" "no" "$([[ -e "$(ETC 2)/desired" ]] && echo yes || echo no)"

echo "== Mise à jour interrompue : la marque d'etcd bloque tout démarrage automatique =="
check "n1 : pose la marque" cl 1 pki-mark set 9.6.3 9.6.4
V="$(ectl 3 get "$MARK" --print-value-only)"
expect_eq "etcd : la marque est lisible par l'arbitre (sans secret)" "n1" "$(cl 3 pki-mark get | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"])')"
expect_eq "…version de départ et d'arrivée" "9.6.3 9.6.4" "$(cl 3 pki-mark get | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["from"], d["to"])')"
check "n1 : repose la même marque (idempotent)" cl 1 pki-mark set 9.6.3 9.6.4
check_fail "n2 : ne peut pas poser la marque d'un autre nœud" cl 2 pki-mark set 9.6.3 9.6.5
expect_grep "…le refus nomme n1" "n1" /dev/stdin <<< "$(cl 2 pki-mark set 9.6.3 9.6.5 2>&1)"
check_fail "n2 : ne peut pas retirer la marque d'un autre nœud" cl 2 pki-mark clear
check_fail "valeurs de marque piégées refusées" cl 1 pki-mark set '9.6.3;id' 9.6.4
# bascule pendant la mise à jour : le nouveau leader (n2) ne démarre rien
rm -f "$B/d2/active"; role 1 replica; role 2 leader
check "n1 : follow (secondaire, arrêt)" cl 1 follow
check "n2 : follow (leader, marque présente)" cl 2 follow
expect_eq "n2 : la PKI ne démarre PAS sur une base peut-être à moitié migrée" "no" "$(active 2)"
expect_eq "n2 : blocage publié" "update-interrupted" "$(cj 2 blocked.reason)"
expect_eq "n2 : blocage attribué à n1" "n1" "$(cj 2 blocked.node)"
expect_grep "n2 : le journal explique et indique la commande" "cluster-unblock" /dev/stdin <<< "$(pki 2 align leader 2>&1)"
cl 2 pki-sync >/dev/null 2>&1; cl 2 follow >/dev/null 2>&1
expect_eq "status : la marque est visible" "n1" "$(cl 2 status 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["ejbca"]["mark"]["node"])')"
check "n2 : cluster-unblock (après vérification)" pki 2 cluster-unblock
expect_eq "…marque retirée" "" "$(cl 2 pki-mark get)"
check "n2 : follow redémarre normalement" cl 2 follow
expect_eq "n2 : conteneur démarré" "yes" "$(active 2)"
expect_eq "n2 : plus de blocage" "" "$(cj 2 blocked.reason)"

echo "== Mise à jour sous marque : une mise à jour refusée avant toute action ne laisse pas de marque =="
check_fail "n2 : update-apply d'une image piégée est refusé" pki 2 update-apply docker.io/evil/x:1.2.3
expect_eq "…aucune marque n'est restée" "" "$(cl 2 pki-mark get)"
check_fail "n1 (secondaire) : update-apply refusé" pki 1 update-apply docker.io/keyfactor/ejbca-ce:9.6.4
mkdir -p "$(ETC 2)/update"; printf '{"state":"running","from":"9.6.3","to":"9.6.4"}' > "$(ETC 2)/update/job.json"
check_fail "n2 : mise à jour interrompue localement : refus d'en lancer une autre" pki 2 update-apply docker.io/keyfactor/ejbca-ce:9.6.4
expect_eq "…la marque RESTE (état local « running »)" "n2" "$(cl 2 pki-mark get | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"])')"
check "n2 : align (bloqué)" pki 2 align leader
expect_eq "…bloqué : update-interrupted" "update-interrupted" "$(cj 2 blocked.reason)"
rm -f "$(ETC 2)/update/job.json"; pki 2 cluster-unblock >/dev/null 2>&1

echo "== Retrait de la PKI (désinstallation) propagé =="
req 2 '{"action":"uninstall"}'
expect_eq "n2 : désinstallation acceptée" "True" "$(res 2 ok)"
check "n2 : publie" cl 2 pki-sync
check "n1 : reçoit" cl 1 pki-sync
expect_eq "n1 : instance.json retiré" "no" "$([[ -e "$(ETC 1)/instance.json" ]] && echo yes || echo no)"
expect_eq "n1 : secrets et données conservés (comme sur n2)" "yes" "$([[ -e "$(ETC 1)/ejbca.env" ]] && echo yes || echo no)"
check "n1 : align replica" pki 1 align replica
expect_eq "n1 : unité retirée" "no" "$([[ -e "$(QU 1)" ]] && echo yes || echo no)"
expect_eq "n1 : pare-feu refermé" "yes" "$(grep -c 'fw set PKI_NETS $' "$B/d1/calls.log" | awk '{print ($1>0)?"yes":"no"}')"
expect_eq "n1 : publié « non installé »" "False" "$(cj 1 installed)"

echo "== Réinstallation puis remise à zéro (aucune autorité) propagées =="
req 2 '{"action":"apply","image":"'"$IMG"'","hostname":"'"$HOST"'","nets":["10.7.0.0/24"]}'
expect_eq "n2 : réinstallation (secrets conservés)" "True" "$(res 2 ok)"
check "n2 : publie" cl 2 pki-sync
check "n1 : reçoit" cl 1 pki-sync
expect_eq "n1 : instance.json de retour" "$(shaof "$(ETC 2)/instance.json")" "$(shaof "$(ETC 1)/instance.json")"
req 2 '{"action":"reset"}'
expect_eq "n2 : remise à zéro acceptée" "True" "$(res 2 ok)"
expect_eq "n2 : secrets effacés" "no" "$([[ -e "$(ETC 2)/ejbca.env" ]] && echo yes || echo no)"
check "n2 : publie « none »" cl 2 pki-sync
expect_eq "etcd : état « none »" "none" "$(ectl 2 get "$KEY" --print-value-only | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')"
check "n1 : reçoit « none »" cl 1 pki-sync
expect_eq "n1 : secrets mis de côté, plus en service" "no" "$([[ -e "$(ETC 1)/ejbca.env" ]] && echo yes || echo no)"
expect_eq "n1 : les états remplacés sont gardés de côté (14 jours) : retrait de l'instance, puis remise à zéro" "2" "$(ls -d "$(ETC 1)"/pre-restore.sync.* 2>/dev/null | wc -l)"
expect_eq "n1 : copie de côté en 0700" "700" "$(stat -c %a "$(ls -d "$(ETC 1)"/pre-restore.sync.* | head -n1)")"
check "n1 : align replica (plus rien à préparer)" pki 1 align replica
expect_eq "n1 : unité retirée" "no" "$([[ -e "$(QU 1)" ]] && echo yes || echo no)"
expect_eq "n1 : à jour" "none" "$(synced 1)"

echo "== Nouvelle installation sur n2 pour les essais hostiles =="
rm -f "$B/d1/active" "$B/d2/active"
req 2 '{"action":"apply","image":"'"$IMG"'","hostname":"'"$HOST"'","nets":[]}'
expect_eq "n2 : installation" "True" "$(res 2 ok)"
mkdir -p "$(DAT 2)/persistent/secrets/tls" "$(DAT 2)/ca"; echo k > "$(DAT 2)/persistent/secrets/tls/server.jks"
check "n2 publie" cl 2 pki-sync
check "n1 applique" cl 1 pki-sync
GOOD="$(tree "$(ETC 1)")$(tree "$(DAT 1)")"; GOODV="$(ectl 1 get "$KEY" --print-value-only)"
hostile() { printf '%s' "$1" | ectl 1 put "$KEY" >/dev/null 2>&1; }
enc_value() {   # enc_value JSON_ÉTAT → valeur d'etcd chiffrée avec la bonne clé d'enveloppe de n1, empreinte annoncée = celle du clair
  local plain="$1" pass gh; pass="$(SECRET="$(sed -n 's/^ *secret "\([A-Za-z0-9+\/=]*\)";$/\1/p' "$(R 1)/etc/bind/ddi-xfr.key")" python3 -c 'import hashlib,hmac,os; print(hmac.new(os.environ["SECRET"].encode(), b"ddibuntu-pki-state-v1", hashlib.sha256).hexdigest(), end="")')"
  gh="$(mktemp -d)"; printf '%s' "$plain" > "$gh/p"
  gpg --homedir "$gh" --batch --quiet --yes --pinentry-mode loopback --passphrase "$pass" --symmetric --cipher-algo AES256 -o "$gh/b" "$gh/p" 2>/dev/null
  PLAIN="$plain" python3 -c 'import base64,hashlib,json,os,sys; print(json.dumps({"v":1,"sha":hashlib.sha256(os.environ["PLAIN"].encode()).hexdigest(),"blob":base64.b64encode(open(sys.argv[1],"rb").read()).decode(),"by":"n2","at":1}), end="")' "$gh/b"
  rm -rf "$gh"
}
unchanged() { [[ "$(tree "$(ETC 1)")$(tree "$(DAT 1)")" = "$GOOD" ]] && echo yes || echo no; }
echo "== Valeurs hostiles dans etcd (n1, secondaire, ne doit rien appliquer) =="
hostile 'pas du json'
check_fail "valeur illisible : refusée" cl 1 pki-sync
expect_eq "…état local inchangé" "yes" "$(unchanged)"
hostile '{"v":1,"sha":"zz","blob":""}'
check_fail "empreinte invalide : refusée" cl 1 pki-sync
hostile '{"v":2,"sha":"none","blob":""}'
check_fail "version inconnue : refusée" cl 1 pki-sync
TAMP="$(printf '%s' "$GOODV" | python3 -c 'import base64,json,sys; d=json.load(sys.stdin); b=bytearray(base64.b64decode(d["blob"])); b[len(b)//2]^=1; d["blob"]=base64.b64encode(bytes(b)).decode(); d["sha"]="0"*64; print(json.dumps(d), end="")')"
hostile "$TAMP"
check_fail "blob altéré : refusé" cl 1 pki-sync
expect_eq "…état local toujours inchangé" "yes" "$(unchanged)"
OTHER="$(printf '%s' "$GOODV" | python3 -c 'import json,sys; d=json.load(sys.stdin); d["sha"]="1"*64; print(json.dumps(d), end="")')"
hostile "$OTHER"
check_fail "empreinte annoncée fausse : refusée" cl 1 pki-sync
mkdir -p "$B/alien/etc/bind"; printf 'key "ddi-xfr" {\n    algorithm hmac-sha256;\n    secret "%s";\n};\n' "$(openssl rand -base64 32)" > "$B/alien/etc/bind/ddi-xfr.key"
ALIEN="$(sed -n 's/.*/&/p' <<< "$GOODV" | python3 -c '
import base64, hashlib, hmac, json, subprocess, sys, tempfile, os
d = json.load(sys.stdin)
secret = [l for l in open(sys.argv[1]).read().split("\"") if len(l) > 20][0]
passw = hmac.new(secret.encode(), b"ddibuntu-pki-state-v1", hashlib.sha256).hexdigest()
gh = tempfile.mkdtemp(); open(gh + "/p", "wb").write(b"x")
subprocess.run(["gpg", "--homedir", gh, "--batch", "--quiet", "--yes", "--pinentry-mode", "loopback", "--passphrase", passw, "--symmetric", "--cipher-algo", "AES256", "-o", gh + "/b", gh + "/p"], check=True, stderr=subprocess.DEVNULL)
d["blob"] = base64.b64encode(open(gh + "/b", "rb").read()).decode(); d["sha"] = hashlib.sha256(b"x").hexdigest()
print(json.dumps(d), end="")' "$B/alien/etc/bind/ddi-xfr.key")"
hostile "$ALIEN"
check_fail "chiffré avec une autre clé de cluster : refusé" cl 1 pki-sync
expect_eq "…état local toujours inchangé" "yes" "$(unchanged)"
expect_eq "…la console voit l'échec" "failed" "$(sj 1 state)"
# correctement chiffré mais dangereux : c'est ddibuntu-pki (state-extract) qui refuse, sans rien toucher
bad_state() { python3 -c 'import base64, json, sys
env = base64.b64encode(b"PASSWORD_ENCRYPTION_KEY=x\n").decode()
files = {"etc/ejbca.env": {"m": 384, "d": env}}
files.update(json.loads(sys.argv[1]))
print(json.dumps({"v": 1, "kind": "pki-state", "dirs": {}, "files": files}, sort_keys=True, separators=(",", ":")), end="")' "$1"; }
x() { printf '%s' "$1" | base64 -w0; }
hostile "$(enc_value "$(bad_state '{"etc/../evil":{"m":384,"d":"eA=="}}')")"
check_fail "chemin « .. » dans l'état : refusé par ddibuntu-pki" cl 1 pki-sync
expect_eq "…état local inchangé" "yes" "$(unchanged)"
expect_eq "…rien n'a été écrit hors des dossiers de la PKI" "no" "$([[ -e "$(R 1)/etc/ddibuntu/evil" ]] && echo yes || echo no)"
hostile "$(enc_value "$(bad_state '{"etc/desired":{"m":384,"d":"'"$(x 'rm -rf /')"'"}}')")"
check_fail "consigne inconnue : refusée" cl 1 pki-sync
hostile "$(enc_value "$(bad_state '{"data/persistent/work/a":{"m":384,"d":"eA=="}}')")"
check_fail "dossier d'échange dans l'état : refusé" cl 1 pki-sync
expect_eq "…état local toujours inchangé" "yes" "$(unchanged)"
check_fail "…refusé à chaque échéance (jamais republié à la place par un secondaire)" cl 1 pki-sync
expect_eq "…la valeur hostile n'a pas été remplacée par n1" "$(enc_value "$(bad_state '{"data/persistent/work/a":{"m":384,"d":"eA=="}}')" | python3 -c 'import json,sys; print(json.load(sys.stdin)["by"])')" "$(ectl 1 get "$KEY" --print-value-only | python3 -c 'import json,sys; print(json.load(sys.stdin)["by"])')"

echo "== Reprise : le leader republie, le secondaire revient à l'état du cluster =="
role 1 replica; role 2 leader
printf 'modif\n' >> "$(DAT 2)/ca/note.txt"
check "n2 (leader) : republie son état" cl 2 pki-sync
expect_eq "n2 : état publié" "published" "$(sj 2 state)"
check "n1 : applique" cl 1 pki-sync
expect_eq "n1 : revenu à l'état du cluster" "$(tree "$(DAT 2)/ca")" "$(tree "$(DAT 1)/ca")"
GOODV="$(ectl 1 get "$KEY" --print-value-only)"

echo "== Un secondaire ne publie JAMAIS =="
printf 'dérive locale\n' > "$(DAT 1)/ca/derive.txt"
check "n1 (secondaire) : pki-sync revient à l'état du cluster" cl 1 pki-sync
expect_eq "…la dérive locale est écartée" "no" "$([[ -e "$(DAT 1)/ca/derive.txt" ]] && echo yes || echo no)"
expect_eq "…etcd n'a pas changé" "$GOODV" "$(ectl 1 get "$KEY" --print-value-only)"
expect_eq "…l'état écarté est conservé de côté" "yes" "$(ls -d "$(ETC 1)"/pre-restore.sync.* >/dev/null 2>&1 && echo yes || echo no)"

echo "== Premier contact d'un nouveau secondaire : le cluster gagne, sans rien publier =="
rm -rf "$(ETC 1)/ejbca.env" "$(ETC 1)/instance.json" "$(DAT 1)" "$(R 1)/var/lib/ddibuntu/cluster/pki-synced"
check "n1 : pki-sync (rien en local, rien de synchronisé)" cl 1 pki-sync
expect_eq "n1 : l'état du cluster est appliqué" "applied" "$(sj 1 state)"
expect_eq "n1 : identique à n2" "$(shaof "$(ETC 2)/ejbca.env")" "$(shaof "$(ETC 1)/ejbca.env")"
expect_eq "…etcd inchangé" "$GOODV" "$(ectl 1 get "$KEY" --print-value-only)"

echo "== Promu sans état local (jamais synchronisé) : applique, ne publie pas « none » =="
rm -rf "$(ETC 1)/ejbca.env" "$(ETC 1)/instance.json" "$(DAT 1)" "$(R 1)/var/lib/ddibuntu/cluster/pki-synced"
role 1 leader; role 2 replica
check "n1 (leader, vide) : pki-sync" cl 1 pki-sync
expect_eq "n1 : a reçu l'état du cluster" "applied" "$(sj 1 state)"
expect_eq "…etcd non écrasé" "$GOODV" "$(ectl 1 get "$KEY" --print-value-only)"

echo "== Conflit : deux PKI différentes (leader avec la sienne, jamais synchronisé) =="
rm -f "$(R 1)/var/lib/ddibuntu/cluster/pki-synced"
printf '\n# autre\n' >> "$(ETC 1)/ejbca.env"
check_fail "n1 : refus d'écraser l'un ou l'autre" cl 1 pki-sync
expect_eq "…état « conflict » signalé" "conflict" "$(sj 1 state)"
expect_eq "…etcd inchangé" "$GOODV" "$(ectl 1 get "$KEY" --print-value-only)"
expect_eq "…état local inchangé" "yes" "$(grep -q '^# autre' "$(ETC 1)/ejbca.env" && echo yes || echo no)"
# retour à la normale : on rétablit l'état du cluster
cp "$(ETC 2)/ejbca.env" "$(ETC 1)/ejbca.env"; printf '%s\n' "$(cat "$B/x.sha")" > /dev/null; ectl 1 get "$KEY" --print-value-only | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])' > "$(R 1)/var/lib/ddibuntu/cluster/pki-synced"
check "n1 : de nouveau à jour" cl 1 pki-sync

echo "== etcd injoignable =="
stop_etcd 2
check "n2 sans etcd : pki-sync ne casse rien" cl 2 pki-sync
expect_eq "…état « failed » signalé" "failed" "$(sj 2 state)"
rm -f "$B/d2/active"; role 2 leader
check "n2 sans etcd : align leader ne démarre rien (marque illisible)" pki 2 align leader
expect_eq "…le conteneur n'est pas démarré à l'aveugle" "no" "$(active 2)"
expect_eq "…blocage publié" "cluster-unreachable" "$(cj 2 blocked.reason)"
start_etcd 2; wait_for 30 "etcd n2 revenu" ectl 2 endpoint health
check "n2 : align leader (etcd revenu)" pki 2 align leader
expect_eq "n2 : démarre" "yes" "$(active 2)"

echo "== Verrou général occupé : les commandes du cluster n'attendent pas =="
( flock 9; sleep 25 ) 9>"$B/d2/lock" &
holder=$!; sleep 1
rc=0; DDI_PKI_CLUSTER_LOCK_WAIT=1 pki 2 state-export "$B/busy.state" >/dev/null 2>&1 || rc=$?
expect_eq "state-export : code 75 (occupé), pas d'attente de 10 minutes" "75" "$rc"
rc=0; DDI_PKI_CLUSTER_LOCK_WAIT=1 pki 2 align leader >/dev/null 2>&1 || rc=$?
expect_eq "align : code 75" "75" "$rc"
check "pki-sync pendant une opération PKI : reporté sans erreur" bash -c "DDI_PKI_CLUSTER_LOCK_WAIT=1 '$B/cl2.sh' pki-sync"
expect_eq "…état « busy »" "busy" "$(sj 2 state)"
kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
check "pull-image ne prend pas le verrou général" bash -c "( flock 9; sleep 3 ) 9>'$B/d2/lock' & sleep 0.5; '$B/pki2.sh' pull-image; wait"

echo "== Aucun secret résiduel =="
expect_eq "dossiers temporaires de pki-sync (n1)" "0" "$(ls -d "$(R 1)"/var/lib/ddibuntu/cluster/.pki.* 2>/dev/null | wc -l)"
expect_eq "dossiers temporaires de pki-sync (n2)" "0" "$(ls -d "$(R 2)"/var/lib/ddibuntu/cluster/.pki.* 2>/dev/null | wc -l)"
expect_eq "dossiers temporaires de ddibuntu-pki (mémoire partagée)" "0" "$(ls -d /dev/shm/ddi-pki.* 2>/dev/null | wc -l)"
expect_eq "fichiers d'état exportés laissés par ddibuntu-pki" "0" "$(find "$(R 1)" "$(R 2)" -name '*.part' 2>/dev/null | wc -l)"

finish
