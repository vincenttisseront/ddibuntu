#!/usr/bin/env bash
# Batterie 41 — la PKI dans le cluster (0.14.9) sur le VRAI conteneur EJBCA : le transport de l'état suffit-il à reprendre la PKI sur un autre nœud ?
# On ne dispose ici que d'une machine : les deux « nœuds » partagent donc le même PostgreSQL (dans un vrai cluster, Patroni réplique la base « ejbca » avec le reste).
# Ce qu'on vérifie avec le vrai conteneur : une PKI installée, avec des autorités, est EXPORTÉE (état déterministe) ; le « nœud » est ensuite VIDÉ de tout ce qui n'est pas la base
# (secrets, instance, métadonnées, volume, unité) ; l'état est IMPORTÉ ; « align leader » écrit l'unité, démarre le conteneur, qui retrouve ses autorités avec les mêmes secrets
# (une signature de CRL par la CLI le prouve : la clé de l'autorité se déchiffre) ; « align replica » l'arrête ; le même état est réimporté sans effet ; un volume perdu n'empêche pas
# EJBCA de repartir (il régénère son keystore TLS).
# DESTRUCTIVE : supprime la base « ejbca » et le conteneur « ddibuntu-ejbca » de la machine ; exige DDI_TEST_PKI_LIVE=1.
# Prérequis : ceux de la batterie 37 (root, podman + image docker.io/keyfactor/ejbca-ce:9.6.3 présente, PostgreSQL local, openssl, curl, port 8080 libre, ~2 Go de mémoire). Durée : ~10 minutes.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

PKI="$RFS/usr/local/sbin/ddibuntu-pki"
IMG="docker.io/keyfactor/ejbca-ce:9.6.3"
read -r -a PARGS <<< "${DDI_TEST_PODMAN_ARGS:-}"
if [[ "${DDI_TEST_PKI_LIVE:-}" != 1 ]]; then note "DDI_TEST_PKI_LIVE=1 absent (la batterie supprime la base « ejbca » et le conteneur « ddibuntu-ejbca ») : ignorée"; finish; exit $?; fi
if [[ "$(id -u)" -ne 0 ]] || ! command -v podman >/dev/null || ! command -v openssl >/dev/null || ! command -v curl >/dev/null || ! command -v runuser >/dev/null \
   || [[ ! -x /usr/lib/systemd/system-generators/podman-system-generator ]]; then
  note "prérequis absents (root, podman et son générateur Quadlet, openssl, curl, runuser) : batterie ignorée"; finish; exit $?
fi
if ! podman "${PARGS[@]}" image exists "$IMG" >/dev/null 2>&1; then note "image $IMG absente (la batterie ne tire rien) : ignorée"; finish; exit $?; fi
if curl -s --noproxy '*' -m 2 -o /dev/null http://127.0.0.1:8080/ 2>/dev/null; then note "le port 8080 est déjà utilisé : batterie ignorée"; finish; exit $?; fi
if ! runuser -u postgres -- psql -X -q -At -d postgres -c 'select 1' >/dev/null 2>&1; then note "PostgreSQL local injoignable : batterie ignorée"; finish; exit $?; fi

D="$T_TMP"; chmod 0755 "$D"
mkdir -p "$D/bin" "$D/etc" "$D/data" "$D/quad" "$D/run" "$D/gen/pki-in" "$D/cl"
GEN="$D/gen"; RUNP="$D/run"
cat > "$D/bin/podman" <<EOF
#!/bin/bash
exec /usr/bin/podman ${PARGS[*]} "\$@"
EOF
cat > "$D/bin/systemctl" <<EOF
#!/bin/bash
P="$D/bin/podman"
case "\$1" in
  daemon-reload) exit 0 ;;
  start|restart)
    [ "\$1" = restart ] && "\$P" stop -t 60 ddibuntu-ejbca >/dev/null 2>&1
    "\$P" rm -f ddibuntu-ejbca >/dev/null 2>&1
    cmd="\$(QUADLET_UNIT_DIRS="$D/quad" /usr/lib/systemd/system-generators/podman-system-generator --dryrun 2>/dev/null | sed -n 's/^ExecStart=//p' | head -n1)"
    [ -n "\$cmd" ] || exit 1
    cmd="\${cmd/\\/usr\\/bin\\/podman/\$P}"; cmd="\${cmd//%t/$D/run}"; cmd="\${cmd//%N/ddibuntu-ejbca}"; cmd="\${cmd/--cgroups=split/--cgroups=enabled}"
    eval "\$cmd" >"$D/start.out" 2>&1 9>&- || { cat "$D/start.out" >&2; exit 1; } ;;
  stop) "\$P" stop -t 90 ddibuntu-ejbca >/dev/null 2>&1; "\$P" rm -f ddibuntu-ejbca >/dev/null 2>&1; exit 0 ;;
  is-active) [ "\$("\$P" inspect -f '{{.State.Running}}' ddibuntu-ejbca 2>/dev/null)" = true ] ;;
  show) "\$P" inspect -f '{{.State.StartedAt}}' ddibuntu-ejbca 2>/dev/null | sed 's/ +0000 UTC//' ;;
  *) exit 0 ;;
esac
EOF
# « ddibuntu-cluster » simulé : ce nœud est le leader (role), aucune marque de mise à jour (pki-mark)
cat > "$D/bin/cluster" <<EOF
#!/bin/bash
echo "\$*" >> "$D/cluster.calls"
case "\$1" in
  role) cat "$D/cl/role" ;;
  pki-mark) case "\$2" in get) exit 0 ;; *) exit 0 ;; esac ;;
  *) exit 0 ;;
esac
EOF
printf '%s\n' leader > "$D/cl/role"; : > "$D/cl/cluster.conf"
cat > "$D/bin/systemd-run" <<EOF
#!/bin/bash
echo "systemd-run \$*" >> "$D/sdrun.log"
EOF
chmod +x "$D/bin/podman" "$D/bin/systemctl" "$D/bin/cluster" "$D/bin/systemd-run"
export DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_PKI_ETC="$D/etc" DDI_PKI_DATA="$D/data" DDI_PKI_QUADLET_DIR="$D/quad"
export DDI_PKI_PODMAN="$D/bin/podman" DDI_PKI_SYSTEMCTL="$D/bin/systemctl" DDI_PKI_LOCK="$D/lock" DDI_FW_BIN="$D/nofw" DDI_PKI_UID=10001
export DDI_GENERATED_DIR="$GEN" DDI_RUN_DIR="$RUNP" DDI_CLUSTER_CONF="$D/cl/cluster.conf" DDI_CLUSTER_CMD="$D/bin/cluster" DDI_PKI_SYSTEMD_RUN="$D/bin/systemd-run" DDI_PKI_PULL_LOCK="$D/pull.lock"
export DDI_PKI_NO_UPDATE_CHECK=1
unset DDI_PKI_PSQL DDI_PKI_ALLOW_USER DDI_PKI_PGDUMP DDI_PKI_PGRESTORE DDI_PKI_HUB_URL

psql_pg() { runuser -u postgres -- psql -X -q -At -d postgres "$@"; }
reset_all() {
  "$D/bin/podman" rm -f ddibuntu-ejbca >/dev/null 2>&1
  psql_pg -c 'drop database if exists ejbca with (force)' -c 'drop role if exists ejbca' >/dev/null 2>&1
}
trap 'reset_all; rm -rf "$T_TMP"' EXIT
reset_all

jget() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    d = d[int(k)] if isinstance(d, list) else d.get(k) if isinstance(d, dict) else None
    if d is None: break
print("" if d is None else (str(d).lower() if isinstance(d, bool) else d))' "$1" "$2" 2>/dev/null; }
req() {
  printf '%s' "$1" > "$GEN/.pki-request"
  "$PKI" request > "$D/req.out" 2>&1 || true
  RES_OK="$(jget "$RUNP/pki-result.json" ok)"
  [[ "$RES_OK" = true ]] || note "demande refusée : $(jget "$RUNP/pki-result.json" message | cut -c1-300)"
}
wait_health() {
  local h
  for _ in $(seq 1 60); do
    h="$(curl -s --noproxy '*' -m 4 http://127.0.0.1:8080/ejbca/publicweb/healthcheck/ejbcahealth 2>/dev/null | head -c 20)"
    [[ "$h" = ALLOK ]] && return 0; sleep 6
  done
  return 1
}
ejpsql() { runuser -u postgres -- psql -X -q -At -d ejbca "$@"; }
shaof() { sha256sum < "$1" | cut -d' ' -f1; }
tree() { ( cd "$1" 2>/dev/null && find . -name work -prune -o -type f -print0 | sort -z | xargs -0 sha256sum 2>/dev/null ); }
cas_listed() { python3 -c 'import json,sys; print(" ".join(sorted(c["name"] for c in json.load(open(sys.argv[1]))["cas"])))' "$RUNP/pki-cas.json" 2>/dev/null; }

echo "== Installation réelle (nœud A, leader) et autorités =="
"$PKI" apply "$IMG" pki.lab.test 10.0.0.0/8 > "$D/apply.out" 2>&1; expect_eq "installation acceptée" 0 "$?"
expect_nogrep "l'unité écrite n'a pas de section [Install] (le cluster seul décide du démarrage)" "^\[Install\]" "$D/quad/ddibuntu-ejbca.container"
check "le conteneur répond « ALLOK »" wait_health
req '{"action":"ca_root","name":"Lab-Root","alg":"rsa3072","days":3650,"cn":"Lab Root CA","o":"Laboratoire","c":"FR"}'; expect_eq "racine créée" true "$RES_OK"
req '{"action":"ca_issuing","name":"Lab-Sub","alg":"ecp256","days":1825,"cn":"Lab Sub CA","o":"Laboratoire","c":"FR","signedBy":"Lab-Root"}'; expect_eq "émettrice créée" true "$RES_OK"
"$PKI" status >/dev/null 2>&1
expect_eq "autorités publiées" "Lab-Root Lab-Sub" "$(cas_listed)"
CAS_DB="$(ejpsql -c "select name from cadata order by name" | tr '\n' ' ')"
KEY_A="$(ejpsql -c "select count(*) from cadata where name = 'Lab-Sub'")"

echo "== Export de l'état =="
"$PKI" state-export "$D/state.json" > "$D/state.sha"; expect_eq "export accepté" 0 "$?"
SHA="$(cat "$D/state.sha")"
expect_eq "empreinte de 64 caractères" 64 "${#SHA}"
expect_eq "état en 0600" 600 "$(stat -c %a "$D/state.json")"
"$PKI" state-export "$D/state2.json" > "$D/state2.sha"
expect_eq "export déterministe malgré un conteneur en marche" "$SHA" "$(cat "$D/state2.sha")"
expect_eq "le volume exporté est celui du keystore TLS du nom public" 2 "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sum(1 for n in d["files"] if n.startswith("data/persistent/")))' "$D/state.json")"
ENVSHA="$(shaof "$D/etc/ejbca.env")"; INSTSHA="$(shaof "$D/etc/instance.json")"; CATREE="$(tree "$D/data/ca")"; TLSSHA="$(tree "$D/data/persistent")"

echo "== Le « nœud » est vidé : tout sauf la base (comme un secondaire qui n'a encore rien reçu) =="
"$D/bin/systemctl" stop ddibuntu-ejbca.service
rm -rf "${D:?}/etc" "${D:?}/data" "${D:?}/quad" "${RUNP:?}"/pki-* ; mkdir -p "$D/etc" "$D/data" "$D/quad"
expect_eq "plus de secrets ni d'instance" "no" "$([[ -e "$D/etc/ejbca.env" ]] || [[ -e "$D/etc/instance.json" ]] && echo yes || echo no)"
expect_eq "la base « ejbca » est intacte (elle est celle du cluster)" "$CAS_DB" "$(ejpsql -c "select name from cadata order by name" | tr '\n' ' ')"
check "align leader sur un nœud sans PKI : sans effet" "$PKI" align leader
expect_eq "…aucune unité écrite" "no" "$([[ -e "$D/quad/ddibuntu-ejbca.container" ]] && echo yes || echo no)"
expect_eq "…aucun conteneur" "no" "$("$D/bin/systemctl" is-active x >/dev/null 2>&1 && echo yes || echo no)"

echo "== Import de l'état sur le nœud vide =="
check "import accepté" "$PKI" state-import "$D/state.json" "$SHA"
expect_eq "ejbca.env identique" "$ENVSHA" "$(shaof "$D/etc/ejbca.env")"
expect_eq "instance.json identique" "$INSTSHA" "$(shaof "$D/etc/instance.json")"
expect_eq "métadonnées des autorités identiques" "$CATREE" "$(tree "$D/data/ca")"
expect_eq "keystore TLS identique" "$TLSSHA" "$(tree "$D/data/persistent")"
expect_eq "ejbca.env en 0600" 600 "$(stat -c %a "$D/etc/ejbca.env")"
expect_eq "le volume appartient à l'utilisateur du conteneur" 10001 "$(stat -c %u "$D/data/persistent")"
"$PKI" state-export "$D/state3.json" > "$D/state3.sha"
expect_eq "ré-export : même empreinte que l'état importé" "$SHA" "$(cat "$D/state3.sha")"
check "réimport du même état : sans effet" "$PKI" state-import "$D/state.json" "$SHA"
expect_eq "…rien n'a été mis de côté" 0 "$(ls -d "$D"/etc/pre-restore.sync.* 2>/dev/null | wc -l)"
check_fail "état altéré : refusé" bash -c "head -c -20 '$D/state.json' > '$D/bad.json'; '$PKI' state-import '$D/bad.json' '$SHA'"
check_fail "empreinte attendue différente : refusé" "$PKI" state-import "$D/state.json" "$(printf 'f%.0s' $(seq 64))"
expect_eq "…état local inchangé" "$ENVSHA" "$(shaof "$D/etc/ejbca.env")"

echo "== Secondaire : l'unité et l'image sont prêtes, le conteneur reste arrêté =="
check "align replica" "$PKI" align replica
check "unité écrite" test -e "$D/quad/ddibuntu-ejbca.container"
expect_nogrep "…sans section [Install]" "^\[Install\]" "$D/quad/ddibuntu-ejbca.container"
expect_eq "image présente" ready "$(jget "$RUNP/pki-cluster.json" image)"
expect_eq "conteneur arrêté" "no" "$("$D/bin/systemctl" is-active x >/dev/null 2>&1 && echo yes || echo no)"
expect_eq "rôle publié" replica "$(jget "$RUNP/pki-cluster.json" role)"

echo "== Promotion : align leader démarre la PKI sur la base du cluster =="
check "align leader" "$PKI" align leader
check "le conteneur répond « ALLOK » avec l'état importé" wait_health
"$PKI" status >/dev/null 2>&1
expect_eq "les autorités sont retrouvées avec les mêmes secrets" "Lab-Root Lab-Sub" "$(cas_listed)"
expect_eq "la base n'a pas été touchée" "$CAS_DB" "$(ejpsql -c "select name from cadata order by name" | tr '\n' ' ')"
req '{"action":"ca_crl","name":"Lab-Sub"}'; expect_eq "la clé de l'autorité se déchiffre : une CRL est signée par le conteneur repris" true "$RES_OK"
expect_eq "l'autorité émettrice porte toujours sa clé" "$KEY_A" "$(ejpsql -c "select count(*) from cadata where name = 'Lab-Sub'")"
expect_eq "rôle publié" leader "$(jget "$RUNP/pki-cluster.json" role)"
expect_eq "unité active" active "$(jget "$RUNP/pki-cluster.json" unit)"
check "align leader suivant : pas de redémarrage" "$PKI" align leader
expect_eq "le conteneur tourne toujours" yes "$("$D/bin/systemctl" is-active x >/dev/null 2>&1 && echo yes || echo no)"

echo "== Rétrogradation puis consigne d'arrêt =="
check "align replica arrête la PKI" "$PKI" align replica
expect_eq "conteneur arrêté" "no" "$("$D/bin/systemctl" is-active x >/dev/null 2>&1 && echo yes || echo no)"
check "start (leader) lève la consigne et démarre" "$PKI" start
check "le conteneur répond à nouveau" wait_health
check "stop (leader) pose la consigne" "$PKI" stop
expect_eq "consigne d'arrêt écrite" stopped "$(tr -d '\n' < "$D/etc/desired")"
check "align leader ne redémarre pas une PKI arrêtée volontairement" "$PKI" align leader
expect_eq "…toujours arrêtée" "no" "$("$D/bin/systemctl" is-active x >/dev/null 2>&1 && echo yes || echo no)"
expect_eq "…consigne publiée" stopped "$(jget "$RUNP/pki-cluster.json" desired)"
check "start lève la consigne" "$PKI" start
check "le conteneur répond" wait_health

echo "== Un volume perdu n'empêche pas la reprise (EJBCA régénère son keystore TLS) =="
"$D/bin/systemctl" stop ddibuntu-ejbca.service
rm -rf "$D/data/persistent"; mkdir -p "$D/data/persistent"; chown 10001:10001 "$D/data/persistent"; chmod 700 "$D/data/persistent"
check "align leader" "$PKI" align leader
check "EJBCA repart sur un volume vide" wait_health
"$PKI" status >/dev/null 2>&1
expect_eq "autorités toujours là" "Lab-Root Lab-Sub" "$(cas_listed)"
expect_eq "keystore régénéré" 2 "$(find "$D/data/persistent" -name 'server.*' -type f | wc -l)"
"$PKI" state-export "$D/state4.json" > "$D/state4.sha"
expect_eq "…l'état exporté change (nouveau keystore) : le cluster le recevra à la prochaine synchronisation" "yes" "$([[ "$(cat "$D/state4.sha")" != "$SHA" ]] && echo yes || echo no)"

echo "== Désinstallation : l'état exporté perd l'instance, garde les secrets =="
"$PKI" uninstall >/dev/null 2>&1; expect_eq "désinstallation acceptée" 0 "$?"
"$PKI" state-export "$D/state5.json" > "$D/state5.sha"
expect_eq "plus d'instance.json dans l'état" 0 "$(python3 -c 'import json,sys; print(sum(1 for n in json.load(open(sys.argv[1]))["files"] if n == "etc/instance.json"))' "$D/state5.json")"
expect_eq "…mais les secrets restent (la base est conservée)" 1 "$(python3 -c 'import json,sys; print(sum(1 for n in json.load(open(sys.argv[1]))["files"] if n == "etc/ejbca.env"))' "$D/state5.json")"

finish
