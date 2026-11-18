#!/usr/bin/env bash
# Batterie 37 — mise à jour de l'image d'EJBCA (0.14.7) sur le VRAI conteneur : installation de la 9.3.7, une racine, une émettrice et un certificat, recherche de versions
# sur Docker Hub, mise à jour réelle vers la 9.6.3 (la vraie image migre elle-même la vraie base), contrôles (santé, schéma, autorités, signature, CRL),
# émission après mise à jour, RETOUR ARRIÈRE réel (base, volume, unité, ancienne image) avec décompte des certificats perdus, seconde mise à jour puis validation,
# refus de réinstaller une image plus ancienne que la base.
# DESTRUCTIVE : supprime la base « ejbca » et le conteneur « ddibuntu-ejbca » de la machine ; exige DDI_TEST_PKI_LIVE=1.
# Prérequis : root, podman + images docker.io/keyfactor/ejbca-ce:9.3.7 ET :9.6.3 déjà présentes (aucun tirage), PostgreSQL local (runuser postgres), openssl, curl,
# port 8080 libre, ~2 Go de mémoire libre ; sinon la batterie est ignorée. Durée : une dizaine de minutes (chaque commande de la CLI d'EJBCA démarre une JVM).
# DDI_TEST_PODMAN_ARGS permet de viser un autre stockage Podman (ex. « --root /tmp/podman-root --runroot /tmp/podman-run »).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

PKI="$RFS/usr/local/sbin/ddibuntu-pki"
OLD="docker.io/keyfactor/ejbca-ce:9.3.7"
NEW="docker.io/keyfactor/ejbca-ce:9.6.3"
read -r -a PARGS <<< "${DDI_TEST_PODMAN_ARGS:-}"
if [ "${DDI_TEST_PKI_LIVE:-}" != 1 ]; then note "DDI_TEST_PKI_LIVE=1 absent (la batterie supprime la base « ejbca » et le conteneur « ddibuntu-ejbca ») : ignorée"; finish; exit $?; fi
if [ "$(id -u)" -ne 0 ] || ! command -v podman >/dev/null || ! command -v openssl >/dev/null || ! command -v curl >/dev/null || ! command -v runuser >/dev/null \
   || [ ! -x /usr/lib/systemd/system-generators/podman-system-generator ]; then
  note "prérequis absents (root, podman et son générateur Quadlet, openssl, curl, runuser) : batterie ignorée"; finish; exit $?
fi
for im in "$OLD" "$NEW"; do
  if ! podman "${PARGS[@]}" image exists "$im" >/dev/null 2>&1; then note "image $im absente (la batterie ne tire rien) : ignorée"; finish; exit $?; fi
done
if curl -s --noproxy '*' -m 2 -o /dev/null http://127.0.0.1:8080/ 2>/dev/null; then note "le port 8080 est déjà utilisé : batterie ignorée"; finish; exit $?; fi
if ! runuser -u postgres -- psql -X -q -At -d postgres -c 'select 1' >/dev/null 2>&1; then note "PostgreSQL local injoignable : batterie ignorée"; finish; exit $?; fi

D="$T_TMP"; chmod 0755 "$D"
mkdir -p "$D/bin" "$D/etc" "$D/data" "$D/quad" "$D/run" "$D/gen/pki-in" "$D/w"
GEN="$D/gen"; RUNP="$D/run"
cat > "$D/bin/podman" <<EOF
#!/bin/bash
exec /usr/bin/podman ${PARGS[*]} "\$@"
EOF
# systemctl : « start » exécute la commande que le VRAI générateur Quadlet produit pour l'unité (ni systemd ni cgroups ici)
cat > "$D/bin/systemctl" <<EOF
#!/bin/bash
P="$D/bin/podman"
case "\$1" in
  daemon-reload) exit 0 ;;
  start|restart)
    [ "\$1" = restart ] && "\$P" stop -t 60 ddibuntu-ejbca >/dev/null 2>&1
    cmd="\$(QUADLET_UNIT_DIRS="$D/quad" /usr/lib/systemd/system-generators/podman-system-generator --dryrun 2>/dev/null | sed -n 's/^ExecStart=//p' | head -n1)"
    [ -n "\$cmd" ] || exit 1
    cmd="\${cmd/\\/usr\\/bin\\/podman/\$P}"; cmd="\${cmd//%t/$D/run}"; cmd="\${cmd//%N/ddibuntu-ejbca}"; cmd="\${cmd/--cgroups=split/--cgroups=enabled}"
    eval "\$cmd" >"$D/start.out" 2>&1 9>&- || { cat "$D/start.out" >&2; exit 1; } ;;
  stop) "\$P" stop -t 90 ddibuntu-ejbca >/dev/null 2>&1; exit 0 ;;
  is-active) [ "\$("\$P" inspect -f '{{.State.Running}}' ddibuntu-ejbca 2>/dev/null)" = true ] ;;
  show) "\$P" inspect -f '{{.State.StartedAt}}' ddibuntu-ejbca 2>/dev/null | sed 's/ +0000 UTC//' ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$D/bin/podman" "$D/bin/systemctl"
export DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_PKI_ETC="$D/etc" DDI_PKI_DATA="$D/data" DDI_PKI_QUADLET_DIR="$D/quad"
export DDI_PKI_PODMAN="$D/bin/podman" DDI_PKI_SYSTEMCTL="$D/bin/systemctl" DDI_PKI_LOCK="$D/lock" DDI_FW_BIN="$D/nofw" DDI_PKI_UID=10001
export DDI_GENERATED_DIR="$GEN" DDI_RUN_DIR="$RUNP"
unset DDI_PKI_PSQL DDI_PKI_ALLOW_USER DDI_PKI_PGDUMP DDI_PKI_PGRESTORE DDI_PKI_HUB_URL

psql_pg() { runuser -u postgres -- psql -X -q -At -d postgres "$@"; }
reset_all() {
  "$D/bin/podman" rm -f ddibuntu-ejbca >/dev/null 2>&1
  psql_pg -c 'drop database if exists ejbca with (force)' -c 'drop role if exists ejbca' >/dev/null 2>&1
}
if [ "${DDI_TEST_PKI_KEEP:-}" = 1 ]; then
  { for v in DDI_LIBDIR DDI_PKI_ETC DDI_PKI_DATA DDI_PKI_QUADLET_DIR DDI_PKI_PODMAN DDI_PKI_SYSTEMCTL DDI_PKI_LOCK DDI_FW_BIN DDI_PKI_UID DDI_GENERATED_DIR DDI_RUN_DIR; do printf 'export %s=%q\n' "$v" "${!v}"; done; printf 'export PKI=%q D=%q\n' "$PKI" "$D"; } > /tmp/b37-keep.env
  trap 'note "état conservé : . /tmp/b37-keep.env"' EXIT
else
  trap 'reset_all; rm -rf "$T_TMP"' EXIT
fi
reset_all

jget() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    d = d[int(k)] if isinstance(d, list) else d.get(k) if isinstance(d, dict) else None
    if d is None: break
print("" if d is None else (str(d).lower() if isinstance(d, bool) else d))' "$1" "$2" 2>/dev/null; }
req() {   # $1 = JSON de la demande ; la demande passe par le vrai « request » (celui que déclenche l'unité .path)
  printf '%s' "$1" > "$GEN/.pki-request"
  "$PKI" request > "$D/req.out" 2>&1 || true
  RES_OK="$(jget "$RUNP/pki-result.json" ok)"
  [ "$RES_OK" = true ] || note "demande refusée : $(jget "$RUNP/pki-result.json" message | cut -c1-300)"
}
wait_health() {
  local h
  for _ in $(seq 1 60); do
    h="$(curl -s --noproxy '*' -m 4 http://127.0.0.1:8080/ejbca/publicweb/healthcheck/ejbcahealth 2>/dev/null | head -c 20)"
    [ "$h" = ALLOK ] && return 0; sleep 6
  done
  return 1
}
fetch_url() { curl -s --noproxy '*' -m 15 -o "$2" -w '%{http_code}' "$(printf '%s' "$1" | sed 's#//pki\.lab\.test:8080#//127.0.0.1:8080#')"; }
ca_get() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
c = [x for x in d["cas"] if x["name"] == sys.argv[2]]
v = c[0] if c else {}
for k in sys.argv[3].split("."):
    v = v.get(k) if isinstance(v, dict) else None
print("" if v is None else (str(v).lower() if isinstance(v, bool) else v))' "$RUNP/pki-cas.json" "$1" "$2" 2>/dev/null; }
ejpsql() { runuser -u postgres -- psql -X -q -At -d ejbca "$@"; }
inst_tag() { jget "$D/etc/instance.json" tag; }
img_of() { "$D/bin/podman" image inspect -f '{{.Digest}}' "$1" 2>/dev/null; }   # empreinte de l'image locale désignée par son étiquette
img_run() { "$D/bin/podman" inspect -f '{{.ImageName}}' ddibuntu-ejbca 2>/dev/null | sed 's/.*@//'; }   # empreinte de l'image du conteneur
certs_in_db() { ejpsql -c "select count(*) from certificatedata" 2>/dev/null; }
issue() {   # $1 identifiant, $2 demande de certificat
  install -m 0644 "$2" "$GEN/pki-in/$1.csr.pem"
  req "$(printf '{"action":"cert_issue","id":"%s","ca":"Lab-Sub","profile":"server","cn":"ddi-test","o":"Laboratoire","c":"FR","dns":["radius1.lab.test"]}' "$1")"
}

echo "== Installation réelle de la 9.3.7 (vrai conteneur, base vierge) =="
"$PKI" apply "$OLD" pki.lab.test 10.0.0.0/8 > "$D/apply.out" 2>&1; expect_eq "installation acceptée" 0 "$?"
check "le conteneur répond « ALLOK » (premier démarrage, quelques minutes)" wait_health
expect_eq "version installée : 9.3.7" 9.3.7 "$(inst_tag)"
expect_eq "version de la base notée : 9.3.7" 9.3.7 "$(cat "$D/etc/db-tag" 2>/dev/null)"
expect_eq "le conteneur tourne bien sous l'image 9.3.7" "$(img_of "$OLD")" "$(img_run)"

echo "== Autorités et certificat avant la mise à jour =="
req '{"action":"ca_root","name":"Lab-Root","alg":"rsa3072","days":3650,"cn":"Lab Root CA","o":"Laboratoire","c":"FR"}'
expect_eq "racine créée" true "$RES_OK"
req '{"action":"ca_issuing","name":"Lab-Sub","alg":"ecp256","days":1825,"cn":"Lab Sub CA","o":"Laboratoire","c":"FR","signedBy":"Lab-Root"}'
expect_eq "émettrice créée" true "$RES_OK"
W="$D/w"
openssl req -newkey rsa:2048 -nodes -keyout "$W/a.key" -out "$W/a.csr" -subj "/CN=ignoré" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$W/b.key" -out "$W/b.csr" -subj "/CN=ignoré" 2>/dev/null
issue 2000000000000001 "$W/a.csr"
expect_eq "certificat A émis sous la 9.3.7" true "$RES_OK"
SERA="$(jget "$RUNP/pki-cert/2000000000000001/meta.json" serial)"
check "numéro de série du certificat A publié" test -n "$SERA"
"$PKI" status >/dev/null 2>&1
expect_eq "deux autorités publiées avant la mise à jour" 2 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["cas"]))' "$RUNP/pki-cas.json")"
CERTS0="$(certs_in_db)"
check "au moins un certificat en base" test "${CERTS0:-0}" -ge 1

echo "== Recherche de versions (Docker Hub) =="
"$PKI" update-check > "$D/check.out" 2>&1; expect_eq "recherche terminée" 0 "$?"
if [ -n "$(jget "$RUNP/pki-update.json" checkError)" ]; then
  note "Docker Hub injoignable depuis ce banc ($(jget "$RUNP/pki-update.json" checkError)) : liste des versions non contrôlée"
else
  expect_eq "version installée publiée" 9.3.7 "$(jget "$RUNP/pki-update.json" current)"
  check "la version 9.6.3 est proposée" bash -c "python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if any(x[\"tag\"] == \"9.6.3\" for x in d[\"available\"]) else 1)' '$RUNP/pki-update.json'"
  LOCAL_DIGEST="$("$D/bin/podman" image inspect -f '{{.Digest}}' "$NEW" 2>/dev/null)"
  expect_eq "l'empreinte annoncée par Docker Hub est celle de l'image locale" "$LOCAL_DIGEST" "$(python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
print(next((x["digest"] for x in d["available"] if x["tag"] == "9.6.3"), ""))' "$RUNP/pki-update.json")"
  check "les notes de version pointent vers la documentation d'EJBCA" bash -c "python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
n = next((x.get(\"notes\", {}) for x in d[\"available\"] if x[\"tag\"] == \"9.6.3\"), {})
sys.exit(0 if all(n.get(k, \"\").startswith(\"https://docs.keyfactor.com/ejbca/\") for k in (\"release\", \"upgrade\")) else 1)' '$RUNP/pki-update.json'"
fi

echo "== Mise à jour réelle 9.3.7 → 9.6.3 =="
"$PKI" update-apply "$NEW" > "$D/upd1.out" 2>&1; expect_eq "mise à jour acceptée" 0 "$?"
"$PKI" status >/dev/null 2>&1
expect_eq "tâche : en attente de validation" pending "$(jget "$RUNP/pki-update.json" job.state)"
expect_eq "version installée : 9.6.3" 9.6.3 "$(inst_tag)"
expect_eq "le conteneur tourne bien sous l'image 9.6.3" "$(img_of "$NEW")" "$(img_run)"
expect_eq "version de la base notée : 9.6.3" 9.6.3 "$(cat "$D/etc/db-tag" 2>/dev/null)"
check "le conteneur répond « ALLOK » après la migration" wait_health
for c in health schema cas signing crl; do
  expect_eq "contrôle « $c » bon" true "$(python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
print(str(next((c["ok"] for c in d["job"]["checks"] if c["id"] == sys.argv[2]), "absent")).lower())' "$RUNP/pki-update.json" "$c")"
done
expect_eq "point de retour disponible" true "$(jget "$RUNP/pki-update.json" job.rollbackAvailable)"
BK="$(find "$D/etc/update" -mindepth 1 -maxdepth 1 -type d -name '2*Z-9.3.7' | head -n1)"
check "point de retour sur le disque (base, fichiers, unité, instance, métadonnées)" bash -c "cd '$BK' && test -s ejbca.dump && test -s files.tgz && test -s quadlet && test -s instance.json && test -s meta.json"
expect_eq "point de retour : dossier en 0700" 700 "$(stat -c %a "$BK")"
expect_eq "point de retour : base en 0600" 600 "$(stat -c %a "$BK/ejbca.dump")"
expect_eq "les deux autorités sont toujours là" 2 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["cas"]))' "$RUNP/pki-cas.json")"
expect_eq "le certificat A est toujours en base" "$CERTS0" "$(certs_in_db)"
code="$(fetch_url "$(ca_get Lab-Sub crlUrl)" "$W/sub-after.crl")"; expect_eq "CRL de l'émettrice servie en HTTP après la mise à jour" 200 "$code"
check "…et signée par l'émettrice" bash -c "openssl crl -inform DER -in '$W/sub-after.crl' -CAfile '$RUNP/pki-ca/Lab-Sub/cert.pem' -noout -verify 2>&1 | grep -q 'verify OK'"

echo "== La 9.6.3 émet et révoque =="
issue 2000000000000002 "$W/b.csr"
expect_eq "certificat B émis sous la 9.6.3" true "$RES_OK"
"$PKI" status >/dev/null 2>&1
expect_eq "publication : un certificat émis depuis la sauvegarde" 1 "$(jget "$RUNP/pki-update.json" certsSince)"
req "$(printf '{"action":"cert_revoke","ca":"Lab-Sub","serial":"%s","reason":1}' "$SERA")"
expect_eq "certificat A révoqué sous la 9.6.3" true "$RES_OK"

echo "== Retour arrière réel =="
"$PKI" update-rollback > "$D/rb.out" 2>&1; expect_eq "retour arrière accepté" 0 "$?"
"$PKI" status >/dev/null 2>&1
expect_eq "tâche : retour arrière effectué" rolled_back "$(jget "$RUNP/pki-update.json" job.state)"
expect_eq "version installée : 9.3.7 de nouveau" 9.3.7 "$(inst_tag)"
expect_eq "le conteneur tourne de nouveau sous l'image 9.3.7" "$(img_of "$OLD")" "$(img_run)"
expect_eq "version de la base notée : 9.3.7" 9.3.7 "$(cat "$D/etc/db-tag" 2>/dev/null)"
check "le conteneur répond « ALLOK » après le retour arrière" wait_health
expect_eq "la base est celle d'avant (le certificat B a disparu)" "$CERTS0" "$(certs_in_db)"
expect_eq "les deux autorités sont toujours là" 2 "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["cas"]))' "$RUNP/pki-cas.json")"
code="$(fetch_url "$(ca_get Lab-Sub crlUrl)" "$W/sub-rb.crl")"; expect_eq "CRL de l'émettrice servie en HTTP après le retour arrière" 200 "$code"
check "…et signée par l'émettrice (la bonne clé est revenue avec la base)" bash -c "openssl crl -inform DER -in '$W/sub-rb.crl' -CAfile '$RUNP/pki-ca/Lab-Sub/cert.pem' -noout -verify 2>&1 | grep -q 'verify OK'"
check "le certificat A n'est pas révoqué dans la base d'avant : il n'apparaît pas dans la CRL" bash -c "! openssl crl -inform DER -in '$W/sub-rb.crl' -noout -text | grep -qi 'Key Compromise'"
rm -f "$GEN/pki-in/2000000000000002.csr.pem"
issue 2000000000000003 "$W/b.csr"
expect_eq "la 9.3.7 réémet après le retour arrière" true "$RES_OK"

echo "== Seconde mise à jour puis validation =="
"$PKI" update-apply "$NEW" > "$D/upd2.out" 2>&1; expect_eq "seconde mise à jour acceptée" 0 "$?"
"$PKI" status >/dev/null 2>&1
expect_eq "tâche : en attente de validation" pending "$(jget "$RUNP/pki-update.json" job.state)"
expect_eq "version installée : 9.6.3" 9.6.3 "$(inst_tag)"
"$PKI" update-validate > "$D/val.out" 2>&1; expect_eq "validation acceptée" 0 "$?"
"$PKI" status >/dev/null 2>&1
expect_eq "tâche : validée" validated "$(jget "$RUNP/pki-update.json" job.state)"
expect_eq "plus de retour arrière proposé" false "$(jget "$RUNP/pki-update.json" job.rollbackAvailable)"
"$PKI" update-rollback > "$D/rb2.out" 2>&1; expect_eq "retour arrière refusé après validation" 1 "$?"
expect_eq "…version inchangée" 9.6.3 "$(inst_tag)"
check "le conteneur répond toujours « ALLOK »" wait_health

echo "== Version de la base : jamais en arrière =="
"$PKI" apply "$OLD" pki.lab.test 10.0.0.0/8 > "$D/old.out" 2>&1; expect_eq "réinstaller la 9.3.7 sur une base migrée en 9.6.3 est refusé" 1 "$?"
check "…le message dit pourquoi" grep -qi "ne change que par la mise à jour" "$D/old.out"
expect_eq "…version installée inchangée" 9.6.3 "$(inst_tag)"
expect_eq "…conteneur toujours sous l'image 9.6.3" "$(img_of "$NEW")" "$(img_run)"

finish
