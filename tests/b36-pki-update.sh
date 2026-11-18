#!/usr/bin/env bash
# Batterie 36 — mise à jour de l'image d'EJBCA Community (0.14.7) : recherche des nouvelles versions sur Docker Hub, politique de version, parcours de mise à jour
# (tirage, arrêt, sauvegarde de retour arrière, migration, contrôles), validation, retour arrière manuel et automatique, tâche interrompue, nettoyage.
# Podman, systemctl, psql, pg_dump, pg_restore et curl sont remplacés par des doublures qui simulent un EJBCA dont la base est « migrée » par chaque nouvelle
# image : on vérifie la logique de ddibuntu-pki et de pki-helper.py (ordre des étapes, retour arrière complet, refus), pas le conteneur lui-même.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

PKI="$RFS/usr/local/sbin/ddibuntu-pki"
H="$RFS/usr/local/lib/ddibuntu/pki-helper.py"
T="$T_TMP"
B="$T/bin"; mkdir -p "$B" "$T/etc" "$T/data" "$T/quad" "$T/run" "$T/gen" "$T/images" "$T/bad"
LOG="$T/calls.log"
QUAD="$T/quad/ddibuntu-ejbca.container"
UPD="$T/etc/update"
RUNF="$T/run/pki-update.json"

# --- doublures -------------------------------------------------------------------------------------------------------------------------------------------
# Empreintes : 9.3.7 → a…, 9.6.3 → b…, 9.6.4 → c…, 9.6.5 → d…. La base simulée (dbstate) retient quelle image l'a migrée en dernier (« owner »).
cat > "$B/podman" <<'EOF'
#!/bin/bash
T=@T@
echo "podman $*" >> "$T/calls.log"
dig() { local c; case "${1##*:}" in 9.3.7) c=a ;; 9.6.3) c=b ;; 9.6.4) c=c ;; *) c=d ;; esac; printf 'sha256:'; printf "$c%.0s" $(seq 64); }
case "$1" in
  image)
    case "$2" in
      exists) [ -f "$T/images/${3##*:}" ] && exit 0; exit 1 ;;
      inspect) dig "${@: -1}"; echo ;;
    esac ;;
  pull) [ -f "$T/pull-fail" ] && { echo "Error: unable to pull" >&2; exit 125; }
        last="${@: -1}"; touch "$T/images/${last##*:}" ;;
  exec) case "$*" in *createcrl*)
          q="$(sed -n 's/^Image=.*@\(sha256:[0-9a-f]*\)$/\1/p' "$T/quad/ddibuntu-ejbca.container")"
          if [ "$(cat "$T/bad/crl" 2>/dev/null)" = "$q" ]; then echo "ERROR: crypto token offline" >&2; exit 1; fi ;;
        esac ;;
esac
exit 0
EOF
cat > "$B/systemctl" <<'EOF'
#!/bin/bash
T=@T@
echo "systemctl $*" >> "$T/calls.log"
q="$(sed -n 's/^Image=.*@\(sha256:[0-9a-f]*\)$/\1/p' "$T/quad/ddibuntu-ejbca.container" 2>/dev/null)"
case "$1" in
  is-active) [ -f "$T/active" ] && exit 0; exit 1 ;;
  show) case "$*" in *NRestarts*) cat "$T/nrestarts" 2>/dev/null || echo 0 ;; *) date -u -d "-20 seconds" '+%a %Y-%m-%d %H:%M:%S UTC' ;; esac ;;
  start|restart)
    [ "$(cat "$T/bad/start" 2>/dev/null)" = "$q" ] && exit 1
    touch "$T/active"
    c="${q:7:1}"   # première lettre de l'empreinte : la nouvelle image migre la base
    [ -f "$T/dbstate" ] && sed -i "s/^owner=.*/owner=$c/" "$T/dbstate" ;;
  stop) rm -f "$T/active" ;;
esac
exit 0
EOF
cat > "$B/psql" <<'EOF'
#!/bin/bash
T=@T@
sqltxt="$(cat)"
{ echo "psql $* :: $(printf '%s' "$sqltxt" | tr '\n' ' ' | cut -c1-110)"; } >> "$T/psql.log"
get() { sed -n "s/^$1=//p" "$T/dbstate" 2>/dev/null | head -n1; }
case "$sqltxt" in
  *"create role ejbca"*) touch "$T/db.created"; echo ensure >> "$T/db.events" ;;
  *"drop database if exists ejbca"*) rm -f "$T/db.created"; echo dropped >> "$T/db.events" ;;
  *"from pg_database where datname = 'ejbca'"*) [ -f "$T/db.created" ] && echo exists ;;
  *"information_schema.tables"*) [ -f "$T/db.created" ] && echo 40 || echo 0 ;;
  *"count(*) from certificatedata where type = 1"*) get certs ;;
  *"count(*) from cadata"*) get cas ;;
  *"information_schema.columns"*) [ "$(get owner)" = "$(cat "$T/bad/schema-owner" 2>/dev/null)" ] && cat "$T/schema-missing" 2>/dev/null; true ;;
  *"select name from cadata where status = 1"*) cat "$T/ca-names" 2>/dev/null; true ;;
  *"select distinct on (c.name)"*) cat "$T/cas.tsv" 2>/dev/null; true ;;
esac
exit 0
EOF
cat > "$B/pgdump" <<'EOF'
#!/bin/bash
T=@T@
echo "pgdump $*" >> "$T/calls.log"
[ -f "$T/pgdump-fail" ] && { echo "pg_dump: error: connection to server failed" >&2; exit 1; }
cat "$T/dbstate"
EOF
cat > "$B/pgrestore" <<'EOF'
#!/bin/bash
T=@T@
echo "pgrestore $*" >> "$T/calls.log"
[ -f "$T/pgrestore-fail" ] && { echo "pg_restore: error: could not execute query" >&2; exit 1; }
cat > "$T/dbstate"; echo restored >> "$T/db.events"
EOF
cat > "$B/curl" <<'EOF'
#!/bin/bash
T=@T@
out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac; done
echo "curl $url" >> "$T/calls.log"
q="$(sed -n 's/^Image=.*@\(sha256:[0-9a-f]*\)$/\1/p' "$T/quad/ddibuntu-ejbca.container" 2>/dev/null)"
case "$url" in
  *hub.docker.com*) [ -f "$T/hub-down" ] && exit 6
                    if [ -f "$T/hub-garbage" ]; then echo 'ceci n est pas du json' > "$out"; exit 0; fi
                    cp "$T/hub.json" "$out"; exit 0 ;;
  */healthcheck/*) [ -f "$T/active" ] && [ "$(cat "$T/bad/health" 2>/dev/null)" != "$q" ] && { printf 'ALLOK'; exit 0; }; exit 22 ;;
  */publicweb/webdist/certdist*) [ "$(cat "$T/bad/crlhttp" 2>/dev/null)" = "$q" ] && exit 22; exit 0 ;;
esac
exit 22
EOF
cat > "$B/fw" <<'EOF'
#!/bin/bash
echo "fw $*" >> @T@/calls.log
EOF
chmod +x "$B"/*
sed -i "s|@T@|$T|g" "$B"/*

export DDI_PKI_ALLOW_USER=1 DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_GENERATED_DIR="$T/gen" DDI_RUN_DIR="$T/run"
export DDI_PKI_ETC="$T/etc" DDI_PKI_DATA="$T/data" DDI_PKI_QUADLET_DIR="$T/quad" DDI_PKI_PODMAN="$B/podman"
export DDI_PKI_SYSTEMCTL="$B/systemctl" DDI_PKI_CURL="$B/curl" DDI_FW_BIN="$B/fw" DDI_PKI_PSQL="$B/psql" DDI_PKI_LOCK="$T/lock" DDI_PKI_UID="$(id -u)"
export DDI_PKI_PGDUMP="$B/pgdump" DDI_PKI_PGRESTORE="$B/pgrestore" DDI_PKI_UPDATE_WAIT=3 DDI_PKI_UPDATE_POLL=1 DDI_PKI_NO_UPDATE_CHECK=1
export DDI_PKI_HUB_URL="https://hub.docker.com/v2/repositories/keyfactor/ejbca-ce/tags"
D() { printf 'sha256:'; printf "$1%.0s" $(seq 64); }
IMG() { printf 'docker.io/keyfactor/ejbca-ce:%s' "$1"; }
HOST=pki.lab.test
jv() { python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
print(eval(sys.argv[2]))' "$1" "$2" 2>&1; }
req() { printf '%s' "$1" > "$T/gen/.pki-request"; "$PKI" request >/dev/null 2>&1; }
res() { jv "$T/run/pki-result.json" "d['$1']"; }
lineno() { grep -n -- "$1" "$LOG" | head -n1 | cut -d: -f1; }
dbget() { sed -n "s/^$1=//p" "$T/dbstate"; }
inst() { jv "$T/etc/instance.json" "d['$1']"; }
qdig() { sed -n 's/^Image=.*@\(sha256:[0-9a-f]*\)$/\1/p' "$QUAD"; }
backups() { find "$UPD" -mindepth 1 -maxdepth 1 -type d -name '2*Z-*' 2>/dev/null | sort; }
reset_flags() { rm -f "$T/pull-fail" "$T/pgdump-fail" "$T/pgrestore-fail" "$T/nrestarts" "$T/hub-down" "$T/hub-garbage" "$T/bad"/* "$T/schema-missing"; }

# --- données -----------------------------------------------------------------------------------------------------------------------------------------------
python3 - "$T/hub.json" <<'PYEOF'
import json, sys
def row(name, ch, day, dg=True):
    return {"name": name, "last_updated": "2026-%s-%sT08:00:00.123456Z" % day, "digest": ("sha256:" + ch * 64) if dg else "pas-une-empreinte", "images": []}
rows = [row("latest", "f", ("10", "01")), row("9.6.5", "d", ("11", "05")), row("9.6.4", "c", ("10", "20")), row("9.6.3", "b", ("09", "01")),
        row("9.3.7", "a", ("03", "01")), row("9.3.6", "9", ("02", "01")), row("10.0.0", "e", ("11", "01")), row("9.6.3-rc1", "8", ("08", "01")),
        row("nightly", "7", ("11", "10")), row("9.7.0", "6", ("11", "08"), dg=False), row("../../etc", "5", ("11", "11")), {"digest": "x"}, "pas-un-objet"]
json.dump({"count": len(rows), "results": rows}, open(sys.argv[1], "w"))
PYEOF
printf 'owner=a\ncerts=5\ncas=2\n' > "$T/dbstate"
printf 'RootCA\nIssuingCA\n' > "$T/ca-names"

echo "== Politique de version =="
pol() { python3 "$H" update-policy "$@"; }
expect_eq "9.3.7 → 9.6.3 : permis (même série)" ok "$(pol 9.3.7 9.3.7 9.6.3)"
expect_eq "même version : refusée" same "$(pol 9.6.3 9.6.3 9.6.3)"
expect_eq "version plus ancienne que l'installée : refusée" older "$(pol 9.6.3 9.3.7 9.3.7)"
expect_eq "plus ancienne que la base (déjà migrée par 9.6.3) : refusée" older_than_db "$(pol 9.3.7 9.6.3 9.4.0)"
expect_eq "changement de série (9 → 10) : refusé" major_jump "$(pol 9.6.3 9.6.3 10.0.0)"
expect_eq "étiquette illisible : refusée" invalid "$(pol 9.6.3 9.6.3 latest)"
expect_eq "étiquette de base absente : l'installée fait foi" ok "$(pol 9.6.3 '' 9.6.4)"
expect_eq "comparaison : 9.6.10 > 9.6.9 (numérique, pas alphabétique)" 1 "$(python3 "$H" update-cmp 9.6.10 9.6.9)"
expect_eq "comparaison : égalité" 0 "$(python3 "$H" update-cmp 9.6.3 9.6.3)"
expect_eq "comparaison : plus petit" -1 "$(python3 "$H" update-cmp 9.3.7 9.6.3)"
check_fail "comparaison : argument illisible refusé" python3 "$H" update-cmp 9.6.3 latest

echo "== Analyse de la réponse de Docker Hub =="
CK="$T/check.json"
check "analyse sans erreur" python3 "$H" update-check-write "$CK" 9.3.7 9.3.7 "$T/hub.json"
expect_eq "versions proposées : seules les étiquettes X.Y.Z plus récentes, plus récente d'abord" "10.0.0 9.7.0 9.6.5 9.6.4 9.6.3" "$(jv "$CK" "' '.join(a['tag'] for a in d['available'])")"
expect_eq "« latest », « nightly », « -rc1 », chemins et lignes mal formées ignorés" 5 "$(jv "$CK" "len(d['available'])")"
expect_eq "plus récente permise : 9.7.0" 9.7.0 "$(jv "$CK" "d['latest']")"
expect_eq "changement de série : proposé mais interdit, avec le motif" "False major_jump major" "$(jv "$CK" "' '.join(str(x) for x in (d['available'][0]['allowed'], d['available'][0]['reason'], d['available'][0]['kind']))")"
expect_eq "9.6.3 : permis, série 9.x, type « minor »" "True minor" "$(jv "$CK" "' '.join(str(x) for x in (d['available'][4]['allowed'], d['available'][4]['kind']))")"
expect_eq "empreinte invalide : ignorée (jamais reprise telle quelle)" "" "$(jv "$CK" "d['available'][1]['digest']")"
expect_eq "empreinte valide conservée" "sha256:$(printf 'd%.0s' $(seq 64))" "$(jv "$CK" "d['available'][2]['digest']")"
expect_eq "date de publication au format AAAA-MM-JJ" 2026-11-05 "$(jv "$CK" "d['available'][2]['pushedAt']")"
expect_eq "notes de version : adresse construite pour la série (9.6)" "https://docs.keyfactor.com/ejbca/latest/ejbca-9-6-release-notes" "$(jv "$CK" "d['available'][4]['notes']['release']")"
expect_eq "notes de mise à niveau : adresse construite pour la série (9.6)" "https://docs.keyfactor.com/ejbca/latest/ejbca-9-6-upgrade-notes" "$(jv "$CK" "d['available'][4]['notes']['upgrade']")"
expect_eq "aucune erreur dans le résultat" "" "$(jv "$CK" "d['error']")"
check "base déjà migrée par 9.6.3 : analyse relancée" python3 "$H" update-check-write "$CK" 9.6.3 9.6.3 "$T/hub.json"
expect_eq "…plus rien d'ancien n'est proposé" "10.0.0 9.7.0 9.6.5 9.6.4" "$(jv "$CK" "' '.join(a['tag'] for a in d['available'])")"
python3 "$H" update-check-write "$CK" 9.6.3 9.6.3 --error=unreachable
expect_eq "erreur : le code est conservé" unreachable "$(jv "$CK" "d['error']")"
expect_eq "…et la dernière liste connue aussi" 4 "$(jv "$CK" "len(d['available'])")"
echo 'pas du json' > "$T/garbage.json"
python3 "$H" update-check-write "$CK" 9.6.3 9.6.3 "$T/garbage.json"
expect_eq "réponse illisible : « bad_answer »" bad_answer "$(jv "$CK" "d['error']")"
python3 "$H" update-check-write "$CK" 9.6.3 9.6.3 "$T/absent.json"
expect_eq "fichier absent : « bad_answer »" bad_answer "$(jv "$CK" "d['error']")"
python3 "$H" update-check-write "$CK" 9.6.3 9.6.3 "--error=../../etc;rm"
expect_eq "code d'erreur nettoyé (lettres et soulignés seulement)" "etcrm" "$(jv "$CK" "d['error']")"

echo "== État de la tâche =="
J="$T/job.json"
check "tâche créée" python3 "$H" update-job "$J" init 9.3.7 9.6.3 "$(D a)" pull stop backup
expect_eq "tâche : état « running », étape « pull »" "running pull" "$(jv "$J" "d['state'] + ' ' + d['step']")"
expect_eq "tâche : trois étapes à faire" 3 "$(jv "$J" "len([s for s in d['steps'] if s['status'] == 'todo'])")"
check "étape en cours" python3 "$H" update-job "$J" step pull running
check "étape terminée" python3 "$H" update-job "$J" step pull done
expect_eq "…statut mémorisé" done "$(jv "$J" "d['steps'][0]['status']")"
check "contrôle inscrit" python3 "$H" update-job "$J" check health true "détail"
check "contrôle en échec inscrit" python3 "$H" update-job "$J" check signing false "signature impossible pour : X"
check "contrôle réécrit sans doublon" python3 "$H" update-job "$J" check health false "santé « »"
expect_eq "…deux contrôles seulement" 2 "$(jv "$J" "len(d['checks'])")"
check_fail "état inconnu refusé" python3 "$H" update-job "$J" set state=nimportequoi
check_fail "clé inconnue refusée" python3 "$H" update-job "$J" set evil=1
check_fail "empreinte invalide refusée" python3 "$H" update-job "$J" set toDigest=abc
check_fail "entier invalide refusé" python3 "$H" update-job "$J" set startedAt=abc
check_fail "version illisible refusée à la création" python3 "$H" update-job "$T/j2.json" init latest 9.6.3 "" pull
check "message nettoyé des caractères de commande" python3 "$H" update-job "$J" set "message=a$(printf '\001')b"
expect_eq "…remplacés par des espaces" "a b" "$(jv "$J" "d['message']")"
expect_eq "fichier de tâche en 0600" 600 "$(stat -c %a "$J")"
python3 "$H" update-job "$J" set state=pending backup=20261101T000000Z-9.3.7 certsAtBackup=5 casAtBackup=2
python3 "$H" update-publish "$CK" "$J" 9.6.3 9.3.7 8 > "$T/pub.json"
expect_eq "publication : retour arrière proposé (en attente + sauvegarde)" True "$(jv "$T/pub.json" "d['job']['rollbackAvailable']")"
expect_eq "publication : certificats émis depuis la sauvegarde" 3 "$(jv "$T/pub.json" "d['certsSince']")"
expect_eq "publication : version de la base" 9.3.7 "$(jv "$T/pub.json" "d['dbTag']")"
python3 "$H" update-job "$J" set state=validated
python3 "$H" update-publish "$CK" "$J" 9.6.3 9.3.7 8 > "$T/pub.json"
expect_eq "publication : plus de retour arrière une fois validée" False "$(jv "$T/pub.json" "d['job']['rollbackAvailable']")"
expect_eq "publication : plus de décompte des certificats" None "$(jv "$T/pub.json" "d['certsSince']")"
expect_nogrep "publication : aucun chemin ni secret dans le JSON" '/etc/ddibuntu|PASSWORD|\.dump' "$T/pub.json"
python3 "$H" update-publish "$T/absent.json" "$T/absent2.json" 9.6.3 "" -1 > "$T/pub.json"
expect_eq "publication sans recherche ni tâche : tâche nulle" None "$(jv "$T/pub.json" "d['job']")"
expect_eq "…la version de la base retombe sur l'installée" 9.6.3 "$(jv "$T/pub.json" "d['dbTag']")"

echo "== Adresses des CRL (contrôle) =="
cat > "$T/cas.json" <<'EOF'
{"cas": [
 {"name": "RootCA", "state": "active", "kind": "root", "crlUrl": "http://pki.lab.test:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3DRoot"},
 {"name": "Issuing", "state": "active", "kind": "issuing", "crlUrl": "http://pki.lab.test:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3DIss"},
 {"name": "Attente", "state": "waiting", "kind": "issuing", "crlUrl": "http://pki.lab.test:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3DW"},
 {"name": "Ailleurs", "state": "active", "kind": "root", "crlUrl": "http://pki.lab.test:8080/autre?x=1"},
 {"name": "Piege", "state": "active", "kind": "root", "crlUrl": "ftp://x/ejbca/y"}]}
EOF
python3 "$H" update-crl-urls "$T/cas.json" 8080 > "$T/crl.out"
expect_eq "deux autorités actives contrôlées" 2 "$(wc -l < "$T/crl.out")"
expect_grep "adresse locale (127.0.0.1) : le contrôle ne dépend ni du DNS ni du pare-feu" '^RootCA	http://127\.0\.0\.1:8080/ejbca/publicweb/webdist/certdist\?cmd=crl' "$T/crl.out"
expect_nogrep "autorité en attente, chemin étranger et schéma étranger ignorés" 'Attente|Ailleurs|Piege|ftp' "$T/crl.out"
check_fail "port invalide refusé" python3 "$H" update-crl-urls "$T/cas.json" 'x;y'

echo "== Demandes de la console (validation) =="
pr() { printf '%s' "$1" | python3 "$H" parse-request; }
expect_eq "update_check : acceptée" "update_check" "$(pr '{"action":"update_check"}' | cut -f2 | head -n1)"
expect_eq "update_validate : acceptée" "update_validate" "$(pr '{"action":"update_validate"}' | cut -f2 | head -n1)"
expect_eq "update_rollback : acceptée" "update_rollback" "$(pr '{"action":"update_rollback"}' | cut -f2 | head -n1)"
expect_eq "update_apply : image rendue" "$(IMG 9.6.3)" "$(pr '{"action":"update_apply","image":"docker.io/keyfactor/ejbca-ce:9.6.3"}' | sed -n 's/^image\t//p')"
expect_eq "update_apply : autre dépôt refusé" "" "$(pr '{"action":"update_apply","image":"docker.io/evil/ejbca-ce:9.6.3"}')"
expect_eq "update_apply : étiquette « latest » refusée" "" "$(pr '{"action":"update_apply","image":"docker.io/keyfactor/ejbca-ce:latest"}')"
expect_eq "update_apply : empreinte refusée" "" "$(pr '{"action":"update_apply","image":"docker.io/keyfactor/ejbca-ce@sha256:'"$(printf 'a%.0s' $(seq 64))"'"}')"
expect_eq "update_apply : champ en trop refusé" "" "$(pr '{"action":"update_apply","image":"docker.io/keyfactor/ejbca-ce:9.6.3","cmd":"id"}')"
expect_eq "update_apply : image absente refusée" "" "$(pr '{"action":"update_apply"}')"
expect_eq "update_check : champ en trop refusé" "" "$(pr '{"action":"update_check","image":"x"}')"
expect_eq "update_rollback : champ en trop refusé" "" "$(pr '{"action":"update_rollback","dir":"/etc"}')"

echo "== Installation de départ (EJBCA 9.3.7) =="
rm -f "$LOG" "$T/active"
out="$("$PKI" apply "$(IMG 9.3.7)" "$HOST" "" 2>&1)"; rc=$?
expect_eq "installation de 9.3.7" 0 "$rc"
expect_eq "version de la base mémorisée : 9.3.7" 9.3.7 "$(cat "$T/etc/db-tag" 2>/dev/null)"
expect_eq "…en 0600" 600 "$(stat -c %a "$T/etc/db-tag" 2>/dev/null)"
expect_eq "publication : version installée" 9.3.7 "$(jv "$RUNF" "d['current']")"
expect_eq "publication : aucune tâche" None "$(jv "$RUNF" "d['job']")"
check_fail "sans recherche préalable : « plus ancienne que la base » ne s'applique pas à l'installée" "$PKI" apply "$(IMG 9.3.6)" "$HOST" ""
expect_eq "…l'installée reste 9.3.7" 9.3.7 "$(inst tag)"

echo "== Recherche de nouvelles versions =="
rm -f "$LOG"
out="$("$PKI" update-check 2>&1)"; rc=$?
expect_eq "update-check : code 0" 0 "$rc"
expect_grep "…annonce la version disponible" 'Nouvelle version disponible : EJBCA 9\.7\.0 \(installée : 9\.3\.7\)' <(printf '%s' "$out")
expect_grep "…Docker Hub a été interrogé" '^curl https://hub\.docker\.com/' "$LOG"
expect_eq "publication : recherche enregistrée" 9.7.0 "$(jv "$RUNF" "d['latest']")"
expect_eq "…avec cinq versions" 5 "$(jv "$RUNF" "len(d['available'])")"
expect_eq "…et l'heure de la recherche" True "$(jv "$RUNF" "d['checkedAt'] > 0")"
expect_eq "fichier de recherche en 0600" 600 "$(stat -c %a "$UPD/check.json")"
expect_eq "dossier de mise à jour en 0700" 700 "$(stat -c %a "$UPD")"
touch "$T/hub-down"
out="$("$PKI" update-check 2>&1)"; rc=$?
expect_eq "Docker Hub injoignable : code 1" 1 "$rc"
expect_grep "…message clair (accès sortant)" 'injoignable' <(printf '%s' "$out")
expect_eq "…erreur publiée" unreachable "$(jv "$RUNF" "d['checkError']")"
expect_eq "…dernière liste conservée" 5 "$(jv "$RUNF" "len(d['available'])")"
rm -f "$T/hub-down"; touch "$T/hub-garbage"
out="$("$PKI" update-check 2>&1)"; rc=$?
expect_eq "réponse illisible : code 1" 1 "$rc"
expect_eq "…erreur publiée" bad_answer "$(jv "$RUNF" "d['checkError']")"
rm -f "$T/hub-garbage"; "$PKI" update-check >/dev/null 2>&1

echo "== Refus avant toute action =="
rm -f "$LOG"
check_fail "même version refusée" "$PKI" update-apply "$(IMG 9.3.7)"
check_fail "version plus ancienne refusée" "$PKI" update-apply "$(IMG 9.3.6)"
out="$("$PKI" update-apply "$(IMG 10.0.0)" 2>&1 || true)"
expect_grep "changement de série refusé, avec la raison" 'série 9.*série 10|pas pris en charge' <(printf '%s' "$out")
check_fail "dépôt étranger refusé" "$PKI" update-apply docker.io/evil/ejbca-ce:9.6.3
check_fail "image sans étiquette refusée" "$PKI" update-apply docker.io/keyfactor/ejbca-ce
check_fail "sans argument refusé" "$PKI" update-apply
expect_nogrep "aucun tirage, aucun arrêt, aucune sauvegarde pendant ces refus" '^podman pull|^systemctl stop|^pgdump' "$LOG"
expect_eq "aucune tâche créée" no "$([ -e "$UPD/job.json" ] && echo yes || echo no)"
rm -f "$T/active"
out="$("$PKI" update-apply "$(IMG 9.6.3)" 2>&1 || true)"
expect_grep "PKI arrêtée : mise à jour refusée (la santé sert de référence)" 'ne répond pas' <(printf '%s' "$out")
touch "$T/active"
out="$(DDI_PKI_UPDATE_MIN_FREE_KB=999999999999 "$PKI" update-apply "$(IMG 9.6.3)" 2>&1 || true)"
expect_grep "place insuffisante : refus avant toute action" 'Mo libres' <(printf '%s' "$out")
expect_nogrep "…rien n'a été touché" '^podman pull|^systemctl stop|^pgdump' "$LOG"

echo "== Échec du tirage : rien n'est modifié =="
touch "$T/pull-fail"; rm -f "$LOG"
out="$("$PKI" update-apply "$(IMG 9.6.3)" 2>&1)"; rc=$?
expect_eq "tirage impossible : code 1" 1 "$rc"
expect_grep "…le message parle du tirage" 'tirage' <(printf '%s' "$out")
expect_eq "…tâche en échec" failed "$(jv "$UPD/job.json" "d['state']")"
expect_eq "…étape « pull » en échec" failed "$(jv "$UPD/job.json" "[s['status'] for s in d['steps'] if s['id'] == 'pull'][0]")"
expect_nogrep "…le conteneur n'a jamais été arrêté" '^systemctl stop' "$LOG"
expect_eq "…version installée inchangée" 9.3.7 "$(inst tag)"
expect_eq "…pas de retour arrière proposé (rien à défaire)" False "$(jv "$RUNF" "d['job']['rollbackAvailable']")"
rm -f "$T/pull-fail"

echo "== Échec de la sauvegarde : l'ancienne image repart =="
touch "$T/pgdump-fail"; rm -f "$LOG"
out="$("$PKI" update-apply "$(IMG 9.6.3)" 2>&1)"; rc=$?
expect_eq "sauvegarde impossible : code 1" 1 "$rc"
expect_grep "…le message le dit" 'sauvegarde' <(printf '%s' "$out")
expect_eq "…le conteneur tourne de nouveau" yes "$([ -f "$T/active" ] && echo yes || echo no)"
expect_eq "…unité inchangée (empreinte de 9.3.7)" "$(D a)" "$(qdig)"
expect_eq "…version installée inchangée" 9.3.7 "$(inst tag)"
expect_eq "…aucun dossier de sauvegarde laissé" 0 "$(backups | wc -l)"
expect_eq "…tâche en échec, sans retour arrière à proposer" "failed False" "$(jv "$RUNF" "d['job']['state'] + ' ' + str(d['job']['rollbackAvailable'])")"
expect_eq "…version de la base inchangée" 9.3.7 "$(cat "$T/etc/db-tag")"
rm -f "$T/pgdump-fail"

echo "== Empreinte annoncée par Docker Hub =="
python3 "$H" update-check-write "$T/check-d.json" 9.3.7 9.3.7 "$T/hub.json"
expect_eq "empreinte de 9.6.3 connue après la recherche" "$(D b)" "$(python3 "$H" update-digest "$T/check-d.json" 9.6.3)"
expect_eq "étiquette absente de la liste : rien" "" "$(python3 "$H" update-digest "$T/check-d.json" 9.1.1)"
expect_eq "empreinte invalide dans la liste : rien (jamais reprise)" "" "$(python3 "$H" update-digest "$T/check-d.json" 9.7.0)"
check_fail "étiquette illisible refusée" python3 "$H" update-digest "$T/check-d.json" latest
sed -i "s/\"sha256:$(printf 'b%.0s' $(seq 64))\"/\"sha256:$(printf 'e%.0s' $(seq 64))\"/" "$T/hub.json"
"$PKI" update-check >/dev/null 2>&1; rm -f "$LOG" "$T/images/9.6.3"
out="$("$PKI" update-apply "$(IMG 9.6.3)" 2>&1)"; rc=$?
expect_eq "image tirée d'une autre empreinte que celle annoncée : refusée" 1 "$rc"
expect_grep "…le message le dit" "n'a pas l'empreinte annoncée" <(printf '%s' "$out")
expect_nogrep "…le conteneur n'a jamais été arrêté, rien n'a été sauvegardé" '^systemctl stop|^pgdump' "$LOG"
expect_eq "…version installée inchangée" 9.3.7 "$(inst tag)"
expect_eq "…tâche en échec sans point de retour (rien à défaire)" "failed False" "$(jv "$RUNF" "d['job']['state'] + ' ' + str(d['job']['rollbackAvailable'])")"
touch "$T/images/9.6.3"; rm -f "$LOG"
check "image déjà présente (chargée à la main) : l'empreinte n'est pas jugée" "$PKI" update-apply "$(IMG 9.6.3)"
check "retour arrière pour la suite" "$PKI" update-rollback
rm -rf "$UPD"/2*Z-* "$UPD/job.json"
printf 'owner=a\ncerts=5\ncas=2\n' > "$T/dbstate"
sed -i "s/\"sha256:$(printf 'e%.0s' $(seq 64))\"/\"sha256:$(printf 'b%.0s' $(seq 64))\"/" "$T/hub.json"
"$PKI" update-check >/dev/null 2>&1

echo "== Mise à jour réussie : 9.3.7 → 9.6.3 =="
rm -f "$LOG" "$T/images/9.6.3"; printf 'owner=a\ncerts=5\ncas=2\n' > "$T/dbstate"
out="$("$PKI" update-apply "$(IMG 9.6.3)" 2>&1)"; rc=$?
expect_eq "mise à jour : code 0" 0 "$rc"
expect_grep "…message de fin : à valider" 'Validez la mise à jour, ou revenez en arrière' <(printf '%s' "$out")
a="$(lineno '^podman pull')"; b="$(lineno '^systemctl stop')"; c="$(lineno '^pgdump')"; d="$(lineno '^systemctl start')"
if [ -n "$a" ] && [ -n "$b" ] && [ -n "$c" ] && [ -n "$d" ] && [ "$a" -lt "$b" ] && [ "$b" -lt "$c" ] && [ "$c" -lt "$d" ]; then ok "ordre : tirage, arrêt, sauvegarde, démarrage"; else ko "ordre des étapes" "pull=$a stop=$b pgdump=$c start=$d"; fi
expect_eq "version installée : 9.6.3" 9.6.3 "$(inst tag)"
expect_eq "empreinte installée : celle de la nouvelle image" "$(D b)" "$(inst digest)"
expect_eq "unité : image épinglée par la nouvelle empreinte" "$(D b)" "$(qdig)"
expect_eq "version de la base : 9.6.3" 9.6.3 "$(cat "$T/etc/db-tag")"
expect_eq "la nouvelle image a migré la base simulée" b "$(dbget owner)"
expect_eq "tâche : en attente de validation" pending "$(jv "$UPD/job.json" "d['state']")"
expect_eq "tâche : toutes les étapes terminées" "" "$(jv "$UPD/job.json" "' '.join(s['id'] for s in d['steps'] if s['status'] != 'done')")"
expect_eq "contrôles : santé, schéma, autorités, signature, CRL tous bons" "" "$(jv "$UPD/job.json" "' '.join(c['id'] for c in d['checks'] if not c['ok'])")"
expect_eq "…cinq contrôles inscrits" 5 "$(jv "$UPD/job.json" "len(d['checks'])")"
expect_eq "tâche : de 9.3.7 vers 9.6.3" "9.3.7 9.6.3" "$(jv "$UPD/job.json" "d['from'] + ' ' + d['to']")"
expect_eq "tâche : empreintes mémorisées" "$(D a) $(D b)" "$(jv "$UPD/job.json" "d['fromDigest'] + ' ' + d['toDigest']")"
expect_eq "un seul point de retour" 1 "$(backups | wc -l)"
BK="$(backups | head -n1)"
expect_grep "…nommé d'après la date et la version d'origine" '/20[0-9]{6}T[0-9]{6}Z-9\.3\.7$' <(printf '%s' "$BK")
expect_eq "…en 0700" 700 "$(stat -c %a "$BK")"
for f in ejbca.dump files.tgz quadlet instance.json meta.json; do check "…contient $f" test -s "$BK/$f"; done
expect_eq "…la sauvegarde de la base est celle d'AVANT la migration" a "$(sed -n 's/^owner=//p' "$BK/ejbca.dump")"
expect_eq "…aucun fichier lisible par un autre utilisateur" 0 "$(find "$BK" -type f -perm /077 | wc -l)"
expect_eq "…les nombres d'autorités et de certificats à la sauvegarde sont notés" "5 2" "$(jv "$UPD/job.json" "str(d['certsAtBackup']) + ' ' + str(d['casAtBackup'])")"
expect_eq "publication : retour arrière proposé" True "$(jv "$RUNF" "d['job']['rollbackAvailable']")"
expect_eq "publication : aucun certificat émis depuis" 0 "$(jv "$RUNF" "d['certsSince']")"
expect_eq "publication : la nouvelle recherche ne propose plus 9.6.3" "10.0.0 9.7.0 9.6.5 9.6.4" "$(jv "$RUNF" "' '.join(a['tag'] for a in d['available'])")"
out="$("$PKI" update-apply "$(IMG 9.6.4)" 2>&1 || true)"
expect_grep "pendant l'attente : une autre mise à jour est refusée" "attend votre validation" <(printf '%s' "$out")
out="$("$PKI" apply "$(IMG 9.3.7)" "$HOST" "" 2>&1 || true)"
expect_grep "une ancienne image ne rouvre pas la base migrée (ou la version ne change que par la mise à jour)" 'ne change que par la mise à jour|déjà été migrée' <(printf '%s' "$out")

echo "== Retour arrière manuel =="
sed -i 's/^certs=.*/certs=7/' "$T/dbstate"   # deux certificats émis depuis la mise à jour
"$PKI" status >/dev/null 2>&1
expect_eq "publication : certificats émis depuis la mise à jour" 2 "$(jv "$RUNF" "d['certsSince']")"
rm -f "$LOG" "$T/db.events"
out="$("$PKI" update-rollback 2>&1)"; rc=$?
expect_eq "retour arrière : code 0" 0 "$rc"
expect_grep "…le message prévient des certificats perdus" '2 certificat\(s\) émis depuis la mise à jour ne sont plus connus' <(printf '%s' "$out")
expect_eq "…base remise comme avant (propriétaire a, 5 certificats)" "a 5" "$(dbget owner) $(dbget certs)"
expect_grep "…la base a été supprimée puis restaurée" 'dropped' "$T/db.events"
expect_grep "…restaurée" 'restored' "$T/db.events"
expect_eq "…version installée : 9.3.7" 9.3.7 "$(inst tag)"
expect_eq "…empreinte installée : celle de l'ancienne image" "$(D a)" "$(inst digest)"
expect_eq "…unité : ancienne empreinte" "$(D a)" "$(qdig)"
expect_eq "…version de la base : 9.3.7" 9.3.7 "$(cat "$T/etc/db-tag")"
expect_eq "…le conteneur tourne" yes "$([ -f "$T/active" ] && echo yes || echo no)"
expect_eq "…et l'ancienne image migre/retrouve sa base (propriétaire a)" a "$(dbget owner)"
expect_eq "tâche : retour arrière effectué" rolled_back "$(jv "$UPD/job.json" "d['state']")"
expect_eq "publication : plus de retour arrière proposé" False "$(jv "$RUNF" "d['job']['rollbackAvailable']")"
expect_eq "contrôles du retour arrière tous bons" "" "$(jv "$UPD/job.json" "' '.join(c['id'] for c in d['checks'] if not c['ok'])")"
check_fail "un second retour arrière est refusé" "$PKI" update-rollback
check_fail "valider sans mise à jour en attente est refusé" "$PKI" update-validate
expect_eq "le point de retour reste sur le disque (14 jours)" 1 "$(backups | wc -l)"

echo "== Validation =="
rm -f "$LOG"; printf 'owner=a\ncerts=5\ncas=2\n' > "$T/dbstate"
check "nouvelle mise à jour 9.3.7 → 9.6.3 (après un retour arrière)" "$PKI" update-apply "$(IMG 9.6.3)"
expect_eq "…en attente" pending "$(jv "$UPD/job.json" "d['state']")"
out="$("$PKI" update-validate 2>&1)"; rc=$?
expect_eq "validation : code 0" 0 "$rc"
expect_grep "…le message donne la durée de conservation" 'gardée 14 jours' <(printf '%s' "$out")
expect_eq "tâche : validée" validated "$(jv "$UPD/job.json" "d['state']")"
expect_eq "publication : plus de retour arrière" False "$(jv "$RUNF" "d['job']['rollbackAvailable']")"
check_fail "retour arrière refusé après validation" "$PKI" update-rollback
expect_eq "version de la base : 9.6.3" 9.6.3 "$(cat "$T/etc/db-tag")"
check "après validation, une mise à jour 9.6.3 → 9.6.4 est permise" "$PKI" update-apply "$(IMG 9.6.4)"
expect_eq "…version installée : 9.6.4" 9.6.4 "$(inst tag)"
expect_eq "…version de la base : 9.6.4" 9.6.4 "$(cat "$T/etc/db-tag")"
expect_eq "…trois points de retour en tout (aucun écrasement)" 3 "$(backups | wc -l)"
check "validée" "$PKI" update-validate
check_fail "descendre de 9.6.4 à 9.6.3 est refusé (plus ancienne que la base)" "$PKI" update-apply "$(IMG 9.6.3)"

echo "== Échec de la nouvelle image : retour arrière automatique =="
# 1. elle ne démarre pas
printf 'owner=c\ncerts=9\ncas=2\n' > "$T/dbstate"; D d > "$T/bad/start"; rm -f "$LOG" "$T/db.events"
out="$("$PKI" update-apply "$(IMG 9.6.5)" 2>&1)"; rc=$?
expect_eq "démarrage impossible : code 1" 1 "$rc"
expect_grep "…le message annonce le retour arrière" 'retour arrière' <(printf '%s' "$out")
expect_grep "…et dit que l'ancienne version est de nouveau en service" 'EJBCA 9\.6\.4 est de nouveau en service' <(printf '%s' "$out")
expect_eq "…version installée : 9.6.4" 9.6.4 "$(inst tag)"
expect_eq "…unité : ancienne empreinte (c)" "$(D c)" "$(qdig)"
expect_eq "…le conteneur tourne" yes "$([ -f "$T/active" ] && echo yes || echo no)"
expect_eq "…tâche : retour arrière effectué, cause « start »" "rolled_back start" "$(jv "$UPD/job.json" "d['state'] + ' ' + d['reason']")"
expect_eq "…version de la base : 9.6.4" 9.6.4 "$(cat "$T/etc/db-tag")"
expect_eq "…base remise comme avant" "c 9" "$(dbget owner) $(dbget certs)"
rm -f "$T/bad/start"
# 2. elle démarre mais n'est jamais en bonne santé
printf 'owner=c\ncerts=9\ncas=2\n' > "$T/dbstate"; D d > "$T/bad/health"; rm -f "$LOG" "$T/db.events"
out="$("$PKI" update-apply "$(IMG 9.6.5)" 2>&1)"; rc=$?
expect_eq "jamais en bonne santé : code 1" 1 "$rc"
expect_grep "…le message le dit" "n'est pas en bonne santé" <(printf '%s' "$out")
expect_eq "…version installée : 9.6.4" 9.6.4 "$(inst tag)"
expect_eq "…tâche : retour arrière effectué, cause « health »" "rolled_back health" "$(jv "$UPD/job.json" "d['state'] + ' ' + d['reason']")"
expect_eq "…base remise comme avant" "c 9" "$(dbget owner) $(dbget certs)"
expect_eq "…et la santé revient avec l'ancienne image" ALLOK "$("$B/curl" -fsS http://127.0.0.1:8080/ejbca/publicweb/healthcheck/ejbcahealth)"
rm -f "$T/bad/health"
# 3. redémarrage en boucle : on n'attend pas la fin du délai
printf 'owner=c\ncerts=9\ncas=2\n' > "$T/dbstate"; D d > "$T/bad/health"; echo 5 > "$T/nrestarts"; rm -f "$LOG"
out="$(DDI_PKI_UPDATE_WAIT=600 "$PKI" update-apply "$(IMG 9.6.5)" 2>&1)"; rc=$?
expect_eq "redémarrage en boucle : code 1" 1 "$rc"
expect_grep "…détecté" 'redémarre en boucle' <(printf '%s' "$out")
expect_eq "…retour arrière effectué" rolled_back "$(jv "$UPD/job.json" "d['state']")"
rm -f "$T/bad/health" "$T/nrestarts"
# 4. un contrôle échoue : colonne d'EJBCA disparue
printf 'owner=c\ncerts=9\ncas=2\n' > "$T/dbstate"; echo d > "$T/bad/schema-owner"; echo 'certificatedata.expiredate' > "$T/schema-missing"
out="$("$PKI" update-apply "$(IMG 9.6.5)" 2>&1)"; rc=$?
expect_eq "schéma modifié : code 1" 1 "$rc"
expect_grep "…retour arrière après les contrôles" 'contrôles en échec' <(printf '%s' "$out")
expect_eq "…version installée : 9.6.4" 9.6.4 "$(inst tag)"
expect_eq "…tâche : retour arrière effectué, cause « checks »" "rolled_back checks" "$(jv "$UPD/job.json" "d['state'] + ' ' + d['reason']")"
rm -f "$T/bad/schema-owner" "$T/schema-missing"
# 5. la signature échoue : jeton de clés hors ligne
printf 'owner=c\ncerts=9\ncas=2\n' > "$T/dbstate"; D d > "$T/bad/crl"
out="$("$PKI" update-apply "$(IMG 9.6.5)" 2>&1)"; rc=$?
expect_eq "signature impossible : code 1" 1 "$rc"
expect_eq "…version installée : 9.6.4" 9.6.4 "$(inst tag)"
expect_eq "…retour arrière effectué" rolled_back "$(jv "$UPD/job.json" "d['state']")"
rm -f "$T/bad/crl"
# 6. moins d'autorités qu'avant la mise à jour
printf 'owner=c\ncerts=9\ncas=2\n' > "$T/dbstate"
cat > "$B/psql-fewer" <<EOF
#!/bin/bash
sql="\$(cat)"
case "\$sql" in *"count(*) from cadata"*) [ "\$(sed -n 's/^owner=//p' $T/dbstate)" = d ] && { echo 1; exit 0; } ;; esac
printf '%s' "\$sql" | $B/psql "\$@"
EOF
chmod +x "$B/psql-fewer"
out="$(DDI_PKI_PSQL="$B/psql-fewer" "$PKI" update-apply "$(IMG 9.6.5)" 2>&1)"; rc=$?
expect_eq "une autorité manque après la migration : code 1" 1 "$rc"
expect_eq "…version installée : 9.6.4" 9.6.4 "$(inst tag)"
expect_eq "…retour arrière effectué" rolled_back "$(jv "$UPD/job.json" "d['state']")"

echo "== Le retour arrière lui-même échoue =="
printf 'owner=c\ncerts=9\ncas=2\n' > "$T/dbstate"; D d > "$T/bad/health"; touch "$T/pgrestore-fail"
out="$("$PKI" update-apply "$(IMG 9.6.5)" 2>&1)"; rc=$?
expect_eq "base non restaurable : code 1" 1 "$rc"
expect_grep "…le message le dit" 'retour arrière a échoué' <(printf '%s' "$out")
expect_eq "…tâche en échec" failed "$(jv "$UPD/job.json" "d['state']")"
expect_eq "…le retour arrière reste proposé" True "$(jv "$RUNF" "d['job']['rollbackAvailable']")"
expect_eq "…le point de retour est gardé" yes "$([ -d "$UPD/$(jv "$UPD/job.json" "d['backup']")" ] && echo yes || echo no)"
out="$("$PKI" update-apply "$(IMG 9.6.5)" 2>&1 || true)"
expect_grep "…aucune nouvelle mise à jour tant qu'il n'a pas été fait" 'point de retour' <(printf '%s' "$out")
rm -f "$T/pgrestore-fail" "$T/bad/health"
out="$("$PKI" update-rollback 2>&1)"; rc=$?
expect_eq "…le retour arrière manuel réussit une fois la cause levée" 0 "$rc"
expect_eq "…tâche : retour arrière effectué" rolled_back "$(jv "$UPD/job.json" "d['state']")"
expect_eq "…version installée : 9.6.4" 9.6.4 "$(inst tag)"

echo "== Maintenance : tâche interrompue, nettoyage, recherche quotidienne =="
python3 "$H" update-job "$UPD/job.json" init 9.6.4 9.6.5 "$(D c)" pull stop backup
"$PKI" maintain >/dev/null 2>&1
expect_eq "tâche restée « en cours » après une coupure : marquée en échec" failed "$(jv "$UPD/job.json" "d['state']")"
expect_grep "…avec un message qui dit quoi faire" 'interrompue' "$UPD/job.json"
old="$UPD/20200101T000000Z-9.0.0"; mkdir -p "$old"; touch -d '60 days ago' "$old"
kept="$UPD/20200102T000000Z-9.0.1"; mkdir -p "$kept"; touch -d '60 days ago' "$kept"
python3 "$H" update-job "$UPD/job.json" set state=failed "backup=20200102T000000Z-9.0.1"
"$PKI" maintain >/dev/null 2>&1
expect_eq "point de retour ancien et inutile : supprimé" no "$([ -e "$old" ] && echo yes || echo no)"
expect_eq "…mais celui d'un retour arrière encore possible est gardé" yes "$([ -e "$kept" ] && echo yes || echo no)"
python3 "$H" update-job "$UPD/job.json" set state=validated
rm -rf "$kept"
rm -f "$LOG" "$UPD/check.json"
DDI_PKI_NO_UPDATE_CHECK=0 "$PKI" maintain >/dev/null 2>&1
expect_eq "recherche quotidienne : faite quand aucune n'existe" 1 "$(grep -c '^curl https://hub\.docker\.com' "$LOG")"
DDI_PKI_NO_UPDATE_CHECK=0 "$PKI" maintain >/dev/null 2>&1
expect_eq "…et pas une deuxième fois dans la journée" 1 "$(grep -c '^curl https://hub\.docker\.com' "$LOG")"
DDI_PKI_NO_UPDATE_CHECK=0 DDI_PKI_UPDATE_CHECK_EVERY=0 "$PKI" maintain >/dev/null 2>&1
expect_eq "…mais de nouveau quand le délai est passé" 2 "$(grep -c '^curl https://hub\.docker\.com' "$LOG")"
touch "$T/hub-down"; rm -f "$UPD/check.json"
check "Docker Hub injoignable : la maintenance ne plante pas" env DDI_PKI_NO_UPDATE_CHECK=0 "$PKI" maintain
rm -f "$T/hub-down"

echo "== Par la console (demandes) =="
req '{"action":"update_check"}'; expect_eq "update_check : ok" True "$(res ok)"
expect_eq "…le résultat porte l'action" update_check "$(res action)"
req '{"action":"update_validate"}'; expect_eq "update_validate sans mise à jour en attente : refusé" False "$(res ok)"
req '{"action":"update_rollback"}'; expect_eq "update_rollback sans mise à jour : refusé" False "$(res ok)"
req '{"action":"update_apply","image":"docker.io/evil/ejbca-ce:9.6.5"}'; expect_eq "image d'un autre dépôt : refusée" False "$(res ok)"
req '{"action":"update_apply","image":"'"$(IMG 9.6.5)"'","x":1}'; expect_eq "champ en trop : refusé" False "$(res ok)"
expect_eq "demande consommée" no "$([ -e "$T/gen/.pki-request" ] && echo yes || echo no)"
printf 'owner=c\ncerts=9\ncas=2\n' > "$T/dbstate"; reset_flags
req '{"action":"update_apply","image":"'"$(IMG 9.6.5)"'"}'
expect_eq "update_apply : ok" True "$(res ok)"
expect_eq "…version installée : 9.6.5" 9.6.5 "$(inst tag)"
expect_eq "…état publié : en attente de validation" pending "$(jv "$RUNF" "d['job']['state']")"
req '{"action":"update_rollback"}'; expect_eq "update_rollback : ok" True "$(res ok)"
expect_eq "…version installée : 9.6.4" 9.6.4 "$(inst tag)"
req '{"action":"update_apply","image":"'"$(IMG 9.6.5)"'"}'; expect_eq "nouvelle mise à jour : ok" True "$(res ok)"
req '{"action":"update_validate"}'; expect_eq "update_validate : ok" True "$(res ok)"
expect_eq "…état publié : validée" validated "$(jv "$RUNF" "d['job']['state']")"

echo "== Remise à zéro : tout ce qui concerne les mises à jour disparaît =="
printf 'owner=d\ncerts=0\ncas=0\n' > "$T/dbstate"
out="$("$PKI" reset 2>&1)"; rc=$?
expect_eq "remise à zéro sans autorité : code 0" 0 "$rc"
expect_eq "…dossier de mise à jour effacé" no "$([ -e "$UPD" ] && echo yes || echo no)"
expect_eq "…version de la base oubliée" no "$([ -e "$T/etc/db-tag" ] && echo yes || echo no)"
expect_eq "…publication effacée" no "$([ -e "$RUNF" ] && echo yes || echo no)"
expect_eq "…plus d'unité" no "$([ -e "$QUAD" ] && echo yes || echo no)"

echo "== Sécurité du code =="
expect_nogrep "aucune évaluation de texte de la console (eval)" '(^|[^a-z_])eval[[:space:]]' <(sed -n '/^# ---- Mises à jour de l.image/,/^# minuteur/p' "$PKI")
expect_nogrep "aucun appel de shell construit à partir d'une variable (bash -c)" 'bash -c' <(sed -n '/^# ---- Mises à jour de l.image/,/^# minuteur/p' "$PKI")
expect_grep "le délai de l'unité de demande couvre un tirage lent et deux attentes de santé" '^TimeoutStartSec=5400$' "$RFS/etc/systemd/system/ddibuntu-pki-request.service"

finish
