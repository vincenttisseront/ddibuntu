#!/usr/bin/env bash
# Batterie 44 — playbook AWX de validation des versions candidates (deploy/awx/dev-validation.yml), joué en local contre un FAUX GitHub :
# rien à faire sans version candidate, installation + verdict « success » avec l'empreinte installée, verdicts « failure » (tests de fumée,
# mise à jour), jeton jamais affiché. Demande ansible-playbook (CI : pip install ansible-core) ; ni root ni appliance.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
for t in ansible-playbook python3; do command -v "$t" >/dev/null 2>&1 || { ko "outil requis absent : $t"; finish; exit; }; done
PB="$(cd "$(dirname "$0")/.." && pwd)/deploy/awx/dev-validation.yml"
W="$T_TMP/w"; A="$W/app"; S="$W/gh"; PORT=$((20000 + RANDOM % 20000)); TOKEN="jeton-factice-$RANDOM$RANDOM"
mkdir -p "$A" "$S"
mk() { mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; chmod "${3:-644}" "$1"; }

# ---- faux GitHub : liste des releases lue dans $S/releases.json, verdicts écrits dans $S/dispatch.json (jeton exigé)
cat > "$W/gh.py" <<'PY'
import http.server, json, os, sys
d, port, tok = sys.argv[1], int(sys.argv[2]), sys.argv[3]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def auth(self):
        if self.headers.get('Authorization') != 'Bearer ' + tok:
            self.send_response(401); self.end_headers(); return False
        return True
    def do_GET(self):
        if not self.auth(): return
        if self.path.startswith('/repos/acme/appliance/releases'):
            b = open(os.path.join(d, 'releases.json'), 'rb').read()
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(b); return
        self.send_response(404); self.end_headers()
    def do_POST(self):
        if not self.auth(): return
        n = int(self.headers.get('Content-Length', 0)); b = self.rfile.read(n)
        if self.path == '/repos/acme/appliance/dispatches':
            open(os.path.join(d, 'dispatch.json'), 'wb').write(b); self.send_response(204); self.end_headers(); return
        self.send_response(404); self.end_headers()
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PY
python3 "$W/gh.py" "$S" "$PORT" "$TOKEN" >/dev/null 2>&1 &
GH_PID=$!
trap 'kill "$GH_PID" 2>/dev/null; rm -rf "$T_TMP"' EXIT
sleep 1

# ---- fausse appliance : mise à jour et tests de fumée simulés
HASH=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
mk "$A/update.conf" 'REPO="acme/appliance"
#CHANNEL=stable'
mk "$A/VERSION" 1.0.0
mk "$A/selfupdate" "#!/bin/bash
echo \"\$*\" >> '$A/selfupdate.calls'
[ -e '$A/update-ko' ] && { echo 'ddibuntu-selfupdate: ERREUR : SIGNATURE INVALIDE' >&2; exit 1; }
echo \"\$2\" > '$A/VERSION'; echo '$HASH  ddibuntu-update-'\"\$2\"'.tar.gz' > '$A/bundle.sha256'" 755
mk "$A/selftest" "#!/bin/bash
v=\$(cat '$A/VERSION')
if [ -e '$A/selftest-ko' ]; then echo '{\"ok\":false,\"version\":\"'\$v'\",\"checks\":[{\"name\":\"service:dhcp\",\"result\":\"ko\",\"detail\":\"failed\"}]}'; exit 1; fi
echo '{\"ok\":true,\"version\":\"'\$v'\",\"checks\":[{\"name\":\"console-version\",\"result\":\"ok\",\"detail\":\"'\$v'\"}]}'" 755
cat > "$W/inv.yml" <<EOF
appliance_dev:
  hosts:
    dev1: { ansible_connection: local, ansible_python_interpreter: "$(command -v python3)" }
EOF
releases() { # releases.json : $1 = corps de la pré-version 2.0.0
  python3 - "$S/releases.json" "$1" <<'PY'
import json, sys
json.dump([{'tag_name': 'v3.0.0', 'draft': True, 'prerelease': True, 'body': '<!-- validation:pending -->'},
           {'tag_name': 'v2.0.0', 'draft': False, 'prerelease': True, 'body': sys.argv[2]},
           {'tag_name': 'v1.0.0', 'draft': False, 'prerelease': False, 'body': None}], open(sys.argv[1], 'w'))
PY
}
play() {
  rm -f "$S/dispatch.json"
  GITHUB_TOKEN="$TOKEN" GITHUB_REPOSITORY=acme/appliance ANSIBLE_NOCOLOR=1 ansible-playbook -i "$W/inv.yml" "$PB" \
    -e ansible_become=false -e github_api="http://127.0.0.1:$PORT" -e update_timeout=60 -e selftest_wait=1 \
    -e awx_public_url=https://awx.exemple.test -e awx_job_id=42 \
    -e appliance_update_conf="$A/update.conf" -e appliance_version_file="$A/VERSION" -e appliance_bundle_hash="$A/bundle.sha256" \
    -e appliance_selfupdate="$A/selfupdate" -e appliance_selftest="$A/selftest" > "$W/play.log" 2>&1
  echo $?
}
dget() { python3 -c "import json; d=json.load(open('$S/dispatch.json')); p=d['client_payload']; print(d['event_type'] if '$1'=='event_type' else p.get('$1'))" 2>/dev/null; }

echo "== 1. Aucune version candidate en attente =="
releases '<!-- validation:passed -->'
expect_eq "code 0" 0 "$(play)"
expect_eq "…aucun verdict envoyé" no "$([ -e "$S/dispatch.json" ] && echo yes || echo no)"
expect_eq "…rien installé" no "$([ -e "$A/selfupdate.calls" ] && echo yes || echo no)"

echo "== 2. Version candidate validée =="
releases $'<!-- validation:pending -->\n> en validation\n<!-- /validation -->\nNotes'
expect_eq "code 0" 0 "$(play)"
expect_eq "…mise à jour en ligne vers la candidate (pas le brouillon 3.0.0)" "apply 2.0.0" "$(cat "$A/selfupdate.calls" 2>/dev/null)"
expect_grep "…canal prerelease posé dans update.conf" '^CHANNEL=prerelease$' "$A/update.conf"
expect_eq "…événement dev-validation" dev-validation "$(dget event_type)"
expect_eq "…version" 2.0.0 "$(dget version)"
expect_eq "…verdict success" success "$(dget result)"
expect_eq "…empreinte de l'archive installée" "$HASH" "$(dget bundle_sha256)"
expect_eq "…lien vers le travail AWX" "https://awx.exemple.test/#/jobs/playbook/42/output" "$(dget job_url)"
if dget report | grep -q "console-version"; then ok "…rapport des tests de fumée joint"; else ko "…rapport" "$(dget report)"; fi
expect_nogrep "…le jeton n'apparaît jamais dans la sortie du travail" "$TOKEN" "$W/play.log"
expect_eq "déjà à jour : pas de nouvelle installation, verdict renvoyé" 0 "$(play)"
expect_eq "…une seule installation" 1 "$(wc -l < "$A/selfupdate.calls")"

echo "== 3. Tests de fumée en échec =="
mk "$A/VERSION" 1.0.0; : > "$A/selftest-ko"
expect_eq "code ≠ 0 (le travail AWX échoue)" 2 "$(play)"
expect_eq "…verdict failure" failure "$(dget result)"
if dget report | grep -q "ko  service:dhcp"; then ok "…le contrôle en échec est nommé dans le rapport"; else ko "…rapport" "$(dget report)"; fi
if dget report | grep -qE "failed|dev1"; then ko "…le rapport (public) ne doit contenir ni détail ni nom d'hôte" "$(dget report)"; else ok "…rapport public sans détail ni nom d'hôte"; fi
expect_grep "…le détail reste dans la sortie du travail AWX" "ko  service:dhcp  failed" "$W/play.log"
rm -f "$A/selftest-ko"

echo "== 4. Mise à jour en ligne refusée =="
mk "$A/VERSION" 1.0.0; rm -f "$A/bundle.sha256"; : > "$A/update-ko"
expect_eq "code ≠ 0" 2 "$(play)"
expect_eq "…verdict failure" failure "$(dget result)"
if dget report | grep -q "SIGNATURE INVALIDE"; then ok "…le message de la mise à jour est dans le rapport"; else ko "…rapport" "$(dget report)"; fi
expect_eq "…aucune empreinte annoncée" "" "$(dget bundle_sha256)"
rm -f "$A/update-ko"

echo "== 5. Jeton refusé par GitHub =="
TOKEN_SAVE="$TOKEN"; TOKEN=mauvais
expect_eq "code ≠ 0" 2 "$(play)"
expect_nogrep "…le jeton refusé n'est pas affiché non plus" "Bearer mauvais" "$W/play.log"
TOKEN="$TOKEN_SAVE"
finish
