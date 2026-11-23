#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Batterie 45 — jeu de clés de confiance des mises à jour et manifestes de rotation (release-keys.sh, ddibuntu-selfupdate,
# tools/release-keys.sh). Uniquement des clés ÉPHÉMÈRES générées ici : « ancienne », « active », « secours », « malveillante ».
# Vérifie chaque refus : signature d'une clé inconnue, clé de secours utilisée pour une archive, manifeste non signé par la clé
# de secours, manifeste altéré, rejeu, clé révoquée réintroduite, et le cas d'urgence (clé active compromise, puis remplacée).
# Contrôle aussi que les clés publiques livrées dans src/rootfs sont valides. Ne demande ni root ni systemd.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
for t in openssl python3 curl flock; do command -v "$t" >/dev/null 2>&1 || { ko "outil requis absent : $t"; finish; exit; }; done
LIB="$RFS/usr/local/lib/ddibuntu/release-keys.sh"
SU="$RFS/usr/local/sbin/ddibuntu-selfupdate"
TOOL="$ROOT/tools/release-keys.sh"
W="$T_TMP/w"; mkdir -p "$W/k"
K="$W/k"
gen() { openssl genpkey -algorithm ed25519 -out "$K/$1.key" 2>/dev/null && openssl pkey -in "$K/$1.key" -pubout -out "$K/$1.pub"; }
for n in ancienne active secours evil k3 k4; do gen "$n"; done
fpr() { openssl pkey -pubin -in "$1" -outform DER | sha256sum | cut -c1-64; }
sign() { openssl pkeyutl -sign -inkey "$K/$1.key" -rawin -in "$2" -out "$3"; }
# manifeste n° seq, révoque « $2 » (empreintes séparées par des virgules), ajoute la clé $3 (nom ou « null »)
manifest() {
  python3 - "$@" <<'PY'
import json, sys
seq, olds, new, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
d = {'format': 1, 'usage': 'release', 'sequence': int(seq), 'date': '2026-11-23', 'reason': 'essai de rotation',
     'old_fingerprints': [x for x in olds.split(',') if x],
     'new_public_key': None if new == 'null' else open(new).read()}
json.dump(d, open(out, 'w'), indent=1)
PY
}

echo "== 0. Clés publiques livrées =="
for f in "$RFS"/etc/ddibuntu/keys/release.d/*.pem "$RFS/etc/ddibuntu/keys/release-secours.pem" "$RFS/etc/ddibuntu/update-pubkey.pem"; do
  t="$(openssl pkey -pubin -in "$f" -noout -text_pub 2>/dev/null | head -1)"
  expect_eq "${f#"$RFS"/} : clé publique Ed25519" "ED25519 Public-Key:" "$t"
done
if grep -l 'PRIVATE KEY' -r "$RFS/etc/ddibuntu" >/dev/null 2>&1; then ko "aucune clé privée dans le dépôt"; else ok "aucune clé privée dans le dépôt"; fi
sec_fp="$(fpr "$RFS/etc/ddibuntu/keys/release-secours.pem")"
for f in "$RFS"/etc/ddibuntu/keys/release.d/*.pem "$RFS/etc/ddibuntu/update-pubkey.pem"; do
  [ "$(fpr "$f")" != "$sec_fp" ] && ok "${f##*/} différente de la clé de secours" || ko "${f##*/} est la clé de secours"
done

echo "== 1. Bibliothèque : vérification par le jeu de clés =="
C="$W/conf"; S="$W/state"
mkdir -p "$C/keys/release.d"
cp "$K/ancienne.pub" "$C/update-pubkey.pem"; cp "$K/active.pub" "$C/keys/release.d/active.pem"; cp "$K/secours.pub" "$C/keys/release-secours.pem"
cp "$K/evil.key" "$C/keys/release.d/pas-une-cle-publique.pem"     # un fichier qui n'est pas une clé publique est ignoré
lib() { ( export RK_CONFDIR="$C" RK_STATE="$S" RK_LEGACY="$C/update-pubkey.pem"
          # shellcheck source=/dev/null
          . "$LIB"; "$@" ); }
echo "contenu signé" > "$W/data"
for n in ancienne active secours evil; do sign "$n" "$W/data" "$W/data.$n.sig"; done
check "signature par la clé active : acceptée" lib rk_verify "$W/data" "$W/data.active.sig"
check "signature par l'ancienne clé (transition) : acceptée" lib rk_verify "$W/data" "$W/data.ancienne.sig"
check_fail "signature par une clé inconnue : refusée" lib rk_verify "$W/data" "$W/data.evil.sig"
check_fail "signature par la clé de secours : refusée (elle ne signe que les rotations)" lib rk_verify "$W/data" "$W/data.secours.sig"
echo "contenu modifié" > "$W/data2"
check_fail "contenu modifié après signature : refusé" lib rk_verify "$W/data2" "$W/data.active.sig"
expect_eq "deux clés de confiance (fichier invalide ignoré)" 2 "$(lib rk_trusted | wc -l)"
vfpr() { rk_verify "$1" "$2" && printf '%s' "$RK_KEY_FPR"; }
expect_eq "la clé qui a vérifié est identifiée (empreinte)" "$(fpr "$K/active.pub")" "$(lib vfpr "$W/data" "$W/data.active.sig")"

echo "== 2. Manifestes refusés =="
OLD_A="$(fpr "$K/active.pub")"
manifest 1 "$OLD_A" "$K/k3.pub" "$W/m1.json"
sign evil "$W/m1.json" "$W/m1.evil.sig"; sign active "$W/m1.json" "$W/m1.active.sig"; sign secours "$W/m1.json" "$W/m1.sig"
check_fail "manifeste signé par une clé inconnue : refusé" lib rk_apply_rotation "$W/m1.json" "$W/m1.evil.sig"
check_fail "manifeste signé par la clé ACTIVE (pas la clé de secours) : refusé" lib rk_apply_rotation "$W/m1.json" "$W/m1.active.sig"
cp "$W/m1.json" "$W/m1-alt.json"; sed -i 's/essai de rotation/rotation modifiée/' "$W/m1-alt.json"
check_fail "manifeste modifié après signature : refusé" lib rk_apply_rotation "$W/m1-alt.json" "$W/m1.sig"
bad() {   # nom, transformation python de d, attendu dans RK_ERR
  python3 - "$W/m1.json" "$W/bad.json" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); exec(sys.argv[3]); json.dump(d, open(sys.argv[2], 'w'))
PY
  sign secours "$W/bad.json" "$W/bad.sig"
  check_fail "manifeste signé mais invalide ($1) : refusé" lib rk_apply_rotation "$W/bad.json" "$W/bad.sig"
}
bad "usage catalogue" "d['usage'] = 'catalog'"
bad "format inconnu" "d['format'] = 2"
bad "séquence nulle" "d['sequence'] = 0"
bad "séquence texte" "d['sequence'] = '1'"
bad "sans motif" "d['reason'] = ''"
bad "empreinte invalide" "d['old_fingerprints'] = ['zz']"
bad "nouvelle clé = clé de secours" "d['new_public_key'] = open('$K/secours.pub').read()"
bad "nouvelle clé privée" "d['new_public_key'] = open('$K/k3.key').read()"
bad "révoque la clé qu'il ajoute" "d['old_fingerprints'] = ['$(fpr "$K/k3.pub")']"
bad "sans effet" "d['old_fingerprints'] = []; d['new_public_key'] = None"
printf 'pas du json' > "$W/bad.json"; sign secours "$W/bad.json" "$W/bad.sig"
check_fail "manifeste illisible : refusé" lib rk_apply_rotation "$W/bad.json" "$W/bad.sig"
expect_eq "aucune rotation appliquée après les refus" 0 "$(lib rk_seq)"
expect_eq "aucune révocation après les refus" no "$([ -s "$S/revoked" ] && echo yes || echo no)"
expect_eq "rien n'est écrit pour des manifestes refusés" no "$([ -n "$(find "$S/release.d" -mindepth 1 2>/dev/null)" ] && echo yes || echo no)"

echo "== 3. Rotation valide, révocation, rejeu =="
check "manifeste n°1 signé par la clé de secours : appliqué" lib rk_apply_rotation "$W/m1.json" "$W/m1.sig"
expect_eq "dernière rotation = 1" 1 "$(lib rk_seq)"
check_fail "clé active révoquée : sa signature est refusée" lib rk_verify "$W/data" "$W/data.active.sig"
sign k3 "$W/data" "$W/data.k3.sig"
check "nouvelle clé (k3) : acceptée" lib rk_verify "$W/data" "$W/data.k3.sig"
check "ancienne clé non révoquée : toujours acceptée" lib rk_verify "$W/data" "$W/data.ancienne.sig"
expect_eq "rejeu du manifeste n°1 : ignoré (code 2)" 2 "$(lib rk_apply_rotation "$W/m1.json" "$W/m1.sig" >/dev/null 2>&1; echo $?)"
manifest 2 "" "$K/active.pub" "$W/m2.json"; sign secours "$W/m2.json" "$W/m2.sig"
check_fail "réintroduire une clé révoquée : refusé" lib rk_apply_rotation "$W/m2.json" "$W/m2.sig"
cp "$K/active.pub" "$C/keys/release.d/active-2.pem"
check_fail "une version qui relivre la clé révoquée ne la rend pas de confiance" lib rk_verify "$W/data" "$W/data.active.sig"
rm -f "$C/keys/release.d/active-2.pem"
manifest 2 "$(fpr "$K/ancienne.pub")" null "$W/m2.json"; sign secours "$W/m2.json" "$W/m2.sig"
check "manifeste n°2 (révocation seule de l'ancienne clé) : appliqué" lib rk_apply_rotation "$W/m2.json" "$W/m2.sig"
check_fail "ancienne clé révoquée : refusée" lib rk_verify "$W/data" "$W/data.ancienne.sig"
expect_eq "rejeu d'un numéro plus petit : ignoré (code 2)" 2 "$(lib rk_apply_rotation "$W/m1.json" "$W/m1.sig" >/dev/null 2>&1; echo $?)"
expect_eq "une seule clé de confiance : k3" "$(fpr "$K/k3.pub")" "$(lib rk_trusted | cut -f1)"
manifest 3 "$(fpr "$K/k3.pub")" null "$W/m3.json"; sign secours "$W/m3.json" "$W/m3.sig"
check "manifeste n°3 (révoque la dernière clé) : appliqué" lib rk_apply_rotation "$W/m3.json" "$W/m3.sig"
check_fail "plus aucune clé de confiance : tout est refusé" lib rk_verify "$W/data" "$W/data.k3.sig"
rm -f "$C/keys/release-secours.pem"
manifest 4 "" "$K/k4.pub" "$W/m4.json"; sign secours "$W/m4.json" "$W/m4.sig"
check_fail "clé de secours absente : aucun manifeste accepté" lib rk_apply_rotation "$W/m4.json" "$W/m4.sig"

echo "== 4. ddibuntu-selfupdate : transition, urgence, manifeste hostile (faux GitHub) =="
R="$W/root"; SRV="$W/srv"; PORT=$((20000 + RANDOM % 20000))
mk() { mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; chmod "${3:-644}" "$1"; }
jget() { python3 -c "import json,sys; d=json.load(open('$1')); v=d.get('$2'); print(v if not isinstance(v,bool) else str(v).lower())" 2>/dev/null; }
mk "$R/usr/local/lib/ddibuntu/VERSION" 0.4.0
cp "$RFS/usr/local/lib/ddibuntu/common.sh" "$LIB" "$R/usr/local/lib/ddibuntu/"
mk "$R/etc/ddibuntu/update.conf" 'REPO="acme/ddibuntu"'
mkdir -p "$R/etc/ddibuntu/keys/release.d"
cp "$K/ancienne.pub" "$R/etc/ddibuntu/update-pubkey.pem"; cp "$K/active.pub" "$R/etc/ddibuntu/keys/release.d/active.pem"; cp "$K/secours.pub" "$R/etc/ddibuntu/keys/release-secours.pem"
mk "$R/opt/ddibuntu/console/app/server/index.mjs" "OLD CONSOLE"
mk "$R/var/lib/ddibuntu/installed-version" 0.4.0
mk "$R/usr/local/sbin/ddibuntu-fw" '#!/bin/bash
true' 755
mkdir -p "$R/run" "$SRV/dl" "$SRV/repos/acme/ddibuntu/releases"
mkrelease() { # version clé [manifestes joints : « n:fichier.json:fichier.sig » …]
  local v="$1" key="$2" d="$W/rel-$1"; shift 2; rm -rf "$d" "$SRV/dl"; mkdir -p "$d/rootfs/usr/local/lib/ddibuntu" "$d/con/app/server" "$d/b" "$SRV/dl"
  echo "$v" > "$d/rootfs/usr/local/lib/ddibuntu/VERSION"; echo "NEW CONSOLE $v" > "$d/con/app/server/index.mjs"
  ( cd "$d/rootfs" && tar --owner=0 --group=0 -cf "$d/b/rootfs.tar" . ); ( cd "$d/b" && sha256sum rootfs.tar > rootfs.tar.sha256 )
  ( cd "$d/con" && tar -czf "$d/b/console.tar.gz" . ); echo "$v" > "$d/b/VERSION"
  ( cd "$d/b" && tar -czf "$SRV/dl/ddibuntu-update-$v.tar.gz" rootfs.tar rootfs.tar.sha256 console.tar.gz VERSION )
  ( cd "$SRV/dl" && sha256sum "ddibuntu-update-$v.tar.gz" > SHA256SUMS )
  sign "$key" "$SRV/dl/SHA256SUMS" "$SRV/dl/SHA256SUMS.sig"
  local names="ddibuntu-update-$v.tar.gz SHA256SUMS SHA256SUMS.sig" m n mj ms
  for m in "$@"; do
    IFS=: read -r n mj ms <<< "$m"
    cp "$mj" "$SRV/dl/key-rotation-$n.json"; cp "$ms" "$SRV/dl/key-rotation-$n.json.sig"
    names="$names key-rotation-$n.json key-rotation-$n.json.sig"
  done
  python3 - "$SRV/repos/acme/ddibuntu/releases/latest" "$v" "$PORT" "$names" <<'PY'
import json, sys
p, v, port, names = sys.argv[1:5]
base = 'http://127.0.0.1:%s/dl/' % port
json.dump({'tag_name': 'v' + v, 'html_url': 'https://github.com/acme/ddibuntu/releases/tag/v' + v, 'published_at': '2026-11-23T10:00:00Z',
           'body': 'Notes %s' % v, 'draft': False, 'prerelease': False,
           'assets': [{'name': n, 'url': base + n} for n in names.split()]}, open(p, 'w'))
PY
}
( cd "$SRV" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >"$W/http.log" 2>&1 ) & HTTP_PID=$!
trap 'kill "$HTTP_PID" 2>/dev/null; rm -rf "$T_TMP"' EXIT
sleep 1
export DDI_TEST=1 DDI_NO_SYSTEMD=1 DDI_ROOT="$R" DDI_LIBDIR="$R/usr/local/lib/ddibuntu" DDI_RUNDIR="$R/run" DDI_UPDATE_API="http://127.0.0.1:$PORT" DDI_HEALTH_TRIES=1 DDI_HEALTH_SLEEP=0
ST="$R/var/lib/ddibuntu/update-status.json"
su_() { bash "$SU" "$@" >"$W/out.log" 2>&1; echo $?; }
console() { cat "$R/opt/ddibuntu/console/app/server/index.mjs"; }

mkrelease 0.5.0 active
expect_eq "version signée par la NOUVELLE clé active : installée" 0 "$(su_ apply 0.5.0)"
expect_eq "…console 0.5.0" "NEW CONSOLE 0.5.0" "$(console)"
mkrelease 0.5.1 ancienne
expect_eq "version signée par l'ANCIENNE clé (transition) : installée" 0 "$(su_ apply 0.5.1)"
mkrelease 0.5.2 secours
expect_eq "version signée par la clé de secours : refusée" 1 "$(su_ apply 0.5.2)"
expect_grep "…signature invalide" "SIGNATURE INVALIDE" "$W/out.log"
expect_eq "keys : code 0" 0 "$(su_ keys)"
expect_grep "keys : clé livrée listée" "$(fpr "$K/active.pub")" "$W/out.log"
expect_grep "keys : clé de secours" "$(fpr "$K/secours.pub")" "$W/out.log"

# manifeste hostile : signé par la clé active (compromise) au lieu de la clé de secours
manifest 1 "$(fpr "$K/ancienne.pub")" "$K/evil.pub" "$W/h1.json"; sign active "$W/h1.json" "$W/h1.sig"
mkrelease 0.6.0 active "001:$W/h1.json:$W/h1.sig"
expect_eq "check avec un manifeste non signé par la clé de secours : code 0" 0 "$(su_ check)"
if jget "$ST" error | grep -q "refusé"; then ok "…le manifeste est signalé refusé"; else ko "…message" "$(jget "$ST" error)"; fi
expect_eq "…et la version n'est pas proposée" false "$(jget "$ST" available)"
expect_eq "apply avec ce manifeste : refusé" 1 "$(su_ apply 0.6.0)"
expect_eq "…console inchangée" "NEW CONSOLE 0.5.1" "$(console)"
expect_eq "…aucune rotation appliquée" no "$([ -e "$R/var/lib/ddibuntu/keys/rotation-seq" ] && echo yes || echo no)"

# urgence : la clé active est compromise. Le manifeste n°1 (clé de secours) la révoque et fait entrer k3.
manifest 1 "$(fpr "$K/active.pub")" "$K/k3.pub" "$W/u1.json"; sign secours "$W/u1.json" "$W/u1.sig"
mkrelease 0.6.0 active "001:$W/u1.json:$W/u1.sig"
expect_eq "archive signée par la clé compromise, publiée avec sa révocation : refusée" 1 "$(su_ apply 0.6.0)"
expect_eq "…rotation n°1 appliquée quand même" 1 "$(cat "$R/var/lib/ddibuntu/keys/rotation-seq" 2>/dev/null)"
expect_grep "…clé compromise révoquée" "$(fpr "$K/active.pub")" "$R/var/lib/ddibuntu/keys/revoked"
mkrelease 0.6.0 k3 "001:$W/u1.json:$W/u1.sig"
expect_eq "même version signée par la nouvelle clé k3 : installée" 0 "$(su_ apply 0.6.0)"
expect_eq "…console 0.6.0" "NEW CONSOLE 0.6.0" "$(console)"
mkrelease 0.7.0 active
expect_eq "plus tard, une archive signée par la clé révoquée (sans manifeste) : refusée" 1 "$(su_ apply 0.7.0)"
mkrelease 0.7.0 k3 "001:$W/u1.json:$W/u1.sig"
expect_eq "manifeste n°1 encore joint : ignoré, installation par k3" 0 "$(su_ apply 0.7.0)"
expect_eq "…rotation toujours à 1" 1 "$(cat "$R/var/lib/ddibuntu/keys/rotation-seq")"

echo "== 5. Repli web (API limitée) : manifeste trouvé à son adresse publique =="
manifest 2 "$(fpr "$K/ancienne.pub")" "$K/k4.pub" "$W/u2.json"; sign secours "$W/u2.json" "$W/u2.sig"
mkrelease 0.8.0 k4 "002:$W/u2.json:$W/u2.sig"
PORT2=$((PORT + 1))
cat > "$W/rate.py" <<'PY'
import http.server, os, sys
dl, port = sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path
        if p.startswith('/repos/'): self.send_response(403); self.end_headers(); return
        if p == '/acme/ddibuntu/releases/latest': self.send_response(302); self.send_header('Location', '/acme/ddibuntu/releases/tag/v0.8.0'); self.end_headers(); return
        if p == '/acme/ddibuntu/releases/tag/v0.8.0': self.send_response(200); self.end_headers(); self.wfile.write(b'ok'); return
        if p.startswith('/acme/ddibuntu/releases/download/v0.8.0/'):
            f = os.path.join(dl, p.rsplit('/', 1)[1])
            if os.path.isfile(f): self.send_response(200); self.end_headers(); self.wfile.write(open(f, 'rb').read()); return
        self.send_response(404); self.end_headers()
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PY
python3 "$W/rate.py" "$SRV/dl" "$PORT2" >/dev/null 2>&1 & RATE_PID=$!
sleep 1
export DDI_UPDATE_API="http://127.0.0.1:$PORT2" DDI_UPDATE_WEB="http://127.0.0.1:$PORT2"
expect_eq "apply 0.8.0 signée par k4, API limitée : installée" 0 "$(su_ apply 0.8.0)"
expect_eq "…rotation n°2 trouvée sur le site et appliquée" 2 "$(cat "$R/var/lib/ddibuntu/keys/rotation-seq")"
kill "$RATE_PID" 2>/dev/null

echo "== 6. Outil des workflows (tools/release-keys.sh) =="
RK="$W/repo"; mkdir -p "$RK/src/rootfs/etc/ddibuntu/keys/release.d" "$RK/keys/rotations"
cp "$K/ancienne.pub" "$RK/src/rootfs/etc/ddibuntu/update-pubkey.pem"; cp "$K/active.pub" "$RK/src/rootfs/etc/ddibuntu/keys/release.d/active.pem"
cp "$K/secours.pub" "$RK/src/rootfs/etc/ddibuntu/keys/release-secours.pem"
tool() { RK_REPO="$RK" bash "$TOOL" "$@"; }
check "outil : signature par la clé active acceptée" tool verify "$W/data" "$W/data.active.sig"
check_fail "outil : signature par une clé inconnue refusée" tool verify "$W/data" "$W/data.evil.sig"
check "outil : la clé privée active est dans le jeu" tool check-signer "$K/active.key"
check_fail "outil : une clé privée hors du jeu est refusée" tool check-signer "$K/evil.key"
check_fail "outil : la clé de secours ne peut pas signer une archive" tool check-signer "$K/secours.key"
cp "$W/u1.json" "$RK/keys/rotations/key-rotation-001.json"; cp "$W/u1.sig" "$RK/keys/rotations/key-rotation-001.json.sig"
check_fail "outil : après le manifeste n°1 du dépôt, la clé révoquée est refusée" tool verify "$W/data" "$W/data.active.sig"
check "outil : …et k3 acceptée" tool verify "$W/data" "$W/data.k3.sig"
check "outil : manifestes du dépôt valides" tool check-rotations
cp "$W/h1.sig" "$RK/keys/rotations/key-rotation-001.json.sig"
check_fail "outil : manifeste du dépôt mal signé : refusé" tool check-rotations

finish
