#!/usr/bin/env bash
# Batterie 05 — construction de l'ISO. L'ISO Canonical n'est pas téléchargeable depuis le banc : on
# utilise une ISO de SUBSTITUTION hybride BIOS+UEFI (grub-mkrescue) dont le grub.cfg imite celui
# d'Ubuntu Server, et un miroir HTTP local signé avec une clé de test. Ce n'est PAS une preuve que
# l'installateur Subiquity fonctionne : c'est la preuve que la chaîne de construction est correcte.
# shellcheck disable=SC2034  # variables lues par les fonctions du script de construction sourcé (INSECURE_TLS, UBUNTU_BASE_URL, NODE_*, TIMEOUT…)
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

FAKE_NAME="ubuntu-24.04.9-live-server-amd64.iso"
ISO_DIR="$ART/iso-substitution"; mkdir -p "$ISO_DIR"
FAKE="$ISO_DIR/$FAKE_NAME"

# shellcheck source=lib-iso.sh
. "$(dirname "$0")/lib-iso.sh"

echo "== ISO de substitution (disposition Ubuntu : MBR hybride, GPT, partition EFI ajoutée) =="
check "ISO de substitution produite" make_fake_iso "$FAKE" normal
expect_grep "substitution : partition EFI ajoutée en GPT (comme Ubuntu)" '^-append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b' <(xorriso -indev "$FAKE" -report_system_area as_mkisofs 2>/dev/null)
xorriso -indev "$FAKE" -report_el_torito plain > "$T_TMP/et.orig" 2>/dev/null
expect_grep "substitution : démarrage BIOS présent" ' BIOS ' "$T_TMP/et.orig"
expect_grep "substitution : démarrage UEFI présent" ' UEFI ' "$T_TMP/et.orig"
FAKE_SHA="$(sha256sum "$FAKE" | cut -d' ' -f1)"

echo "== Construction avec --iso et empreinte =="
OUT1="$ART/build-1"; rm -rf "$OUT1"
bash "$DIST" --no-docker --iso "$FAKE" --sha256 "$FAKE_SHA" --skip-debs --skip-node --timeout 7 --out "$OUT1" >"$T_TMP/build1.log" 2>&1; rc=$?
expect_eq "build : code retour 0" 0 "$rc"
ISO1="$OUT1/ddibuntu-$(tr -d '\n' < "$ROOT/src/VERSION")-amd64.iso"
check "ISO produite" test -s "$ISO1"
check "fichier .sha256 valide (sha256sum -c)" bash -c "cd '$OUT1' && sha256sum -c --quiet '$(basename "$ISO1").sha256'"
expect_grep "journal : contrôles de démarrage BIOS et UEFI" 'démarrage BIOS et UEFI conservés' "$T_TMP/build1.log"
xorriso -indev "$ISO1" -report_el_torito plain > "$T_TMP/et.new" 2>/dev/null
expect_grep "ISO produite : démarrage BIOS conservé" ' BIOS ' "$T_TMP/et.new"
expect_grep "ISO produite : démarrage UEFI conservé" ' UEFI ' "$T_TMP/et.new"
expect_eq "mêmes entrées de démarrage avant/après (nombre)" "$(grep -c 'El Torito boot img' "$T_TMP/et.orig")" "$(grep -c 'El Torito boot img' "$T_TMP/et.new")"

X1="$T_TMP/x1"; mkdir -p "$X1"
xorriso -osirrox on -indev "$ISO1" -extract /ddibuntu "$X1/ddibuntu" -extract /boot/grub/grub.cfg "$X1/grub.cfg" -extract /casper/vmlinuz "$X1/vmlinuz" -extract /.disk/info "$X1/info" >/dev/null 2>&1
echo "== Menu GRUB =="
n_first="$(grep -n '^menuentry' "$X1/grub.cfg" | head -1 | cut -d: -f2-)"
expect_grep "première entrée du menu = installation DDI-Buntu" '^menuentry "Install DDI-Buntu [0-9.]+ \(automatic - ERASES the target disk\)"' <(printf '%s\n' "$n_first")
expect_grep "entrées d'origine conservées (Try or Install)" '^menuentry "Try or Install Ubuntu Server"' "$X1/grub.cfg"
expect_grep "entrées d'origine conservées (HWE)" '^menuentry "Ubuntu Server with the HWE kernel"' "$X1/grub.cfg"
if grep -qF 'ds=nocloud\;s=/cdrom/ddibuntu/' "$X1/grub.cfg"; then ok "paramètre autoinstall : l'antislash de « nocloud\\; » a survécu"; else ko "paramètre autoinstall : antislash perdu" "$(grep -n 'autoinstall' "$X1/grub.cfg")"; fi
expect_grep "noyau : paramètre autoinstall présent" 'linux	/casper/vmlinuz autoinstall ds=nocloud' "$X1/grub.cfg"
t_orig="$(grep -n '^set timeout=30' "$X1/grub.cfg" | cut -d: -f1)"; t_new="$(grep -n '^set timeout=7' "$X1/grub.cfg" | cut -d: -f1)"
m_first="$(grep -n '^menuentry' "$X1/grub.cfg" | head -1 | cut -d: -f1)"
if [ -n "$t_orig" ] && [ -n "$t_new" ] && [ "$t_new" -gt "$t_orig" ] && [ "$t_new" -lt "$m_first" ]; then ok "délai 7 s placé après le délai d'origine et avant le menu (il l'emporte)"; else ko "ordre des délais" "origine=$t_orig nouveau=$t_new menu=$m_first"; fi
expect_grep "entrée par défaut = 0" '^set default=0$' "$X1/grub.cfg"
expect_grep "menu : entrée de mise à jour (Update) présente" '^menuentry "Update an existing DDI-Buntu installation to [0-9.]+ \(keeps data, never erases the disk\)"' "$X1/grub.cfg"
if grep -qF 'autoinstall ds=nocloud\;s=/cdrom/ddibuntu/update/ ---' "$X1/grub.cfg"; then ok "entrée Update : graine /cdrom/ddibuntu/update/ (antislash conservé)"; else ko "entrée Update : graine absente" "$(grep -n 'update/' "$X1/grub.cfg")"; fi
upd_line="$(grep -n 'Update an existing' "$X1/grub.cfg" | head -1 | cut -d: -f1)"; ins_line="$(grep -n 'Install DDI-Buntu' "$X1/grub.cfg" | head -1 | cut -d: -f1)"
if [ -n "$upd_line" ] && [ -n "$ins_line" ] && [ "$upd_line" -gt "$ins_line" ]; then ok "l'entrée Update vient APRÈS l'installation (jamais l'entrée par défaut)"; else ko "ordre des entrées Install/Update" "install=$ins_line update=$upd_line"; fi

echo "== Contenu /ddibuntu de l'ISO =="
for f in rootfs.tar rootfs.tar.sha256 late.sh update.sh user-data meta-data update/user-data update/meta-data VERSION MANIFEST.txt console.tar.gz payloads.sha256; do check "présent : /ddibuntu/$f" test -f "$X1/ddibuntu/$f"; done
expect_grep "graine Update : early-commands lance update.sh" 'bash /cdrom/ddibuntu/update.sh' "$X1/ddibuntu/update/user-data"
expect_nogrep "graine Update : aucune section de stockage (jamais d'effacement)" 'storage:|layout:|identity:|late-commands' "$X1/ddibuntu/update/user-data"
check "payloads.sha256 : console conforme" bash -c "cd '$X1/ddibuntu' && sha256sum -c --quiet payloads.sha256"
expect_eq "--skip-node : le fichier Node n'est pas embarqué" no "$([ -e "$X1/ddibuntu/node-linux-x64.tar.gz" ] && echo yes || echo no)"
mkdir -p "$X1/console"; tar -xzf "$X1/ddibuntu/console.tar.gz" -C "$X1/console"
check "console embarquée : application construite (app/server/index.mjs)" test -s "$X1/console/app/server/index.mjs"
check "console embarquée : fichiers publics (app/public/_nuxt)" test -d "$X1/console/app/public/_nuxt"
check "console embarquée : identique à la console construite (index.mjs)" cmp "$X1/console/app/server/index.mjs" "$ROOT/webui/.output/server/index.mjs"
check "rootfs.tar : somme SHA-256 conforme" bash -c "cd '$X1/ddibuntu' && sha256sum -c --quiet rootfs.tar.sha256"
tar -tvf "$X1/ddibuntu/rootfs.tar" > "$T_TMP/tar.list"
expect_grep "rootfs.tar : ddibuntu-fw en 0755, propriétaire root" '^-rwxr-xr-x 0/0 .* \./usr/local/sbin/ddibuntu-fw$' "$T_TMP/tar.list"
expect_grep "rootfs.tar : nftables.nft livré" '\./etc/ddibuntu/nftables.nft$' "$T_TMP/tar.list"
expect_grep "rootfs.tar : unité systemd de l'assistant" '\./etc/systemd/system/ddibuntu-firstboot.service$' "$T_TMP/tar.list"
expect_eq "rootfs.tar : aucun fichier appartenant à un autre utilisateur que root" 0 "$(grep -vc ' 0/0 ' "$T_TMP/tar.list")"
mkdir -p "$X1/rootfs"; tar -xf "$X1/ddibuntu/rootfs.tar" -C "$X1/rootfs"
check "rootfs.tar : ddibuntu-fw identique à la source" cmp "$X1/rootfs/usr/local/sbin/ddibuntu-fw" "$RFS/usr/local/sbin/ddibuntu-fw"
check "rootfs.tar : catalogue français identique à la source" cmp "$X1/rootfs/usr/local/lib/ddibuntu/lang/fr.sh" "$RFS/usr/local/lib/ddibuntu/lang/fr.sh"
expect_eq "VERSION de l'ISO = VERSION des sources" "$(tr -d '\n' < "$ROOT/src/VERSION")" "$(tr -d '\n' < "$X1/ddibuntu/VERSION")"
expect_eq "VERSION embarquée dans l'appliance = VERSION de l'ISO" "$(tr -d '\n' < "$X1/ddibuntu/VERSION")" "$(tr -d '\n' < "$X1/rootfs/usr/local/lib/ddibuntu/VERSION")"
expect_grep "MANIFEST : empreinte de l'ISO de base" "SHA-256 base : $FAKE_SHA" "$X1/ddibuntu/MANIFEST.txt"
check "ISO d'origine : /casper/vmlinuz conservé à l'identique" bash -c "
  mkdir -p '$T_TMP/o' && xorriso -osirrox on -indev '$FAKE' -extract /casper/vmlinuz '$T_TMP/o/vmlinuz' >/dev/null 2>&1 && cmp '$T_TMP/o/vmlinuz' '$X1/vmlinuz'"
check "ISO d'origine : /.disk/info conservé" cmp "$X1/info" <(echo "Ubuntu-Server 24.04.9 LTS (substitution de test)")
expect_eq "user-data : permissions 0600 dans l'ISO" 600 "$(stat -c %a "$X1/ddibuntu/user-data")"
check "user-data de l'ISO : conforme au schéma Subiquity, empreinte \$6\$ générée" python3 - "$X1/ddibuntu/user-data" /home/claude/tools/autoinstall-schema.json <<'PY'
import json, sys, yaml, jsonschema
doc = yaml.safe_load(open(sys.argv[1]))
jsonschema.validate(doc['autoinstall'], json.load(open(sys.argv[2])))
pw = doc['autoinstall']['identity']['password']
assert pw.startswith('$6$') and '@@' not in pw, pw[:10]
assert '@@' not in open(sys.argv[1]).read(), 'marqueur non remplacé'
PY
expect_nogrep "user-data : aucun marqueur @@ résiduel" '@@' "$X1/ddibuntu/user-data"

echo "== Reproductibilité et secret jetable =="
OUT2="$ART/build-2"; rm -rf "$OUT2"
bash "$DIST" --no-docker --iso "$FAKE" --sha256 "$FAKE_SHA" --skip-debs --skip-node --timeout 7 --out "$OUT2" >"$T_TMP/build2.log" 2>&1
X2="$T_TMP/x2"; mkdir -p "$X2"
xorriso -osirrox on -indev "$OUT2/$(basename "$ISO1")" -extract /ddibuntu "$X2/ddibuntu" >/dev/null 2>&1
check "rootfs.tar identique entre deux constructions (déterministe)" cmp "$X1/ddibuntu/rootfs.tar" "$X2/ddibuntu/rootfs.tar"
if cmp -s "$X1/ddibuntu/user-data" "$X2/ddibuntu/user-data"; then ko "le mot de passe du compte d'installation doit différer à chaque construction"; else ok "mot de passe du compte d'installation différent à chaque construction"; fi
if grep -rqF "$(grep 'password:' "$X1/ddibuntu/user-data" | cut -d'"' -f2)" "$T_TMP/build1.log"; then ko "l'empreinte du mot de passe ne doit pas apparaître dans le journal"; else ok "l'empreinte du mot de passe n'apparaît pas dans le journal du build"; fi

echo "== Relance dans le même dossier =="
bash "$DIST" --no-docker --iso "$FAKE" --sha256 "$FAKE_SHA" --skip-debs --skip-node --timeout 7 --out "$OUT1" >"$T_TMP/rebuild.log" 2>&1; rc=$?
expect_eq "relance dans le même dossier : code retour 0" 0 "$rc"
check "relance : .sha256 à jour pour la nouvelle ISO" bash -c "cd '$OUT1' && sha256sum -c --quiet '$(basename "$ISO1").sha256'"
expect_eq "relance : aucun fichier temporaire laissé" 0 "$(find "$OUT1" -maxdepth 1 -name '.ddibuntu-*.partial' | wc -l)"

echo "== Refus et échecs de la construction =="
OUTX="$ART/build-x"; rm -rf "$OUTX"
bash "$DIST" --no-docker --iso "$FAKE" --skip-debs --skip-node --out "$OUTX" >"$T_TMP/f1.log" 2>&1; rc=$?
expect_eq "--iso sans --sha256 : refusé" 1 "$rc"
expect_grep "message : --iso exige --sha256" '--iso exige --sha256' "$T_TMP/f1.log"
bash "$DIST" --no-docker --iso "$FAKE" --sha256 "$(printf '0%.0s' {1..64})" --skip-debs --skip-node --out "$OUTX" >"$T_TMP/f2.log" 2>&1; rc=$?
expect_eq "empreinte fausse : refusé" 1 "$rc"
expect_grep "message : somme SHA-256 incorrecte" 'incorrecte' "$T_TMP/f2.log"
expect_eq "empreinte fausse : aucune ISO produite" 0 "$(find "$OUTX" -name '*.iso' 2>/dev/null | wc -l)"
rm -rf "$ART/build-3"
bash "$DIST" --no-docker --iso "$FAKE" --allow-unverified --skip-debs --skip-node --out "$ART/build-3" >"$T_TMP/f3.log" 2>&1; rc=$?
expect_eq "--allow-unverified : accepté" 0 "$rc"
expect_grep "--allow-unverified : avertissement affiché" 'NON vérifiée' "$T_TMP/f3.log"
check "ISO de substitution sans menuentry créée" make_fake_iso "$T_TMP/sans-menu.iso" sans-menuentry
bash "$DIST" --no-docker --iso "$T_TMP/sans-menu.iso" --allow-unverified --skip-debs --skip-node --out "$OUTX" >"$T_TMP/f4.log" 2>&1; rc=$?
expect_eq "grub.cfg sans menuentry : refusé" 1 "$rc"
expect_grep "message : format de grub.cfg inattendu" 'menuentry' "$T_TMP/f4.log"
expect_eq "grub.cfg sans menuentry : aucune ISO produite" 0 "$(find "$OUTX" -name '*.iso' 2>/dev/null | wc -l)"
make_fake_iso "$T_TMP/sans-noyau.iso" sans-noyau
bash "$DIST" --no-docker --iso "$T_TMP/sans-noyau.iso" --allow-unverified --skip-debs --skip-node --out "$OUTX" >"$T_TMP/f5.log" 2>&1; rc=$?
expect_eq "ISO sans /casper/vmlinuz : refusé" 1 "$rc"
expect_grep "message : version d'Ubuntu inattendue" 'vmlinuz absent' "$T_TMP/f5.log"
bash "$DIST" --no-docker --timeout abc --iso "$FAKE" --allow-unverified --out "$OUTX" >"$T_TMP/f6.log" 2>&1; rc=$?
expect_eq "--timeout non numérique : refusé" 1 "$rc"
bash "$DIST" --option-inconnue >"$T_TMP/f7.log" 2>&1; rc=$?
expect_eq "option inconnue : refusée" 1 "$rc"
expect_eq "--version : affiche la version" "DDI-Buntu $(tr -d '\n' < "$ROOT/src/VERSION")" "$(bash "$DIST" --version)"
bash "$DIST" --no-docker --iso /nexiste/pas.iso --allow-unverified --out "$OUTX" >"$T_TMP/f8.log" 2>&1; rc=$?
expect_eq "ISO introuvable : refusé" 1 "$rc"

echo "== Fonctions de vérification (signature Canonical simulée par une clé de test) =="
load_build_functions
GH="$T_TMP/gnupg"; mkdir -p "$GH"; chmod 700 "$GH"
gpgq() { gpg --homedir "$GH" --batch --quiet --pinentry-mode loopback --passphrase '' "$@"; }
gpgq --quick-generate-key "Cle CD de test <cd@test.invalid>" ed25519 sign never 2>/dev/null
gpgq --quick-generate-key "Autre cle <autre@test.invalid>" ed25519 sign never 2>/dev/null
GOOD_FPR="$(gpgq --list-keys --with-colons cd@test.invalid | awk -F: '/^fpr/{print $10; exit}')"
OTHER_FPR="$(gpgq --list-keys --with-colons autre@test.invalid | awk -F: '/^fpr/{print $10; exit}')"
gpgq --export > "$T_TMP/test-keyring.gpg"
SUMS="$T_TMP/SHA256SUMS"
printf '%s  %s\n' "$FAKE_SHA" "$FAKE_NAME" > "$SUMS"
printf '%s *%s\n' "$(printf 'a%.0s' {1..64})" "ubuntu-24.04.9-live-server-arm64.iso" >> "$SUMS"
printf '%s *%s\n' "$(printf 'b%.0s' {1..64})" "ubuntu-24.04.9-desktop-amd64.iso" >> "$SUMS"
gpgq --local-user "$GOOD_FPR" --detach-sign -o "$SUMS.gpg" "$SUMS"
vs() { ( KEYRING="$T_TMP/test-keyring.gpg" CD_KEY_FPRS="$GOOD_FPR" verify_sums_signature "$1" "$2" ); }
check "signature valide d'une clé attendue : acceptée" vs "$SUMS" "$SUMS.gpg"
cp "$SUMS" "$T_TMP/SUMS.tampered"; echo "$(printf 'c%.0s' {1..64})  evil.iso" >> "$T_TMP/SUMS.tampered"
check_fail "SHA256SUMS modifié après signature : refusé" vs "$T_TMP/SUMS.tampered" "$SUMS.gpg"
gpgq --local-user "$OTHER_FPR" --detach-sign -o "$T_TMP/other.gpg" "$SUMS"
check_fail "signature valide mais d'une autre clé que celle attendue : refusée" vs "$SUMS" "$T_TMP/other.gpg"
check_fail "fichier de signature absent : refusé" vs "$SUMS" "$T_TMP/nexiste.gpg"
head -c 100 /dev/urandom > "$T_TMP/garbage.gpg"
check_fail "signature corrompue : refusée" vs "$SUMS" "$T_TMP/garbage.gpg"
check_fail "clé non présente dans le trousseau : refusée" bash -c "
  DDI_BUILD_SOURCE_ONLY=1 DDI_SELF='$DIST' . '$DIST'; KEYRING='$KEYRING'; CD_KEY_FPRS='$GOOD_FPR'; verify_sums_signature '$SUMS' '$SUMS.gpg'"
check "trousseau Ubuntu du banc contient bien la clé CD Image 2012 attendue par le script" bash -c "gpg --show-keys --with-colons /usr/share/keyrings/ubuntu-archive-keyring.gpg | grep -q '^fpr:::::::::843938DF228D22F7B3742BC0D94AA3F0EFE21092:'"
expect_eq "select_iso_name : un seul live-server-amd64" "$FAKE_NAME" "$(select_iso_name "$SUMS" 'live-server-amd64[.]iso$')"
# Plusieurs versions dans le même SHA256SUMS signé (cas réel Canonical : 24.04.3, .4 et .5 coexistent) : la plus récente est retenue.
# (Ancien comportement : refus dès deux candidats, ce qui a fait échouer la première construction sur un vrai Mac.)
printf '%s *ubuntu-24.04.8-live-server-amd64.iso\n' "$(printf 'd%.0s' {1..64})" >> "$SUMS"
expect_eq "select_iso_name : deux versions (.8 et .9) -> la plus récente" "$FAKE_NAME" "$(select_iso_name "$SUMS" 'live-server-amd64[.]iso$' 2>/dev/null)"
H64="$(printf 'd%.0s' {1..64})"; SUMSV="$T_TMP/SUMS.versions"
printf '%s *ubuntu-24.04.3-live-server-amd64.iso\n%s *ubuntu-24.04.5-live-server-amd64.iso\n%s *ubuntu-24.04.4-live-server-amd64.iso\n%s *ubuntu-24.04.5.1-desktop-amd64.iso\n%s *ubuntu-24.04.5-live-server-amd64.iso.zsync\n' "$H64" "$H64" "$H64" "$H64" "$H64" > "$SUMSV"
expect_eq "select_iso_name : répertoire réel (.3, .5, .4 + desktop 5.1 + zsync) -> 24.04.5, quel que soit l'ordre" ubuntu-24.04.5-live-server-amd64.iso "$(select_iso_name "$SUMSV" 'live-server-amd64[.]iso$' 2>/dev/null)"
printf '%s *ubuntu-24.04.9-live-server-amd64.iso\n%s *ubuntu-24.04.10-live-server-amd64.iso\n' "$H64" "$H64" > "$SUMSV"
expect_eq "select_iso_name : comparaison numérique (24.04.10 > 24.04.9)" ubuntu-24.04.10-live-server-amd64.iso "$(select_iso_name "$SUMSV" 'live-server-amd64[.]iso$' 2>/dev/null)"
printf '%s *ubuntu-24.04.5-live-server-amd64.iso\n%s *ubuntu-24.04.5.1-live-server-amd64.iso\n' "$H64" "$H64" > "$SUMSV"
expect_eq "select_iso_name : 24.04.5.1 > 24.04.5" ubuntu-24.04.5.1-live-server-amd64.iso "$(select_iso_name "$SUMSV" 'live-server-amd64[.]iso$' 2>/dev/null)"
expect_grep "select_iso_name : le choix est annoncé" 'la plus récente est retenue : ubuntu-24.04.5.1-live-server-amd64.iso' <(select_iso_name "$SUMSV" 'live-server-amd64[.]iso$' 2>&1)
printf '%s *ubuntu-24.04.5-live-server-amd64.iso\n%s *evil-live-server-amd64.iso\n' "$H64" "$H64" > "$SUMSV"
check_fail "select_iso_name : plusieurs candidats dont un nom inattendu -> refus (pas de devinette)" bash -c "DDI_BUILD_SOURCE_ONLY=1 DDI_SELF='$DIST' . '$DIST'; select_iso_name '$SUMSV' 'live-server-amd64[.]iso\$'"
check_fail "select_iso_name : aucune candidate -> refus" bash -c "DDI_BUILD_SOURCE_ONLY=1 DDI_SELF='$DIST' . '$DIST'; select_iso_name '$SUMS' 'inexistant'"
expect_eq "sums_hash_for : nom exact, format « * »" "$(printf 'a%.0s' {1..64})" "$(sums_hash_for "$SUMS" ubuntu-24.04.9-live-server-arm64.iso)"

echo "== Téléchargement complet (miroir local signé) =="
MIRROR="$T_TMP/mirror"; mkdir -p "$MIRROR"
cp "$FAKE" "$MIRROR/$FAKE_NAME"
printf '%s  %s\n' "$FAKE_SHA" "$FAKE_NAME" > "$MIRROR/SHA256SUMS"
gpgq --local-user "$GOOD_FPR" --detach-sign -o "$MIRROR/SHA256SUMS.gpg" "$MIRROR/SHA256SUMS"
PORT=$((20000 + RANDOM % 20000))
( cd "$MIRROR" && python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) &
HTTP_PID=$!
trap 'kill $HTTP_PID 2>/dev/null; rm -rf "$T_TMP"' EXIT
sleep 1
export DDI_UBUNTU_URL="http://127.0.0.1:$PORT" DDI_KEYRING="$T_TMP/test-keyring.gpg" DDI_CD_KEY_FPRS="$GOOD_FPR"
OUT4="$ART/build-4"; rm -rf "$OUT4"
bash "$DIST" --no-docker --skip-debs --skip-node --timeout 5 --out "$OUT4" >"$T_TMP/dl.log" 2>&1; rc=$?
expect_eq "build par téléchargement : code retour 0" 0 "$rc"
expect_grep "journal : signature Canonical valide" 'Signature Canonical valide' "$T_TMP/dl.log"
expect_grep "journal : nom d'ISO détecté dans SHA256SUMS" "Téléchargement de $FAKE_NAME" "$T_TMP/dl.log"
check "ISO produite par téléchargement" test -s "$OUT4/$(basename "$ISO1")"
bash "$DIST" --no-docker --skip-debs --skip-node --timeout 5 --out "$OUT4" >"$T_TMP/dl2.log" 2>&1
expect_grep "second build : ISO déjà présente et vérifiée (cache)" 'déjà présente et vérifiée' "$T_TMP/dl2.log"
# Canonical garde plusieurs versions dans SHA256SUMS : la plus récente est retenue, les anciennes (absentes du miroir) ne sont jamais demandées
printf '%s *ubuntu-24.04.3-live-server-amd64.iso\n%s *ubuntu-24.04.4-live-server-amd64.iso\n%s *%s\n' "$(printf 'd%.0s' {1..64})" "$(printf 'd%.0s' {1..64})" "$FAKE_SHA" "$FAKE_NAME" > "$MIRROR/SHA256SUMS"
gpgq --yes --local-user "$GOOD_FPR" --detach-sign -o "$MIRROR/SHA256SUMS.gpg" "$MIRROR/SHA256SUMS"
OUT7="$ART/build-7"; rm -rf "$OUT7"
bash "$DIST" --no-docker --skip-debs --skip-node --timeout 5 --out "$OUT7" >"$T_TMP/dl7.log" 2>&1; rc=$?
expect_eq "miroir à plusieurs versions : build réussi avec la plus récente" 0 "$rc"
expect_grep "miroir à plusieurs versions : choix annoncé" "la plus récente est retenue : $FAKE_NAME" "$T_TMP/dl7.log"
expect_eq "miroir à plusieurs versions : une seule ISO dans le cache" 1 "$(find "$OUT7/.ddibuntu-cache" -name '*.iso' | wc -l)"
printf '%s  %s\n' "$FAKE_SHA" "$FAKE_NAME" > "$MIRROR/SHA256SUMS"
gpgq --yes --local-user "$GOOD_FPR" --detach-sign -o "$MIRROR/SHA256SUMS.gpg" "$MIRROR/SHA256SUMS"
echo "== Mode dépôt : le dépôt et le fichier unique produisent exactement la même chose =="
REPOSH="$ROOT/build-ddibuntu.sh"
expect_eq "mode dépôt : --version lit src/VERSION" "DDI-Buntu $(tr -d '\n' < "$ROOT/src/VERSION")" "$(bash "$REPOSH" --version)"
check_fail "le fichier unique n'est jamais pris pour un dépôt (même posé à la racine du dépôt)" bash -c "cp '$DIST' '$ROOT/.x-single.sh'; trap \"rm -f '$ROOT/.x-single.sh'\" EXIT; bash '$ROOT/.x-single.sh' --stage '$T_TMP/zz'"
check_fail "console non construite : refus avec la marche à suivre" env DDI_CONSOLE_OUTPUT=/nonexistent bash "$REPOSH" --stage "$T_TMP/nocons"
expect_grep "console non construite : le message cite tools/build-console.sh" 'tools/build-console.sh' <(DDI_CONSOLE_OUTPUT=/nonexistent bash "$REPOSH" --stage "$T_TMP/nocons2" 2>&1)
check_fail "--makeps1 depuis le dépôt : refusé (il vise le fichier unique)" bash "$REPOSH" --makeps1 --out "$T_TMP"
expect_grep "--makeps1 depuis le dépôt : le message cite tools/make-single.sh" 'tools/make-single.sh' <(bash "$REPOSH" --makeps1 --out "$T_TMP" 2>&1)
if [ -f "$ROOT/webui/.output/server/index.mjs" ]; then
  bash "$REPOSH" --stage "$T_TMP/stage-repo" >/dev/null 2>&1; rc=$?
  expect_eq "--stage depuis le dépôt : code 0" 0 "$rc"
  # shellcheck source=/dev/null
  ( DDI_BUILD_SOURCE_ONLY=1 DDI_SELF="$DIST"; . "$DIST"; payload_extract "$T_TMP/stage-single" )
  tree() { ( cd "$1" && find . -type f -printf '%m %p\n' | sort; find . -type f | sort | xargs sha256sum ); }
  expect_eq "charge utile : mêmes fichiers, mêmes modes, mêmes empreintes (dépôt = fichier unique)" "$(tree "$T_TMP/stage-single")" "$(tree "$T_TMP/stage-repo")"
  expect_eq "charge utile : au moins 25 fichiers comparés" 1 "$([ "$(find "$T_TMP/stage-repo" -type f | wc -l)" -ge 25 ] && echo 1 || echo 0)"
  OUT8="$ART/build-8"; rm -rf "$OUT8"
  bash "$REPOSH" --no-docker --skip-debs --skip-node --timeout 5 --out "$OUT8" >"$T_TMP/dl8.log" 2>&1; rc=$?
  expect_eq "build complet depuis le dépôt : code 0" 0 "$rc"
  # Une ISO n'est jamais identique au bit près d'une construction à l'autre, par conception : MANIFEST.txt porte la date de
  # construction et user-data le sel du mot de passe ALÉATOIRE jeté du compte d'installation. Tout le reste doit être identique.
  rm -rf "$T_TMP/i7" "$T_TMP/i8"
  xorriso -osirrox on -indev "$OUT7"/ddibuntu-*.iso -extract /ddibuntu "$T_TMP/i7" >/dev/null 2>&1
  xorriso -osirrox on -indev "$OUT8"/ddibuntu-*.iso -extract /ddibuntu "$T_TMP/i8" >/dev/null 2>&1
  expect_eq "ISO du dépôt vs ISO du fichier unique : seuls MANIFEST.txt (date) et user-data (sel aléatoire) diffèrent" "MANIFEST.txt user-data" "$(diff -rq "$T_TMP/i7" "$T_TMP/i8" | sed -n 's#^Files .*/\([^/]*\) and .*#\1#p' | sort | tr '\n' ' ' | sed 's/ $//')"
  expect_eq "ISO du dépôt vs ISO du fichier unique : rootfs.tar, console.tar.gz, late.sh, payloads.sha256 identiques" 4 "$(cd "$T_TMP/i7" && sha256sum rootfs.tar console.tar.gz late.sh payloads.sha256 | sed 's#  #  i7/#' | sort | awk '{print $1}' > "$T_TMP/h7"; cd "$T_TMP/i8" && sha256sum rootfs.tar console.tar.gz late.sh payloads.sha256 | awk '{print $1}' | sort > "$T_TMP/h8"; diff "$T_TMP/h7" "$T_TMP/h8" >/dev/null && wc -l < "$T_TMP/h7" | tr -d ' ')"
  expect_eq "ISO de base : le contenu hors /ddibuntu (amorçage BIOS/UEFI, casper, pool) est identique" 0 "$(xorriso -indev "$OUT7"/ddibuntu-*.iso -find / -exec lsl 2>/dev/null | grep -v ' /ddibuntu' | sed 's/^[^ ]* *//' | sort | md5sum | cut -c1-8 > "$T_TMP/l7"; xorriso -indev "$OUT8"/ddibuntu-*.iso -find / -exec lsl 2>/dev/null | grep -v ' /ddibuntu' | sed 's/^[^ ]* *//' | sort | md5sum | cut -c1-8 > "$T_TMP/l8"; cmp -s "$T_TMP/l7" "$T_TMP/l8"; echo $?)"
else note "console non construite : tests de charge utile et d'ISO du mode dépôt non exécutés (tools/build-console.sh)"; fi

# ISO falsifiée sur le miroir : le build doit refuser et ne rien produire
OUT5="$ART/build-5"; rm -rf "$OUT5"
cp "$FAKE" "$MIRROR/$FAKE_NAME"; printf 'X' | dd of="$MIRROR/$FAKE_NAME" bs=1 seek=100000 conv=notrunc 2>/dev/null
bash "$DIST" --no-docker --skip-debs --skip-node --out "$OUT5" >"$T_TMP/dl3.log" 2>&1; rc=$?
expect_eq "ISO falsifiée sur le miroir : refusée" 1 "$rc"
expect_grep "message : somme SHA-256 incorrecte" 'incorrecte' "$T_TMP/dl3.log"
expect_eq "ISO falsifiée : aucune ISO produite" 0 "$(find "$OUT5" -name 'ddibuntu-*.iso' 2>/dev/null | wc -l)"
expect_eq "ISO falsifiée : le fichier téléchargé est supprimé du cache" 0 "$(find "$OUT5/.ddibuntu-cache" -name '*.iso' 2>/dev/null | wc -l)"
# SHA256SUMS falsifié : signature invalide
cp "$FAKE" "$MIRROR/$FAKE_NAME"; printf '%s  %s\n' "$(printf 'e%.0s' {1..64})" "$FAKE_NAME" > "$MIRROR/SHA256SUMS"
OUT6="$ART/build-6"; rm -rf "$OUT6"
bash "$DIST" --no-docker --skip-debs --skip-node --out "$OUT6" >"$T_TMP/dl4.log" 2>&1; rc=$?
expect_eq "SHA256SUMS falsifié : refusé" 1 "$rc"
expect_grep "message : signature INVALIDE" 'INVALIDE' "$T_TMP/dl4.log"
expect_eq "SHA256SUMS falsifié : aucune ISO téléchargée" 0 "$(find "$OUT6" -name '*.iso' 2>/dev/null | wc -l)"
kill "$HTTP_PID" 2>/dev/null

echo "== Chemin macOS / Docker Desktop (faux uname Darwin et faux docker : les arguments transmis sont vérifiés) =="
FB="$T_TMP/fakebin"; mkdir -p "$FB"
printf '#!/bin/sh\nif [ "$1" = "-s" ]; then echo Darwin; else exec /usr/bin/uname "$@"; fi\n' > "$FB/uname"
printf '#!/bin/sh\ncase "$1" in info) exit "${FAKE_DOCKER_INFO_RC:-0}" ;; run) printf "%%s\\n" "$@" > "$DOCKER_LOG"; exit 0 ;; *) exit 0 ;; esac\n' > "$FB/docker"
chmod 755 "$FB/uname" "$FB/docker"
export DOCKER_LOG="$T_TMP/docker.args"; MACOUT="$T_TMP/macout"
PATH="$FB:$PATH" bash "$DIST" --out "$MACOUT" --timeout 7 >"$T_TMP/mac1.log" 2>&1; rc=$?
expect_eq "macOS : le script délègue à Docker sans droits root" 0 "$rc"
for a in run --rm --platform linux/amd64 ubuntu:24.04 bash /ddi-src/build-ddibuntu.sh --in-container --out /ddi-out --timeout 7; do
  expect_eq "macOS : docker reçoit l'argument « $a »" 1 "$(grep -cxF -- "$a" "$DOCKER_LOG")"
done
expect_eq "macOS : le dossier du script est monté en lecture seule" 1 "$(grep -cxF -- "$(dirname "$DIST"):/ddi-src:ro" "$DOCKER_LOG")"
expect_eq "macOS : le dossier de sortie est monté en écriture" 1 "$(grep -cE ':/ddi-out$' "$DOCKER_LOG")"
expect_eq "macOS : l'identité de l'utilisateur est transmise (propriété des fichiers produits)" 2 "$(grep -cE '^DDI_HOST_(UID|GID)=[0-9]+$' "$DOCKER_LOG")"
expect_eq "macOS : aucune option de test n'est transmise par défaut" 0 "$(grep -cE 'skip-debs|skip-node|allow-unverified' "$DOCKER_LOG")"
PATH="$FB:$PATH" bash "$DIST" --out "$MACOUT" --iso "$FAKE" --sha256 "$FAKE_SHA" --timeout 5 >"$T_TMP/mac2.log" 2>&1
expect_eq "macOS --iso : le dossier de l'ISO est monté en lecture seule" 1 "$(grep -cE ':/ddi-iso:ro$' "$DOCKER_LOG")"
expect_eq "macOS --iso : chemin de l'ISO et empreinte transmis" 2 "$(grep -cxE -- "/ddi-iso/$FAKE_NAME|$FAKE_SHA" "$DOCKER_LOG")"
FAKE_DOCKER_INFO_RC=1 PATH="$FB:$PATH" bash "$DIST" --out "$MACOUT" >"$T_TMP/mac3.log" 2>&1; rc=$?
expect_eq "Docker Desktop arrêté : refus clair" 1 "$rc"; expect_grep "message : démarrer Docker Desktop" 'Docker Desktop' "$T_TMP/mac3.log"
bash "$DIST" --docker --out "$MACOUT" >"$T_TMP/mac4.log" 2>&1; rc=$?
if command -v docker >/dev/null 2>&1; then note "docker présent sur le banc : test « Docker absent » non exécuté"; else expect_eq "Docker absent : refus clair" 1 "$rc"; expect_grep "message : installer Docker Desktop" 'Docker est requis' "$T_TMP/mac4.log"; fi
printf '#!/bin/sh\necho arm64\n' > "$FB/dpkg"; chmod 755 "$FB/dpkg"
PATH="$FB:$PATH" bash "$DIST" --no-docker --iso "$FAKE" --allow-unverified --skip-debs --skip-node --out "$T_TMP/archout" >"$T_TMP/arch.log" 2>&1; rc=$?
expect_eq "architecture arm64 : construction refusée" 1 "$rc"; expect_grep "message : amd64 exigé" 'doit tourner en amd64' "$T_TMP/arch.log"
expect_eq "architecture arm64 : aucune ISO produite" 0 "$(find "$T_TMP/archout" -name '*.iso' 2>/dev/null | wc -l)"
rm -f "$FB/dpkg" "$FB/uname"

echo "== Proxy d'entreprise qui inspecte le HTTPS : autorité privée, aide, options =="
CAD="$T_TMP/ca"; mkdir -p "$CAD"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CAD/ca.key" -out "$CAD/ca.pem" -days 2 -subj "/CN=Autorite-Entreprise-Test" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$CAD/s.key" -out "$CAD/s.csr" -subj "/CN=127.0.0.1" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1\n' > "$CAD/ext"
openssl x509 -req -in "$CAD/s.csr" -CA "$CAD/ca.pem" -CAkey "$CAD/ca.key" -CAcreateserial -out "$CAD/s.pem" -days 2 -extfile "$CAD/ext" 2>/dev/null
mkdir -p "$CAD/www"; echo "bonjour" > "$CAD/www/x"
TPORT=$((20000 + RANDOM % 20000))
python3 - "$CAD" "$TPORT" >/dev/null 2>&1 <<'PY' &
import http.server, ssl, sys, os, functools
d, port = sys.argv[1], int(sys.argv[2])
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=os.path.join(d, 'www'))
srv = http.server.HTTPServer(('127.0.0.1', port), h)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(os.path.join(d, 's.pem'), os.path.join(d, 's.key'))
srv.socket = ctx.wrap_socket(srv.socket, server_side=True); srv.serve_forever()
PY
THTTP=$!; sleep 1
curl -sS -m 5 "https://127.0.0.1:$TPORT/x" >/dev/null 2>&1; rc=$?
expect_eq "TLS inspecté : curl refuse l'autorité inconnue (code 60, comme sur votre Mac)" 60 "$rc"
# shellcheck disable=SC2034  # UBUNTU_BASE_URL et INSECURE_TLS sont lues par les fonctions du script sourcé
out="$( ( UBUNTU_BASE_URL="https://127.0.0.1:$TPORT"; fetch_iso "$T_TMP/tlscache" ) 2>&1 )"; rc=$?
expect_eq "fetch_iso : échec TLS => refus" 1 "$rc"
expect_grep "fetch_iso : l'aide explique le proxy d'entreprise" "proxy d'entreprise qui inspecte le HTTPS" <(printf '%s\n' "$out")
expect_grep "fetch_iso : l'aide cite --ca-from-keychain" '--ca-from-keychain' <(printf '%s\n' "$out")
expect_grep "fetch_iso : l'aide rappelle que l'intégrité reste vérifiée" "l'intégrité reste garantie" <(printf '%s\n' "$out")
expect_eq "--insecure-tls : le téléchargement aboutit (serveur à autorité inconnue)" bonjour "$( ( INSECURE_TLS=1; dlcurl -fsS -m 5 "https://127.0.0.1:$TPORT/x" ) 2>&1 )"
expect_eq "sans --insecure-tls : le même téléchargement échoue" 60 "$( ( INSECURE_TLS=0; dlcurl -fsS -m 5 "https://127.0.0.1:$TPORT/x" >/dev/null 2>&1; echo $? ) )"
if ( install_extra_ca "$CAD/ca.pem" ) >"$T_TMP/ca-install.log" 2>&1; then ok "install_extra_ca : autorité ajoutée au magasin"; else ko "install_extra_ca" "$(cat "$T_TMP/ca-install.log")"; fi
expect_eq "après install_extra_ca : le serveur de l'entreprise est reconnu (HTTPS vérifié, sans -k)" bonjour "$(curl -sS -m 5 "https://127.0.0.1:$TPORT/x" 2>&1)"
rm -f /usr/local/share/ca-certificates/ddibuntu-extra.crt; update-ca-certificates --fresh >/dev/null 2>&1
expect_eq "autorité retirée après le test : de nouveau refusée" 60 "$(curl -sS -m 5 "https://127.0.0.1:$TPORT/x" >/dev/null 2>&1; echo $?)"
check_fail "install_extra_ca refuse un fichier qui n'est pas un certificat PEM" bash -c "DDI_BUILD_SOURCE_ONLY=1 DDI_SELF='$DIST' . '$DIST'; echo pas-un-pem > '$T_TMP/bad.pem'; install_extra_ca '$T_TMP/bad.pem'"
kill "$THTTP" 2>/dev/null
# chemin macOS : autorités et options transmises à Docker, fichier déposé puis supprimé
cat > "$FB/docker" <<'DK'
#!/bin/sh
case "$1" in
  info) exit 0 ;;
  run) printf "%s\n" "$@" > "$DOCKER_LOG"
       for a in "$@"; do case "$a" in *:/ddi-out) d="${a%:/ddi-out}"; [ -f "$d/.ddibuntu-ca.pem" ] && cp "$d/.ddibuntu-ca.pem" "$DOCKER_CA_COPY" ;; esac; done
       exit 0 ;;
  *) exit 0 ;;
esac
DK
chmod 755 "$FB/docker"; printf '#!/bin/sh\nif [ "$1" = "-s" ]; then echo Darwin; else exec /usr/bin/uname "$@"; fi\n' > "$FB/uname"; chmod 755 "$FB/uname"
export DOCKER_CA_COPY="$T_TMP/ca-copy.pem"; MACOUT2="$T_TMP/macout2"
PATH="$FB:$PATH" bash "$DIST" --out "$MACOUT2" --ca-cert "$CAD/ca.pem" >"$T_TMP/ca1.log" 2>&1; rc=$?
expect_eq "macOS --ca-cert : code retour 0" 0 "$rc"
expect_eq "macOS --ca-cert : l'autorité est transmise au conteneur" 1 "$(grep -cxF -- '--ca-cert' "$DOCKER_LOG")"
expect_eq "macOS --ca-cert : chemin dans le conteneur" 1 "$(grep -cxF -- '/ddi-out/.ddibuntu-ca.pem' "$DOCKER_LOG")"
check "macOS --ca-cert : le PEM vu par Docker est celui de l'entreprise" cmp "$DOCKER_CA_COPY" "$CAD/ca.pem"
expect_eq "macOS --ca-cert : le PEM déposé est supprimé après la construction" no "$([ -e "$MACOUT2/.ddibuntu-ca.pem" ] && echo yes || echo no)"
printf '#!/bin/sh\n[ "$1" = find-certificate ] && cat "%s/ca.pem" "%s/ca.pem"\nexit 0\n' "$CAD" "$CAD" > "$FB/security"; chmod 755 "$FB/security"
rm -f "$DOCKER_CA_COPY"
PATH="$FB:$PATH" bash "$DIST" --out "$MACOUT2" --ca-from-keychain >"$T_TMP/ca2.log" 2>&1; rc=$?
expect_eq "macOS --ca-from-keychain : code retour 0" 0 "$rc"
expect_grep "macOS --ca-from-keychain : nombre de certificats annoncé" 'Trousseau macOS : 2 certificats' "$T_TMP/ca2.log"
expect_eq "macOS --ca-from-keychain : 2 certificats transmis, sans clé privée" "2 0" "$(grep -c 'BEGIN CERTIFICATE' "$DOCKER_CA_COPY") $(grep -c 'PRIVATE KEY' "$DOCKER_CA_COPY")"
expect_eq "macOS --ca-from-keychain : PEM supprimé après la construction" no "$([ -e "$MACOUT2/.ddibuntu-ca.pem" ] && echo yes || echo no)"
printf '#!/bin/sh\nexit 0\n' > "$FB/security"
PATH="$FB:$PATH" bash "$DIST" --out "$MACOUT2" --ca-from-keychain >"$T_TMP/ca3.log" 2>&1; rc=$?
expect_eq "trousseau vide : refus" 1 "$rc"; expect_grep "message : aucun certificat exporté" 'aucun certificat exporté' "$T_TMP/ca3.log"
rm -f "$FB/security"
PATH="$FB:$PATH" bash "$DIST" --out "$MACOUT2" --insecure-tls >"$T_TMP/ca4.log" 2>&1
expect_eq "macOS --insecure-tls : option transmise au conteneur" 1 "$(grep -cxF -- '--insecure-tls' "$DOCKER_LOG")"
printf '#!/bin/sh\nif [ "$1" = "-s" ]; then echo Linux; else exec /usr/bin/uname "$@"; fi\n' > "$FB/uname"
PATH="$FB:$PATH" bash "$DIST" --docker --out "$MACOUT2" --ca-from-keychain >"$T_TMP/ca5.log" 2>&1; rc=$?
if command -v security >/dev/null 2>&1; then note "commande security présente : test « hors macOS » non exécuté"; else expect_eq "--ca-from-keychain hors macOS : refus clair" 1 "$rc"; expect_grep "message : réservé à macOS" "n'existe que sous macOS" "$T_TMP/ca5.log"; fi
check_fail "--ca-cert natif (hors conteneur) : refusé, le magasin du poste n'est jamais modifié" bash "$DIST" --no-docker --iso "$FAKE" --allow-unverified --skip-debs --skip-node --ca-cert "$CAD/ca.pem" --out "$T_TMP/nativeca"
rm -f "$FB/uname"

echo "== Node.js : signature des sommes, clés épinglées, empreinte (miroir local signé par une clé de test) =="
NM="$T_TMP/nodemirror"; make_node_mirror "$NM" tiny
NPORT=$((20000 + RANDOM % 20000))
( cd "$NM" && python3 -m http.server "$NPORT" --bind 127.0.0.1 >/dev/null 2>&1 ) &
NHTTP=$!
sleep 1
NDIR="$NM/node/latest-v22.x"; NASC="$NDIR/SHASUMS256.txt.asc"; NTGZ="$NDIR/node-v22.99.0-linux-x64.tar.gz"
# shellcheck disable=SC2034  # NODE_* sont lues par fetch_node (fonction du script sourcé)
nodefetch() {   # [empreintes épinglées] -> « nom hash » sur la dernière ligne, code retour de fetch_node
  ( NODE_BASE_URL="http://127.0.0.1:$NPORT/node/latest-v22.x"; NODE_KEYS_URL="http://127.0.0.1:$NPORT/keys"; NODE_KEY_FPRS="${1:-$NODE_MIRROR_FPR}"
    fetch_node "$T_TMP/ncache.$RANDOM" && echo "$NODE_NAME $NODE_HASH" )
}
out="$(nodefetch 2>&1)"; rc=$?
expect_eq "Node : téléchargement vérifié, code retour 0" 0 "$rc"
expect_eq "Node : l'archive linux-x64 .tar.gz est choisie parmi les leurres (arm64, .tar.xz)" "node-v22.99.0-linux-x64.tar.gz $(sha256sum "$NTGZ" | cut -d' ' -f1)" "$(printf '%s\n' "$out" | tail -1)"
expect_grep "Node : message « signature valide (clé épinglée) »" 'Signature Node valide' <(printf '%s\n' "$out")
cp "$NTGZ" "$T_TMP/ntgz.bak"; printf 'X' >> "$NTGZ"
out="$(nodefetch 2>&1)"; rc=$?; cp "$T_TMP/ntgz.bak" "$NTGZ"
expect_eq "Node : archive falsifiée sur le miroir : refusée" 1 "$rc"; expect_grep "Node : message somme incorrecte" 'incorrecte' <(printf '%s\n' "$out")
cp "$NASC" "$T_TMP/nasc.bak"; sed -i 's/^[0-9a-f]\{64\}  node-v22.99.0-linux-x64.tar.gz$/'"$(printf 'c%.0s' {1..64})"'  node-v22.99.0-linux-x64.tar.gz/' "$NASC"
out="$(nodefetch 2>&1)"; rc=$?; cp "$T_TMP/nasc.bak" "$NASC"
expect_eq "Node : somme modifiée dans le texte signé : refusée" 1 "$rc"; expect_grep "Node : message signature INVALIDE" 'INVALIDE' <(printf '%s\n' "$out")
OTHER_GH="$T_TMP/othergpg"; mkdir -p "$OTHER_GH"; chmod 700 "$OTHER_GH"
gpg --homedir "$OTHER_GH" --batch --quiet --pinentry-mode loopback --passphrase '' --quick-generate-key "Autre <autre@test.invalid>" ed25519 sign never 2>/dev/null
OTHER_FPR="$(gpg --homedir "$OTHER_GH" --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')"
gpg --homedir "$OTHER_GH" --armor --export "$OTHER_FPR" > "$NM/keys/$OTHER_FPR.asc"
out="$(nodefetch "$OTHER_FPR" 2>&1)"; rc=$?
expect_eq "Node : somme signée par une clé hors de la liste épinglée : refusée" 1 "$rc"
cp "$NM/keys/$NODE_MIRROR_FPR.asc" "$T_TMP/key.bak"; cp "$NM/keys/$OTHER_FPR.asc" "$NM/keys/$NODE_MIRROR_FPR.asc"
out="$(nodefetch 2>&1)"; rc=$?; cp "$T_TMP/key.bak" "$NM/keys/$NODE_MIRROR_FPR.asc"
expect_eq "Node : fichier de clé dont l'empreinte ne correspond pas à l'empreinte épinglée : refusé" 1 "$rc"; expect_grep "Node : message empreinte de la clé" "porte l'empreinte" <(printf '%s\n' "$out")
printf '%s  node-v22.99.0-linux-x64.tar.gz\n' "$(printf 'd%.0s' {1..64})" >> "$NASC"
out="$(nodefetch 2>&1)"; rc=$?; cp "$T_TMP/nasc.bak" "$NASC"
if printf '%s\n' "$out" | grep -q "$(printf 'd%.0s' {1..64})"; then ko "Node : une ligne ajoutée APRÈS la signature n'est jamais utilisée"; else ok "Node : une ligne ajoutée après la signature n'est jamais utilisée (refus ou ignorée)"; fi
rm -f "$NM/keys/$NODE_MIRROR_FPR.asc"
out="$(nodefetch 2>&1)"; rc=$?; cp "$T_TMP/key.bak" "$NM/keys/$NODE_MIRROR_FPR.asc"
expect_eq "Node : clé de publication introuvable : refusé" 1 "$rc"
# deux archives candidates dans le texte signé : ambiguïté refusée
{ gpg --homedir "$NODE_MIRROR_GH" --batch --pinentry-mode loopback --passphrase '' --local-user "$NODE_MIRROR_FPR" --decrypt "$NASC" 2>/dev/null; printf '%s  node-v22.98.0-linux-x64.tar.gz\n' "$(printf 'e%.0s' {1..64})"; } > "$T_TMP/dup.txt"
rm -f "$NASC"   # gpg refuse d'écraser un fichier existant en mode batch
gpg --homedir "$NODE_MIRROR_GH" --batch --pinentry-mode loopback --passphrase '' --local-user "$NODE_MIRROR_FPR" --clearsign --output "$NASC" "$T_TMP/dup.txt" 2>/dev/null
out="$(nodefetch 2>&1)"; rc=$?; cp "$T_TMP/nasc.bak" "$NASC"
expect_eq "Node : deux archives linux-x64 candidates : refusé" 1 "$rc"
check "les huit empreintes épinglées par défaut sont celles du README officiel nodejs/release-keys" bash -c "
  for f in 5BE8A3F6C8A5C01D106C0AD820B1A390B168D356 DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7 CC68F5A3106FF448322E48ED27F5E38D5B0A215F 890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4 C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C 108F52B48DB57BB0CC439B2997B01419BD92F80A 655F3B5C1FB3FA8D1A0CA6BDE4A7D232B936D2FD A363A499291CBBC940DD62E41F10027AF002F8B0; do grep -q \$f '$DIST' || exit 1; done"
kill "$NHTTP" 2>/dev/null

echo "== patch_grub : variantes de grub.cfg =="
# shellcheck disable=SC2034  # TIMEOUT et DDI_VERSION sont lues par patch_grub (fonction du script sourcé)
pg() { ( TIMEOUT=11; DDI_VERSION=1.2.3; patch_grub "$1" "$2" ); }
printf 'set timeout=30\n  menuentry "Indente" {\n  linux /x\n}\n' > "$T_TMP/g1"
check "patch_grub : première entrée indentée" pg "$T_TMP/g1" "$T_TMP/g1.out"
expect_grep "patch_grub : insertion avant l'entrée indentée" '^menuentry "Install DDI-Buntu 1.2.3' "$T_TMP/g1.out"
expect_grep "patch_grub : entrée d'origine conservée" 'menuentry "Indente"' "$T_TMP/g1.out"
printf 'set timeout=30\n' > "$T_TMP/g2"
check_fail "patch_grub : sans entrée -> échec" pg "$T_TMP/g2" "$T_TMP/g2.out"

finish
