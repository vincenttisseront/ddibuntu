#!/usr/bin/env bash
# Batterie 35 — sauvegarde et restauration de la PKI (0.14.5), sans conteneur ni PostgreSQL (bouchons) mais avec du VRAI openssl :
# (1) le certificat PUBLIC de récupération (contrôles du helper, enregistrement par la ligne de commande et par la demande de la console, empreinte publiée) ;
# (2) le lot chiffré (secrets, métadonnées des autorités, volume sans « work », liens ignorés ; rien de lisible sans la clé privée) ;
# (3) l'essai de restauration (bonne clé, mauvaise clé, phrase secrète, lot corrompu) ;
# (4) la restauration (machine neuve, secrets différents refusés sans --force puis mis de côté, base vide refusée, démarrage par « apply », idempotence) ;
# (5) les lots hostiles (lien symbolique, nom hors liste, ejbca.env falsifié) ; (6) la purge des secrets mis de côté.
# Le vrai EJBCA relit ensuite les secrets restaurés dans la batterie 33 ; la sauvegarde de la base elle-même (PostgreSQL réel) est dans la batterie 18.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

H="$RFS/usr/local/lib/ddibuntu/pki-helper.py"
PKI="$RFS/usr/local/sbin/ddibuntu-pki"
T="$T_TMP"
W="$T/m"; mkdir -p "$W"
for t in openssl python3 tar; do command -v "$t" >/dev/null 2>&1 || { note "$t absent : batterie ignorée"; finish; exit $?; }; done
ph() { python3 "$H" "$@"; }
fpr() { openssl x509 -in "$1" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'; }
jget() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]));
for k in sys.argv[2].split("."):
    v = v.get(k) if isinstance(v, dict) else None
print(str(v).lower() if isinstance(v, bool) else ("" if v is None else v))' "$1" "$2"; }

echo "== Matériel de test : clé de récupération (RSA 3072) et variantes refusables =="
openssl req -x509 -newkey rsa:3072 -nodes -keyout "$W/rec.key" -out "$W/rec.pem" -days 36500 -subj "/CN=Ipnoria PKI recovery test" 2>/dev/null
openssl req -x509 -newkey rsa:3072 -nodes -keyout "$W/other.key" -out "$W/other.pem" -days 36500 -subj "/CN=Autre cle" 2>/dev/null
openssl pkcs8 -topk8 -v2 aes-256-cbc -in "$W/rec.key" -out "$W/rec.enc.key" -passout pass:phrase-secrete-test 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/r2048.key" -out "$W/r2048.pem" -days 36500 -subj "/CN=Trop petite" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$W/ec.key" 2>/dev/null
openssl req -x509 -new -key "$W/ec.key" -out "$W/ec.pem" -days 36500 -subj "/CN=Courbe elliptique" 2>/dev/null
openssl req -x509 -newkey rsa:3072 -nodes -keyout "$W/short.key" -out "$W/short.pem" -days 100 -subj "/CN=Expire bientot" 2>/dev/null
cat "$W/rec.pem" "$W/other.pem" > "$W/two.pem"
printf 'pas un certificat\n' > "$W/garbage.pem"
head -c 20000 /dev/zero | tr '\0' 'A' > "$W/big.pem"
ln -s "$W/rec.pem" "$W/link.pem"
for f in rec other r2048 ec short; do check "matériel : $f.pem fabriqué" test -s "$W/$f.pem"; done
REC_FP="$(fpr "$W/rec.pem")"; OTHER_FP="$(fpr "$W/other.pem")"

echo "== Helper : contrôle du certificat de récupération =="
chk() { ph recovery-check "$1" "$W/out.pem" 2>&1; }   # sortie « OK<TAB>empreinte<TAB>bits<TAB>fin »
out="$(chk "$W/rec.pem")"; rc=$?
expect_eq "certificat RSA 3072 valable : accepté" 0 "$rc"
expect_eq "empreinte rendue = SHA-256 du certificat" "$REC_FP" "$(printf '%s' "$out" | cut -f2)"
expect_eq "taille de clé rendue" 3072 "$(printf '%s' "$out" | cut -f3)"
check "PEM canonique écrit (0600)" test "$(stat -c %a "$W/out.pem")" = 600
expect_eq "PEM écrit = certificat d'origine" "$REC_FP" "$(fpr "$W/out.pem")"
rm -f "$W/out.pem"
refus() {   # refus NOM FICHIER : refusé, avec un message, sans rien écrire
  local out rc; rm -f "$W/out.pem"; out="$(ph recovery-check "$2" "$W/out.pem" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && [ "${out%%	*}" = ERR ] && [ ! -e "$W/out.pem" ]; then ok "refusé : $1"; else ko "refusé : $1" "rc=$rc sortie=[$out]"; fi
}
refus "RSA 2048 bits" "$W/r2048.pem"
refus "clé elliptique" "$W/ec.pem"
refus "certificat qui expire dans moins d'un an" "$W/short.pem"
refus "deux certificats" "$W/two.pem"
refus "texte quelconque" "$W/garbage.pem"
refus "fichier trop gros" "$W/big.pem"
refus "lien symbolique" "$W/link.pem"
refus "fichier absent" "$W/nexiste-pas.pem"
echo "$(ph recovery-info "$W/rec.pem")" > "$W/info.json"
expect_eq "recovery-info : empreinte" "$REC_FP" "$(jget "$W/info.json" fingerprint)"
expect_eq "recovery-info : sujet" "CN=Ipnoria PKI recovery test" "$(jget "$W/info.json" subject)"
check_fail "recovery-info : fichier illisible" ph recovery-info "$W/garbage.pem"
pr() { printf '%s' "$1" | ph parse-request; }
expect_eq "demande recovery_set acceptée" "action	recovery_set" "$(pr '{"action":"recovery_set"}')"
refuse() { local out rc; out="$(pr "$2" 2>/dev/null)"; rc=$?; if [ "$rc" -ne 0 ] && [ -z "$out" ]; then ok "refusée : $1"; else ko "refusée : $1" "rc=$rc sortie=[$out]"; fi; }
refuse "recovery_set avec un champ en plus (certificat glissé dans la demande)" '{"action":"recovery_set","cert":"-----BEGIN CERTIFICATE-----"}'

echo "== Montage : instance installée avec bouchons =="
B="$T/bin"; mkdir -p "$B" "$T/etc" "$T/data" "$T/quad" "$T/run" "$T/gen/pki-in"
LOG="$T/calls.log"; : > "$LOG"
cat > "$B/podman" <<EOF
#!/bin/bash
echo "podman \$*" >> "$LOG"
case "\$1" in
  image) case "\$2" in exists) [ -f "$T/image.present" ]; exit \$? ;; inspect) echo "sha256:$(printf 'b%.0s' $(seq 64))" ;; esac ;;
  pull) touch "$T/image.present" ;;
esac
exit 0
EOF
cat > "$B/systemctl" <<EOF
#!/bin/bash
echo "systemctl \$*" >> "$LOG"
case "\$1" in is-active) [ -f "$T/active" ] ;; start|restart) touch "$T/active" ;; stop) rm -f "$T/active" ;; esac
EOF
cat > "$B/psql" <<EOF
#!/bin/bash
sql="\$(cat)"
[ -f "$T/psql.fail" ] && exit 1
case "\$sql" in
  *"pg_database where datname = 'ejbca'"*) [ -f "$T/db.exists" ] && echo exists ;;
  *information_schema.tables*) cat "$T/tables" 2>/dev/null || echo 0 ;;
  *"from cadata where name <> 'ManagementCA'"*) echo 1 ;;
esac
exit 0
EOF
printf '#!/bin/bash\nexit 22\n' > "$B/curl"
printf '#!/bin/bash\nexit 0\n' > "$B/fw"
chmod +x "$B"/*
PKI_UID="$(id -u)"
export DDI_PKI_ALLOW_USER=1 DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu" DDI_GENERATED_DIR="$T/gen" DDI_RUN_DIR="$T/run"
export DDI_PKI_ETC="$T/etc" DDI_PKI_DATA="$T/data" DDI_PKI_QUADLET_DIR="$T/quad" DDI_PKI_PODMAN="$B/podman"
export DDI_PKI_SYSTEMCTL="$B/systemctl" DDI_PKI_CURL="$B/curl" DDI_FW_BIN="$B/fw" DDI_PKI_PSQL="$B/psql" DDI_PKI_LOCK="$T/lock" DDI_PKI_UID="$PKI_UID"
IMG=docker.io/keyfactor/ejbca-ce:9.6.3; HOST=pki.lab.test
G="$T/gen"; R="$T/run"
req() { printf '%s' "$1" > "$G/.pki-request"; "$PKI" request >"$T/req.out" 2>&1; RES_OK="$(jget "$R/pki-result.json" ok)"; RES_MSG="$(jget "$R/pki-result.json" message)"; }
st() { jget "$R/pki-status.json" "$1"; }

echo "== Rien à sauvegarder avant l'installation =="
"$PKI" secrets-pack "$T/none.cms" > "$T/pack0.out" 2>/dev/null; rc=$?
expect_eq "pack sans instance : code 0" 0 "$rc"
expect_eq "pack sans instance : raison « none »" none "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("reason"))' "$T/pack0.out")"
check "aucun lot écrit" test ! -e "$T/none.cms"

touch "$T/db.exists"; echo 0 > "$T/tables"
"$PKI" apply "$IMG" "$HOST" "10.0.0.0/8" >/dev/null 2>&1
check "instance installée (secrets créés)" test -f "$T/etc/ejbca.env"
mkdir -p "$T/data/ca/Lab-Root" "$T/data/ca/Lab-Sub" "$T/data/ca/ExtRoot-0a1b2c3d" "$T/data/persistent/secrets/tls/ks-ejbca" "$T/data/persistent/work"
echo '{"kind":"root","signedBy":"","alg":"rsa4096","createdAt":1}' > "$T/data/ca/Lab-Root/meta.json"
echo '{"kind":"issuing","signedBy":"Lab-Root","alg":"ecp384","createdAt":2}' > "$T/data/ca/Lab-Sub/meta.json"
printf -- '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n' > "$T/data/ca/Lab-Root/chain.pem"
echo '{"kind":"external-root"}' > "$T/data/ca/ExtRoot-0a1b2c3d/meta.json"
head -c 2500 /dev/urandom > "$T/data/persistent/secrets/tls/ks-ejbca/server.p12"; chmod 0600 "$T/data/persistent/secrets/tls/ks-ejbca/server.p12"
echo "ne doit pas être sauvegardé" > "$T/data/persistent/work/scratch.txt"
ln -s /etc/passwd "$T/data/persistent/lien-dangereux"
PWKEY="$(sed -n 's/^PASSWORD_ENCRYPTION_KEY=//p' "$T/etc/ejbca.env")"

echo "== Sans clé de récupération : le lot n'est pas créé =="
"$PKI" secrets-pack "$T/nokey.cms" > "$T/pack1.out" 2>/dev/null; rc=$?
expect_eq "pack sans clé de récupération : code 0" 0 "$rc"
expect_eq "raison « no-recovery-key »" no-recovery-key "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("reason"))' "$T/pack1.out")"
check "aucun lot écrit" test ! -e "$T/nokey.cms"
"$PKI" status >/dev/null 2>&1
expect_eq "état publié : aucune clé de récupération" "" "$(st recovery.fingerprint)"

echo "== Enregistrement de la clé de récupération (ligne de commande) =="
"$PKI" recovery-set "$W/ec.pem" > "$T/rs0.out" 2>&1; rc=$?
expect_eq "certificat elliptique refusé" 1 "$rc"
check "aucune clé enregistrée après un refus" test ! -e "$T/etc/recovery.pem"
"$PKI" recovery-set "$W/rec.pem" > "$T/rs1.out" 2>&1; rc=$?
expect_eq "certificat RSA 3072 enregistré" 0 "$rc"
check "message : garder la clé privée hors de la machine" grep -q "hors de cette machine" "$T/rs1.out"
check "recovery.pem lisible (public)" test -s "$T/etc/recovery.pem"
expect_eq "état publié : empreinte" "$REC_FP" "$(st recovery.fingerprint)"
expect_eq "état publié : 3072 bits" 3072 "$(st recovery.bits)"
check "recovery.pem ne contient aucune clé privée" bash -c '! grep -q "PRIVATE KEY" "$0"' "$T/etc/recovery.pem"

echo "== Lot chiffré =="
"$PKI" secrets-pack "$T/pki-secrets.cms" > "$T/pack2.out" 2>"$T/pack2.err"; rc=$?
expect_eq "pack : code 0" 0 "$rc"
expect_eq "pack : secrets sauvegardés" true "$(jget "$T/pack2.out" secrets)"
expect_eq "pack : empreinte de la clé de récupération" "$REC_FP" "$(jget "$T/pack2.out" recoveryFp)"
expect_eq "pack : 2 autorités du DDI + 1 racine externe comptées" 3 "$(jget "$T/pack2.out" cas)"
expect_eq "pack : version d'EJBCA" 9.6.3 "$(jget "$T/pack2.out" tag)"
check "lot écrit (0600)" test "$(stat -c %a "$T/pki-secrets.cms")" = 600
check "lot : structure CMS valide" openssl cms -cmsout -inform DER -in "$T/pki-secrets.cms" -noout
check "lot : aucun secret lisible (PASSWORD_ENCRYPTION_KEY absente en clair)" bash -c '! grep -aq "$1" "$2"' _ "$PWKEY" "$T/pki-secrets.cms"
check "lot : aucun nom de fichier lisible" bash -c '! grep -aq "ejbca.env" "$0"' "$T/pki-secrets.cms"
check "aucun fichier temporaire de lot laissé" bash -c '! ls "$0".part >/dev/null 2>&1' "$T/pki-secrets.cms"
openssl cms -decrypt -inform DER -in "$T/pki-secrets.cms" -inkey "$W/rec.key" -out "$T/plain.tgz" 2>/dev/null
tar -tzf "$T/plain.tgz" | sort > "$T/members.txt"
expect_grep "contenu : ejbca.env" '^etc/ejbca\.env$' "$T/members.txt"
expect_grep "contenu : instance.json" '^etc/instance\.json$' "$T/members.txt"
expect_grep "contenu : métadonnées d'une autorité" '^data/ca/Lab-Sub/meta\.json$' "$T/members.txt"
expect_grep "contenu : racine externe" '^data/ca/ExtRoot-0a1b2c3d/meta\.json$' "$T/members.txt"
expect_grep "contenu : volume du conteneur" '^data/persistent/secrets/tls/ks-ejbca/server\.p12$' "$T/members.txt"
expect_nogrep "contenu : le dossier d'échange (work) n'est pas sauvegardé" 'work' "$T/members.txt"
expect_nogrep "contenu : le lien symbolique est ignoré" 'lien-dangereux' "$T/members.txt"
expect_nogrep "contenu : le certificat de récupération n'est pas dans son propre lot" 'recovery' "$T/members.txt"
check "déchiffrement par la clé de récupération : le contenu d'ejbca.env est intact" bash -c 'tar -xzOf "$0" etc/ejbca.env | cmp -s - "$1"' "$T/plain.tgz" "$T/etc/ejbca.env"
rm -f "$T/plain.tgz"

echo "== Essai de restauration (secrets-verify) =="
"$PKI" secrets-verify --file "$T/pki-secrets.cms" --key "$W/rec.key" > "$T/ver1.out" 2>"$T/ver1.err"; rc=$?
expect_eq "bonne clé : lot lisible" 0 "$rc"
check "résumé : nom public, version et autorités" bash -c 'grep -q "pki.lab.test" "$0" && grep -q "9.6.3" "$0" && grep -q "Lab-Root" "$0" && grep -q "Lab-Sub" "$0"' "$T/ver1.out"
"$PKI" secrets-verify --file "$T/pki-secrets.cms" --key "$W/other.key" > "$T/ver2.out" 2>"$T/ver2.err"; rc=$?
expect_eq "mauvaise clé : refusé" 1 "$rc"
check "mauvaise clé : message explicite" grep -q "déchiffrement impossible" "$T/ver2.err"
"$PKI" secrets-verify --file "$T/pki-secrets.cms" --key "$W/rec.enc.key" > "$T/ver3.out" 2>&1 < /dev/null; rc=$?
expect_eq "clé protégée par une phrase, sans la phrase : refusé" 1 "$rc"
DDI_RECOVERY_PASS=phrase-secrete-test "$PKI" secrets-verify --file "$T/pki-secrets.cms" --key "$W/rec.enc.key" > "$T/ver4.out" 2>&1; rc=$?
expect_eq "clé protégée par une phrase, avec la bonne phrase : lisible" 0 "$rc"
DDI_RECOVERY_PASS=mauvaise "$PKI" secrets-verify --file "$T/pki-secrets.cms" --key "$W/rec.enc.key" > "$T/ver5.out" 2>&1 < /dev/null; rc=$?
expect_eq "mauvaise phrase : refusé" 1 "$rc"
check "la phrase secrète n'apparaît dans aucune sortie" bash -c '! grep -q "phrase-secrete-test" "$@"' _ "$T/ver3.out" "$T/ver4.out" "$T/ver5.out"
cp "$T/pki-secrets.cms" "$T/bad.cms"; printf '\xff\xff\xff\xff' | dd of="$T/bad.cms" bs=1 seek=400 conv=notrunc 2>/dev/null
"$PKI" secrets-verify --file "$T/bad.cms" --key "$W/rec.key" > "$T/ver6.out" 2>&1; rc=$?
expect_eq "lot altéré : refusé" 1 "$rc"
head -c 100 "$T/pki-secrets.cms" > "$T/short.cms"
"$PKI" secrets-verify --file "$T/short.cms" --key "$W/rec.key" > "$T/ver7.out" 2>&1; rc=$?
expect_eq "lot tronqué : refusé" 1 "$rc"
"$PKI" secrets-verify --file "$T/absent.cms" --key "$W/rec.key" > "$T/ver8.out" 2>&1; rc=$?
expect_eq "lot absent : refusé" 1 "$rc"
"$PKI" secrets-verify --file "$T/pki-secrets.cms" > "$T/ver9.out" 2>&1; rc=$?
expect_eq "sans clé : usage" 1 "$rc"
check "l'essai n'installe rien (pas de dossier mis de côté, secrets inchangés)" bash -c 'ls "$0"/etc | grep -vq "^pre-restore" && test -f "$0/etc/ejbca.env"' "$T"
check "aucun dossier temporaire de secrets laissé dans /dev/shm" bash -c '! ls /dev/shm/ddi-pki.* >/dev/null 2>&1'

echo "== Restauration sur une machine neuve =="
T2="$T/neuf"; mkdir -p "$T2/etc" "$T2/data"
NEW() { DDI_PKI_ETC="$T2/etc" DDI_PKI_DATA="$T2/data" "$PKI" "$@"; }
rm -f "$T/db.exists"; echo 0 > "$T/tables"
NEW secrets-restore --file "$T/pki-secrets.cms" --key "$W/rec.key" --no-start > "$T/rst0.out" 2>&1; rc=$?
expect_eq "base « ejbca » absente : restauration refusée" 1 "$rc"
check "message : restaurer d'abord la base du DDI" grep -q "restaurez d'abord la base" "$T/rst0.out"
check "rien n'a été installé" test ! -e "$T2/etc/ejbca.env"
touch "$T/psql.fail"
NEW secrets-restore --file "$T/pki-secrets.cms" --key "$W/rec.key" --no-start > "$T/rst0b.out" 2>&1; rc=$?
expect_eq "PostgreSQL injoignable : restauration refusée" 1 "$rc"
rm -f "$T/psql.fail"
touch "$T/db.exists"; echo 12 > "$T/tables"; : > "$LOG"
NEW secrets-restore --file "$T/pki-secrets.cms" --key "$W/other.key" --no-start > "$T/rst1.out" 2>&1; rc=$?
expect_eq "mauvaise clé : restauration refusée" 1 "$rc"
check "rien n'a été installé (mauvaise clé)" test ! -e "$T2/etc/ejbca.env"
NEW secrets-restore --file "$T/pki-secrets.cms" --key "$W/rec.key" --no-start > "$T/rst2.out" 2>&1; rc=$?
expect_eq "restauration sans démarrage : réussie" 0 "$rc"
check "ejbca.env identique (octet pour octet)" cmp -s "$T/etc/ejbca.env" "$T2/etc/ejbca.env"
check "ejbca.env en 0600" test "$(stat -c %a "$T2/etc/ejbca.env")" = 600
check "instance.json identique" cmp -s "$T/etc/instance.json" "$T2/etc/instance.json"
check "métadonnées des autorités identiques" diff -r "$T/data/ca" "$T2/data/ca"
check "volume restauré (keystore identique)" cmp -s "$T/data/persistent/secrets/tls/ks-ejbca/server.p12" "$T2/data/persistent/secrets/tls/ks-ejbca/server.p12"
check "keystore en 0600" test "$(stat -c %a "$T2/data/persistent/secrets/tls/ks-ejbca/server.p12")" = 600
check "le dossier d'échange n'est pas revenu avec son contenu, mais il existe vide (0700, au nom du conteneur) : la CLI d'EJBCA s'y place à chaque appel" bash -c 'test -d "$0" && test -z "$(ls -A "$0")" && test "$(stat -c %a "$0")" = 700 && test "$(stat -c %u "$0")" = "$1"' "$T2/data/persistent/work" "$PKI_UID"
check "le lien symbolique n'est pas revenu" test ! -e "$T2/data/persistent/lien-dangereux"
check "volume en 0700, au nom de l'utilisateur du conteneur" bash -c 'test "$(stat -c %a "$0")" = 700 && test "$(stat -c %u "$0")" = "$1"' "$T2/data/persistent" "$PKI_UID"
check "aucun conteneur démarré (--no-start)" bash -c '! grep -q "systemctl start" "$0"' "$LOG"
check "aucun dossier temporaire de secrets laissé dans /dev/shm" bash -c '! ls /dev/shm/ddi-pki.* >/dev/null 2>&1'
check "rien mis de côté sur une machine neuve" bash -c '! ls "$0"/etc | grep -q "^pre-restore"' "$T2"

echo "== Restauration : secrets différents déjà présents =="
NEW secrets-restore --file "$T/pki-secrets.cms" --key "$W/rec.key" --no-start > "$T/rst3.out" 2>&1; rc=$?
expect_eq "mêmes secrets déjà installés : restauration idempotente" 0 "$rc"
sed -i 's/^CA_KEYSTOREPASS=.*/CA_KEYSTOREPASS=AbsolumentAutreSecret0123456789abcdef/' "$T2/etc/ejbca.env"
OTHERSUM="$(sha256sum "$T2/etc/ejbca.env" | cut -c1-16)"
NEW secrets-restore --file "$T/pki-secrets.cms" --key "$W/rec.key" --no-start > "$T/rst4.out" 2>&1; rc=$?
expect_eq "secrets différents : refusé sans --force" 1 "$rc"
check "message : rendrait illisibles les autorités actuelles" grep -q "illisibles" "$T/rst4.out"
expect_eq "secrets actuels intacts" "$OTHERSUM" "$(sha256sum "$T2/etc/ejbca.env" | cut -c1-16)"
NEW secrets-restore --file "$T/pki-secrets.cms" --key "$W/rec.key" --no-start --force > "$T/rst5.out" 2>&1; rc=$?
expect_eq "avec --force : réussi" 0 "$rc"
check "secrets remplacés par ceux du lot" cmp -s "$T/etc/ejbca.env" "$T2/etc/ejbca.env"
# la restauration idempotente précédente a, elle aussi, mis de côté ses fichiers (même contenu) : on retient le dossier qui porte les secrets d'AVANT cette restauration
ASIDE=""
for d in "$T2"/etc/pre-restore.*; do [ -f "$d/ejbca.env" ] && [ "$(sha256sum "$d/ejbca.env" | cut -c1-16)" = "$OTHERSUM" ] && ASIDE="$d"; done
check "anciens secrets gardés à côté" test -n "$ASIDE" -a -f "$ASIDE/ejbca.env"
expect_eq "copie mise de côté : secrets d'avant" "$OTHERSUM" "$(sha256sum "$ASIDE/ejbca.env" | cut -c1-16)"
check "dossier mis de côté fermé (0700)" test "$(stat -c %a "$ASIDE")" = 700
touch -d "20 days ago" "$ASIDE"; mkdir -p "$T2/etc/pre-restore.recent"
NEW maintain >/dev/null 2>&1
check "maintain : copie de plus de 14 jours supprimée" test ! -e "$ASIDE"
check "maintain : copie récente conservée" test -d "$T2/etc/pre-restore.recent"
rmdir "$T2/etc/pre-restore.recent"

echo "== Restauration : base vide, avec --force =="
rm -rf "$T2"; mkdir -p "$T2/etc" "$T2/data"; rm -f "$T/db.exists"
NEW secrets-restore --file "$T/pki-secrets.cms" --key "$W/rec.key" --no-start --force > "$T/rst6.out" 2>&1; rc=$?
expect_eq "base vide + --force : installé quand même" 0 "$rc"
check "secrets en place" cmp -s "$T/etc/ejbca.env" "$T2/etc/ejbca.env"

echo "== Restauration avec démarrage (apply) =="
rm -rf "$T2" "$T/quad"/*; mkdir -p "$T2/etc" "$T2/data"; touch "$T/db.exists"; echo 12 > "$T/tables"; : > "$LOG"; rm -f "$T/image.present"
NEW secrets-restore --file "$T/pki-secrets.cms" --key "$W/rec.key" > "$T/rst7.out" 2>&1; rc=$?
expect_eq "restauration + démarrage : réussie" 0 "$rc"
check "message : PKI restaurée en version 9.6.3" grep -q "PKI restaurée (EJBCA 9.6.3)" "$T/rst7.out"
check "unité Quadlet écrite" test -s "$T/quad/ddibuntu-ejbca.container"
check "conteneur démarré" grep -q "systemctl start ddibuntu-ejbca.service" "$LOG"
check "image tirée à la version du lot" grep -q "podman pull --quiet $IMG" "$LOG"
check "pare-feu rouvert pour les réseaux du lot" grep -q . "$T/etc/instance.json"
check "secrets toujours ceux du lot après apply" cmp -s "$T/etc/ejbca.env" "$T2/etc/ejbca.env"

echo "== Lots hostiles (chiffrés avec la vraie clé publique : seul le contenu est en cause) =="
mkbundle() {   # mkbundle NOM CODE_PYTHON : lot sain + une modification ; le résultat est chiffré pour la clé de récupération
  python3 - "$T" "$1" "$2" <<'PYEOF'
import io, sys, tarfile, subprocess, re
T, name, code = sys.argv[1:4]
openssl_pub = f"{T}/m/rec.pem"
subprocess.run(["openssl", "cms", "-decrypt", "-inform", "DER", "-in", f"{T}/pki-secrets.cms", "-inkey", f"{T}/m/rec.key", "-out", f"{T}/hostile.tgz"], check=True)
src = tarfile.open(f"{T}/hostile.tgz")
members = [(m, src.extractfile(m).read() if m.isfile() else None) for m in src]
env = dict(members=members, tarfile=tarfile, io=io, re=re)
exec(code, env)
members = env["members"]
with tarfile.open(f"{T}/hostile2.tgz", "w:gz") as tf:
    for m, data in members:
        tf.addfile(m, io.BytesIO(data) if data is not None else None)
subprocess.run(["openssl", "cms", "-encrypt", "-aes256", "-binary", "-outform", "DER", "-in", f"{T}/hostile2.tgz", "-out", f"{T}/{name}.cms", "-recip", openssl_pub], check=True)
PYEOF
}
hostile() {   # hostile NOM CODE MOTIF : le lot est refusé à l'essai ET à la restauration, et rien n'est installé
  local n="$1" rc
  mkbundle "$n" "$2" || { ko "fabrication du lot hostile : $n" ""; return; }
  "$PKI" secrets-verify --file "$T/$n.cms" --key "$W/rec.key" > "$T/h.out" 2>&1; rc=$?
  if [ "$rc" -ne 0 ] && grep -q "$3" "$T/h.out"; then ok "refusé à l'essai : $4"; else ko "refusé à l'essai : $4" "rc=$rc $(head -c 200 "$T/h.out" | tr '\n' ' ')"; fi
  rm -rf "$T/h2"; mkdir -p "$T/h2/etc" "$T/h2/data"
  DDI_PKI_ETC="$T/h2/etc" DDI_PKI_DATA="$T/h2/data" "$PKI" secrets-restore --file "$T/$n.cms" --key "$W/rec.key" --no-start --force > "$T/h.out" 2>&1; rc=$?
  if [ "$rc" -ne 0 ] && [ ! -e "$T/h2/etc/ejbca.env" ] && [ -z "$(find "$T/h2/data" -type f | head -n1)" ]; then ok "refusé à la restauration, rien installé : $4"; else ko "refusé à la restauration, rien installé : $4" "rc=$rc"; fi
}
hostile h-sym 'ti = tarfile.TarInfo("data/persistent/evil"); ti.type = tarfile.SYMTYPE; ti.linkname = "/etc/shadow"; members.append((ti, None))' "lot refusé" "lien symbolique dans le lot"
hostile h-abs 'ti = tarfile.TarInfo("/etc/cron.d/evil"); ti.size = 4; members.append((ti, b"evil"))' "lot refusé" "chemin absolu"
hostile h-dots 'ti = tarfile.TarInfo("data/ca/../../../etc/evil"); ti.size = 4; members.append((ti, b"evil"))' "lot refusé" "remontée d'arborescence"
hostile h-other 'ti = tarfile.TarInfo("etc/ssh_host_key"); ti.size = 4; members.append((ti, b"evil"))' "lot refusé" "fichier hors liste dans etc/"
hostile h-work 'ti = tarfile.TarInfo("data/persistent/work/x"); ti.size = 4; members.append((ti, b"evil"))' "lot refusé" "dossier d'échange"
hostile h-dev 'ti = tarfile.TarInfo("data/persistent/null"); ti.type = tarfile.CHRTYPE; members.append((ti, None))' "lot refusé" "fichier spécial"
hostile h-dup 'members.append(next(x for x in members if x[0].name == "etc/ejbca.env"))' "doubl" "entrée en double"
hostile h-jdbc 'members[:] = [(m, d.replace(b"127.0.0.1:5432", b"203.0.113.9:5432") if m.name == "etc/ejbca.env" else d) for m, d in members]; [setattr(m, "size", len(d)) for m, d in members if d is not None]' "réglages de base inattendus" "ejbca.env pointant vers une autre base"
hostile h-envkey 'members[:] = [(m, d + b"PASSWORD_ENCRYPTION_KEY=x\n" if m.name == "etc/ejbca.env" else d) for m, d in members]; [setattr(m, "size", len(d)) for m, d in members if d is not None]' "double" "clé d'ejbca.env en double"
hostile h-envline 'members[:] = [(m, d + b"$(touch /tmp/pwned)\n" if m.name == "etc/ejbca.env" else d) for m, d in members]; [setattr(m, "size", len(d)) for m, d in members if d is not None]' "ligne illisible" "ligne de commande glissée dans ejbca.env"
hostile h-host 'members[:] = [(m, d.replace(b"pki.lab.test", b"autre.lab.test") if m.name == "etc/instance.json" else d) for m, d in members]; [setattr(m, "size", len(d)) for m, d in members if d is not None]' "ne correspond pas" "nom public d'instance.json différent d'ejbca.env"
hostile h-tag 'members[:] = [(m, d.replace(b"9.6.3", b"9.6.3; rm -rf /") if m.name == "etc/instance.json" else d) for m, d in members]; [setattr(m, "size", len(d)) for m, d in members if d is not None]' "version invalide" "version d'image falsifiée"
hostile h-fmt 'members[:] = [(m, d.replace(b"\"format\": 1", b"\"format\": 99") if m.name == "MANIFEST.json" else d) for m, d in members]; [setattr(m, "size", len(d)) for m, d in members if d is not None]' "format de lot inconnu" "format de lot inconnu"
check "le contenu hostile n'a rien exécuté" test ! -e /tmp/pwned

echo "== Demande de la console : enregistrement de la clé de récupération =="
rm -f "$T/etc/recovery.pem"
cp "$W/other.pem" "$G/pki-in/recovery.pem"
req '{"action":"recovery_set"}'
expect_eq "résultat : ok" true "$RES_OK"
check "dépôt consommé" test ! -e "$G/pki-in/recovery.pem"
expect_eq "état publié : empreinte de la clé déposée" "$OTHER_FP" "$(st recovery.fingerprint)"
cp "$W/ec.pem" "$G/pki-in/recovery.pem"
req '{"action":"recovery_set"}'
expect_eq "certificat elliptique : refusé" false "$RES_OK"
check "message de refus lisible" bash -c 'grep -qi "refus" <<< "$0"' "$RES_MSG"
check "dépôt consommé même après un refus" test ! -e "$G/pki-in/recovery.pem"
expect_eq "la clé enregistrée n'a pas changé" "$OTHER_FP" "$(st recovery.fingerprint)"
req '{"action":"recovery_set"}'
expect_eq "sans dépôt : refusé" false "$RES_OK"
cp "$W/rec.pem" "$G/pki-in/recovery.pem"
req '{"action":"recovery_set","cert":"x"}'
expect_eq "demande avec champ en trop : refusée" false "$RES_OK"
rm -f "$G/pki-in/recovery.pem"

echo "== Un lot fabriqué pour l'ancienne clé reste lisible avec l'ancienne clé =="
"$PKI" secrets-verify --file "$T/pki-secrets.cms" --key "$W/rec.key" >/dev/null 2>&1; rc=$?
expect_eq "après changement de clé de récupération : l'ancien lot se lit toujours avec l'ancienne clé privée" 0 "$rc"
"$PKI" secrets-verify --file "$T/pki-secrets.cms" --key "$W/other.key" >/dev/null 2>&1; rc=$?
expect_eq "…et pas avec la nouvelle" 1 "$rc"

finish
