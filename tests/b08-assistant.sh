#!/usr/bin/env bash
# Batterie 08 — console texte : clavier appliqué TOUT DE SUITE puis testé, logo (écran, /etc/issue), points de
# restauration et retour arrière automatique. L'assistant est piloté dans un vrai terminal (pty) avec un faux
# « whiptail » qui rejoue des réponses et journalise chaque boîte de dialogue dans l'ordre.
# shellcheck disable=SC1112  # apostrophes typographiques des messages français
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

LIB="$RFS/usr/local/lib/ddibuntu"; SB="$RFS/usr/local/sbin"
export DDI_LIBDIR="$LIB" DDI_FW_BIN="$SB/ddibuntu-fw" DDI_ROLLBACK_BIN="$SB/ddibuntu-rollback" DDI_APPLY_BIN="$SB/ddibuntu-apply"
RB="$SB/ddibuntu-rollback"; APPLY="$SB/ddibuntu-apply"; SETUP="$SB/ddibuntu-setup"
FB="$T_TMP/fakebin"; mkdir -p "$FB"

newroot() { local r; r="$(mktemp -d "$T_TMP/root.XXXXXX")"; mkdir -p "$r/etc" "$r/var/lib" "$r/run"; printf '%s' "$r"; }
cfg() { local f; f="$(mktemp "$T_TMP/cfg.XXXXXX")"; printf '%s\n' "$@" > "$f"; printf '%s' "$f"; }
app() { local r="$1" c="$2"; shift 2; DDI_ROOT="$r" "$APPLY" --config "$c" "$@" >"$T_TMP/apply.out" 2>&1; }
rb() { local r="$1"; shift; DDI_ROOT="$r" DDI_SYSTEMD_RUN="$FB/systemd-run" DDI_SYSTEMCTL="$FB/systemctl" "$RB" "$@"; }
snaps() { find "$1/var/lib/ddibuntu/snapshots" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l; }
confval() { sed -n "s/^$2='\(.*\)'$/\1/p" "$1/etc/ddibuntu/ddibuntu.conf" | head -1; }

# faux systemd-run / systemctl : ils journalisent leurs arguments
printf '#!/bin/sh\necho "systemd-run $*" >> "$SEQ"\nexit 0\n' > "$FB/systemd-run"
printf '#!/bin/sh\necho "systemctl $*" >> "$SEQ"\nexit 0\n' > "$FB/systemctl"
chmod 755 "$FB/systemd-run" "$FB/systemctl"
export SEQ="$T_TMP/seq"; : > "$SEQ"

BASE=("LANGUAGE='fr'" "KEYBOARD='fr'" "TIMEZONE='Europe/Paris'" "HOSTNAME='alpha'" "NET_MODE='static'" "NET_IFACE='eth0'" "NET_ADDR='192.168.50.10/24'" "NET_GW='192.168.50.1'" "ADMIN_NETS='192.168.50.0/24'")
CA="$(cfg "${BASE[@]}")"
CB="$(cfg "LANGUAGE='fr'" "KEYBOARD='us'" "TIMEZONE='Europe/Paris'" "HOSTNAME='bravo'" "NET_MODE='static'" "NET_IFACE='eth0'" "NET_ADDR='192.168.50.20/24'" "NET_GW='192.168.50.1'" "ADMIN_NETS='192.168.50.0/24'")"

echo "== Points de restauration : création, liste, contenu, secrets =="
R="$(newroot)"
check_fail "create sans configuration existante : refusé" rb "$R" create
app "$R" "$CA"; rc=$?
expect_eq "1re application : code 0" 0 "$rc"
expect_eq "1re application : un point « etat-initial » créé" 1 "$(find "$R/var/lib/ddibuntu/snapshots" -maxdepth 1 -name '*-etat-initial' | wc -l)"
# secrets présents sur la machine : ils ne doivent JAMAIS entrer dans un point de restauration
mkdir -p "$R/etc/ddibuntu/tls"; printf 'CLE-PRIVEE-SECRETE\n' > "$R/etc/ddibuntu/tls/server.key"; printf 'JETON-SECRET\n' > "$R/var/lib/ddibuntu/setup-token"
ID="$(rb "$R" create "Test manuel !")"
expect_grep "create : identifiant au format attendu (raison nettoyée)" '^[0-9]{8}T[0-9]{6}Z-test-manuel$' <(printf '%s\n' "$ID")
expect_eq "last : le plus récent" "$ID" "$(rb "$R" last)"
expect_eq "list --porcelain : 3 colonnes (id, date, raison)" 3 "$(rb "$R" list --porcelain | head -1 | awk -F'\t' '{print NF}')"
expect_grep "list : la raison apparaît" 'test-manuel' <(rb "$R" list)
expect_grep "show : contient la configuration" "HOSTNAME='alpha'" <(rb "$R" show "$ID")
expect_eq "aucun secret dans les points de restauration (clé TLS, jeton)" 0 "$(grep -rlE 'CLE-PRIVEE-SECRETE|JETON-SECRET' "$R/var/lib/ddibuntu/snapshots" 2>/dev/null | wc -l)"
expect_eq "copie d'audit : le fichier netplan est conservé" 1 "$(find "$R/var/lib/ddibuntu/snapshots/$ID" -name 50-ddibuntu.yaml | wc -l)"
expect_eq "dossier des points de restauration : droits 0700" 700 "$(stat -c %a "$R/var/lib/ddibuntu/snapshots")"

echo "== Identifiants hostiles refusés =="
for bad in "../../etc" "../x" "" "x;rm -rf /" "20260101T000000Z/../../etc" "$(printf 'a%.0s' {1..80})"; do
  check_fail "show « ${bad:0:24} » : refusé" rb "$R" show "$bad"
  check_fail "restore « ${bad:0:24} » : refusé" rb "$R" restore "$bad" --yes
done
check_fail "identifiant valide mais inexistant : refusé" rb "$R" show 20200101T000000Z
expect_grep "message : introuvable" 'introuvable' <(rb "$R" show 20200101T000000Z 2>&1)

echo "== Restauration et réversibilité =="
R2="$(newroot)"
app "$R2" "$CA"; app "$R2" "$CB"
expect_eq "après la 2e application : nom = bravo, clavier = us" "bravo us" "$(confval "$R2" HOSTNAME) $(confval "$R2" KEYBOARD)"
BEFORE="$(find "$R2/var/lib/ddibuntu/snapshots" -maxdepth 1 -name '*-avant-application*' | head -1 | xargs basename)"
check "restore de « avant-application » réussit" rb "$R2" restore "$BEFORE" --yes
expect_eq "restauré : nom de machine = alpha" alpha "$(confval "$R2" HOSTNAME)"
expect_eq "restauré : /etc/hostname = alpha" alpha "$(tr -d '\n' < "$R2/etc/hostname")"
expect_eq "restauré : clavier = fr" fr "$(confval "$R2" KEYBOARD)"
expect_grep "restauré : /etc/default/keyboard = fr" 'XKBLAYOUT="fr"' "$R2/etc/default/keyboard"
expect_grep "restauré : netplan = ancienne adresse" '192\.168\.50\.10/24' "$R2/etc/netplan/50-ddibuntu.yaml"
PRE="$(find "$R2/var/lib/ddibuntu/snapshots" -maxdepth 1 -name '*-avant-restauration*' | head -1 | xargs basename)"
check "l'état d'avant la restauration est lui-même conservé" test -n "$PRE"
check "la restauration est réversible : retour à l'état « bravo »" rb "$R2" restore "$PRE" --yes
expect_eq "réversible : nom de machine = bravo" bravo "$(confval "$R2" HOSTNAME)"
expect_eq "réversible : clavier = us" us "$(confval "$R2" KEYBOARD)"
# la restauration ne doit jamais produire de nouveau point « avant-application » (pas de boucle)
expect_eq "restauration : pas de point « avant-application » supplémentaire" 1 "$(find "$R2/var/lib/ddibuntu/snapshots" -maxdepth 1 -name '*-avant-application*' | wc -l)"

echo "== Restauration d'un point invalide : état conservé =="
R3="$(newroot)"; app "$R3" "$CA"; app "$R3" "$CB"
BAD="$(rb "$R3" create corrompu)"
sed -i "s/^HOSTNAME=.*/HOSTNAME='nom invalide !'/" "$R3/var/lib/ddibuntu/snapshots/$BAD/ddibuntu.conf"
rb "$R3" restore "$BAD" --yes >"$T_TMP/rb.out" 2>&1; rc=$?
expect_eq "point corrompu : restauration refusée (code 1)" 1 "$rc"
expect_grep "message : retour à l'état précédent" 'a échoué' "$T_TMP/rb.out"
expect_eq "point corrompu : la configuration n'a pas bougé (nom = bravo)" bravo "$(confval "$R3" HOSTNAME)"

echo "== Conservation limitée =="
R4="$(newroot)"; app "$R4" "$CA"
for i in 1 2 3 4 5 6; do DDI_SNAPSHOT_KEEP=3 rb "$R4" create "n$i" >/dev/null; done
expect_eq "KEEP=3 : trois points conservés" 3 "$(snaps "$R4")"
expect_grep "KEEP=3 : le plus récent est conservé" 'n6' <(rb "$R4" list)
expect_nogrep "KEEP=3 : le plus ancien est supprimé" 'etat-initial|n1' <(rb "$R4" list)

echo "== Retour arrière automatique (minuteur) =="
: > "$SEQ"
check "arm 120 : programmé" rb "$R2" arm 120 "$BEFORE"
expect_grep "systemd-run : unité, délai et commande de retour" "systemd-run --quiet --unit=ddibuntu-revert --on-active=120s --collect .*ddibuntu-rollback restore $BEFORE --yes" "$SEQ"
check "fichier d'attente écrit" test -s "$R2/var/lib/ddibuntu/revert-pending"
: > "$SEQ"; check "confirm : accepté" rb "$R2" confirm
expect_grep "confirm : le minuteur est arrêté" 'systemctl stop ddibuntu-revert.timer ddibuntu-revert.service' "$SEQ"
check "confirm : fichier d'attente supprimé" test ! -e "$R2/var/lib/ddibuntu/revert-pending"
for bad in 5 9 3601 99999 abc ""; do check_fail "arm « $bad » : délai refusé" rb "$R2" arm "$bad" "$BEFORE"; done
check_fail "arm vers un identifiant invalide : refusé" rb "$R2" arm 60 "../x"

echo "== Rien n'est modifié si le point de restauration ne peut pas être créé =="
R5="$(newroot)"; app "$R5" "$CA"
DDI_ROLLBACK_BIN=/bin/false app "$R5" "$CB"; rc=$?
expect_eq "point de restauration impossible : application refusée" 2 "$rc"
expect_grep "message explicite" 'point de restauration impossible' "$T_TMP/apply.out"
expect_eq "rien n'a été modifié : nom = alpha" alpha "$(tr -d '\n' < "$R5/etc/hostname")"
expect_eq "rien n'a été modifié : clavier = fr" fr "$(confval "$R5" KEYBOARD)"
DDI_NO_SNAPSHOT=1 DDI_ROLLBACK_BIN=/bin/false app "$R5" "$CB"; rc=$?
expect_eq "DDI_NO_SNAPSHOT=1 : application possible (utilisé par ddibuntu-rollback)" 0 "$rc"

echo "== Logo =="
L="$(bash -c ". '$LIB/logo.sh'; ddi_logo plain")"
expect_eq "logo : 5 lignes + devise" 6 "$(printf '%s\n' "$L" | wc -l)"
expect_eq "logo : largeur <= 60 colonnes (console 80x25)" 0 "$(printf '%s\n' "$L" | awk 'length($0) > 60' | wc -l)"
expect_eq "logo plain : aucun code d'échappement" 0 "$(printf '%s' "$L" | grep -c $'\e' || true)"
expect_eq "logo color : au moins 3 séquences de couleur sur la 1re ligne (début, bascule, remise à zéro)" 1 "$(bash -c ". '$LIB/logo.sh'; ddi_logo color" | head -1 | grep -o $'\e\\[[0-9;]*m' | wc -l | awk '{print ($1>=3)?1:0}')"
expect_eq "logo auto hors terminal : aucune couleur" 0 "$(bash -c ". '$LIB/logo.sh'; ddi_logo" | grep -c $'\e' || true)"
expect_eq "logo avec NO_COLOR : aucune couleur" 0 "$(NO_COLOR=1 TERM=linux bash -c ". '$LIB/logo.sh'; ddi_logo auto" | grep -c $'\e' || true)"
# /etc/issue : agetty traite « \ » comme un début de code ; une fois les codes interprétés, le logo doit être intact
printf '%s\n' "$L" > "$T_TMP/logo.txt"
python3 - "$R/etc/issue" "$T_TMP/logo.txt" <<'PY' && ok "/etc/issue : une fois interprété comme agetty (« \\x » -> x), le logo est identique" || ko "/etc/issue : logo altéré par l'interprétation agetty"
import re, sys
issue = open(sys.argv[1], encoding='utf-8').read().split('\n')[:5]
want = open(sys.argv[2], encoding='utf-8').read().split('\n')[:5]
sys.exit(0 if [re.sub(r'\\(.)', r'\1', l) for l in issue] == want else 1)
PY
expect_grep "/etc/issue : les codes agetty (nom, tty, adresses) sont conservés" '\\n.*\\l' "$R/etc/issue"
expect_grep "/etc/issue : adresses IPv4/IPv6 (\\4 \\6)" '\\4 +\\6' "$R/etc/issue"

echo "== Clavier : primitives =="
src() { bash -c ". '$LIB/common.sh'; $1"; }
for kv in fr:azerty be:azerty de:qwertz ch:qwertz us:qwerty gb:qwerty es:qwerty it:qwerty; do
  expect_eq "mot de test de la disposition ${kv%%:*}" "${kv##*:}" "$(src "ddi_kbd_testword ${kv%%:*}")"
done
bad=0; for k in $(src 'printf %s "$DDI_KBD_LIST"'); do src "ddi_valid_keyboard $k" || bad=$((bad + 1)); [ -n "$(src "ddi_kbd_name $k")" ] || bad=$((bad + 1)); done
expect_eq "chaque disposition proposée est acceptée par ddibuntu-apply et porte un nom" 0 "$bad"
expect_eq "8 dispositions proposées" 8 "$(src 'set -- $DDI_KBD_LIST; echo $#')"
RK="$(newroot)"; DDI_ROOT="$RK" bash -c ". '$LIB/common.sh'; ddi_kbd_write fr"
expect_grep "ddi_kbd_write : XKBLAYOUT" 'XKBLAYOUT="fr"' "$RK/etc/default/keyboard"
# fausses commandes setupcon / loadkeys
printf '#!/bin/sh\necho "setupcon $*" >> "$SEQ"\nexit "${FAKE_SETUPCON_RC:-0}"\n' > "$FB/setupcon"; printf '#!/bin/sh\necho "loadkeys $*" >> "$SEQ"\nexit "${FAKE_LOADKEYS_RC:-0}"\n' > "$FB/loadkeys"; chmod 755 "$FB/setupcon" "$FB/loadkeys"
kapply() { PATH="$FB:$PATH" DDI_ROOT="$RK" DDI_KBD_FORCE=1 bash -c ". '$LIB/common.sh'; ddi_kbd_apply_now $*"; }
: > "$SEQ"; PATH="$FB:$PATH" DDI_ROOT="$RK" bash -c ". '$LIB/common.sh'; ddi_kbd_apply_now fr"; expect_eq "hors-ligne sans DDI_KBD_FORCE : aucune commande lancée" 0 "$(wc -l < "$SEQ")"
: > "$SEQ"; kapply fr; rc=$?; expect_eq "setupcon disponible : appliqué (code 0)" 0 "$rc"; expect_eq "setupcon -k appelé sans --save" "setupcon -k" "$(cat "$SEQ")"
: > "$SEQ"; kapply fr save; expect_eq "avec « save » : setupcon -k --save" "setupcon -k --save" "$(cat "$SEQ")"
: > "$SEQ"; FAKE_SETUPCON_RC=1 kapply be; rc=$?; expect_eq "setupcon en échec : repli sur loadkeys (code 0)" 0 "$rc"; expect_grep "repli : keymap be-latin1" 'loadkeys be-latin1' "$SEQ"
: > "$SEQ"; FAKE_SETUPCON_RC=1 FAKE_LOADKEYS_RC=1 kapply fr; rc=$?; expect_eq "les deux en échec : non appliqué (code 1), l'assistant le dit" 1 "$rc"

echo "== Assistant dans un vrai terminal (faux whiptail) =="
# faux whiptail : file de réponses WT_ANSWERS ; YES/NO pour yesno ; CANCEL = Échap ; journal des boîtes de dialogue
cat > "$FB/whiptail" <<'WT'
#!/bin/bash
kind=""; text=""; args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[i]}" in --inputbox|--passwordbox|--menu|--msgbox|--yesno) kind="${args[i]#--}"; text="${args[i+1]}" ;; esac
done
printf 'dlg:%s:%s\n' "$kind" "$(printf '%s' "$text" | tr '\n' '~')" >> "$SEQ"
[ "$kind" != msgbox ] || exit 0
line="$(head -1 "$WT_ANSWERS")"; sed -i 1d "$WT_ANSWERS"
case "$line" in CANCEL|NO|'') exit 1 ;; YES) exit 0 ;; *) printf '%s' "$line" >&2; exit 0 ;; esac
WT
# faux apply : journalise le clavier reçu et si un mot de passe est arrivé sur l'entrée (jamais sa valeur)
cat > "$FB/apply-stub" <<'AP'
#!/bin/bash
cfgf=""; pw=0
while [ $# -gt 0 ]; do case "$1" in --config) cfgf="$2"; shift ;; --password-stdin) pw=1 ;; esac; shift; done
[ "$pw" -eq 0 ] || { IFS= read -r p; [ -z "$p" ] || echo "apply-pw-recu" >> "$SEQ"; }
echo "apply keyboard=$(sed -n "s/^KEYBOARD='\(.*\)'$/\1/p" "$cfgf") host=$(sed -n "s/^HOSTNAME='\(.*\)'$/\1/p" "$cfgf")" >> "$SEQ"
exit 0
AP
printf '#!/bin/sh\nexit 0\n' > "$FB/fw-stub"; chmod 755 "$FB/whiptail" "$FB/apply-stub" "$FB/fw-stub"
SYSNET="$T_TMP/sysnet"; mkdir -p "$SYSNET/eth0"; : > "$SYSNET/eth0/device"
command -v script >/dev/null 2>&1 || note "commande « script » absente : tests de l'assistant non exécutables"
wiz() {   # wiz RACINE "rép1|rép2|..." [options de ddibuntu-setup] -> code retour ; journal dans $SEQ
  local r="$1" ans="$2"; shift 2
  : > "$SEQ"; printf '%s\n' "$ans" | tr '|' '\n' > "$T_TMP/answers"
  WT_ANSWERS="$T_TMP/answers" PATH="$FB:$PATH" DDI_ROOT="$r" DDI_KBD_FORCE=1 DDI_KBD_TEST=1 DDI_SYSNET="$SYSNET" DDI_APPLY_BIN="${WIZ_APPLY:-$FB/apply-stub}" DDI_FW_BIN="$FB/fw-stub" \
    DDI_SYSTEMD_RUN="$FB/systemd-run" DDI_SYSTEMCTL="$FB/systemctl" timeout 60 script -qefc "$SETUP $*" /dev/null >"$T_TMP/wiz.out" 2>&1
}
seqn() { grep -n "$1" "$SEQ" | head -1 | cut -d: -f1; }
newcfg_root() { local r; r="$(newroot)"; app "$r" "$CA"; printf '%s' "$r"; }

RW="$(newcfg_root)"
wiz "$RW" "fr|fr|azerty|YES" --language; rc=$?
expect_eq "--language : code 0" 0 "$rc"
expect_eq "clavier : la disposition est appliquée AVANT le test de saisie" 1 "$([ "$(seqn 'setupcon -k')" -lt "$(seqn 'dlg:inputbox')" ] && echo 1 || echo 0)"
expect_grep "clavier : /etc/default/keyboard écrit dès le choix" 'XKBLAYOUT="fr"' "$RW/etc/default/keyboard"
expect_grep "clavier : le test affiche la disposition et la consigne (6 lettres du haut)" 'dlg:inputbox:Test du clavier.*Français \(AZERTY\).*6 premi' "$SEQ"
expect_grep "clavier : appliqué avec la bonne valeur" 'apply keyboard=fr' "$SEQ"

wiz "$RW" "fr|fr|qwerty|keep|YES" --language
expect_grep "qwerty sur AZERTY : le décalage est signalé (saisi / attendu)" 'dlg:menu:Vous avez saisi « qwerty ».*Français \(AZERTY\).*« azerty »' "$SEQ"
expect_grep "« conserver quand même » : la disposition choisie est gardée" 'apply keyboard=fr' "$SEQ"

wiz "$RW" "fr|fr|qwerty|other|us|qwerty|YES" --language
expect_eq "décalage puis « autre disposition » : setupcon appelé pour fr puis pour us" 2 "$(grep -c '^setupcon -k$' "$SEQ")"
expect_grep "disposition finale : us" 'apply keyboard=us' "$SEQ"
expect_grep "disposition finale : /etc/default/keyboard = us" 'XKBLAYOUT="us"' "$RW/etc/default/keyboard"

wiz "$RW" "fr|fr|qwerty|retry|  AZERTY |YES" --language
expect_grep "refaire le test : majuscules et espaces tolérés, disposition acceptée" 'apply keyboard=fr' "$SEQ"
expect_eq "refaire le test : une seule application du clavier" 1 "$(grep -c '^setupcon -k$' "$SEQ")"

wiz "$RW" "fr|de|qwertz|YES" --language
expect_grep "de : le mot de test est qwertz" 'apply keyboard=de' "$SEQ"
wiz "$RW" "fr|be|azerty|YES" --language
expect_grep "be : le mot de test est azerty" 'apply keyboard=be' "$SEQ"

FAKE_SETUPCON_RC=1 FAKE_LOADKEYS_RC=1 wiz "$RW" "fr|fr|azerty|YES" --language
expect_grep "clavier non applicable à la console : l'utilisateur en est informé" 'dlg:msgbox:La disposition n’a pas pu être appliquée' "$SEQ"
wiz "$RW" "fr|fr|CANCEL" --language; rc=$?
expect_eq "Échap pendant le test : l'assistant s'arrête sans rien appliquer" 0 "$(grep -c '^apply ' "$SEQ")"
: > "$SEQ"
printf 'fr\nfr\nYES\n' > "$T_TMP/answers"
WT_ANSWERS="$T_TMP/answers" PATH="$FB:$PATH" DDI_ROOT="$RW" DDI_KBD_FORCE=1 DDI_APPLY_BIN="$FB/apply-stub" DDI_FW_BIN="$FB/fw-stub" timeout 60 script -qefc "$SETUP --language" /dev/null >/dev/null 2>&1
expect_eq "hors console (pty/SSH) : pas de test de saisie proposé" 0 "$(grep -c 'Test du clavier' "$SEQ")"
expect_grep "hors console : la disposition est quand même appliquée" 'apply keyboard=fr' "$SEQ"

wiz "$RW" "us|qwerty|YES" --keyboard
expect_grep "--keyboard : mode dédié, disposition us" 'apply keyboard=us' "$SEQ"

echo "== Assistant complet : le clavier est appliqué avant la saisie du mot de passe =="
RF="$(newroot)"
wiz "$RF" "fr|fr|azerty|ddi01|Europe/Paris|dhcp|192.168.1.0/24|ddiadmtest|Correct-Horse-Battery-9|Correct-Horse-Battery-9|YES" --first-boot; rc=$?
expect_eq "assistant complet : code 0" 0 "$rc"
p="$(seqn 'dlg:passwordbox')"; k="$(seqn 'setupcon -k')"
expect_eq "setupcon -k est lancé AVANT la 1re demande de mot de passe" 1 "$([ -n "$p" ] && [ -n "$k" ] && [ "$k" -lt "$p" ] && echo 1 || echo 0)"
h="$(seqn 'dlg:inputbox:Nom de la machine')"
expect_eq "… et avant la saisie du nom de machine" 1 "$([ -n "$h" ] && [ "$k" -lt "$h" ] && echo 1 || echo 0)"
expect_grep "le mot de passe est demandé en rappelant la disposition active" 'dlg:passwordbox:Mot de passe.*Clavier actuel : Français \(AZERTY\)' "$SEQ"
expect_eq "le mot de passe est bien transmis à ddibuntu-apply (sur l'entrée, sans valeur journalisée)" 1 "$(grep -c '^apply-pw-recu' "$SEQ")"
expect_eq "aucun mot de passe en clair dans le journal des dialogues" 0 "$(grep -c 'Correct-Horse' "$SEQ")"
expect_grep "accueil : la 1re boîte est l'écran avec le logo" '^dlg:msgbox: ____ .*Bienvenue / Welcome' "$SEQ"
expect_eq "accueil : affiché une seule fois" 1 "$(grep -c 'Bienvenue / Welcome' "$SEQ")"

echo "== Restauration par l'assistant, avec retour arrière automatique =="
RR="$(newroot)"; app "$RR" "$CA"; app "$RR" "$CB"
PRE1="$(find "$RR/var/lib/ddibuntu/snapshots" -maxdepth 1 -name '*-avant-application*' | head -1 | xargs basename)"
WIZ_APPLY="$APPLY" wiz "$RR" "$PRE1|YES|YES" --restore --arm 120; rc=$?
expect_eq "--restore : code 0" 0 "$rc"
expect_grep "restore : le menu liste les points avec leur raison" "dlg:menu:Choisissez le point de restauration" "$SEQ"
expect_grep "restore : retour automatique programmé (120 s)" 'systemd-run --quiet --unit=ddibuntu-revert --on-active=120s' "$SEQ"
expect_grep "restore : question de conservation avec le délai" 'dlg:yesno:La nouvelle configuration est active.*120 s' "$SEQ"
expect_grep "restore : réponse Oui => le minuteur est arrêté (confirm)" 'systemctl stop ddibuntu-revert' "$SEQ"
expect_nogrep "restore : réponse Oui => pas de retour arrière" 'dlg:msgbox:La configuration précédente a été restaurée' "$SEQ"
expect_eq "restore : la configuration de ancien point est revenue (nom = alpha)" alpha "$(confval "$RR" HOSTNAME)"

RR2="$(newroot)"; app "$RR2" "$CA"; app "$RR2" "$CB"
PRE2="$(find "$RR2/var/lib/ddibuntu/snapshots" -maxdepth 1 -name '*-avant-application*' | head -1 | xargs basename)"
WIZ_APPLY="$APPLY" wiz "$RR2" "$PRE2|YES|NO" --restore --arm 120
expect_grep "réponse Non => retour à l'état d'avant" 'dlg:msgbox:La configuration précédente a été restaurée' "$SEQ"
expect_eq "réponse Non => nom de machine de nouveau bravo" bravo "$(confval "$RR2" HOSTNAME)"
expect_eq "réponse Non => clavier de nouveau us" us "$(confval "$RR2" KEYBOARD)"
expect_grep "réponse Non => le minuteur est annulé avant la restauration" 'systemctl stop ddibuntu-revert' "$SEQ"

# aucun point : message, pas de menu
RE="$(newroot)"; wiz "$RE" "" --restore
expect_grep "aucun point de restauration : message dédié" 'dlg:msgbox:Aucun point de restauration' "$SEQ"
# annulation dans le menu : rien ne change
RC="$(newroot)"; app "$RC" "$CA"; app "$RC" "$CB"; wiz "$RC" "CANCEL" --restore
expect_eq "annulation du menu : configuration inchangée (bravo)" bravo "$(confval "$RC" HOSTNAME)"

# minuteur impossible (systemd-run absent) : l'utilisateur est prévenu que rien ne sera annulé tout seul
printf '#!/bin/sh\nexit 1\n' > "$FB/systemd-run-ko"; chmod 755 "$FB/systemd-run-ko"
RK2="$(newroot)"; app "$RK2" "$CA"; app "$RK2" "$CB"; P3="$(find "$RK2/var/lib/ddibuntu/snapshots" -maxdepth 1 -name '*-avant-application*' | head -1 | xargs basename)"
: > "$SEQ"; printf '%s\nYES\n' "$P3" > "$T_TMP/answers"
WT_ANSWERS="$T_TMP/answers" PATH="$FB:$PATH" DDI_ROOT="$RK2" DDI_APPLY_BIN="$SB/ddibuntu-apply" DDI_FW_BIN="$FB/fw-stub" DDI_SYSTEMD_RUN="$FB/systemd-run-ko" DDI_SYSTEMCTL="$FB/systemctl" timeout 60 script -qefc "$SETUP --restore --arm 120" /dev/null >/dev/null 2>&1
expect_grep "minuteur impossible : avertissement explicite" 'dlg:msgbox:Le retour arrière automatique n’a pas pu être programmé' "$SEQ"

echo "== Menu console =="
M="$RFS/usr/local/bin/ddibuntu-menu"
expect_grep "menu : entrée Clavier" 'keyboard "\$M_MENU_KEYBOARD"' "$M"
expect_grep "menu : entrée Points de restauration" 'restore "\$M_MENU_RESTORE"' "$M"
expect_grep "menu : toute modification passe par --arm (retour arrière automatique)" 'ddibuntu-setup --arm 120' "$M"
expect_grep "menu : SSH => pare-feu ET retour arrière à 60 s" 'ddibuntu-setup --fw-confirm 60 --arm 60' "$M"
expect_grep "menu : bandeau avec la version" 'backtitle "\$DDI_BACKTITLE"' "$M"
expect_grep "menu : l'écran d'état affiche le logo" 'ddi_logo plain' "$M"

finish
