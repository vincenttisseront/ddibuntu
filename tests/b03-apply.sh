#!/usr/bin/env bash
# Batterie 03 — ddibuntu-apply en mode hors-ligne (DDI_ROOT) : validation stricte avant toute
# écriture, fichiers produits (validés par netplan et nft), idempotence, bannière à jour, secrets.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

LIB="$RFS/usr/local/lib/ddibuntu"
APPLY="$RFS/usr/local/sbin/ddibuntu-apply"
export DDI_LIBDIR="$LIB" DDI_FW_BIN="$RFS/usr/local/sbin/ddibuntu-fw" DDI_ROLLBACK_BIN="$RFS/usr/local/sbin/ddibuntu-rollback" DDI_APPLY_BIN="$RFS/usr/local/sbin/ddibuntu-apply"

newroot() { local r; r="$(mktemp -d "$T_TMP/root.XXXXXX")"; mkdir -p "$r/etc" "$r/var/lib" "$r/run"; printf '%s' "$r"; }
apply() {   # apply ROOT CONFIG [options...] -> rc ; sortie dans $T_TMP/apply.out
  local r="$1" c="$2"; shift 2
  DDI_ROOT="$r" "$APPLY" --config "$c" "$@" >"$T_TMP/apply.out" 2>&1
}
cfg() { local f; f="$(mktemp "$T_TMP/cfg.XXXXXX")"; printf '%s\n' "$@" > "$f"; printf '%s' "$f"; }
files_hash() { ( cd "$1" && find . -type f ! -name configured | sort | xargs sha256sum ); }

echo "== Configuration réseau fixe =="
R="$(newroot)"
C="$(cfg "LANGUAGE='fr'" "KEYBOARD='fr'" "TIMEZONE='Europe/Paris'" "HOSTNAME='ddi01'" "NET_MODE='static'" "NET_IFACE='ens192'" \
  "NET_ADDR='10.20.30.40/24'" "NET_GW='10.20.30.1'" "NET_DNS='10.20.30.2, 10.20.30.3'" "NET_DOMAIN='corp.example.com'" "ADMIN_NETS='10.20.30.40/24, 192.168.50.0/24'")"
apply "$R" "$C"; rc=$?
expect_eq "apply : code retour 0" 0 "$rc"
expect_eq "nom de machine écrit" "ddi01" "$(cat "$R/etc/hostname")"
expect_grep "/etc/hosts : 127.0.1.1 ddi01" '^127\.0\.1\.1 ddi01$' "$R/etc/hosts"
expect_eq "fuseau : lien /etc/localtime" "/usr/share/zoneinfo/Europe/Paris" "$(readlink "$R/etc/localtime")"
expect_grep "clavier : XKBLAYOUT=fr" '^XKBLAYOUT="fr"$' "$R/etc/default/keyboard"
expect_eq "netplan : permissions 0600" 600 "$(stat -c %a "$R/etc/netplan/50-ddibuntu.yaml")"
expect_grep "netplan : adresse fixe" 'addresses: \["10.20.30.40/24"\]' "$R/etc/netplan/50-ddibuntu.yaml"
expect_grep "netplan : passerelle par défaut" 'via: "10.20.30.1"' "$R/etc/netplan/50-ddibuntu.yaml"
expect_grep "netplan : DNS et domaine de recherche" 'addresses: \["10.20.30.2", "10.20.30.3"\]' "$R/etc/netplan/50-ddibuntu.yaml"
check "netplan generate valide le YAML produit" netplan generate --root-dir "$R"
expect_grep "netplan generate : adresse réellement générée" '^Address=10\.20\.30\.40/24$' "$R/run/systemd/network/10-netplan-ens192.network"
expect_grep "netplan generate : passerelle réellement générée" '^Gateway=10\.20\.30\.1$' "$R/run/systemd/network/10-netplan-ens192.network"
expect_grep "pare-feu : réseau d'administration normalisé (bits hôte effacés)" 'elements = \{ 10\.20\.30\.0/24, 192\.168\.50\.0/24 \}' "$R/etc/ddibuntu/nftables.nft"
check "pare-feu produit : syntaxe valide (nft -c)" nft -c -f "$R/etc/ddibuntu/nftables.nft"
expect_grep "configuration persistée : réseaux normalisés" "^ADMIN_NETS='10.20.30.0/24,192.168.50.0/24'$" "$R/etc/ddibuntu/ddibuntu.conf"
expect_grep "marqueur de configuration créé avec la version" "^$(tr -d '\n' < "$LIB/VERSION") " "$R/var/lib/ddibuntu/configured"

echo "== Bannières (piège : code agetty \\n et version à jour) =="
expect_grep "/etc/issue : \\n littéral (nom de machine agetty)" 'DDI-Buntu [0-9.]+  -  \\n  -  \\l$' "$R/etc/issue"
expect_grep "/etc/issue : \\4 et \\6 littéraux (adresses agetty)" ' : \\4  \\6$' "$R/etc/issue"
expect_grep "/etc/issue : texte français" '^Adresses réseau' "$R/etc/issue"
# issue.net est lu tel quel par sshd : aucun code agetty (\n, \l, \4...) ; les antislashs du logo ASCII sont du dessin (jamais suivis d'une lettre ou d'un chiffre)
expect_nogrep "/etc/issue.net : aucun code agetty" '\\[A-Za-z0-9]' "$R/etc/issue.net"
expect_grep "/etc/issue.net : logo présent, tel quel (sans antislash doublé)" '^\|  _ \\ \|  _ \\ \|_ _\|' "$R/etc/issue.net"
expect_grep "/etc/issue.net : version courante" "^DDI-Buntu $(tr -d '\n' < "$LIB/VERSION") - " "$R/etc/issue.net"
# mise à jour simulée : nouvelle version -> bannière à jour partout, sans rester sur l'ancienne
NEWLIB="$T_TMP/newlib"; cp -r "$LIB" "$NEWLIB"; printf '9.9.9\n' > "$NEWLIB/VERSION"
DDI_LIBDIR="$NEWLIB" DDI_ROOT="$R" "$APPLY" >"$T_TMP/apply.out" 2>&1
expect_grep "après mise à jour : /etc/issue affiche 9.9.9" '^DDI-Buntu 9\.9\.9 ' "$R/etc/issue"
expect_grep "après mise à jour : /etc/issue.net affiche 9.9.9" '^DDI-Buntu 9\.9\.9 ' "$R/etc/issue.net"
expect_nogrep "après mise à jour : plus aucune trace de l'ancienne version" "DDI-Buntu $(tr -d '\n' < "$LIB/VERSION") " "$R/etc/issue"

echo "== Idempotence et fusion avec la configuration existante =="
R2="$(newroot)"; apply "$R2" "$C"; files_hash "$R2" > "$T_TMP/h1"
apply "$R2" "$C"; files_hash "$R2" > "$T_TMP/h2"
# Les points de restauration (snapshots/, last-snapshot) sont la seule chose qui change : la 2e application en crée un.
grep -vE 'var/lib/ddibuntu/(snapshots/|last-snapshot)' "$T_TMP/h1" > "$T_TMP/h1f"; grep -vE 'var/lib/ddibuntu/(snapshots/|last-snapshot)' "$T_TMP/h2" > "$T_TMP/h2f"
check "deux applications successives : fichiers de configuration identiques" diff "$T_TMP/h1f" "$T_TMP/h2f"
expect_eq "1re application : un point de restauration « état initial »" 1 "$(find "$R2/var/lib/ddibuntu/snapshots" -maxdepth 1 -name '*-etat-initial' | wc -l)"
expect_eq "2e application : un point de restauration « avant-application » créé avant la modification" 1 "$(find "$R2/var/lib/ddibuntu/snapshots" -maxdepth 1 -name '*-avant-application*' | wc -l)"
C2="$(cfg "HOSTNAME='ddi02'")"
apply "$R2" "$C2"; rc=$?
expect_eq "changement du seul nom : rc 0" 0 "$rc"
expect_eq "changement du seul nom : nouveau nom écrit" "ddi02" "$(cat "$R2/etc/hostname")"
expect_grep "changement du seul nom : adresse fixe conservée" 'addresses: \["10.20.30.40/24"\]' "$R2/etc/netplan/50-ddibuntu.yaml"

echo "== DHCP, anglais, IPv6 =="
R3="$(newroot)"
C3="$(cfg "LANGUAGE='en'" "HOSTNAME='ddi03'" "NET_MODE='dhcp'" "NET_IFACE='eth0'" "ADMIN_NETS='2001:db8:1::5/64'" "KEYBOARD='us'")"
apply "$R3" "$C3"; rc=$?
expect_eq "DHCP + IPv6 : rc 0" 0 "$rc"
check "netplan generate (DHCP)" netplan generate --root-dir "$R3"
expect_grep "DHCP : DHCP=ipv4 généré" '^DHCP=ipv4$' "$R3/run/systemd/network/10-netplan-eth0.network"
expect_grep "bannière anglaise" '^Network addresses' "$R3/etc/issue"
expect_grep "pare-feu : réseau IPv6 normalisé" 'elements = \{ 2001:db8:1::/64 \}' "$R3/etc/ddibuntu/nftables.nft"
check "pare-feu IPv6 : syntaxe valide" nft -c -f "$R3/etc/ddibuntu/nftables.nft"

echo "== Entrées invalides : refus (code 2) et AUCUNE écriture =="
bad() {   # bad "nom" lignes-de-config...
  local n="$1"; shift
  local r f; r="$(newroot)"; f="$(cfg "$@")"
  apply "$r" "$f"; local rc=$?
  local written; written="$(find "$r" -type f | wc -l)"
  if [ "$rc" -eq 2 ] && [ "$written" -eq 0 ]; then ok "refusé sans rien écrire : $n"; else ko "refusé sans rien écrire : $n" "rc=$rc, fichiers écrits=$written, sortie=$(head -c 200 "$T_TMP/apply.out" | tr '\n' ' ')"; fi
}
bad "nom de machine avec majuscule/souligné" "HOSTNAME='Bad_Name'"
bad "nom de machine de 64 caractères" "HOSTNAME='$(printf 'a%.0s' {1..64})'"
bad "nom de machine commençant par un tiret" "HOSTNAME='-x'"
bad "fuseau horaire inconnu" "TIMEZONE='Mars/Olympus'"
bad "fuseau horaire avec ../" "TIMEZONE='../../etc/passwd'"
bad "clavier non pris en charge" "KEYBOARD='xx'"
bad "langue inconnue" "LANGUAGE='de'"
bad "mode réseau inconnu" "NET_MODE='wifi'"
bad "IP statique invalide" "NET_MODE='static'" "NET_ADDR='999.1.1.1/24'" "NET_GW='10.0.0.1'"
bad "IP statique sans masque" "NET_MODE='static'" "NET_ADDR='10.0.0.5'" "NET_GW='10.0.0.1'"
bad "IP statique sans passerelle" "NET_MODE='static'" "NET_ADDR='10.0.0.5/24'"
bad "serveur DNS invalide" "NET_MODE='static'" "NET_ADDR='10.0.0.5/24'" "NET_GW='10.0.0.1'" "NET_DNS='10.0.0.2, nope'"
bad "domaine de recherche invalide" "NET_DOMAIN='bad domain!'"
bad "interface invalide" "NET_IFACE='eth0; reboot'"
bad "réseau d'administration 0.0.0.0/0" "ADMIN_NETS='0.0.0.0/0'"
bad "réseau d'administration ::/0" "ADMIN_NETS='::/0'"
bad "réseau d'administration invalide dans une liste" "ADMIN_NETS='10.0.0.0/8, abc'"
bad "compte réservé root" "ADMIN_USER='root'"
bad "compte réservé postgres" "ADMIN_USER='postgres'"
bad "compte avec majuscule" "ADMIN_USER='Admin'"
bad "clé inconnue" "FOO='bar'"
bad "guillemet dans une valeur (injection)" "HOSTNAME='a'; touch $T_TMP/pwned'"
bad "caractère de contrôle dans une valeur" "HOSTNAME='a	b'"
expect_eq "aucune commande injectée n'a été exécutée" no "$([ -e "$T_TMP/pwned" ] && echo yes || echo no)"
R4="$(newroot)"; C4="$(cfg "HOSTNAME='\$(touch $T_TMP/pwned2)'")"
apply "$R4" "$C4"
expect_eq "substitution de commande dans une valeur : rien d'exécuté" no "$([ -e "$T_TMP/pwned2" ] && echo yes || echo no)"

echo "== Mot de passe administrateur (--check, aucune écriture) =="
chk() {   # chk "nom" rc_attendu mot_de_passe|AUCUN ligne-de-config
  local n="$1" want="$2" pw="$3" f rc; shift 3
  f="$(cfg "$@")"; local r; r="$(newroot)"
  if [ "$pw" = "AUCUN" ]; then DDI_ROOT="$r" "$APPLY" --config "$f" --check >"$T_TMP/pw.out" 2>&1; rc=$?
  else printf '%s\n' "$pw" | DDI_ROOT="$r" "$APPLY" --config "$f" --check --password-stdin >"$T_TMP/pw.out" 2>&1; rc=$?; fi
  if [ "$rc" -eq "$want" ]; then ok "$n"; else ko "$n" "rc=$rc attendu=$want : $(head -c 200 "$T_TMP/pw.out")"; fi
  if [ "$pw" != "AUCUN" ] && grep -qF -- "$pw" "$T_TMP/pw.out"; then ko "$n : le mot de passe n'apparaît pas dans la sortie"; fi
}
chk "mot de passe valide accepté" 0 'Correct-Horse-9' "ADMIN_USER='jdupont'"
chk "mot de passe de 11 caractères refusé" 2 'Short-Pass1' "ADMIN_USER='jdupont'"
chk "mot de passe contenant l'identifiant refusé" 2 'xx-jdupont-xx-123' "ADMIN_USER='jdupont'"
chk "création de compte sans mot de passe refusée" 2 AUCUN "ADMIN_USER='jdupont'"
chk "mot de passe refusé : jamais répété dans le message" 2 'Tiny-pw-1' "ADMIN_USER='jdupont'"

echo "== Validateurs de common.sh =="
V() { bash -c ". '$LIB/common.sh'; $1"; }
for h in ddi01 a a-b-c 0x; do check "nom de machine valide : $h" V "ddi_valid_hostname '$h'"; done
for h in '' A_b -a a- 'a.b' ' a'; do check_fail "nom de machine invalide : [$h]" V "ddi_valid_hostname '$h'"; done
for u in admin j-dupont _svc a1; do check "compte valide : $u" V "ddi_valid_user '$u'"; done
for u in root ddisetup Admin 1abc 'a b' ''; do check_fail "compte invalide : [$u]" V "ddi_valid_user '$u'"; done
expect_eq "ddi_norm_net 10.1.2.3/24" "10.1.2.0/24" "$(V "ddi_norm_net 10.1.2.3/24")"
expect_eq "ddi_norm_net 2001:db8::1/64" "2001:db8::/64" "$(V "ddi_norm_net 2001:db8::1/64")"
expect_eq "ddi_norm_net hôte seul -> /32" "10.0.0.1/32" "$(V "ddi_norm_net 10.0.0.1")"
check_fail "ddi_norm_net refuse /0" V "ddi_norm_net 0.0.0.0/0"
expect_eq "ddi_split_list garde le dernier élément (piège sed sans saut de ligne final)" "4" "$(V "ddi_split_list 'a, b c,d' | wc -l" | tr -d ' ')"
expect_eq "ddi_split_list : un seul élément sans saut de ligne" "1" "$(V "ddi_split_list 'seul' | wc -l" | tr -d ' ')"

finish
