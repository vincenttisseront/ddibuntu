#!/bin/bash
# DDI-Buntu — fonctions communes (fichier sourcé, ne s'exécute pas seul).
# shellcheck shell=bash
# shellcheck disable=SC2034  # variables lues par les scripts qui sourcent ce fichier

DDI_ROOT="${DDI_ROOT:-}"                    # non vide = mode hors-ligne (tests, chroot)
DDI_LIBDIR="${DDI_LIBDIR:-/usr/local/lib/ddibuntu}"
DDI_CONFDIR="${DDI_ROOT}/etc/ddibuntu"
DDI_STATEDIR="${DDI_ROOT}/var/lib/ddibuntu"
DDI_CONFFILE="${DDI_CONFDIR}/ddibuntu.conf"
DDI_KEYS="LANGUAGE KEYBOARD TIMEZONE HOSTNAME NET_MODE NET_IFACE NET_ADDR NET_GW NET_DNS NET_DOMAIN ADMIN_NETS ADMIN_USER"

ddi_version() { tr -d '\n' < "${DDI_LIBDIR}/VERSION" 2>/dev/null || printf 'inconnue'; }
ddi_log() { logger -t ddibuntu -- "$*" 2>/dev/null || true; }   # jamais de secret dans $*
ddi_die() { printf 'ddibuntu: %s\n' "$*" >&2; exit 2; }
ddi_warn() { printf 'ddibuntu: %s\n' "$*" >&2; }
ddi_offline() { [ -n "$DDI_ROOT" ]; }

ddi_load_lang() {
  local l="${1:-fr}"
  case "$l" in fr|en) ;; *) l=fr ;; esac
  # shellcheck source=/dev/null
  . "${DDI_LIBDIR}/lang/${l}.sh"
  DDI_LANG="$l"
}

# Formatage d'un message du catalogue : ddi_fmt "$M_XXX" arg...
ddi_fmt() {
  local f="$1"; shift
  # shellcheck disable=SC2059
  printf -- "$f" "$@"
}

# ---- Validations (aucune ne suppose que l'entrée est sûre) ----
ddi_valid_hostname() { [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; }
ddi_valid_domain()   { [[ "$1" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; }
ddi_valid_iface()    { [[ "$1" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]]; }
ddi_valid_user() {
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || return 1
  case "$1" in
    root|ddisetup|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|nobody|ubuntu|postgres|bind|kea) return 1 ;;
  esac
  return 0
}
ddi_valid_ip() {
  python3 -c 'import ipaddress,sys
try: ipaddress.ip_address(sys.argv[1])
except ValueError: sys.exit(1)' "$1"
}
ddi_valid_ifaddr() {   # adresse/masque obligatoire (bits hôte autorisés)
  case "$1" in */*) ;; *) return 1 ;; esac
  python3 -c 'import ipaddress,sys
try: ipaddress.ip_interface(sys.argv[1])
except ValueError: sys.exit(1)' "$1"
}
ddi_norm_net() {       # réseau normalisé sur stdout ; échec si invalide ou /0
  python3 -c 'import ipaddress,sys
try: n = ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError: sys.exit(1)
if n.prefixlen == 0: sys.exit(1)
print(n)' "$1"
}
ddi_valid_tz() {
  [[ "$1" =~ ^[A-Za-z0-9_+/-]+$ ]] || return 1
  case "$1" in *..*) return 1 ;; esac
  [ -f "${DDI_ZONEINFO:-/usr/share/zoneinfo}/$1" ]
}
ddi_valid_keyboard() { case "$1" in fr|us|gb|de|es|it|be|ch) return 0 ;; *) return 1 ;; esac; }
ddi_valid_password() {  # $1 = mot de passe, $2 = identifiant ; 12 caractères minimum
  [ "${#1}" -ge 12 ] || return 1
  case "$1" in *"$2"*) return 1 ;; esac
  [[ "$1" != *[[:cntrl:]]* ]]
}

# Liste séparée par virgules/espaces -> un élément par ligne
ddi_split_list() { printf '%s\n' "$1" | tr -s '[:space:],' '\n' | sed '/^$/d'; }   # saut de ligne final obligatoire pour « while read »

# ---- Lecture sûre d'un fichier CLE='valeur' (jamais de source/eval) ----
ddi_cfg_read() {
  local f="$1" line k v
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    k="${line%%=*}"; v="${line#*=}"
    case " $DDI_KEYS " in *" $k "*) ;; *) ddi_die "clé inconnue dans la configuration : $k" ;; esac
    v="${v#\'}"; v="${v%\'}"
    if [[ "$v" =~ [[:cntrl:]\'] ]]; then ddi_die "valeur invalide pour $k"; fi
    printf -v "CFG_$k" '%s' "$v"
  done < "$f"
}
ddi_cfg_reset() { local k; for k in $DDI_KEYS; do printf -v "CFG_$k" '%s' ''; done; }

# ---- Clavier : écrit (persistant) puis appliqué tout de suite à la console courante ----
DDI_KBD_LIST="fr be ch us gb de es it"
ddi_kbd_name() {
  case "$1" in
    fr) printf 'Français (AZERTY)' ;; be) printf 'Belge (AZERTY)' ;; ch) printf 'Suisse (QWERTZ)' ;;
    us) printf 'English (US) - QWERTY' ;; gb) printf 'English (UK) - QWERTY' ;; de) printf 'Deutsch (QWERTZ)' ;;
    es) printf 'Español (QWERTY)' ;; it) printf 'Italiano (QWERTY)' ;; *) printf '%s' "$1" ;;
  esac
}
# Les six premières lettres de la rangée du haut, telles qu'elles doivent s'afficher avec cette disposition.
ddi_kbd_testword() { case "$1" in fr|be) printf 'azerty' ;; de|ch) printf 'qwertz' ;; *) printf 'qwerty' ;; esac; }
ddi_kbd_loadkeys_map() { case "$1" in fr) printf 'fr' ;; be) printf 'be-latin1' ;; ch) printf 'sg' ;; de) printf 'de' ;; es) printf 'es' ;; it) printf 'it' ;; gb) printf 'uk' ;; *) printf 'us' ;; esac; }
ddi_kbd_write() {   # $1 = disposition : fichier lu au démarrage par console-setup
  mkdir -p "$DDI_ROOT/etc/default"
  printf 'XKBMODEL="pc105"\nXKBLAYOUT="%s"\nXKBVARIANT=""\nXKBOPTIONS=""\nBACKSPACE="guess"\n' "$1" > "$DDI_ROOT/etc/default/keyboard"
}
# $1 = disposition, $2 = « save » pour rendre persistant le cache de console-setup. Échec = non appliquée à la console.
# DDI_KBD_FORCE : exécute les commandes même en mode hors-ligne (tests avec de fausses commandes).
ddi_kbd_apply_now() {
  if ddi_offline && [ -z "${DDI_KBD_FORCE:-}" ]; then return 0; fi
  if command -v setupcon >/dev/null 2>&1; then
    if [ "${2:-}" = save ]; then setupcon -k --save >/dev/null 2>&1 && return 0; else setupcon -k >/dev/null 2>&1 && return 0; fi
  fi
  if command -v loadkeys >/dev/null 2>&1 && loadkeys "$(ddi_kbd_loadkeys_map "$1")" >/dev/null 2>&1; then return 0; fi
  return 1
}
# Le test de saisie n'a de sens que sur la console (écran/clavier de la VM), pas dans une session SSH.
ddi_kbd_on_console() {
  [ -z "${DDI_KBD_TEST:-}" ] || return 0
  case "$(tty 2>/dev/null)" in /dev/tty[0-9]*|/dev/hvc*|/dev/console) return 0 ;; *) return 1 ;; esac
}
