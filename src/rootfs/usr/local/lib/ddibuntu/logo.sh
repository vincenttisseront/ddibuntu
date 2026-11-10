#!/bin/bash
# DDI-Buntu — logo en texte (fichier sourcé). Largeur : 50 colonnes, 5 lignes, lisible sur une console 80x25.
# shellcheck shell=bash
DDI_LOGO_SPLIT=21     # colonne où « Buntu » commence (couleur différente)
DDI_LOGO_TAGLINE="DNS  -  DHCP  -  IPAM"

ddi_logo_lines() {
  cat <<'DDI_LOGO'
 ____   ____   ___    ____              _
|  _ \ |  _ \ |_ _|  | __ ) _   _ _ __ | |_ _   _
| | | || | | | | |   |  _ \| | | | '_ \| __| | | |
| |_| || |_| | | |   | |_) | |_| | | | | |_| |_| |
|____/ |____/ |___|  |____/ \__,_|_| |_|\__|\__,_|
DDI_LOGO
}

# ddi_logo [plain|color|auto] : logo + devise ; la couleur n'est utilisée que sur un terminal (et jamais si NO_COLOR est défini)
ddi_logo() {
  local mode="${1:-auto}" c1='' c2='' c0='' l
  if [ "$mode" = auto ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then mode=color; fi
  if [ "$mode" = color ]; then c1=$'\e[1;34m'; c2=$'\e[1;33m'; c0=$'\e[0m'; fi
  while IFS= read -r l; do
    printf '%s%s%s%s%s\n' "$c1" "${l:0:DDI_LOGO_SPLIT}" "$c2" "${l:DDI_LOGO_SPLIT}" "$c0"
  done < <(ddi_logo_lines)
  printf '%s%*s%s%s\n' "$c2" 12 '' "$DDI_LOGO_TAGLINE" "$c0"
}

# Version pour /etc/issue : agetty traite « \ » comme un début de code (\n, \l, \4…), donc chaque antislash est doublé.
ddi_logo_issue() { ddi_logo plain | sed 's/\\/\\\\/g'; }
