#!/usr/bin/env bash
# Batterie 02 — traductions : un catalogue unique (français = langue source), mêmes clés en anglais,
# aucun doublon, aucune clé utilisée mais absente, aucune clé morte, mêmes variables de formatage.
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

L="$RFS/usr/local/lib/ddibuntu/lang"
keys_of() { grep -oE '^M_[A-Z0-9_]+=' "$1" | tr -d '=' | sort; }

keys_of "$L/fr.sh" > "$T_TMP/fr.keys"; keys_of "$L/en.sh" > "$T_TMP/en.keys"
n="$(wc -l < "$T_TMP/fr.keys")"
if [ "$n" -gt 40 ]; then ok "catalogue français : $n clés"; else ko "catalogue français trop court" "$n clés"; fi
check "mêmes clés en français et en anglais" diff "$T_TMP/fr.keys" "$T_TMP/en.keys"
expect_eq "aucune clé en double (français)" "" "$(uniq -d "$T_TMP/fr.keys")"
expect_eq "aucune clé en double (anglais)" "" "$(uniq -d "$T_TMP/en.keys")"

# Valeurs : chargées dans un sous-shell, une ligne « clé<TAB>valeur » par clé
# shellcheck disable=SC1090  # catalogue choisi à l'exécution
dump() { ( set +u; . "$1"; for k in $(keys_of "$1"); do printf '%s\t%s\n' "$k" "${!k}"; done ); }
dump "$L/fr.sh" > "$T_TMP/fr.tsv"; dump "$L/en.sh" > "$T_TMP/en.tsv"
expect_eq "aucune valeur vide (français)" 0 "$(awk -F'\t' '$2 == ""' "$T_TMP/fr.tsv" | wc -l)"
expect_eq "aucune valeur vide (anglais)" 0 "$(awk -F'\t' '$2 == ""' "$T_TMP/en.tsv" | wc -l)"
expect_eq "aucune traduction en double (deux clés, même texte français)" "" "$(cut -f2 "$T_TMP/fr.tsv" | sort | uniq -d)"
expect_eq "aucune traduction en double (deux clés, même texte anglais)" "" "$(cut -f2 "$T_TMP/en.tsv" | sort | uniq -d)"

# Variables de formatage et sauts de ligne identiques d'une langue à l'autre
count_tokens() { awk -F'\t' '{ s = $2; p = gsub(/%s/, "", s); n = gsub(/\\n/, "", s); print $1 "\t" p "\t" n }' "$1"; }
count_tokens "$T_TMP/fr.tsv" > "$T_TMP/fr.tok"; count_tokens "$T_TMP/en.tsv" > "$T_TMP/en.tok"
check "mêmes nombres de %s et de \\n par message en français et en anglais" diff "$T_TMP/fr.tok" "$T_TMP/en.tok"

# Texte non traduit : seul M_MENU_PROMPT (nom du produit et variables) peut être identique
join -t "$(printf '\t')" "$T_TMP/fr.tsv" "$T_TMP/en.tsv" | awk -F'\t' '$2 == $3 { print $1 }' | grep -vx 'M_MENU_PROMPT' > "$T_TMP/same" || true
expect_eq "aucun message anglais identique au français (hors M_MENU_PROMPT)" "" "$(tr '\n' ' ' < "$T_TMP/same")"

# Usage : clés utilisées dans le code <-> clés définies
grep -rhoE '\$\{?M_[A-Z0-9_]+' "$RFS/usr/local/sbin" "$RFS/usr/local/bin" | tr -d '${' | sort -u > "$T_TMP/used"
comm -23 "$T_TMP/used" "$T_TMP/fr.keys" > "$T_TMP/undefined"
comm -13 "$T_TMP/used" "$T_TMP/fr.keys" > "$T_TMP/dead"
expect_eq "toute clé utilisée par le code est définie" "" "$(tr '\n' ' ' < "$T_TMP/undefined")"
expect_eq "aucune clé morte (définie mais jamais utilisée)" "" "$(tr '\n' ' ' < "$T_TMP/dead")"

# Pièges connus : le « \n » du catalogue est un saut de ligne pour printf, pas pour agetty
expect_nogrep "catalogue : pas de \\n ni \\4 ni \\l dans les textes de bannière (codes agetty)" '^M_ISSUE_.*\\[n4l6]' "$L/fr.sh"
expect_nogrep "catalogue : pas d'apostrophe droite dans les textes français (typographie ’)" "^M_[A-Z0-9_]+='[^']*[a-z]'[a-z]" "$L/fr.sh"

# Chaque langue se charge sans erreur et la langue inconnue retombe sur le français
check "ddi_load_lang en" bash -c "DDI_LIBDIR='$RFS/usr/local/lib/ddibuntu'; . \"\$DDI_LIBDIR/common.sh\"; ddi_load_lang en; [ \"\$DDI_LANG\" = en ] && [ -n \"\$M_TITLE\" ]"
check "ddi_load_lang inconnue -> fr" bash -c "DDI_LIBDIR='$RFS/usr/local/lib/ddibuntu'; . \"\$DDI_LIBDIR/common.sh\"; ddi_load_lang xx; [ \"\$DDI_LANG\" = fr ]"
check "ddi_load_lang refuse un chemin piégé (../)" bash -c "DDI_LIBDIR='$RFS/usr/local/lib/ddibuntu'; . \"\$DDI_LIBDIR/common.sh\"; ddi_load_lang '../x'; [ \"\$DDI_LANG\" = fr ]"
# Formatage réel d'un message à variables
fmt="$(bash -c "DDI_LIBDIR='$RFS/usr/local/lib/ddibuntu'; . \"\$DDI_LIBDIR/common.sh\"; ddi_load_lang en; ddi_fmt \"\$M_HOST_INVALID\" 'Bad_Name'")"
expect_eq "ddi_fmt formate le message anglais" 'Invalid machine name: "Bad_Name". Use lowercase letters, digits and hyphens (63 characters at most).' "$fmt"
sum="$(bash -c "DDI_LIBDIR='$RFS/usr/local/lib/ddibuntu'; . \"\$DDI_LIBDIR/common.sh\"; ddi_load_lang fr; ddi_fmt \"\$M_SUMMARY\" fr fr Europe/Paris ddi01 static 10.0.0.2/24 10.0.0.1 10.0.0.0/24 admin" | wc -l)"
expect_eq "résumé : 5 lignes (les \\n du catalogue deviennent de vrais sauts de ligne)" 5 "$sum"

finish
