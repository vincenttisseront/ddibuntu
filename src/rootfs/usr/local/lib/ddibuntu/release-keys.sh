# shellcheck shell=bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# release-keys.sh — jeu de clés de confiance des mises à jour (Ed25519) et manifestes de rotation.
# Sourcé par ddibuntu-selfupdate sur l'appliance, et par tools/release-keys.sh dans les workflows (mêmes règles des deux côtés).
#
# Clés de confiance pour signer SHA256SUMS (une seule suffit) :
#   - RK_LEGACY                        ancienne clé unique (update-pubkey.pem), conservée pendant la transition ;
#   - $RK_CONFDIR/keys/release.d/*.pem clés actives livrées par les versions signées ;
#   - $RK_STATE/release.d/*.pem        clés ajoutées par un manifeste de rotation (état de l'appliance, jamais écrasé par une mise à jour) ;
#   moins les empreintes révoquées ($RK_STATE/revoked) et moins la clé de secours.
# Clé de secours : $RK_CONFDIR/keys/release-secours.pem. Elle ne signe QUE les manifestes de rotation, jamais une archive.
#
# Manifeste de rotation (key-rotation-NNN.json, signé par la clé de secours dans key-rotation-NNN.json.sig) :
#   {"format": 1, "usage": "release", "sequence": 1, "date": "AAAA-MM-JJ", "reason": "…",
#    "old_fingerprints": ["<sha256 hex de la clé publique DER>", …], "new_public_key": "-----BEGIN PUBLIC KEY-----…" | null}
# Appliqué une seule fois, dans l'ordre des numéros : les anciennes empreintes sont révoquées pour toujours, la nouvelle clé
# devient une clé de confiance. Un numéro déjà appliqué (ou plus petit) n'est jamais rejoué.
# Empreinte d'une clé = SHA-256 de la clé publique au format DER : openssl pkey -pubin -in k.pem -outform DER | sha256sum
# RK_ERR (motif d'un refus) et RK_KEY_FPR (clé qui a vérifié) sont lus par l'appelant.
# shellcheck disable=SC2034

RK_CONFDIR="${RK_CONFDIR:-${DDI_CONFDIR:-/etc/ddibuntu}}"
RK_STATE="${RK_STATE:-${DDI_STATEDIR:-/var/lib/ddibuntu}/keys}"
RK_LEGACY="${RK_LEGACY-$RK_CONFDIR/update-pubkey.pem}"
RK_MAX_MANIFEST=8192
RK_ERR=""; RK_KEY_FPR=""

rk_fpr() {   # empreinte d'une clé publique Ed25519 (64 hex) ; échec si le fichier n'en est pas une
  local f="$1" t
  [ -f "$f" ] && [ ! -L "$f" ] || return 1
  t="$(openssl pkey -pubin -in "$f" -noout -text_pub 2>/dev/null | head -1)" || return 1
  [ "$t" = "ED25519 Public-Key:" ] || return 1
  openssl pkey -pubin -in "$f" -outform DER 2>/dev/null | sha256sum | cut -c1-64
}
rk_revoked() { [ -f "$RK_STATE/revoked" ] && grep -qxF "$1" "$RK_STATE/revoked"; }
rk_secours_fpr() { rk_fpr "$RK_CONFDIR/keys/release-secours.pem" 2>/dev/null || true; }

# Liste « empreinte<TAB>origine<TAB>chemin » des clés de confiance (révoquées, invalides et secours exclues, sans doublon).
rk_trusted() {
  local f fp sec seen="" origin
  sec="$(rk_secours_fpr)"
  for f in ${RK_LEGACY:+"$RK_LEGACY"} "$RK_CONFDIR"/keys/release.d/*.pem "$RK_STATE"/release.d/*.pem; do
    [ -f "$f" ] || continue
    fp="$(rk_fpr "$f")" || continue
    [ "$fp" != "$sec" ] || continue
    rk_revoked "$fp" && continue
    case " $seen " in *" $fp "*) continue ;; esac
    seen="$seen $fp"
    case "$f" in "$RK_STATE"/*) origin=rotation ;; "${RK_LEGACY:-//}") origin=ancienne ;; *) origin=livree ;; esac
    printf '%s\t%s\t%s\n' "$fp" "$origin" "$f"
  done
}

# rk_verify FICHIER SIGNATURE : 0 si une clé de confiance vérifie la signature (empreinte dans RK_KEY_FPR).
rk_verify() {
  local data="$1" sig="$2" fp origin path
  RK_ERR=""; RK_KEY_FPR=""
  while IFS=$'\t' read -r fp origin path; do
    [ -n "$fp" ] || continue
    if openssl pkeyutl -verify -pubin -inkey "$path" -rawin -in "$data" -sigfile "$sig" >/dev/null 2>&1; then
      RK_KEY_FPR="$fp"; return 0
    fi
  done < <(rk_trusted)
  if [ -z "$(rk_trusted)" ]; then RK_ERR="aucune clé de confiance (clés absentes ou toutes révoquées)"
  else RK_ERR="signature invalide pour toutes les clés de confiance"; fi
  return 1
}

rk_seq() { local s; s="$(cat "$RK_STATE/rotation-seq" 2>/dev/null || true)"; [[ "$s" =~ ^[0-9]{1,6}$ ]] && printf '%s' "$s" || printf 0; }

# rk_apply_rotation MANIFESTE SIGNATURE : 0 = appliqué ; 2 = déjà appliqué (numéro ≤ dernier) ; 1 = refusé (motif dans RK_ERR).
rk_apply_rotation() {
  local m="$1" sig="$2" sec tmp seq newfp out
  RK_ERR=""
  [ -f "$m" ] && [ -f "$sig" ] || { RK_ERR="manifeste ou signature absent"; return 1; }
  [ "$(stat -c %s "$m")" -le "$RK_MAX_MANIFEST" ] || { RK_ERR="manifeste trop grand"; return 1; }
  [ "$(stat -c %s "$sig")" -le 128 ] || { RK_ERR="signature trop grande"; return 1; }
  sec="$RK_CONFDIR/keys/release-secours.pem"
  rk_fpr "$sec" >/dev/null || { RK_ERR="clé de secours absente ou invalide ($sec) : manifeste refusé"; return 1; }
  openssl pkeyutl -verify -pubin -inkey "$sec" -rawin -in "$m" -sigfile "$sig" >/dev/null 2>&1 \
    || { RK_ERR="manifeste de rotation NON signé par la clé de secours : refusé"; return 1; }
  tmp="$(mktemp -d)"
  out="$(python3 - "$m" "$tmp/new.pem" <<'PY'
import json, re, sys
try:
    d = json.load(open(sys.argv[1], encoding='utf-8'))
except Exception:
    print('manifeste illisible (JSON invalide)'); sys.exit(1)
def bad(msg): print(msg); sys.exit(1)
if not isinstance(d, dict): bad('manifeste invalide')
if d.get('format') != 1: bad('format de manifeste inconnu')
if d.get('usage') != 'release': bad('manifeste destiné à un autre usage que les mises à jour')
s = d.get('sequence')
if not isinstance(s, int) or isinstance(s, bool) or not 1 <= s <= 999999: bad('numéro de séquence invalide')
if not isinstance(d.get('date'), str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', d['date']): bad('date invalide')
r = d.get('reason')
if not isinstance(r, str) or not r.strip() or len(r) > 500: bad('motif absent ou trop long')
olds = d.get('old_fingerprints')
if not isinstance(olds, list) or len(olds) > 8 or not all(isinstance(x, str) and re.fullmatch(r'[0-9a-f]{64}', x) for x in olds): bad('empreintes à révoquer invalides')
k = d.get('new_public_key')
if isinstance(k, str):
    k = k.replace('\r\n', '\n')
if k is None:
    if not olds: bad('manifeste sans effet')
    k = ''
elif not isinstance(k, str) or len(k) > 1024 or not re.fullmatch(r'-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?', k): bad('nouvelle clé publique invalide')
if k:
    open(sys.argv[2], 'w').write(k if k.endswith('\n') else k + '\n')
print(s)
for x in olds: print(x)
PY
)" || { RK_ERR="${out:-manifeste invalide}"; rm -rf "$tmp"; return 1; }
  seq="$(printf '%s\n' "$out" | head -1)"
  if [ "$seq" -le "$(rk_seq)" ]; then rm -rf "$tmp"; return 2; fi
  newfp=""
  if [ -f "$tmp/new.pem" ]; then
    newfp="$(rk_fpr "$tmp/new.pem")" || { RK_ERR="la nouvelle clé n'est pas une clé publique Ed25519"; rm -rf "$tmp"; return 1; }
    [ "$newfp" != "$(rk_secours_fpr)" ] || { RK_ERR="la nouvelle clé active ne peut pas être la clé de secours"; rm -rf "$tmp"; return 1; }
    ! rk_revoked "$newfp" || { RK_ERR="la nouvelle clé est une clé révoquée"; rm -rf "$tmp"; return 1; }
    ! printf '%s\n' "$out" | tail -n +2 | grep -qxF "$newfp" || { RK_ERR="le manifeste révoque la clé qu'il ajoute"; rm -rf "$tmp"; return 1; }
  fi
  mkdir -p "$RK_STATE/release.d" "$RK_STATE/applied"; chmod 0755 "$RK_STATE"
  # révocations d'abord : une interruption laisse au pire une clé révoquée sans remplaçante, jamais l'inverse
  printf '%s\n' "$out" | tail -n +2 | while IFS= read -r fp; do
    [ -n "$fp" ] && ! rk_revoked "$fp" && printf '%s\n' "$fp" >> "$RK_STATE/revoked"
  done
  if [ -n "$newfp" ]; then install -m 0644 "$tmp/new.pem" "$RK_STATE/release.d/$newfp.pem"; fi
  install -m 0644 "$m" "$RK_STATE/applied/key-rotation-$(printf '%03d' "$seq").json"
  install -m 0644 "$sig" "$RK_STATE/applied/key-rotation-$(printf '%03d' "$seq").json.sig"
  printf '%s\n' "$seq" > "$RK_STATE/rotation-seq.tmp" && mv -f "$RK_STATE/rotation-seq.tmp" "$RK_STATE/rotation-seq"
  rm -rf "$tmp"
  return 0
}
