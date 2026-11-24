#!/usr/bin/env bash
# Batterie 46 — assistant root RADIUS : aucune expansion FreeRADIUS ne doit venir du compte ou du mot de passe de liaison LDAP (audit de sécurité 0.24.1).
# FreeRADIUS développe « %{…} » (xlat) dans « identity » et « password » du module LDAP : un « %{exec:…} » saisi par un administrateur de la console serait exécuté.
# La console dépose des DONNÉES, root les valide (ddibuntu-radius check-authz) : cette batterie rejoue la validation seule (sans FreeRADIUS, sans annuaire, sans root).
# Prérequis : bash, python3, openssl.
# shellcheck disable=SC2016  # les chaînes entre apostrophes sont des valeurs hostiles littérales : aucune expansion voulue
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

RAD="$RFS/usr/local/sbin/ddibuntu-radius"
for b in python3 openssl; do command -v "$b" >/dev/null || { note "$b absent : batterie ignorée"; finish; exit $?; }; done
D="$T_TMP"; export DDI_LIBDIR="$RFS/usr/local/lib/ddibuntu"
GOLD="$ROOT/tests/radius-rules-compiled.json"

# fichier de clients attendu par le jeu de règles de référence (mêmes noms que la batterie 30 ; secrets factices)
CL="$D/clients.conf"; : > "$CL"
printf 'client "ddi-selftest" {\n\tipaddr = 127.0.0.1\n\tsecret = "0123456789abcdef0123456789abcdef"\n\tshortname = ddi-selftest\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n' >> "$CL"
n=2; for c in wifi-ctrl vpn-gw sw1; do
  printf '\nclient "%s" {\n\tipaddr = 10.1.0.%d\n\tsecret = "%s"\n\tshortname = %s\n\trequire_message_authenticator = yes\n\tnas_type = other\n}\n' "$c" "$n" "$(printf '%032d' "$n")" "$c" >> "$CL"; n=$((n + 1))
done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=lab-ca.exemple.test" -keyout "$D/ca.key" -out "$D/ca.pem" 2>/dev/null

# mk DOSSIER BINDDN BINDPW : dépôt des règles de la console (jeu de référence + réglages d'annuaire factices)
mk() {
  rm -rf "$1"; mkdir -p "$1"
  cp "$GOLD" "$1/rules.json"; cp "$D/ca.pem" "$1/ldap-ca.pem"
  python3 - "$1/ldap.json" "$2" "$3" <<'PY'
import json, sys
json.dump({"urls": ["ldaps://dc1.lab.test"], "baseDn": "DC=lab,DC=test", "bindDn": sys.argv[2], "bindPassword": sys.argv[3], "tlsRejectUnauthorized": True}, open(sys.argv[1], "w"))
PY
  chmod 0600 "$1"/*
}
A="$D/az"

echo "== Référence : réglages d'annuaire ordinaires =="
mk "$A" 'svc-radius@lab.test' 'Passw0rd-svc-1!'
check "dépôt conforme accepté (la validation tourne ici sans FreeRADIUS)" bash "$RAD" check-authz "$A" "$CL"

echo "== Caractères spéciaux légitimes toujours acceptés =="
mk "$A" 'CN=svc radius,OU=Comptes de service,DC=lab,DC=test' 'p&a=s+x}1{y 100% sûr [ok] (ok)'
check "« % » isolé, accolades, crochets et parenthèses sans « % » acceptés" bash "$RAD" check-authz "$A" "$CL"
mk "$A" 'svc-radius@lab.test' 'a%b%%c%'
check "« % » non suivi de « { », « ( » ou « [ » accepté" bash "$RAD" check-authz "$A" "$CL"

echo "== Expansions refusées (compte de liaison) =="
for v in '%{exec:/bin/id}' 'svc%{sql:select 1}@lab.test' '%(x)' '%[x]' 'CN=%{Tmp-String-0},DC=lab' '$ENV{HOME}' '${x}' '$(id)'; do
  mk "$A" "$v" 'Passw0rd-svc-1!'
  check_fail "compte de liaison « $v » refusé" bash "$RAD" check-authz "$A" "$CL"
done

echo "== Expansions refusées (mot de passe de liaison) =="
for v in '%{exec:/bin/id}' 'abc%{sql:x}' 'p%(x)q' 'p%[x]q' '$ENV{HOME}' '${x}' '$(id)'; do
  mk "$A" 'svc-radius@lab.test' "$v"
  check_fail "mot de passe de liaison « $v » refusé" bash "$RAD" check-authz "$A" "$CL"
done

echo "== Le message de refus nomme le champ, jamais la valeur =="
mk "$A" 'svc-radius@lab.test' 'secret-%{exec:/bin/true}'
bash "$RAD" check-authz "$A" "$CL" >"$D/refus.out" 2>&1
expect_grep "refus : mot de passe de liaison désigné" 'mot de passe de liaison' "$D/refus.out"
expect_nogrep "refus : la valeur saisie n'est pas répétée" 'secret-' "$D/refus.out"

finish
