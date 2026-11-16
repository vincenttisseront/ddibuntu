#!/usr/bin/env bash
# lib-pki.sh — fabrique une PKI de test avec le binaire openssl (aucune dépendance Python) : racine, autorités émettrices, certificats serveur
# et clients (valide, expiré, mauvais usage, révoqué), CRL valide ou expirée. À sourcer ; chaque fonction écrit dans le dossier indiqué.
#   pki_root DIR CN                       racine autosignée (DIR/ca.pem, DIR/ca.key)
#   pki_inter DIR PARENT_DIR CN           autorité émettrice signée par PARENT_DIR
#   pki_issue CA_DIR PREFIX CN PROFIL [SAN] [DEBUT FIN]   certificat PREFIX.pem + PREFIX.key (PROFIL : server | client | clientbad)
#   pki_revoke CA_DIR CERT.pem            marque le certificat révoqué
#   pki_crl CA_DIR OUT.pem [JOURS | expire]   émet la CRL (« expire » = déjà périmée)
# DEBUT / FIN : dates au format AAAAMMJJHHMMSSZ (pour fabriquer un certificat déjà expiré).

_pki_cnf() {   # _pki_cnf DIR : écrit la configuration openssl de l'autorité
  local d="$1"
  cat > "$d/openssl.cnf" <<EOF
[ ca ]
default_ca = CA
[ CA ]
dir = $d
database = $d/index.txt
new_certs_dir = $d/newcerts
certificate = $d/ca.pem
private_key = $d/ca.key
serial = $d/serial
crlnumber = $d/crlnumber
default_md = sha256
policy = pol
unique_subject = no
copy_extensions = none
[ pol ]
commonName = supplied
[ v3_inter ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ crl_ext ]
authorityKeyIdentifier = keyid
EOF
  : > "$d/index.txt"; echo 1000 > "$d/serial"; echo 1000 > "$d/crlnumber"; mkdir -p "$d/newcerts"
}

pki_root() {   # DIR CN
  mkdir -p "$1"; _pki_cnf "$1"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$1/ca.key" -out "$1/ca.pem" -subj "/CN=$2" -days 3650 -sha256 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" 2>/dev/null
}
pki_inter() {   # DIR PARENT CN
  mkdir -p "$1"; _pki_cnf "$1"
  openssl req -new -newkey rsa:2048 -nodes -keyout "$1/ca.key" -out "$1/ca.csr" -subj "/CN=$3" 2>/dev/null
  openssl ca -batch -config "$2/openssl.cnf" -extensions v3_inter -in "$1/ca.csr" -out "$1/ca.pem" -days 1825 -notext 2>/dev/null
}
pki_issue() {   # CA_DIR PREFIX CN PROFIL [SAN] [DEBUT FIN]
  local ca="$1" out="$2" cn="$3" prof="$4" san="${5:-}" start="${6:-}" end="${7:-}" eku usage extra=()
  case "$prof" in
    server) eku="serverAuth"; usage="digitalSignature,keyEncipherment" ;;
    client) eku="clientAuth"; usage="digitalSignature" ;;
    clientbad) eku="serverAuth"; usage="digitalSignature" ;;   # mauvais usage : un certificat de serveur présenté comme certificat client
    *) return 1 ;;
  esac
  { echo "[ ext ]"; echo "basicConstraints = CA:FALSE"; echo "keyUsage = $usage"; echo "extendedKeyUsage = $eku"
    echo "subjectKeyIdentifier = hash"; echo "authorityKeyIdentifier = keyid"
    [ -n "$san" ] && echo "subjectAltName = $san"; } > "$out.ext"
  openssl req -new -newkey rsa:2048 -nodes -keyout "$out.key" -out "$out.csr" -subj "/CN=$cn" 2>/dev/null
  [ -n "$start" ] && extra+=(-startdate "$start"); [ -n "$end" ] && extra+=(-enddate "$end") || extra+=(-days 365)
  openssl ca -batch -config "$ca/openssl.cnf" -extfile "$out.ext" -extensions ext -in "$out.csr" -out "$out.pem" -notext "${extra[@]}" 2>/dev/null
}
pki_revoke() { openssl ca -batch -config "$1/openssl.cnf" -revoke "$2" 2>/dev/null; }
pki_crl() {   # CA_DIR OUT [JOURS | expire]
  local opts=(-crldays "${3:-7}")
  [ "${3:-}" = expire ] && opts=(-crl_lastupdate 20200101000000Z -crl_nextupdate 20200108000000Z)
  openssl ca -batch -config "$1/openssl.cnf" -gencrl -crlexts crl_ext "${opts[@]}" -out "$2" 2>/dev/null
}
