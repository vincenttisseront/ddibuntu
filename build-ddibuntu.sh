#!/usr/bin/env bash
# build-ddibuntu.sh — construit l'ISO d'installation automatique DDI-Buntu @@VERSION@@.
#
# Deux modes, un seul code :
#   - DÉPÔT   : lancé depuis une copie du dépôt Git (dossiers src/ et webui/ à côté du script), il lit les fichiers de
#               l'appliance dans ces dossiers. La console web doit être construite : tools/build-console.sh.
#   - FICHIER : le fichier unique de publication (tools/make-single.sh) embarque les mêmes fichiers (archive en fin de script).
# Dans les deux cas il télécharge l'ISO Ubuntu Server 24.04 LTS, vérifie sa somme SHA-256 ET la signature
# Canonical (gpgv) avant d'y toucher, puis produit une ISO hybride BIOS + UEFI.
#
#   macOS / Windows : la construction passe par Docker (Desktop). Linux : natif (root) ou Docker.
#   --makeps1       : génère build-ddibuntu.ps1, lanceur Windows autonome (script embarqué compressé,
#                     empreinte SHA-256 vérifiée au lancement).
#
# Partie « hôte » compatible bash 3.2 (macOS) : pas de tableaux associatifs, pas de mapfile,
# pas de ${var,,}, pas de readlink -f, pas de sed -i.
set -euo pipefail

DDI_VERSION="@@VERSION@@"
UBUNTU_SERIES="24.04"
UBUNTU_BASE_URL="${DDI_UBUNTU_URL:-https://releases.ubuntu.com/${UBUNTU_SERIES}}"
KEYRING="${DDI_KEYRING:-/usr/share/keyrings/ubuntu-archive-keyring.gpg}"
# Empreinte de la clé « Ubuntu CD Image Automatic Signing Key (2012) » : seule signature acceptée.
CD_KEY_FPRS="${DDI_CD_KEY_FPRS:-843938DF228D22F7B3742BC0D94AA3F0EFE21092}"
DOCKER_IMAGE="ubuntu:24.04"
DDI_PACKAGES="nftables whiptail postgresql postgresql-client bind9 bind9-utils bind9-dnsutils kea-dhcp4-server kea-admin python3 open-vm-tools patroni etcd-server etcd-client python3-psycopg2 gnupg openssl curl keepalived"
# Node.js : dernière 22.x, vérifiée par la signature de l'équipe de publication (clés ACTIVES, épinglées par empreinte,
# README de https://github.com/nodejs/release-keys). Une signature par une autre clé est refusée.
NODE_BASE_URL="${DDI_NODE_URL:-https://nodejs.org/dist/latest-v22.x}"
NODE_KEYS_URL="${DDI_NODE_KEYS_URL:-https://raw.githubusercontent.com/nodejs/release-keys/main/keys}"
NODE_KEY_FPRS="${DDI_NODE_FPRS:-5BE8A3F6C8A5C01D106C0AD820B1A390B168D356 DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7 CC68F5A3106FF448322E48ED27F5E38D5B0A215F 890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4 C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C 108F52B48DB57BB0CC439B2997B01419BD92F80A 655F3B5C1FB3FA8D1A0CA6BDE4A7D232B936D2FD A363A499291CBBC940DD62E41F10027AF002F8B0}"
PAYLOAD_MARK="#__DDIBUNTU_PAYLOAD_BELOW__"
SELF="${DDI_SELF:-$0}"

OUT_DIR="$(pwd)"; ISO_IN=""; ISO_SHA=""; ALLOW_UNVERIFIED=0; TIMEOUT=10; SKIP_DEBS=0
FORCE_DOCKER=0; NO_DOCKER=0; IN_CONTAINER=0; MAKEPS1=0; BUNDLE=0; KEEP_WORK=0; SKIP_NODE=0
CA_CERT=""; CA_KEYCHAIN=0; INSECURE_TLS=0; CA_STAGED=""; STAGE_DIR=""

say() { printf '==> %s\n' "$*"; }
warn() { printf 'AVERTISSEMENT : %s\n' "$*" >&2; }
die() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---- Mode dépôt : pas de charge utile embarquée, mais src/ à côté du script ----
SELF_DIR="$(cd "$(dirname "$SELF")" && pwd)"
REPO_MODE=0
if [ -d "$SELF_DIR/src/rootfs" ] && [ -f "$SELF_DIR/src/VERSION" ] && ! grep -q -x -F -- "$PAYLOAD_MARK" "$SELF" 2>/dev/null; then REPO_MODE=1; fi
if [ "$DDI_VERSION" = "@@VERSION@@" ]; then
  [ "$REPO_MODE" = 1 ] || die "version non renseignée et aucun dépôt (src/) à côté du script"
  DDI_VERSION="$(tr -d '\n' < "$SELF_DIR/src/VERSION")"
fi

usage() {
  cat <<'USAGE'
Usage : ./build-ddibuntu.sh [options]
  --out DOSSIER       dossier de sortie (défaut : dossier courant)
  --timeout SECONDES  délai du menu GRUB avant l'installation automatique (défaut 10 ; -1 = attendre)
  --iso FICHIER       utiliser une ISO Ubuntu locale au lieu de la télécharger
  --sha256 EMPREINTE  somme attendue pour --iso (obligatoire sauf --allow-unverified)
  --allow-unverified  accepter une ISO locale sans vérification (tests uniquement)
  --skip-debs         ne pas embarquer de paquets (tests)
  --skip-node         ne pas embarquer Node.js (tests)
  --ca-from-keychain  (macOS) ajoute les certificats de votre trousseau (dont l'autorité de votre entreprise) au conteneur
  --ca-cert FICHIER   ajoute une autorité de certification (PEM) au conteneur, par exemple celle d'un proxy d'entreprise
  --insecure-tls      désactive la vérification TLS des téléchargements (l'intégrité reste vérifiée par signature et empreinte)
  --docker            forcer la construction dans Docker
  --no-docker         forcer la construction native (Linux Ubuntu/Debian, root)
  --makeps1           générer build-ddibuntu.ps1 (lanceur Windows) puis quitter (fichier unique : tools/make-single.sh)
  --stage DOSSIER     (développement) prépare la charge utile depuis le dépôt dans DOSSIER puis quitte
  --bundle            produit ddibuntu-update-<version>.tar.gz (mise à jour en ligne, sans ISO) dans --out puis quitte
  --keep-work         conserver le dossier de travail
  --version           afficher la version
  -h, --help          cette aide
Sortie : ddibuntu-<version>-amd64.iso et son fichier .sha256
USAGE
}

# Tous les téléchargements passent par dlcurl : --insecure-tls n'enlève que la vérification du certificat du SERVEUR ;
# l'ISO Ubuntu, Node et les clés restent vérifiés par signature et empreinte, indépendamment du TLS.
dlcurl() { if [ "$INSECURE_TLS" = 1 ]; then curl -k "$@"; else curl "$@"; fi; }
tls_hint() {
  cat >&2 <<'HINT'

Le certificat du serveur n'a pas pu être vérifié. Causes fréquentes : un proxy d'entreprise qui inspecte le HTTPS (Zscaler, etc.)
dont l'autorité de certification est inconnue du conteneur de construction, ou un réseau Docker Desktop filtré. Solutions, de la plus simple à la moins sûre :
  --ca-from-keychain   (macOS) reprend les certificats de votre trousseau, dont celui de l'entreprise
  --ca-cert FICHIER    ajoute l'autorité de l'entreprise (fichier PEM fourni par votre service informatique)
  --insecure-tls       désactive la vérification TLS des téléchargements : l'intégrité reste garantie (signatures et empreintes
                       vérifiées par le script), seule la confidentialité des téléchargements n'est plus protégée
HINT
}
# dldie CODE_CURL MESSAGE : aide TLS si le code curl est une erreur de certificat (60) ou de négociation (35), puis arrêt
dldie() { local rc="$1"; shift; if [ "$rc" = 60 ] || [ "$rc" = 35 ]; then tls_hint; fi; die "$*"; }
# Ajoute une autorité de certification au magasin du conteneur (jamais sur un poste : uniquement avec --in-container)
install_extra_ca() {   # $1 = fichier PEM
  [ -f "$1" ] || die "autorité de certification introuvable : $1"
  grep -q 'BEGIN CERTIFICATE' "$1" || die "$1 n'est pas un certificat PEM"
  local dir="${DDI_CA_DIR:-/usr/local/share/ca-certificates}"
  mkdir -p "$dir"
  cp "$1" "$dir/ddibuntu-extra.crt"
  update-ca-certificates >/dev/null 2>&1 || die "update-ca-certificates a échoué"
  say "Autorité(s) de certification ajoutée(s) au conteneur de construction"
}
# Côté hôte (Docker) : dépose le PEM dans le dossier de sortie, déjà monté dans le conteneur ; supprimé à la fin.
stage_ca() {   # $1 = dossier de sortie absolu
  CA_STAGED=""
  local dst="$1/.ddibuntu-ca.pem" n
  if [ "$CA_KEYCHAIN" = 1 ]; then
    have security || die "--ca-from-keychain n'existe que sous macOS (commande « security » absente)"
    # certificats seulement (jamais de clé privée) ; un trousseau absent ne doit pas empêcher d'exporter l'autre
    security find-certificate -a -p /Library/Keychains/System.keychain "$HOME/Library/Keychains/login.keychain-db" > "$dst" 2>/dev/null || true
    grep -q 'BEGIN CERTIFICATE' "$dst" 2>/dev/null || { rm -f "$dst"; die "aucun certificat exporté du trousseau macOS"; }
    n="$(grep -c 'BEGIN CERTIFICATE' "$dst")"
    say "Trousseau macOS : $n certificats ajoutés comme autorités de confiance du conteneur de construction (jetable)"
  elif [ -n "$CA_CERT" ]; then
    [ -f "$CA_CERT" ] || die "fichier introuvable : $CA_CERT"
    grep -q 'BEGIN CERTIFICATE' "$CA_CERT" || die "$CA_CERT n'est pas un certificat PEM"
    cp "$CA_CERT" "$dst"
  else
    return 0
  fi
  CA_STAGED="$dst"
  trap 'rm -f "$CA_STAGED"' EXIT
}

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'
  else die "ni sha256sum ni shasum n'est disponible"
  fi
}

b64_decode() { if base64 -d </dev/null >/dev/null 2>&1; then base64 -d; else base64 -D; fi; }

# ---------------------------------------------------------------------------------
# Contenu embarqué
# ---------------------------------------------------------------------------------
# Charge utile construite depuis le dépôt. tools/make-single.sh appelle « --stage » : le fichier unique embarque donc
# EXACTEMENT ce que le mode dépôt lit (un seul chemin de code, vérifié par un test).
repo_stage() {   # $1 = dossier de destination (vide ou inexistant)
  local d="$1" src="$SELF_DIR/src" out="${DDI_CONSOLE_OUTPUT:-$SELF_DIR/webui/.output}"
  [ "$REPO_MODE" = 1 ] || die "cette opération ne s'utilise que depuis un dépôt (dossier src/ à côté du script, sans contenu embarqué)"
  [ -f "$out/server/index.mjs" ] || die "console web non construite ($out) : lancer tools/build-console.sh"
  mkdir -p "$d/console"
  cp -a "$src/rootfs" "$src/iso" "$src/ps1" "$d/"; cp "$src/VERSION" "$d/"
  # Console web construite (nuxt build) : embarquée telle quelle, sous le nom « app »
  tar --sort=name --mtime='@1700000000' --owner=0 --group=0 --numeric-owner --transform 's,^\./,app/,;s,^\.output,app,' -czf "$d/console/console.tar.gz" -C "$out" .
  cp "$src/VERSION" "$d/rootfs/usr/local/lib/ddibuntu/VERSION"
  # /etc/ddibuntu/nftables.nft livré = rendu du pare-feu par défaut (aucun réseau d'administration)
  DDI_LIBDIR="$d/rootfs/usr/local/lib/ddibuntu" DDI_FW_CONF="$d/rootfs/etc/ddibuntu/firewall.conf" DDI_FW_STATE="$d/.fwstate" "$d/rootfs/usr/local/sbin/ddibuntu-fw" render > "$d/rootfs/etc/ddibuntu/nftables.nft"
  # Modes explicites : ne dépendent ni du système de fichiers ni de l'outil d'archive
  find "$d" -type d -exec chmod 0755 {} +
  find "$d" -type f -exec chmod 0644 {} +
  chmod 0755 "$d"/rootfs/usr/local/sbin/ddibuntu-* "$d/rootfs/usr/local/bin/ddibuntu-menu" "$d/iso/late.sh" "$d/iso/update.sh" "$d/rootfs/usr/local/lib/ddibuntu/console-start"
  # Aucune fin de ligne Windows dans ce qui part vers Linux
  if grep -rlI "$(printf '\r')" "$d/rootfs" "$d/iso" "$d/ps1" >/dev/null 2>&1; then die "fins de ligne CRLF détectées dans les sources"; fi
}

payload_extract() {   # $1 = dossier de destination
  local n
  if [ "$REPO_MODE" = 1 ]; then repo_stage "$1"; return 0; fi
  n="$(grep -c -x -F -- "$PAYLOAD_MARK" "$SELF" || true)"
  [ "$n" = "1" ] || die "le marqueur de contenu embarqué doit apparaître une fois (trouvé : $n)"
  mkdir -p "$1"
  awk -v m="$PAYLOAD_MARK" 'f { print } $0 == m { f = 1 }' "$SELF" | b64_decode | tar -xzf - -C "$1"
}

# ---------------------------------------------------------------------------------
# Lanceur Windows
# ---------------------------------------------------------------------------------
make_ps1() {
  local work tpl out sha b64
  [ "$REPO_MODE" = 0 ] || die "--makeps1 s'applique au fichier unique : lancer tools/make-single.sh puis dist/build-ddibuntu.sh --makeps1"
  work="$(mktemp -d "${TMPDIR:-/tmp}/ddibuntu-ps1.XXXXXX")"
  payload_extract "$work"
  tpl="$work/ps1/launcher.ps1.in"
  [ -f "$tpl" ] || die "modèle PowerShell absent du contenu embarqué"
  sha="$(sha256_of "$SELF")"
  b64="$(gzip -9 -n -c "$SELF" | base64 | tr -d '\n' | fold -w 100)"
  out="$OUT_DIR/build-ddibuntu.ps1"
  mkdir -p "$OUT_DIR"
  : > "$out"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "@@B64@@") printf '%s\n' "$b64" >> "$out" ;;
      *) line="${line//@@SHA256@@/$sha}"; line="${line//@@VERSION@@/$DDI_VERSION}"; printf '%s\n' "$line" >> "$out" ;;
    esac
  done < "$tpl"
  rm -rf "$work"
  say "Lanceur Windows : $out"
  say "Empreinte SHA-256 du script embarqué : $sha"
}

# ---------------------------------------------------------------------------------
# Docker (macOS, Windows via le .ps1, Linux sans root)
# ---------------------------------------------------------------------------------
run_in_docker() {
  have docker || die "Docker est requis sur ce poste : installez Docker Desktop (macOS, Windows) ou Docker Engine (Linux)"
  docker info >/dev/null 2>&1 || die "Docker est installé mais ne répond pas : démarrez Docker Desktop puis relancez"
  local self_dir self_name out_abs extra=""
  self_dir="$(cd "$(dirname "$SELF")" && pwd)"; self_name="$(basename "$SELF")"
  mkdir -p "$OUT_DIR"; out_abs="$(cd "$OUT_DIR" && pwd)"
  [ -z "$ISO_SHA" ] || extra="$extra --sha256 $ISO_SHA"
  [ "$ALLOW_UNVERIFIED" = 0 ] || extra="$extra --allow-unverified"
  [ "$SKIP_DEBS" = 0 ] || extra="$extra --skip-debs"
  [ "$SKIP_NODE" = 0 ] || extra="$extra --skip-node"
  [ "$INSECURE_TLS" = 0 ] || extra="$extra --insecure-tls"
  stage_ca "$out_abs"
  [ -z "$CA_STAGED" ] || extra="$extra --ca-cert /ddi-out/.ddibuntu-ca.pem"
  say "Construction dans Docker ($DOCKER_IMAGE, plateforme linux/amd64 ; émulée, donc plus lente, sur un Mac Apple Silicon)"
  if [ -n "$ISO_IN" ]; then
    # shellcheck disable=SC2086  # $extra : options sans espaces, découpées volontairement
    docker run --rm --platform linux/amd64 -e DDI_HOST_UID="$(id -u)" -e DDI_HOST_GID="$(id -g)" \
      -v "$self_dir:/ddi-src:ro" -v "$out_abs:/ddi-out" -v "$(cd "$(dirname "$ISO_IN")" && pwd):/ddi-iso:ro" \
      "$DOCKER_IMAGE" bash "/ddi-src/$self_name" --in-container --out /ddi-out --timeout "$TIMEOUT" \
      --iso "/ddi-iso/$(basename "$ISO_IN")" $extra
  else
    # shellcheck disable=SC2086
    docker run --rm --platform linux/amd64 -e DDI_HOST_UID="$(id -u)" -e DDI_HOST_GID="$(id -g)" \
      -v "$self_dir:/ddi-src:ro" -v "$out_abs:/ddi-out" \
      "$DOCKER_IMAGE" bash "/ddi-src/$self_name" --in-container --out /ddi-out --timeout "$TIMEOUT" $extra
  fi
}

# ---------------------------------------------------------------------------------
# Vérifications d'intégrité (fonctions isolées pour être testées seules)
# ---------------------------------------------------------------------------------
# $1 = SHA256SUMS, $2 = SHA256SUMS.gpg. Échoue si la signature est absente, invalide,
# ou faite par une autre clé que celle de Canonical attendue.
verify_sums_signature() {
  local out fpr ok=0
  [ -f "$KEYRING" ] || die "trousseau Ubuntu introuvable : $KEYRING (paquet ubuntu-keyring)"
  out="$(gpgv --keyring "$KEYRING" --status-fd 1 "$2" "$1" 2>/dev/null)" || die "signature de SHA256SUMS INVALIDE : l'ISO ne sera pas utilisée"
  for fpr in $CD_KEY_FPRS; do
    if printf '%s\n' "$out" | grep -q "^\[GNUPG:\] VALIDSIG .* $fpr\$"; then ok=1; fi
  done
  [ "$ok" = 1 ] || die "SHA256SUMS signé par une clé inattendue (attendu : $CD_KEY_FPRS)"
  say "Signature Canonical valide (clé $CD_KEY_FPRS)"
}

# $1 = SHA256SUMS, $2 = motif de nom. Écrit le nom du fichier retenu.
# Canonical garde plusieurs versions dans le même SHA256SUMS signé (24.04.3, 24.04.4, 24.04.5…) : la plus récente est retenue
# (comparaison numérique composant par composant : 24.04.10 > 24.04.9, 24.04.5.1 > 24.04.5). Avec plusieurs candidats, tout nom qui
# n'a pas la forme ubuntu-<version>-… est refusé plutôt que deviné. Aucun candidat : refus.
select_iso_name() {
  local names n best
  names="$(awk -v pat="$2" '{ f = $2; sub(/^\*/, "", f); if (f ~ pat) print f }' "$1")"
  n="$(printf '%s\n' "$names" | grep -c . || true)"
  [ "$n" != "0" ] || die "SHA256SUMS : aucun fichier ne correspond à « $2 »"
  if [ "$n" = "1" ]; then printf '%s\n' "$names"; return 0; fi
  best="$(printf '%s\n' "$names" | awk '
    function newer(a, b,   x, y, i, m) {
      m = split(a, x, "."); i = split(b, y, "."); if (i > m) m = i
      for (i = 1; i <= m; i++) if ((x[i] + 0) != (y[i] + 0)) return (x[i] + 0) > (y[i] + 0)
      return 0
    }
    { if ($0 !~ /^ubuntu-[0-9]+([.][0-9]+)*-/) { if (bad == "") bad = $0; next }
      v = $0; sub(/^ubuntu-/, "", v); sub(/-.*$/, "", v)
      if (pick == "" || newer(v, pv)) { pick = $0; pv = v } }
    END { if (bad != "") print "BAD " bad; else print "OK " pick }')"
  case "$best" in
    "BAD "*) die "SHA256SUMS : plusieurs fichiers correspondent à « $2 » et l'un a un nom inattendu (${best#BAD }) : refus de choisir" ;;
  esac
  say "SHA256SUMS : $n ISO correspondent ; la plus récente est retenue : ${best#OK }" >&2
  printf '%s\n' "${best#OK }"
}

sums_hash_for() {     # $1 = SHA256SUMS, $2 = nom exact
  awk -v n="$2" '{ f = $2; sub(/^\*/, "", f); if (f == n) { print $1; exit } }' "$1"
}

fetch_iso() {         # $1 = dossier de cache ; écrit le chemin de l'ISO vérifiée
  local cache="$1" sums sig name want got
  mkdir -p "$cache"
  sums="$cache/SHA256SUMS"; sig="$cache/SHA256SUMS.gpg"
  say "Téléchargement de SHA256SUMS et de sa signature"
  dlcurl -fsSL --retry 3 -o "$sums" "$UBUNTU_BASE_URL/SHA256SUMS" || dldie $? "téléchargement de SHA256SUMS impossible ($UBUNTU_BASE_URL)"
  dlcurl -fsSL --retry 3 -o "$sig" "$UBUNTU_BASE_URL/SHA256SUMS.gpg" || dldie $? "téléchargement de SHA256SUMS.gpg impossible"
  verify_sums_signature "$sums" "$sig"
  name="${DDI_ISO_NAME:-$(select_iso_name "$sums" 'live-server-amd64[.]iso$')}"
  want="$(sums_hash_for "$sums" "$name")"
  [ -n "$want" ] || die "$name absent de SHA256SUMS"
  if [ -f "$cache/$name" ] && [ "$(sha256_of "$cache/$name")" = "$want" ]; then
    say "ISO déjà présente et vérifiée : $name"
  else
    say "Téléchargement de $name"
    dlcurl -fL --retry 3 -C - -o "$cache/$name" "$UBUNTU_BASE_URL/$name" || dldie $? "téléchargement de l'ISO impossible"
    got="$(sha256_of "$cache/$name")"
    [ "$got" = "$want" ] || { rm -f "$cache/$name"; die "somme SHA-256 de $name incorrecte (attendu $want, obtenu $got)"; }
  fi
  ISO_PATH="$cache/$name"; ISO_NAME="$name"; ISO_HASH="$want"
}

# ---------------------------------------------------------------------------------
# Construction native
# ---------------------------------------------------------------------------------
ensure_tools() {
  local missing="" t
  for t in xorriso gpgv gpg curl openssl tar gzip awk base64 sha256sum apt-get; do have "$t" || missing="$missing $t"; done
  [ -f "$KEYRING" ] || missing="$missing ubuntu-keyring"
  [ -z "$missing" ] && return 0
  if [ "$IN_CONTAINER" = 1 ] && have apt-get; then
    say "Installation des outils de construction dans le conteneur"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends xorriso gpgv gnupg ubuntu-keyring curl ca-certificates openssl >/dev/null
  else
    die "outils manquants :$missing — sous Ubuntu/Debian : apt-get install xorriso gpgv ubuntu-keyring curl openssl (ou utiliser Docker)"
  fi
}

# Trousseau limité aux clés de publication Node ÉPINGLÉES : chaque clé téléchargée doit avoir l'empreinte attendue.
build_node_keyring() {   # $1 = dossier de travail ; positionne NODE_GNUPGHOME
  local d="$1" fpr got
  NODE_GNUPGHOME="$d/gnupg"; mkdir -p "$NODE_GNUPGHOME"; chmod 700 "$NODE_GNUPGHOME"
  for fpr in $NODE_KEY_FPRS; do
    dlcurl -fsSL --retry 3 -o "$d/$fpr.asc" "$NODE_KEYS_URL/$fpr.asc" || dldie $? "clé de publication Node introuvable : $fpr"
    got="$(gpg --homedir "$NODE_GNUPGHOME" --batch --show-keys --with-colons "$d/$fpr.asc" 2>/dev/null | awk -F: '$1=="pub"{p=1;next} $1=="fpr"&&p{print $10; p=0}')"
    [ "$got" = "$fpr" ] || die "la clé téléchargée pour $fpr porte l'empreinte « $got » : refus"
    gpg --homedir "$NODE_GNUPGHOME" --batch --quiet --import "$d/$fpr.asc" 2>/dev/null || die "import de la clé $fpr impossible"
  done
}
# $1 = SHASUMS256.txt.asc (signature en clair), $2 = sortie : SHASUMS256.txt, SEULEMENT le contenu signé.
verify_node_sums() {
  local st fpr ok=0
  st="$(gpg --homedir "$NODE_GNUPGHOME" --batch --status-fd 1 --output "$2" --decrypt "$1" 2>/dev/null)" || { rm -f "$2"; die "signature de SHASUMS256.txt (Node) INVALIDE : Node ne sera pas utilisé"; }
  for fpr in $NODE_KEY_FPRS; do
    if printf '%s\n' "$st" | grep -q "^\[GNUPG:\] VALIDSIG .* $fpr\$"; then ok=1; fi
  done
  [ "$ok" = 1 ] || { rm -f "$2"; die "SHASUMS256.txt (Node) signé par une clé hors de la liste épinglée"; }
  say "Signature Node valide (clé épinglée)"
}
fetch_node() {           # $1 = dossier de cache ; positionne NODE_TGZ NODE_NAME NODE_HASH
  local cache="$1" w sums name want got
  w="$(mktemp -d "${TMPDIR:-/tmp}/ddibuntu-node.XXXXXX")"
  say "Téléchargement de la signature des sommes Node"
  dlcurl -fsSL --retry 3 -o "$w/SHASUMS256.txt.asc" "$NODE_BASE_URL/SHASUMS256.txt.asc" || dldie $? "téléchargement de SHASUMS256.txt.asc impossible ($NODE_BASE_URL)"
  build_node_keyring "$w"
  sums="$w/SHASUMS256.txt"
  verify_node_sums "$w/SHASUMS256.txt.asc" "$sums"
  name="$(select_iso_name "$sums" 'node-v[0-9.]+-linux-x64[.]tar[.]gz$')"
  want="$(sums_hash_for "$sums" "$name")"
  [ -n "$want" ] || die "$name absent de SHASUMS256.txt"
  mkdir -p "$cache"
  if [ -f "$cache/$name" ] && [ "$(sha256_of "$cache/$name")" = "$want" ]; then
    say "Node déjà présent et vérifié : $name"
  else
    say "Téléchargement de $name"
    dlcurl -fL --retry 3 -o "$cache/$name" "$NODE_BASE_URL/$name" || dldie $? "téléchargement de Node impossible"
    got="$(sha256_of "$cache/$name")"
    [ "$got" = "$want" ] || { rm -f "$cache/$name"; die "somme SHA-256 de $name incorrecte (attendu $want, obtenu $got)"; }
  fi
  NODE_TGZ="$cache/$name"; NODE_NAME="$name"; NODE_HASH="$want"
  rm -rf "$w"
}

fetch_debs() {        # $1 = dossier de destination. Résolution relative à l'image de base courante.
  local d="$1"
  export DEBIAN_FRONTEND=noninteractive
  mkdir -p "$d/partial"
  # Les miroirs Ubuntu (surtout security.ubuntu.com) sont parfois en cours de synchronisation : l'index annonce un paquet
  # que le pool n'a pas encore (404). On réessaie avec un index rafraîchi avant d'abandonner.
  local try=1
  while :; do
    apt-get update -qq -o Acquire::Retries=3
    # shellcheck disable=SC2086  # DDI_PACKAGES est une liste de noms de paquets
    if apt-get install -y -qq --download-only --no-install-recommends -o Acquire::Retries=3 \
      -o APT::Sandbox::User=root -o Dir::Cache::archives="$d" -o APT::Keep-Downloaded-Packages=1 $DDI_PACKAGES >/dev/null; then
      break
    fi
    [ "$try" -lt 4 ] || die "téléchargement des paquets impossible après $try essais (miroir Ubuntu incohérent : réessayez plus tard)"
    warn "téléchargement des paquets échoué (essai $try/4) ; nouvel essai dans 30 s avec un index rafraîchi"
    try=$((try + 1)); sleep 30; rm -rf /var/lib/apt/lists/*
  done
  rm -rf "$d/partial" "$d/lock"
  ls "$d"/*.deb >/dev/null 2>&1 || die "aucun paquet téléchargé : la liste « $DDI_PACKAGES » est peut-être déjà installée sur cette machine (utiliser Docker)"
  ( cd "$d" && sha256sum ./*.deb | sed 's| \./| |' > SHA256SUMS )
}

build_native() {
  if have dpkg && [ "$(dpkg --print-architecture)" != "amd64" ]; then
    die "la construction doit tourner en amd64 (ici : $(dpkg --print-architecture)) : les paquets embarqués seraient inutilisables. Avec Docker, utiliser --platform linux/amd64 (fait automatiquement par ce script)."
  fi
  # Les paquets de l'appliance sont résolus AVANT l'installation des outils de construction, dans le conteneur encore
  # « propre » : sinon les bibliothèques tirées par curl, xorriso… (libldap2, etc.) manqueraient à la fermeture de
  # dépendances alors qu'un Ubuntu Server minimal ne les a pas forcément (défaut constaté sur un système cible réel).
  EARLY_DEBS=""
  if [ "$IN_CONTAINER" = 1 ] && [ "$SKIP_DEBS" = 0 ]; then
    EARLY_DEBS="$(mktemp -d "${TMPDIR:-/tmp}/ddibuntu-debs.XXXXXX")"
    say "Paquets embarqués : $DDI_PACKAGES (résolution dans le conteneur propre)"
    fetch_debs "$EARLY_DEBS"
  fi
  ensure_tools
  have openssl || die "openssl est requis"
  if [ "$IN_CONTAINER" = 1 ] && [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then die "le magasin de certificats du conteneur est vide (ca-certificates)"; fi
  if [ -n "$CA_CERT" ]; then
    [ "$IN_CONTAINER" = 1 ] || die "--ca-cert n'est géré que dans le conteneur Docker (le magasin de votre poste n'est jamais modifié)"
    install_extra_ca "$CA_CERT"
  fi
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/ddibuntu-build.XXXXXX")"
  mkdir -p "$OUT_DIR"
  # un échec ne laisse jamais d'ISO au nom définitif : écriture dans un fichier temporaire
  trap 'rm -f "$OUT_DIR"/.ddibuntu-*.partial; if [ "$KEEP_WORK" = 0 ]; then rm -rf "$WORK"; fi' EXIT
  local cache="$OUT_DIR/.ddibuntu-cache" payload="$WORK/payload" iso="$WORK/iso/ddibuntu" hash tmpl content f

  say "DDI-Buntu $DDI_VERSION — dossier de travail : $WORK"
  payload_extract "$payload"

  # --- ISO Ubuntu de départ : vérifiée avant toute utilisation ---
  if [ -n "$ISO_IN" ]; then
    [ -f "$ISO_IN" ] || die "ISO introuvable : $ISO_IN"
    if [ -n "$ISO_SHA" ]; then
      [ "$(sha256_of "$ISO_IN")" = "$ISO_SHA" ] || die "somme SHA-256 de l'ISO fournie incorrecte"
    elif [ "$ALLOW_UNVERIFIED" = 1 ]; then
      warn "ISO locale NON vérifiée (--allow-unverified) : ne pas diffuser le résultat"
    else
      die "--iso exige --sha256 (ou --allow-unverified pour des tests)"
    fi
    ISO_PATH="$ISO_IN"; ISO_NAME="$(basename "$ISO_IN")"; ISO_HASH="$(sha256_of "$ISO_IN")"
  else
    fetch_iso "$cache"
  fi

  # --- Fichiers propres à l'ISO (/ddibuntu) ---
  mkdir -p "$iso"
  ( cd "$payload" && tar --sort=name --mtime='@1700000000' --owner=0 --group=0 --numeric-owner -cf "$iso/rootfs.tar" -C rootfs . )
  ( cd "$iso" && sha256sum rootfs.tar > rootfs.tar.sha256 )
  cp "$payload/iso/late.sh" "$payload/iso/update.sh" "$payload/iso/meta-data" "$iso/"
  chmod 0755 "$iso/late.sh" "$iso/update.sh"
  printf '%s\n' "$DDI_VERSION" > "$iso/VERSION"
  # mot de passe du compte d'installation : aléatoire, jamais affiché ni conservé (l'assistant le supprime)
  hash="$(openssl rand -base64 33 | openssl passwd -6 -stdin)"
  tmpl="$(cat "$payload/iso/user-data.tmpl")"
  content="${tmpl//@@PASSHASH@@/$hash}"; content="${content//@@VERSION@@/$DDI_VERSION}"
  printf '%s\n' "$content" > "$iso/user-data"
  chmod 0600 "$iso/user-data"
  # mode « mise à jour » : graine cloud-init distincte (aucun secret, aucune étape de stockage)
  mkdir -p "$iso/update"
  cp "$payload/iso/meta-data" "$iso/update/meta-data"
  tmpl="$(cat "$payload/iso/user-data-update.tmpl")"
  printf '%s\n' "${tmpl//@@VERSION@@/$DDI_VERSION}" > "$iso/update/user-data"
  if [ "$SKIP_DEBS" = 0 ]; then
    if [ -n "$EARLY_DEBS" ]; then
      mkdir -p "$iso/debs"; cp -a "$EARLY_DEBS"/. "$iso/debs"/; rm -rf "$EARLY_DEBS"
    else
      warn "résolution des paquets relative à CET hôte, pas à un système propre : utiliser Docker pour une ISO reproductible"
      say "Paquets embarqués : $DDI_PACKAGES"
      fetch_debs "$iso/debs"
    fi
  fi
  # console web (construite, embarquée dans ce script) et Node.js vérifié
  cp "$payload/console/console.tar.gz" "$iso/console.tar.gz"
  local sumfiles="console.tar.gz"
  if [ "$SKIP_NODE" = 0 ]; then
    fetch_node "$cache"
    cp "$NODE_TGZ" "$iso/node-linux-x64.tar.gz"; sumfiles="$sumfiles node-linux-x64.tar.gz"
  else
    warn "Node.js non embarqué (--skip-node) : la console ne démarrera pas sur cette ISO"
  fi
  # shellcheck disable=SC2086  # liste de noms de fichiers sans espaces
  ( cd "$iso" && sha256sum $sumfiles > payloads.sha256 )
  {
    printf 'DDI-Buntu %s\nconstruit le %s\nISO de base : %s\nSHA-256 base : %s\n' "$DDI_VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ISO_NAME" "$ISO_HASH"
    if [ "$SKIP_NODE" = 0 ]; then printf 'Node.js : %s (SHA-256 %s, signature vérifiée)\n' "$NODE_NAME" "$NODE_HASH"; fi
    if [ -d "$iso/debs" ]; then
      printf 'paquets embarqués :\n'
      for f in "$iso"/debs/*.deb; do printf '  %s\n' "${f##*/}"; done
    fi
  } > "$iso/MANIFEST.txt"

  # --- Menu GRUB : l'entrée automatique est insérée avant la première entrée d'origine ---
  say "Lecture et modification de /boot/grub/grub.cfg"
  xorriso -osirrox on -indev "$ISO_PATH" -extract /boot/grub/grub.cfg "$WORK/grub.orig" >/dev/null 2>&1 || die "/boot/grub/grub.cfg absente de l'ISO de base"
  xorriso -indev "$ISO_PATH" -find /casper -name 'vmlinuz' 2>/dev/null | grep -q vmlinuz || die "/casper/vmlinuz absent de l'ISO de base : version d'Ubuntu inattendue"
  xorriso -indev "$ISO_PATH" -find /casper -name 'initrd' 2>/dev/null | grep -q initrd || die "/casper/initrd absent de l'ISO de base"
  patch_grub "$WORK/grub.orig" "$WORK/grub.cfg"

  # --- Écriture de l'ISO hybride (BIOS + UEFI conservés par « replay ») ---
  local out="$OUT_DIR/ddibuntu-${DDI_VERSION}-amd64.iso" part="$OUT_DIR/.ddibuntu-${DDI_VERSION}-amd64.iso.partial"
  rm -f "$part"
  say "Écriture de $out"
  xorriso -indev "$ISO_PATH" -outdev "$part" -overwrite on \
    -boot_image any replay \
    -map "$iso" /ddibuntu \
    -map "$WORK/grub.cfg" /boot/grub/grub.cfg \
    -commit >"$WORK/xorriso.log" 2>&1 || { tail -20 "$WORK/xorriso.log" >&2; die "xorriso a échoué"; }

  verify_iso "$part" "$iso"
  rm -f "$out" "$out.sha256"
  mv -f "$part" "$out"
  ( cd "$OUT_DIR" && sha256_of "$out" | awk -v f="$(basename "$out")" '{print $1 "  " f}' > "$out.sha256" )
  if [ -n "${DDI_HOST_UID:-}" ]; then chown -R "$DDI_HOST_UID:${DDI_HOST_GID:-$DDI_HOST_UID}" "$OUT_DIR" 2>/dev/null || warn "droits du dossier de sortie non ajustés"; fi
  say "ISO prête : $out"
  say "SHA-256  : $(cut -d' ' -f1 "$out.sha256")"
}

# Archive de mise à jour en ligne : MÊMES rootfs.tar et console.tar.gz que l'ISO (un seul chemin de code), sans Ubuntu,
# sans paquets ni Node. Elle est signée à la publication (SHA256SUMS + Ed25519, voir docs/RELEASING.md).
make_bundle() {
  local w p b out
  w="$(mktemp -d "${TMPDIR:-/tmp}/ddibuntu-bundle.XXXXXX")"; p="$w/payload"; b="$w/b"
  payload_extract "$p"
  mkdir -p "$b" "$OUT_DIR"
  ( cd "$p" && tar --sort=name --mtime='@1700000000' --owner=0 --group=0 --numeric-owner -cf "$b/rootfs.tar" -C rootfs . )
  ( cd "$b" && sha256sum rootfs.tar > rootfs.tar.sha256 )
  cp "$p/console/console.tar.gz" "$b/console.tar.gz"
  printf '%s\n' "$DDI_VERSION" > "$b/VERSION"
  out="$(cd "$OUT_DIR" && pwd)/ddibuntu-update-${DDI_VERSION}.tar.gz"
  ( cd "$b" && tar --sort=name --mtime='@1700000000' --owner=0 --group=0 --numeric-owner -czf "$out" rootfs.tar rootfs.tar.sha256 console.tar.gz VERSION )
  rm -rf "$w"
  say "Archive de mise à jour : $out"
}

# Insère l'entrée DDI-Buntu avant la première entrée du menu et force default/timeout.
# $1 = grub.cfg d'origine, $2 = destination. Échoue si aucune entrée « menuentry » n'est trouvée.
patch_grub() {
  local entry
  entry="$(cat <<EOF
set default=0
set timeout=${TIMEOUT}
set timeout_style=menu
menuentry "Install DDI-Buntu ${DDI_VERSION} (automatic - ERASES the target disk)" {
	set gfxpayload=keep
	linux	/casper/vmlinuz autoinstall ds=nocloud\\;s=/cdrom/ddibuntu/ ---
	initrd	/casper/initrd
}
menuentry "Update an existing DDI-Buntu installation to ${DDI_VERSION} (keeps data, never erases the disk)" {
	set gfxpayload=keep
	linux	/casper/vmlinuz autoinstall ds=nocloud\\;s=/cdrom/ddibuntu/update/ ---
	initrd	/casper/initrd
}
EOF
)"
  # l'entrée passe par un fichier (getline) : « awk -v » interpréterait les antislash de « \; »
  printf '%s\n' "$entry" > "$2.entry"
  awk -v ef="$2.entry" '
    !done && /^[[:space:]]*menuentry[[:space:]]/ { while ((getline l < ef) > 0) print l; close(ef); done = 1 }
    { print }
    END { if (!done) exit 3 }
  ' "$1" > "$2" || die "aucune entrée « menuentry » dans grub.cfg : format inattendu, rien n'a été modifié"
  rm -f "$2.entry"
}

# Contrôles après construction : démarrage BIOS et UEFI conservés, fichiers présents et identiques.
verify_iso() {        # $1 = ISO produite, $2 = dossier /ddibuntu source
  local iso="$1" src="$2" tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/ddibuntu-verify.XXXXXX")"
  xorriso -indev "$iso" -report_el_torito plain >"$tmp/eltorito.txt" 2>/dev/null || true
  grep -q ' BIOS ' "$tmp/eltorito.txt" || die "contrôle : l'ISO produite n'a plus d'entrée de démarrage BIOS"
  grep -q ' UEFI ' "$tmp/eltorito.txt" || die "contrôle : l'ISO produite n'a plus d'entrée de démarrage UEFI"
  xorriso -osirrox on -indev "$iso" -extract /ddibuntu "$tmp/ddibuntu" -extract /boot/grub/grub.cfg "$tmp/grub.cfg" >/dev/null 2>&1 || die "contrôle : extraction impossible"
  local f
  for f in rootfs.tar rootfs.tar.sha256 late.sh update.sh user-data meta-data update/user-data update/meta-data VERSION MANIFEST.txt console.tar.gz payloads.sha256; do
    [ -f "$tmp/ddibuntu/$f" ] || die "contrôle : /ddibuntu/$f absent de l'ISO"
    cmp -s "$tmp/ddibuntu/$f" "$src/$f" || die "contrôle : /ddibuntu/$f différent de la source"
  done
  grep -q 'ds=nocloud\\;s=/cdrom/ddibuntu/ ---' "$tmp/grub.cfg" || die "contrôle : l'entrée automatique est absente de grub.cfg"
  grep -q 'ds=nocloud\\;s=/cdrom/ddibuntu/update/' "$tmp/grub.cfg" || die "contrôle : l'entrée de mise à jour est absente de grub.cfg"
  grep -q 'update.sh' "$tmp/ddibuntu/update/user-data" || die "contrôle : la graine de mise à jour n'appelle pas update.sh"
  say "Contrôles : démarrage BIOS et UEFI conservés, fichiers identiques"
  rm -rf "$tmp"
}

# ---------------------------------------------------------------------------------
main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --out) OUT_DIR="${2:?--out attend un dossier}"; shift ;;
      --timeout) TIMEOUT="${2:?--timeout attend un nombre}"; shift ;;
      --iso) ISO_IN="${2:?--iso attend un fichier}"; shift ;;
      --sha256) ISO_SHA="${2:?--sha256 attend une empreinte}"; shift ;;
      --allow-unverified) ALLOW_UNVERIFIED=1 ;;
      --skip-debs) SKIP_DEBS=1 ;;
      --skip-node) SKIP_NODE=1 ;;
      --ca-from-keychain) CA_KEYCHAIN=1 ;;
      --ca-cert) CA_CERT="${2:?--ca-cert attend un fichier PEM}"; shift ;;
      --insecure-tls) INSECURE_TLS=1 ;;
      --docker) FORCE_DOCKER=1 ;;
      --no-docker) NO_DOCKER=1 ;;
      --in-container) IN_CONTAINER=1 ;;
      --makeps1) MAKEPS1=1 ;;
      --stage) STAGE_DIR="${2:?--stage attend un dossier}"; shift ;;
      --bundle) BUNDLE=1 ;;
      --keep-work) KEEP_WORK=1 ;;
      --version) printf 'DDI-Buntu %s\n' "$DDI_VERSION"; exit 0 ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "option inconnue : $1" ;;
    esac
    shift
  done
  case "$TIMEOUT" in -1|[0-9]|[0-9][0-9]|[0-9][0-9][0-9]) ;; *) die "--timeout attend -1 ou un nombre de secondes (0 à 999)" ;; esac

  if [ "$MAKEPS1" = 1 ]; then make_ps1; exit 0; fi
  if [ -n "$STAGE_DIR" ]; then repo_stage "$STAGE_DIR"; say "Charge utile préparée : $STAGE_DIR"; exit 0; fi
  if [ "$BUNDLE" = 1 ]; then make_bundle; exit 0; fi

  local os
  os="$(uname -s)"
  if [ "$IN_CONTAINER" = 1 ] || [ "$NO_DOCKER" = 1 ]; then
    [ "$(id -u)" = 0 ] || die "la construction native demande les droits root (sudo)"
    build_native
  elif [ "$FORCE_DOCKER" = 1 ] || [ "$os" != "Linux" ]; then
    run_in_docker
  elif [ "$(id -u)" = 0 ] && [ -f /etc/os-release ] && grep -qiE '^ID(_LIKE)?=.*(ubuntu|debian)' /etc/os-release; then
    build_native
  else
    run_in_docker
  fi
}

if [ "${DDI_BUILD_SOURCE_ONLY:-0}" != 1 ]; then
  main "$@"
  exit 0
fi
# shellcheck disable=SC2317  # atteint seulement quand le fichier est sourcé (tests)
return 0 2>/dev/null || exit 0
