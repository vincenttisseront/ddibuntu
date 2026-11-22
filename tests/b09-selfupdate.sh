#!/usr/bin/env bash
# Batterie 09 — mise à jour en ligne (ddibuntu-selfupdate) contre un FAUX GitHub local (serveur HTTP) avec de vraies
# signatures Ed25519 : détection, notes, demandes hostiles, signature invalide, archive altérée, retour arrière si la
# console ne redémarre pas, installation réussie (données, pare-feu et réglages conservés), hors-ligne.
# Ne demande ni root ni systemd (DDI_TEST=1, DDI_NO_SYSTEMD=1, DDI_ROOT).
set -u
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
for t in openssl python3 curl flock; do command -v "$t" >/dev/null 2>&1 || { ko "outil requis absent : $t"; finish; exit; }; done
SU="$RFS/usr/local/sbin/ddibuntu-selfupdate"
COMMON="$RFS/usr/local/lib/ddibuntu/common.sh"
W="$T_TMP/w"; mkdir -p "$W"
R=$W/root; SRV=$W/srv; PORT=$((20000 + RANDOM % 20000))
mk() { mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; chmod "${3:-644}" "$1"; }
jget() { python3 -c "import json,sys; d=json.load(open('$1')); v=d.get('$2'); print(v if not isinstance(v,bool) else str(v).lower())" 2>/dev/null; }
openssl genpkey -algorithm ed25519 -out "$W/priv.pem" 2>/dev/null; openssl pkey -in "$W/priv.pem" -pubout -out "$W/pub.pem"
openssl genpkey -algorithm ed25519 -out "$W/evil.pem" 2>/dev/null

echo "== Système simulé 0.4.0 =="
mk "$R/usr/local/lib/ddibuntu/VERSION" 0.4.0; cp "$COMMON" "$R/usr/local/lib/ddibuntu/common.sh"
mk "$R/etc/ddibuntu/update.conf" 'REPO="acme/ddibuntu"'
mk "$R/usr/local/lib/ddibuntu/update-packages" "podman freeradius freeradius-ldap freeradius-rest winbind samba-common-bin"
cp "$W/pub.pem" "$R/etc/ddibuntu/update-pubkey.pem"
mk "$R/etc/ddibuntu/firewall.conf" 'ADMIN_NETS="10.1.0.0/16"'
mk "$R/etc/ddibuntu/nftables.nft" "REGLES ADMIN"
mk "$R/opt/ddibuntu/console/app/server/index.mjs" "OLD CONSOLE"
mk "$R/var/lib/ddibuntu/installed-version" 0.4.0
mk "$R/var/lib/ddibuntu/pgdata-marker" "DONNEES"
# shellcheck disable=SC2016  # le $1 du stub doit rester littéral
mk "$R/usr/local/sbin/ddibuntu-fw" '#!/bin/bash
echo "$1" > "$(dirname "$0")/../../../etc/ddibuntu/fw-called"' 755
mkdir -p "$R/run" "$SRV/dl"

mkrelease() { # version signing-key [dossier debs à embarquer]
  local v="$1" key="$2" d="$W/rel-$1" members="rootfs.tar rootfs.tar.sha256 console.tar.gz VERSION"; rm -rf "$d"; mkdir -p "$d/rootfs/usr/local/lib/ddibuntu" "$d/rootfs/etc/ddibuntu" "$d/rootfs/usr/local/sbin" "$d/con/app/server" "$d/b"
  echo "$v" > "$d/rootfs/usr/local/lib/ddibuntu/VERSION"; echo "NEW CONSOLE $v" > "$d/con/app/server/index.mjs"
  echo 'ADMIN_NETS=""' > "$d/rootfs/etc/ddibuntu/firewall.conf"; echo "REGLES DEFAUT" > "$d/rootfs/etc/ddibuntu/nftables.nft"; echo "NOUVEAU $v" > "$d/rootfs/etc/ddibuntu/nouveau.txt"
  cp "$R/usr/local/sbin/ddibuntu-fw" "$d/rootfs/usr/local/sbin/"; chmod 755 "$d/rootfs/usr/local/sbin/ddibuntu-fw"
  ( cd "$d/rootfs" && tar --owner=0 --group=0 -cf "$d/b/rootfs.tar" . ) ; ( cd "$d/b" && sha256sum rootfs.tar > rootfs.tar.sha256 )
  ( cd "$d/con" && tar -czf "$d/b/console.tar.gz" . ); echo "$v" > "$d/b/VERSION"
  if [[ -n "${3:-}" ]]; then cp -a "$3" "$d/b/debs"; members="$members debs"; fi
  # shellcheck disable=SC2086  # $members : liste de noms sans espace ni joker
  ( cd "$d/b" && tar -czf "$SRV/dl/ddibuntu-update-$v.tar.gz" $members )
  ( cd "$SRV/dl" && sha256sum "ddibuntu-update-$v.tar.gz" > SHA256SUMS )
  openssl pkeyutl -sign -inkey "$key" -rawin -in "$SRV/dl/SHA256SUMS" -out "$SRV/dl/SHA256SUMS.sig"
  mkdir -p "$SRV/repos/acme/ddibuntu/releases"
  python3 - "$SRV/repos/acme/ddibuntu/releases/latest" "$v" "$PORT" <<'PY'
import json, sys
p, v, port = sys.argv[1:4]
base = 'http://127.0.0.1:%s/dl/' % port
json.dump({'tag_name': 'v' + v, 'html_url': 'https://github.com/acme/ddibuntu/releases/tag/v' + v, 'published_at': '2026-11-10T10:00:00Z',
           'body': 'Notes de version %s\n- changement A\n- changement B' % v, 'draft': False, 'prerelease': False,
           'assets': [{'name': n, 'url': base + n} for n in ['ddibuntu-update-%s.tar.gz' % v, 'SHA256SUMS', 'SHA256SUMS.sig']]}, open(p, 'w'))
PY
}
( cd "$SRV" && python3 -m http.server $PORT --bind 127.0.0.1 >"$W/http.log" 2>&1 & echo $! > "$W/http.pid" )
sleep 1
cleanup_http() { kill "$(cat "$W/http.pid")" 2>/dev/null; }
trap 'cleanup_http; rm -rf "$T_TMP"' EXIT

export DDI_TEST=1 DDI_NO_SYSTEMD=1 DDI_ROOT="$R" DDI_LIBDIR="$R/usr/local/lib/ddibuntu" DDI_RUNDIR="$R/run" DDI_UPDATE_API="http://127.0.0.1:$PORT"
ST="$R/var/lib/ddibuntu/update-status.json"
req() { mkdir -p "$R/var/lib/ddibuntu/generated"; printf '%s' "$1" > "$R/var/lib/ddibuntu/generated/.update-request"; bash "$SU" request >"$W/out.log" 2>&1; echo $?; }

echo "== 0. Dépôt sans release publiée (404) : message distinct d'une panne réseau =="
expect_eq "aucune release : code 1" 1 "$(bash "$SU" check >"$W/out.log" 2>&1; echo $?)"
if jget "$ST" error | grep -q "Aucune release"; then ok "message : aucune release publiée"; else ko "message aucune release" "$(jget "$ST" error)"; fi
if jget "$ST" error | grep -q "joindre GitHub"; then ko "ne doit PAS dire « impossible de joindre GitHub » pour un simple 404"; else ok "pas confondu avec une panne réseau"; fi

echo "== 1. Détection =="
mkrelease 0.5.0 "$W/priv.pem"
expect_eq "check : code 0" 0 "$(bash "$SU" check >"$W/out.log" 2>&1; echo $?)"
expect_eq "état : latest = 0.5.0" 0.5.0 "$(jget "$ST" latest)"
expect_eq "état : current = 0.4.0" 0.4.0 "$(jget "$ST" current)"
expect_eq "état : available = true" true "$(jget "$ST" available)"
if jget "$ST" notes | grep -q "changement A"; then ok "notes de version récupérées"; else ko "notes" "$(jget "$ST" notes)"; fi
if stat -c %a "$ST" | grep -q 644; then ok "état lisible par la console (0644)"; else ko "mode état"; fi

echo "== 2. Demandes invalides (la console n'est pas fiable) =="
expect_eq "demande : JSON invalide ignorée" 0 "$(req 'pas du json')"
expect_eq "demande : action inconnue ignorée" 0 "$(req '{"action":"rm","version":"0.5.0"}')"
expect_eq "demande : version non numérique ignorée" 0 "$(req '{"action":"apply","version":"0.5.0; touch /tmp/pwn"}')"
if [ ! -e /tmp/pwn ]; then ok "aucune injection de commande"; else ko "injection"; fi
expect_eq "console intacte après demandes invalides" "OLD CONSOLE" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "demande consommée" no "$([[ -e "$R/var/lib/ddibuntu/generated/.update-request" ]] && echo yes || echo no)"
expect_eq "apply d'une version qui n'est pas la dernière : refus" 1 "$(req '{"action":"apply","version":"0.9.9"}')"
expect_eq "état : failed" failed "$(jget "$ST" state)"

echo "== 3. Signature invalide (release signée par une autre clé) =="
mkrelease 0.6.0 "$W/evil.pem"
expect_eq "signature invalide : code 1" 1 "$(req '{"action":"apply","version":"0.6.0"}')"
expect_grep "message SIGNATURE INVALIDE" "SIGNATURE INVALIDE" "$W/out.log"
expect_eq "signature invalide : console intacte" "OLD CONSOLE" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "signature invalide : version intacte" 0.4.0 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"

echo "== 4. Archive altérée (signature valide sur d'autres sommes) =="
mkrelease 0.6.0 "$W/priv.pem"; echo corrompu >> "$SRV/dl/ddibuntu-update-0.6.0.tar.gz"
expect_eq "archive altérée : code 1" 1 "$(req '{"action":"apply","version":"0.6.0"}')"
if grep -q "SHA-256" "$W/out.log"; then ok "somme SHA-256 incorrecte détectée"; else ko "message" "$(tail -3 "$W/out.log")"; fi

echo "== 5. Échec de santé -> retour arrière =="
mkrelease 0.5.0 "$W/priv.pem"
expect_eq "santé KO : code 1" 1 "$(DDI_TEST_HEALTH_FAIL=1 DDI_HEALTH_TRIES=2 DDI_HEALTH_SLEEP=0 req '{"action":"apply","version":"0.5.0"}')"
expect_eq "retour arrière : ancienne console restaurée" "OLD CONSOLE" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "retour arrière : version restaurée" 0.4.0 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
expect_eq "retour arrière : état failed" failed "$(jget "$ST" state)"
expect_eq "retour arrière : pas de console.old résiduelle" no "$([[ -e "$R/opt/ddibuntu/console.old" ]] && echo yes || echo no)"
expect_eq "retour arrière : fichier nouveau VERSION restauré" 0.4.0 "$(tr -d '\n' < "$R/usr/local/lib/ddibuntu/VERSION")"

echo "== 5b. Cluster : le leader attend que les secondaires soient à jour (ddibuntu-cluster rolling-check) =="
# faux « ddibuntu-cluster » : refuse (code 3, message sur la sortie d'erreur) tant que $W/rc-mode contient "refuse"
# shellcheck disable=SC2016  # variables du stub
printf '#!/bin/bash\n[ "$1" = rolling-check ] || exit 2\nif [ "$(cat %s/rc-mode)" = refuse ]; then echo "ce noeud est le leader : mettez d abord a jour n2" >&2; exit 3; fi\necho "$2" > %s/rc-called\nexit 0\n' "$W" "$W" > "$W/fake-cluster"; chmod 755 "$W/fake-cluster"
echo refuse > "$W/rc-mode"; : > "$W/cluster.conf"
NB0="$(find "$R/var/lib/ddibuntu/update-backup" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
export DDI_CLUSTER_CONF="$W/cluster.conf" DDI_CLUSTER_CMD="$W/fake-cluster"
expect_eq "leader trop en avance : refus (code 1)" 1 "$(req '{"action":"apply","version":"0.5.0"}')"
if jget "$ST" error | grep -q "mettez d abord a jour n2"; then ok "…le message du contrôle est montré à l'administrateur"; else ko "message" "$(jget "$ST" error)"; fi
expect_eq "…rien n'a été installé (console)" "OLD CONSOLE" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "…version inchangée" 0.4.0 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
expect_eq "…aucune sauvegarde créée avant le refus" "$NB0" "$(find "$R/var/lib/ddibuntu/update-backup" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
echo autorise > "$W/rc-mode"

echo "== 6. Installation réussie =="
expect_eq "apply 0.5.0 : code 0" 0 "$(req '{"action":"apply","version":"0.5.0"}')"
expect_eq "…le contrôle de mise à jour progressive a été appelé avec la version visée" 0.5.0 "$(cat "$W/rc-called" 2>/dev/null)"
tail -3 "$W/out.log"
expect_eq "console remplacée" "NEW CONSOLE 0.5.0" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "installed-version = 0.5.0" 0.5.0 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
expect_eq "VERSION de l'appliance = 0.5.0" 0.5.0 "$(tr -d '\n' < "$R/usr/local/lib/ddibuntu/VERSION")"
expect_eq "nouveau fichier déployé" "NOUVEAU 0.5.0" "$(cat "$R/etc/ddibuntu/nouveau.txt")"
expect_eq "firewall.conf de l'admin conservé" 'ADMIN_NETS="10.1.0.0/16"' "$(cat "$R/etc/ddibuntu/firewall.conf")"
expect_eq "nftables.nft de l'admin conservé" "REGLES ADMIN" "$(cat "$R/etc/ddibuntu/nftables.nft")"
expect_eq "update.conf conservé" 'REPO="acme/ddibuntu"' "$(cat "$R/etc/ddibuntu/update.conf")"
expect_eq "données conservées" DONNEES "$(cat "$R/var/lib/ddibuntu/pgdata-marker")"
expect_eq "re-rendu du pare-feu demandé" write "$(cat "$R/etc/ddibuntu/fw-called" 2>/dev/null)"
expect_eq "état : done" "done" "$(jget "$ST" state)"
expect_eq "état : current = 0.5.0" 0.5.0 "$(jget "$ST" current)"
expect_eq "état : available = false" false "$(jget "$ST" available)"
if grep -q "0.4.0 -> 0.5.0" "$R/var/lib/ddibuntu/update-history"; then ok "historique écrit"; else ko "historique"; fi
BK="$(find "$R/var/lib/ddibuntu/update-backup" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
if tar -tzf "$BK/replaced-files.tar.gz" | grep -q 'usr/local/lib/ddibuntu/VERSION'; then ok "sauvegarde des fichiers remplacés"; else ko "sauvegarde"; fi
expect_eq "répertoire de travail nettoyé" no "$([[ -e "$R/var/lib/ddibuntu/update-work" ]] && echo yes || echo no)"
expect_eq "apply de la même version : refus" 1 "$(req '{"action":"apply","version":"0.5.0"}')"

echo "== 7. Aucun accès réseau =="
export DDI_UPDATE_API="http://127.0.0.1:1"
expect_eq "check sans réseau : code 1" 1 "$(bash "$SU" check >"$W/out.log" 2>&1; echo $?)"
if jget "$ST" error | grep -q "joindre GitHub"; then ok "erreur lisible dans l'état"; else ko "erreur" "$(jget "$ST" error)"; fi
expect_eq "check sans réseau : version actuelle conservée" 0.5.0 "$(jget "$ST" current)"

echo "== 8. API GitHub limitée (403) : repli sur le site web =="
mkrelease 0.6.0 "$W/priv.pem"
PORT2=$((PORT + 1))
cat > "$W/rate.py" <<'PY'
import http.server, os, sys
dl, port = sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path
        if p.startswith('/repos/'): self.send_response(403); self.end_headers(); self.wfile.write(b'rate limit exceeded'); return
        if p == '/acme/ddibuntu/releases/latest': self.send_response(302); self.send_header('Location', '/acme/ddibuntu/releases/tag/v0.6.0'); self.end_headers(); return
        if p == '/acme/ddibuntu/releases/tag/v0.6.0': self.send_response(200); self.end_headers(); self.wfile.write(b'ok'); return
        if p.startswith('/acme/ddibuntu/releases/download/v0.6.0/'):
            f = os.path.join(dl, p.rsplit('/', 1)[1])
            if os.path.isfile(f): self.send_response(200); self.end_headers(); self.wfile.write(open(f, 'rb').read()); return
        self.send_response(404); self.end_headers()
http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
PY
python3 "$W/rate.py" "$SRV/dl" "$PORT2" >/dev/null 2>&1 & RATE_PID=$!
sleep 1
export DDI_UPDATE_API="http://127.0.0.1:$PORT2" DDI_UPDATE_WEB="http://127.0.0.1:$PORT2"
expect_eq "check avec API limitée : code 0" 0 "$(bash "$SU" check >"$W/out.log" 2>&1; echo $?)"
expect_eq "…la dernière release est lue sur le site" 0.6.0 "$(jget "$ST" latest)"
expect_eq "…et elle est proposée" true "$(jget "$ST" available)"
expect_eq "apply avec API limitée : code 0" 0 "$(req '{"action":"apply","version":"0.6.0"}')"
expect_eq "…version installée" 0.6.0 "$(cat "$R/var/lib/ddibuntu/installed-version")"
kill "$RATE_PID" 2>/dev/null

echo "== 9. Paquets embarqués (debs/) : podman, freeradius… posés sans accès à apt =="
export DDI_UPDATE_API="http://127.0.0.1:$PORT"; unset DDI_UPDATE_WEB
# faux dpkg / dpkg-query / dpkg-deb / apt-get : une « base » texte (paquet version) ; les « .deb » sont de petits fichiers texte
FB="$W/fakebin"; FD="$W/fake"; mkdir -p "$FB" "$FD"
export FAKE_DB="$FD/db" FAKE_DIR="$FD" FAKE_ROOT="$R"
cat > "$FB/dpkg" <<'FAKE'
#!/bin/bash
if [ "$1" = --compare-versions ]; then exec /usr/bin/dpkg "$@"; fi
files=(); seen=0
for a in "$@"; do if [ "$seen" = 1 ]; then files+=("$a"); elif [ "$a" = -i ]; then seen=1; fi; done
n=$(($(cat "$FAKE_DIR/dpkg-count" 2>/dev/null || echo 0) + 1)); echo "$n" > "$FAKE_DIR/dpkg-count"
echo "appel $n fichiers=${#files[@]} politique=$([ -x "$FAKE_ROOT/usr/sbin/policy-rc.d" ] && echo oui || echo non) frontend=${DEBIAN_FRONTEND:-}" >> "$FAKE_DIR/dpkg-calls"
case "$(cat "$FAKE_DIR/dpkg-mode" 2>/dev/null)" in
  fail) echo "dpkg: erreur de dépendance : libbidon requis" >&2; exit 1 ;;
  refuse-first) if [ "$n" -le 1 ]; then echo "dpkg: dépendances non satisfaites" >&2; exit 1; fi ;;
esac
for f in "${files[@]}"; do
  p="$(sed -n 's/^Package: //p' "$f")"; v="$(sed -n 's/^Version: //p' "$f")"
  grep -v "^$p " "$FAKE_DB" > "$FAKE_DB.n" || true; echo "$p $v" >> "$FAKE_DB.n"; mv "$FAKE_DB.n" "$FAKE_DB"
done
exit 0
FAKE
cat > "$FB/dpkg-query" <<'FAKE'
#!/bin/bash
fmt="${2#-f=}"; line="$(grep "^$3 " "$FAKE_DB")" || exit 1
case "$fmt" in
  '${Status}') printf 'install ok installed' ;;
  '${Version}') printf '%s' "${line#* }" ;;
esac
FAKE
cat > "$FB/dpkg-deb" <<'FAKE'
#!/bin/bash
sed -n "s/^$3: //p" "$2" | head -1
FAKE
cat > "$FB/apt-get" <<'FAKE'
#!/bin/bash
echo "apt-get $*" >> "$FAKE_DIR/apt-calls"
[ "$(cat "$FAKE_DIR/apt-mode" 2>/dev/null)" = ok ] || { echo "E: Unmet dependencies. Try 'apt --fix-broken install'" >&2; exit 100; }
seen=0; for a in "$@"; do if [ "$seen" = 1 ]; then grep -v "^$a " "$FAKE_DB" > "$FAKE_DB.n" || true; echo "$a 9.9.9-apt" >> "$FAKE_DB.n"; mv "$FAKE_DB.n" "$FAKE_DB"; elif [ "$a" = --no-install-recommends ]; then seen=1; fi; done
exit 0
FAKE
chmod 755 "$FB"/*
export PATH="$FB:$PATH"
mkdeb() { printf 'Package: %s\nVersion: %s\nArchitecture: %s\n' "$2" "$3" "${4:-amd64}" > "$1/$2_$3_${4:-amd64}.deb"; }
mkdebs() { # dossier : podman et ses dépendances, comme dans l'archive de la release
  local d="$1"; rm -rf "$d"; mkdir -p "$d"
  mkdeb "$d" podman 4.9.3+ds1-1ubuntu0.2; mkdeb "$d" freeradius 3.2.5-3; mkdeb "$d" freeradius-ldap 3.2.5-3; mkdeb "$d" freeradius-rest 3.2.5-3; mkdeb "$d" winbind 4.19.5-1; mkdeb "$d" samba-common-bin 4.19.5-1; mkdeb "$d" conmon 2.1.10-1
  mkdeb "$d" perl-base 5.38.2-3.2; mkdeb "$d" libfoo 1.1; mkdeb "$d" libautre 1.0 i386
  printf 'podman\nfreeradius\nfreeradius-ldap\nfreeradius-rest\nwinbind\nsamba-common-bin\n' > "$d/REQUESTED"
  ( cd "$d" && sha256sum ./*.deb > SHA256SUMS )
}
resetdb() { printf 'perl-base 5.40.0-1\nlibfoo 1.0\nca-certificates 20990101\n' > "$FAKE_DB"; rm -f "$FD"/dpkg-count "$FD"/dpkg-calls "$FD"/apt-calls "$FD"/dpkg-mode "$FD"/apt-mode "$R/var/lib/ddibuntu/packages-attempt"; }
have() { grep -q "^$1 " "$FAKE_DB" && echo yes || echo no; }
ver() { sed -n "s/^$1 //p" "$FAKE_DB"; }
mkdebs "$W/debs-ok"
mk "$R/usr/sbin/policy-rc.d" "ORIGINAL" 755

echo "-- 9a. mise à jour d'un nœud de données sans podman : paquets posés AVANT le déploiement, sans rétrograder ni sur-mettre à jour --"
resetdb; : > "$W/cluster.conf"
mkrelease 0.7.0 "$W/priv.pem" "$W/debs-ok"
expect_eq "apply 0.7.0 avec debs : code 0" 0 "$(req '{"action":"apply","version":"0.7.0"}')"
expect_eq "…podman posé" yes "$(have podman)"; expect_eq "…freeradius posé" yes "$(have freeradius)"; expect_eq "…freeradius-ldap posé" yes "$(have freeradius-ldap)"
expect_eq "…dépendance absente posée (conmon)" yes "$(have conmon)"
expect_eq "…perl-base plus récent déjà installé : PAS rétrogradé" 5.40.0-1 "$(ver perl-base)"
expect_eq "…dépendance plus ancienne non touchée tant que dpkg n'a pas refusé" 1.0 "$(ver libfoo)"
expect_eq "…paquet d'une autre architecture ignoré" no "$(have libautre)"
expect_eq "…un seul appel dpkg" 1 "$(cat "$FD/dpkg-count")"
expect_grep "…aucun service ne démarre pendant la pose (policy-rc.d actif) et dpkg est non interactif" "politique=oui frontend=noninteractive" "$FD/dpkg-calls"
expect_eq "…policy-rc.d d'origine restauré" ORIGINAL "$(cat "$R/usr/sbin/policy-rc.d")"
expect_eq "…aucun résidu .ddi-orig" no "$([[ -e "$R/usr/sbin/policy-rc.d.ddi-orig" ]] && echo yes || echo no)"
expect_eq "…état : done" "done" "$(jget "$ST" state)"; expect_eq "…version installée 0.7.0" 0.7.0 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
expect_eq "…état des paquets : ok" ok "$(jget "$ST" packages_state)"
expect_eq "…console remplacée" "NEW CONSOLE 0.7.0" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "…aucun appel apt (dpkg a réussi)" no "$([[ -e "$FD/apt-calls" ]] && echo yes || echo no)"

echo "-- 9b. dpkg refuse le strict nécessaire : nouvel essai avec tout ce qui est plus récent --"
resetdb; echo refuse-first > "$FD/dpkg-mode"
mkrelease 0.7.1 "$W/priv.pem" "$W/debs-ok"
expect_eq "apply 0.7.1 : code 0" 0 "$(req '{"action":"apply","version":"0.7.1"}')"
expect_eq "…deux appels dpkg" 2 "$(cat "$FD/dpkg-count")"
expect_eq "…podman posé" yes "$(have podman)"; expect_eq "…libfoo mis à niveau au second essai" 1.1 "$(ver libfoo)"
expect_eq "…perl-base toujours pas rétrogradé" 5.40.0-1 "$(ver perl-base)"
expect_eq "…état des paquets : ok" ok "$(jget "$ST" packages_state)"

echo "-- 9c. dpkg échoue : apt-get en secours --"
resetdb; echo fail > "$FD/dpkg-mode"; echo ok > "$FD/apt-mode"
mkrelease 0.7.2 "$W/priv.pem" "$W/debs-ok"
expect_eq "apply 0.7.2 : code 0" 0 "$(req '{"action":"apply","version":"0.7.2"}')"
expect_grep "…apt-get appelé avec les paquets demandés" "install -y -qq --no-install-recommends podman freeradius freeradius-ldap freeradius-rest winbind samba-common-bin" "$FD/apt-calls"
expect_eq "…podman posé par apt" yes "$(have podman)"
expect_eq "…état des paquets : ok" ok "$(jget "$ST" packages_state)"
expect_eq "…policy-rc.d d'origine restauré" ORIGINAL "$(cat "$R/usr/sbin/policy-rc.d")"

echo "-- 9d. dpkg ET apt échouent : la mise à jour aboutit quand même (jamais de retour arrière pour un paquet) --"
resetdb; echo fail > "$FD/dpkg-mode"; echo ko > "$FD/apt-mode"
mkrelease 0.7.3 "$W/priv.pem" "$W/debs-ok"
expect_eq "apply 0.7.3 : code 0" 0 "$(req '{"action":"apply","version":"0.7.3"}')"
expect_eq "…version installée 0.7.3 (pas de retour arrière)" 0.7.3 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
expect_eq "…console remplacée" "NEW CONSOLE 0.7.3" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "…état : done" "done" "$(jget "$ST" state)"
expect_eq "…état des paquets : failed" failed "$(jget "$ST" packages_state)"
if jget "$ST" message | grep -q "avertissement : paquets non installés"; then ok "…l'avertissement est montré à l'administrateur"; else ko "avertissement" "$(jget "$ST" message)"; fi
if jget "$ST" packages_message | grep -q "podman"; then ok "…le message nomme les paquets manquants"; else ko "message paquets" "$(jget "$ST" packages_message)"; fi
expect_eq "…policy-rc.d d'origine restauré malgré l'échec" ORIGINAL "$(cat "$R/usr/sbin/policy-rc.d")"
expect_eq "…historique : mise à jour inscrite" yes "$(grep -q '0.7.2 -> 0.7.3' "$R/var/lib/ddibuntu/update-history" && echo yes || echo no)"

echo "-- 9e. arbitre (witness) : aucun paquet --"
resetdb; printf 'NODE_ROLE=witness\n' > "$W/cluster.conf"
mkrelease 0.7.4 "$W/priv.pem" "$W/debs-ok"
expect_eq "apply 0.7.4 sur l'arbitre : code 0" 0 "$(req '{"action":"apply","version":"0.7.4"}')"
expect_eq "…rien n'est installé" no "$(have podman)"; expect_eq "…aucun appel dpkg" no "$([[ -e "$FD/dpkg-count" ]] && echo yes || echo no)"
expect_eq "…la mise à jour elle-même a eu lieu" 0.7.4 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
echo "-- 9e'. et « packages » ne fait rien non plus sur l'arbitre --"
expect_eq "packages sur l'arbitre : code 0" 0 "$(bash "$SU" packages >"$W/out.log" 2>&1; echo $?)"
expect_eq "…rien n'est installé" no "$(have podman)"

echo "-- 9f. empreinte d'un paquet embarqué incorrecte : paquets refusés, mise à jour poursuivie --"
resetdb; : > "$W/cluster.conf"
mkdebs "$W/debs-bad"; echo "modifié" >> "$W/debs-bad/podman_4.9.3+ds1-1ubuntu0.2_amd64.deb"
mkrelease 0.7.5 "$W/priv.pem" "$W/debs-bad"
expect_eq "apply 0.7.5 : code 0" 0 "$(req '{"action":"apply","version":"0.7.5"}')"
expect_eq "…rien n'a été installé" no "$(have podman)"
expect_eq "…état des paquets : failed" failed "$(jget "$ST" packages_state)"
if jget "$ST" packages_message | grep -q "empreinte"; then ok "…motif : empreinte"; else ko "motif" "$(jget "$ST" packages_message)"; fi
expect_eq "…version installée 0.7.5" 0.7.5 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"

echo "-- 9g. « packages » : rattrape un nœud mis à jour par une version qui n'en posait aucun (passage 0.14.10 → 0.14.11) --"
resetdb
mkrelease 0.7.6 "$W/priv.pem" "$W/debs-ok"
expect_eq "packages --auto : code 0" 0 "$(bash "$SU" packages --auto >"$W/out.log" 2>&1; echo $?)"
expect_eq "…podman posé depuis l'archive signée de la dernière release" yes "$(have podman)"
expect_eq "…état des paquets : ok" ok "$(jget "$ST" packages_state)"
expect_eq "…la version installée n'a pas bougé (ce n'est pas une mise à jour)" 0.7.5 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
expect_eq "…console inchangée" "NEW CONSOLE 0.7.5" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "…dossier de travail nettoyé" no "$([[ -e "$R/var/lib/ddibuntu/packages-work" ]] && echo yes || echo no)"
printf 'perl-base 5.40.0-1\n' > "$FAKE_DB"; rm -f "$FD/dpkg-count"
expect_eq "packages --auto à nouveau (< 6 h) : rien" 0 "$(bash "$SU" packages --auto >"$W/out.log" 2>&1; echo $?)"
expect_eq "…pas de nouvel essai (anti-boucle)" no "$(have podman)"
expect_eq "packages (manuel) : passe outre le délai" 0 "$(bash "$SU" packages >"$W/out.log" 2>&1; echo $?)"
expect_eq "…podman posé" yes "$(have podman)"
rm -f "$FD/dpkg-count"
expect_eq "packages quand rien ne manque : code 0" 0 "$(bash "$SU" packages >"$W/out.log" 2>&1; echo $?)"
expect_eq "…sans aucun appel dpkg" no "$([[ -e "$FD/dpkg-count" ]] && echo yes || echo no)"
expect_eq "…état des paquets : ok" ok "$(jget "$ST" packages_state)"

echo "-- 9h. release sans paquets embarqués (avant la 0.14.11) : message clair --"
resetdb
mkrelease 0.7.7 "$W/priv.pem"
expect_eq "packages : code 1" 1 "$(bash "$SU" packages >"$W/out.log" 2>&1; echo $?)"
expect_eq "…état des paquets : failed" failed "$(jget "$ST" packages_state)"
if jget "$ST" packages_message | grep -q "n'embarque pas de paquets"; then ok "…motif lisible"; else ko "motif" "$(jget "$ST" packages_message)"; fi
expect_eq "…rien installé" no "$(have podman)"
expect_eq "…le déroulement de la mise à jour n'est pas touché (état update inchangé)" "done" "$(jget "$ST" state)"

echo "-- 9i. debs/ piégé dans l'archive (lien symbolique) : mise à jour refusée avant toute modification --"
mkdebs "$W/debs-ok2"; mkdir -p "$W/trap"; ln -s /etc "$W/trap/debs"
mkrelease 0.7.8 "$W/priv.pem"
d="$W/rel-0.7.8"; ln -s /etc "$d/b/debs"
( cd "$d/b" && tar -czf "$SRV/dl/ddibuntu-update-0.7.8.tar.gz" rootfs.tar rootfs.tar.sha256 console.tar.gz VERSION debs ) && ( cd "$SRV/dl" && sha256sum "ddibuntu-update-0.7.8.tar.gz" > SHA256SUMS ) && openssl pkeyutl -sign -inkey "$W/priv.pem" -rawin -in "$SRV/dl/SHA256SUMS" -out "$SRV/dl/SHA256SUMS.sig"
expect_eq "apply 0.7.8 : code 1" 1 "$(req '{"action":"apply","version":"0.7.8"}')"
expect_grep "…motif : debs/ invalide" "debs/ invalide" "$W/out.log"
expect_eq "…version inchangée" 0.7.5 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
expect_eq "…console inchangée" "NEW CONSOLE 0.7.5" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"

echo "== 10. Une seule liste de paquets : exécution (update-packages), construction (build-ddibuntu.sh) et ISO (DDI_PACKAGES) =="
ROOTDIR="$(cd "$(dirname "$0")/.." && pwd)"
RT="$(tr -s ' \t\n' ' ' < "$RFS/usr/local/lib/ddibuntu/update-packages" | sed 's/^ //;s/ $//')"
BT="$(sed -n 's/^DDI_UPDATE_PACKAGES="\(.*\)"$/\1/p' "$ROOTDIR/build-ddibuntu.sh" | head -1)"
expect_eq "update-packages (exécution) = DDI_UPDATE_PACKAGES (construction)" "$BT" "$RT"
ISO_PKGS=" $(sed -n 's/^DDI_PACKAGES="\(.*\)"$/\1/p' "$ROOTDIR/build-ddibuntu.sh" | head -1) "
miss=""; for p in $RT; do case "$ISO_PKGS" in *" $p "*) ;; *) miss="$miss $p" ;; esac; done
expect_eq "chaque paquet de la mise à jour est aussi installé par l'ISO" "" "$miss"

echo "== 11. Suivi du cluster (« follow ») : paquet manquant -> « ddibuntu-selfupdate packages --auto » en arrière-plan =="
printf '#!/bin/bash\necho "$*" >> "%s/sdrun-calls"\n' "$FD" > "$FB/systemd-run"; chmod 755 "$FB/systemd-run"
# la fonction pkg_step est extraite telle quelle du script livré
eval "$(sed -n '/^pkg_step() {/,/^}/p' "$RFS/usr/local/sbin/ddibuntu-cluster")"
log() { printf '%s\n' "$*" >> "$FD/follow.log"; }
# shellcheck disable=SC2034  # ROOT est lue par pkg_step (fonction évaluée plus haut)
ROOT="$R"; export DDI_LIBDIR="$R/usr/local/lib/ddibuntu"
mk "$R/usr/local/sbin/ddibuntu-selfupdate" '#!/bin/sh' 755
resetdb; rm -f "$FD/sdrun-calls" "$FD/follow.log"; unset DDI_TEST
pkg_step
expect_grep "paquet manquant : récupération lancée en arrière-plan" "--unit=ddibuntu-packages .*ddibuntu-selfupdate packages --auto" "$FD/sdrun-calls"
expect_grep "…le journal nomme les paquets manquants" "paquets manquants : podman freeradius freeradius-ldap freeradius-rest winbind samba-common-bin" "$FD/follow.log"
mkdir -p "$R/var/lib/ddibuntu"; : > "$R/var/lib/ddibuntu/packages-attempt"; rm -f "$FD/sdrun-calls"
pkg_step
expect_eq "essai récent (< 6 h) : rien n'est relancé" no "$([[ -e "$FD/sdrun-calls" ]] && echo yes || echo no)"
rm -f "$R/var/lib/ddibuntu/packages-attempt"; printf 'podman 4.9.3\nfreeradius 3.2.5\nfreeradius-ldap 3.2.5\nfreeradius-rest 3.2.5\nwinbind 4.19\nsamba-common-bin 4.19\n' > "$FAKE_DB"
pkg_step
expect_eq "rien ne manque : rien n'est lancé" no "$([[ -e "$FD/sdrun-calls" ]] && echo yes || echo no)"
resetdb; chmod 644 "$R/usr/local/sbin/ddibuntu-selfupdate"
pkg_step
expect_eq "ddibuntu-selfupdate absent ou non exécutable : rien n'est lancé" no "$([[ -e "$FD/sdrun-calls" ]] && echo yes || echo no)"
chmod 755 "$R/usr/local/sbin/ddibuntu-selfupdate"; export DDI_TEST=1
pkg_step
expect_eq "essai automatisé (DDI_TEST) : jamais de systemd-run" no "$([[ -e "$FD/sdrun-calls" ]] && echo yes || echo no)"


echo "== 12. Canal « prerelease » (instance de validation) : versions candidates acceptées, brouillons jamais ; canal stable inchangé =="
unset DDI_CLUSTER_CONF DDI_CLUSTER_CMD DDI_UPDATE_WEB; export DDI_UPDATE_API="http://127.0.0.1:$PORT"
mkrelease 50.0.0 "$W/priv.pem"
python3 - "$SRV/repos/acme/ddibuntu/releases" "$PORT" <<'PY'
import json, sys
d, port = sys.argv[1], sys.argv[2]
base = 'http://127.0.0.1:%s/dl/' % port
rel = lambda v, **k: dict({'tag_name': 'v' + v, 'html_url': 'https://github.com/acme/ddibuntu/releases/tag/v' + v, 'published_at': '2026-11-20T10:00:00Z',
                           'body': 'Version candidate %s' % v, 'draft': False, 'prerelease': False,
                           'assets': [{'name': n, 'url': base + n} for n in ['ddibuntu-update-%s.tar.gz' % v, 'SHA256SUMS', 'SHA256SUMS.sig']]}, **k)
json.dump(rel('49.0.0'), open(d + '/latest', 'w'))                       # stable : ce que voient les appliances de production
json.dump([rel('51.0.0', draft=True), rel('50.0.0', prerelease=True), rel('49.0.0'), {'tag_name': 'v99.0.0-rc.1'}], open(d + '/index.html', 'w'))
PY
mk "$R/etc/ddibuntu/update.conf" 'REPO="acme/ddibuntu"'
expect_eq "canal stable : check code 0" 0 "$(bash "$SU" check >"$W/out.log" 2>&1; echo $?)"
expect_eq "…la pré-version 50.0.0 est ignorée (latest = 49.0.0)" 49.0.0 "$(jget "$ST" latest)"
expect_eq "…canal annoncé dans l'état : stable" stable "$(jget "$ST" channel)"
expect_eq "canal stable : apply de la pré-version refusé" 1 "$(req '{"action":"apply","version":"50.0.0"}')"
mk "$R/etc/ddibuntu/update.conf" 'REPO="acme/ddibuntu"
CHANNEL=prerelease'
expect_eq "canal prerelease : check code 0" 0 "$(bash "$SU" check >"$W/out.log" 2>&1; echo $?)"
expect_eq "…la version candidate est vue (brouillon 51.0.0 et tag non numérique écartés)" 50.0.0 "$(jget "$ST" latest)"
expect_eq "…et proposée" true "$(jget "$ST" available)"
expect_eq "…canal annoncé : prerelease" prerelease "$(jget "$ST" channel)"
expect_eq "canal prerelease : apply 50.0.0 code 0" 0 "$(req '{"action":"apply","version":"50.0.0"}')"
expect_eq "…version candidate installée (signature et empreinte vérifiées)" 50.0.0 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
expect_eq "…console remplacée" "NEW CONSOLE 50.0.0" "$(cat "$R/opt/ddibuntu/console/app/server/index.mjs")"
expect_eq "…empreinte de l'archive installée enregistrée (celle de SHA256SUMS signé)" "$(cat "$SRV/dl/SHA256SUMS")" "$(cat "$R/var/lib/ddibuntu/installed-bundle.sha256")"
mkrelease 52.0.0 "$W/evil.pem"
python3 - "$SRV/repos/acme/ddibuntu/releases" "$PORT" <<'PY'
import json, sys
d, port = sys.argv[1], sys.argv[2]; base = 'http://127.0.0.1:%s/dl/' % port
json.dump([{'tag_name': 'v52.0.0', 'draft': False, 'prerelease': True, 'html_url': '', 'published_at': '', 'body': '',
            'assets': [{'name': n, 'url': base + n} for n in ['ddibuntu-update-52.0.0.tar.gz', 'SHA256SUMS', 'SHA256SUMS.sig']]}], open(d + '/index.html', 'w'))
PY
expect_eq "canal prerelease : version candidate mal signée refusée" 1 "$(req '{"action":"apply","version":"52.0.0"}')"
expect_grep "…message SIGNATURE INVALIDE" "SIGNATURE INVALIDE" "$W/out.log"
expect_eq "…version inchangée" 50.0.0 "$(tr -d '\n' < "$R/var/lib/ddibuntu/installed-version")"
mk "$R/etc/ddibuntu/update.conf" 'REPO="acme/ddibuntu"
CHANNEL=nightly'
expect_eq "canal inconnu : refus" 1 "$(bash "$SU" check >"$W/out.log" 2>&1; echo $?)"
expect_grep "…motif lisible" "canal de mises à jour invalide" "$W/out.log"

finish
