#!/usr/bin/env python3
"""Aides de ddibuntu-pki (bibliothèque standard + openssl, rien d'autre).

Tout ce qui vient de la console est traité ici comme hostile : la demande JSON est revalidée champ par champ (jamais de DN, de nom ou
de chemin repris tel quel), les certificats et CRL déposés sont relus avec O_NOFOLLOW puis réécrits sous forme canonique, et la
publication de l'état des autorités ne contient que des données publiques (certificats, CRL, demandes de certificat), jamais de clé.

Sous-commandes :
  parse-request            stdin = JSON de la console ; sortie = lignes « clé<TAB>valeur » validées (rien si la demande est invalide)
  deposit                  relit un dépôt de la console (PEM / DER) et l'écrit en PEM canonique (ou en DER pour une CRL) ; KIND = certs | crl | csr (demande de certificat)
  check-issued             contrôle le certificat signé rendu par la racine hors ligne avant de l'importer dans EJBCA
  check-leaf               contrôle le certificat final émis par EJBCA (clé de la demande, chaîne, CA:FALSE, validité), l'écrit en PEM canonique et en extrait les champs publics
  hex2dec                  numéro de série hexadécimal → décimal (la base d'EJBCA stocke les séries en décimal)
  check-chain              contrôle la chaîne de l'autorité qui signera (la racine auto-signée en dernier) et en extrait la racine
  dn-find                  nom de l'autorité (lignes « nom<TAB>DN » sur l'entrée standard) qui porte un nom distinctif, quel que soit l'ordre de ses éléments
  p12-check                contrôle le PKCS#12 d'une autorité existante (clé, certificat, chaîne), le « rhabille » avec un mot de passe aléatoire à usage unique
  check-crl                contrôle une CRL de racine (signature, validité) avant de l'importer
  publish-cas              construit pki-cas.json et les fichiers publics de chaque autorité
  urls                     adresses publiques (CRL, certificat) d'une autorité
  b64pem                   certificat DER en base64 (entrée standard) → PEM
  bundle-pack              (0.14.5) archive les secrets, les métadonnées des autorités et le volume (avant chiffrement par la clé publique de récupération)
  bundle-extract           (0.14.5) revalide et extrait une telle archive (types, noms, tailles, ejbca.env et instance.json) sous un dossier temporaire
  recovery-check           (0.14.5) contrôle le certificat de récupération déposé par la console (RSA, 3072 bits au moins, chiffrement possible)
  recovery-info            (0.14.5) empreinte, taille et fin de validité du certificat de récupération enregistré
  update-policy            (0.14.7) « ok » ou le motif du refus d'une mise à jour de l'image (même version, plus ancienne, plus ancienne que la base, saut de version majeure)
  update-cmp               (0.14.7) compare deux versions (-1, 0, 1)
  update-check-write       (0.14.7) analyse les étiquettes publiées par Docker Hub et écrit le résultat de la recherche de nouvelles versions
  update-job               (0.14.7) tient l'état de la mise à jour en cours (étapes, contrôles, sauvegarde de retour arrière)
  update-publish           (0.14.7) construit pki-update.json (recherche + mise à jour en cours) pour la console
  update-digest            (0.14.7) empreinte annoncée par Docker Hub pour une étiquette lors de la dernière recherche (vide si inconnue)
  update-crl-urls          (0.14.7) adresses locales des CRL des autorités actives (contrôle après une mise à jour)
  scep-pw                  (0.14.8) lit le mot de passe à usage unique d'un équipement SCEP déposé par la console (le défi de l'équipement)
  scep-publish             (0.14.8) construit pki-scep.json (alias, adresse, équipements préenregistrés et leur état) pour la console
"""
import base64
import calendar
import hashlib
import io
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse

MAX_REQUEST = 4096
MAX_DEPOSIT = 16384
MAX_P12 = 65536          # PKCS#12 d'une autorité (clé + chaîne) : 64 Ko au plus
MAX_P12_PW = 512         # mot de passe du PKCS#12 (octets UTF-8)
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,47}")
RESERVED_NAMES = {"ManagementCA"}
ALGS = ("rsa3072", "rsa4096", "ecp256", "ecp384")
IMAGE_RE = re.compile(r"docker\.io/keyfactor/ejbca-ce:[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}")
HOST_RE = re.compile(r"[a-z0-9.-]{3,253}")
NET_RE = re.compile(r"[0-9A-Fa-f:.]{2,45}(/[0-9]{1,3})?")
# valeur d'un élément de nom distinctif : aucun séparateur (virgule, plus, égal, barre oblique inverse, guillemets, <, >, ;, #, /), aucun
# caractère de contrôle, jamais d'espace en tête ou en queue
DN_VALUE_RE = re.compile(r"[^\x00-\x1f\x7f,+=\\\"<>;#/\s]([^\x00-\x1f\x7f,+=\\\"<>;#/]{0,62}[^\x00-\x1f\x7f,+=\\\"<>;#/\s])?")
CERT_RE = re.compile(r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----")
CRL_RE = re.compile(r"-----BEGIN X509 CRL-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END X509 CRL-----")
CA_DAYS = {"ca_root": (365, 7305), "ca_issuing": (365, 3650)}
CSR_RE = re.compile(r"-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END (?:NEW )?CERTIFICATE REQUEST-----")
# Émission de certificats (0.14.3). Les profils sont ceux que fournit le DDI (tools/pki-profiles/Gen.java) : le nom côté EJBCA, les types de SAN permis
# et les types dont au moins un est obligatoire. Mêmes règles que la console (utils/pki-certs.ts) : ici elles sont la protection, là un guide.
PROFILES = {"server": "DDI-RADIUS-Server", "machine": "DDI-Client-Machine", "user": "DDI-Client-User", "network": "DDI-Network-Device"}
SAN_ALLOWED = {"server": ("dns", "ip"), "machine": ("dns",), "user": ("upn", "mail"), "network": ("dns", "ip")}
SAN_NEEDED = {"server": ("dns",), "machine": ("dns",), "user": ("upn", "mail"), "network": ("dns", "ip")}
SAN_MAX = {"dns": 8, "ip": 4, "mail": 2, "upn": 2}
SAN_LABEL = {"dns": "dNSName", "ip": "iPAddress", "mail": "rfc822Name", "upn": "upn"}
ID_RE = re.compile(r"[0-9a-f]{16}")
DNS_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")
MAIL_RE = re.compile(r"[A-Za-z0-9._-]{1,64}@[A-Za-z0-9]([A-Za-z0-9.-]{0,188}[A-Za-z0-9])?")
SERIAL_RE = re.compile(r"[0-9A-Fa-f]{1,40}")
REVOKE_REASONS = (0, 1, 3, 4, 5)   # non précisé, clé compromise, changement d'affiliation, remplacé, cessation d'activité
# SCEP (0.14.8). Le nom d'utilisateur de l'entité finale EST le CN de la demande de l'équipement (mode « CA » d'EJBCA : le mode « RA » à défi partagé n'existe
# pas dans la Community) ; le mot de passe à usage unique est le défi. L'alias est unique et son nom, fixe.
SCEP_ALIAS = "ddibuntu"
SCEP_CN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}")
SCEP_PW_RE = re.compile(r"[A-Za-z0-9]{16,64}")
SCEP_RESERVED = ("ejbca", "superadmin")   # entités de service d'EJBCA ; les noms « ddi-… » sont ceux des entités temporaires d'émission
SCEP_PROFILE_OF = {5010001: "server", 5010002: "machine", 5010003: "user", 5010004: "network"}
RSA_BITS = (2048, 3072, 4096)
EC_CURVES = ("prime256v1", "secp384r1")


def valid_name(n):
    return isinstance(n, str) and NAME_RE.fullmatch(n) is not None and n not in RESERVED_NAMES and not n.startswith("ExtRoot-")


def build_dn(d):
    """CN obligatoire ; O, OU, C facultatifs. Retourne None si une valeur est refusée."""
    cn = d.get("cn")
    if not (isinstance(cn, str) and DN_VALUE_RE.fullmatch(cn)):
        return None
    parts = ["CN=" + cn]
    for key, label in (("ou", "OU"), ("o", "O")):
        v = d.get(key)
        if v in (None, ""):
            continue
        if not (isinstance(v, str) and DN_VALUE_RE.fullmatch(v)):
            return None
        parts.append(label + "=" + v)
    c = d.get("c")
    if c not in (None, ""):
        if not (isinstance(c, str) and re.fullmatch(r"[A-Z]{2}", c)):
            return None
        parts.append("C=" + c)
    return ",".join(parts)


def san_values(d, kind):
    """Liste de valeurs d'un type de SAN : chacune revalidée et normalisée ; None si une valeur est refusée."""
    v = d.get(kind, [])
    if v in (None, ""):
        return []
    if not (isinstance(v, list) and len(v) <= SAN_MAX[kind]):
        return None
    out = []
    for x in v:
        if not isinstance(x, str):
            return None
        if kind == "dns":
            if not DNS_RE.fullmatch(x):
                return None
            x = x.lower()
        elif kind == "ip":
            try:
                x = str(ipaddress.ip_address(x))
            except ValueError:
                return None
        elif not MAIL_RE.fullmatch(x):
            return None
        if x not in out:
            out.append(x)
    return out


def parse_cert_issue(d):
    """Demande d'émission : (id, ca, profile, dn, altname) validés, ou None. Le profil impose les types de SAN permis et ceux dont un au moins est requis."""
    rid, ca, prof = d.get("id"), d.get("ca"), d.get("profile")
    if not (isinstance(rid, str) and ID_RE.fullmatch(rid) and valid_name(ca) and prof in PROFILES):
        return None
    dn = build_dn(d)
    if not dn:
        return None
    parts, count = [], {}
    for kind in ("dns", "ip", "mail", "upn"):
        vals = san_values(d, kind)
        if vals is None or (vals and kind not in SAN_ALLOWED[prof]):
            return None
        count[kind] = len(vals)
        parts += ["%s=%s" % (SAN_LABEL[kind], x) for x in vals]
    if not any(count.get(k) for k in SAN_NEEDED[prof]):
        return None
    return [("id", rid), ("ca", ca), ("profile", prof), ("dn", dn), ("altname", ",".join(parts))]


def scep_cn_ok(cn):
    """Nom de l'équipement : devient le nom d'utilisateur de l'entité finale d'EJBCA, donc sans fantaisie et jamais celui d'une entité de service."""
    return (isinstance(cn, str) and SCEP_CN_RE.fullmatch(cn) is not None and cn.lower() not in SCEP_RESERVED and not cn.lower().startswith("ddi-"))


def parse_scep_offer(d):
    """Préenregistrement d'un équipement : les mêmes champs qu'une émission (autorité, profil, nom, SAN) ; le nom doit aussi être un nom d'utilisateur sûr."""
    r = parse_cert_issue(d)
    if r is None or not scep_cn_ok(d.get("cn")):
        return None
    return r + [("cn", d["cn"])]


def parse_request():
    raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST:
        return 1
    try:
        d = json.loads(raw.decode("utf-8"))
    except Exception:
        return 1
    if not isinstance(d, dict):
        return 1
    a = d.get("action")
    out = []
    if a in ("start", "stop", "restart", "status", "uninstall", "reset", "recovery_set", "update_check", "update_validate", "update_rollback") and set(d) == {"action"}:
        out = [("action", a)]
    elif a == "apply":
        img, host, nets = d.get("image"), d.get("hostname"), d.get("nets", [])
        ok = (isinstance(img, str) and IMAGE_RE.fullmatch(img)
              and isinstance(host, str) and HOST_RE.fullmatch(host) and not re.search(r"\.[0-9]+$", host)
              and isinstance(nets, list) and len(nets) <= 64 and all(isinstance(n, str) and NET_RE.fullmatch(n) for n in nets))
        if not ok:
            return 1
        out = [("action", a), ("image", img), ("hostname", host), ("nets", ",".join(nets))]
    elif a in ("ca_root", "ca_issuing"):
        name, alg, days = d.get("name"), d.get("alg"), d.get("days")
        lo, hi = CA_DAYS[a]
        dn = build_dn(d)
        if not (valid_name(name) and alg in ALGS and isinstance(days, int) and not isinstance(days, bool) and lo <= days <= hi and dn):
            return 1
        out = [("action", a), ("name", name), ("alg", alg), ("days", str(days)), ("dn", dn)]
        if a == "ca_issuing":
            by = d.get("signedBy", "external")
            if by != "external" and not valid_name(by):
                return 1
            out.append(("signedBy", by))
    elif a == "update_apply":
        img = d.get("image")
        if not (set(d) == {"action", "image"} and isinstance(img, str) and IMAGE_RE.fullmatch(img)):
            return 1
        out = [("action", a), ("image", img)]
    elif a in ("scep_enable", "scep_disable") and set(d) == {"action"}:
        out = [("action", a)]
    elif a == "scep_offer":
        r = parse_scep_offer(d)
        if r is None:
            return 1
        out = [("action", a)] + r
    elif a == "scep_rearm":
        if not (set(d) == {"action", "id", "cn"} and scep_cn_ok(d.get("cn")) and isinstance(d.get("id"), str) and ID_RE.fullmatch(d["id"])):
            return 1
        out = [("action", a), ("id", d["id"]), ("cn", d["cn"])]
    elif a == "scep_cancel":
        if not (set(d) == {"action", "cn"} and scep_cn_ok(d.get("cn"))):
            return 1
        out = [("action", a), ("cn", d["cn"])]
    elif a == "ca_import_p12":
        if not valid_name(d.get("name")):
            return 1
        out = [("action", a), ("name", d["name"])]
    elif a in ("ca_import", "ca_crl"):
        if not valid_name(d.get("name")):
            return 1
        out = [("action", a), ("name", d["name"])]
    elif a == "ca_rootcrl":
        n = d.get("name")
        if not (isinstance(n, str) and re.fullmatch(r"ExtRoot-[0-9a-f]{8}", n)):
            return 1
        out = [("action", a), ("name", n)]
    elif a == "cert_issue":
        r = parse_cert_issue(d)
        if r is None:
            return 1
        out = [("action", a)] + r
    elif a == "cert_revoke":
        ca, ser, why, rid = d.get("ca"), d.get("serial"), d.get("reason"), d.get("id")
        if not (valid_name(ca) and isinstance(ser, str) and SERIAL_RE.fullmatch(ser) and isinstance(why, int) and not isinstance(why, bool) and why in REVOKE_REASONS):
            return 1
        out = [("action", a), ("ca", ca), ("serial", ser.upper().lstrip("0") or "0"), ("reason", str(why))]
        if rid is not None:   # référence facultative : root la recopie dans son résultat, la console sait ainsi quelle demande a abouti
            if not (isinstance(rid, str) and ID_RE.fullmatch(rid)):
                return 1
            out.append(("id", rid))
    else:
        return 1
    for k, v in out:
        if "\n" in v or "\t" in v:
            return 1
        sys.stdout.write("%s\t%s\n" % (k, v))
    return 0


# ---------- dépôts de la console ----------
def read_deposit(path, limit=MAX_DEPOSIT):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise ValueError("dépôt refusé : fichier ordinaire de %d Ko au plus attendu" % max(1, limit // 1024))
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise ValueError("dépôt trop gros")
        return data
    finally:
        os.close(fd)


def read_deposit_path(path):
    return read_deposit(path)


def pem_of(der, label="CERTIFICATE"):
    b = base64.b64encode(der).decode()
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(b[i:i + 64] for i in range(0, len(b), 64)), label)


def parse_certs(data):
    """PEM (un ou plusieurs certificats, rien d'autre) ou DER (un seul) → liste de DER."""
    if data[:1] == b"\x30":
        return [data]
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("fichier ni PEM ni DER")
    blocks = CERT_RE.findall(text)
    rest = CERT_RE.sub("", text)
    if not blocks or rest.strip():
        raise ValueError("le fichier ne doit contenir que des certificats au format PEM")
    out = []
    for b in blocks:
        try:
            der = base64.b64decode("".join(b.split()), validate=True)
        except Exception:
            raise ValueError("certificat PEM illisible (base64)")
        if not der or der[0] != 0x30 or len(der) > 8192:
            raise ValueError("certificat PEM illisible")
        out.append(der)
    return out


def openssl(args, data=None):
    p = subprocess.run(["openssl"] + args, input=data, capture_output=True, timeout=30)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def cert_ok(der):
    rc, _, _ = openssl(["x509", "-inform", "DER", "-noout"], der)
    return rc == 0


def csr_der(data):
    """Demande de certificat PKCS#10 en PEM (CERTIFICATE REQUEST) ou en DER → DER ; ValueError sinon."""
    if data[:1] == b"\x30":
        return data
    text = data.decode("ascii", "replace")
    m = CSR_RE.search(text)
    if not m or CSR_RE.sub("", text).strip():
        raise ValueError("la demande de certificat doit être au format PEM (CERTIFICATE REQUEST) ou DER, et ne rien contenir d'autre")
    try:
        return base64.b64decode("".join(m.group(1).split()), validate=True)
    except Exception:
        raise ValueError("demande de certificat PEM illisible (base64)")


def csr_check(der):
    """Contrôle d'une demande : signature valide (preuve de possession de la clé), clé admise par les profils du DDI. Retourne (algorithme, détail)."""
    # OpenSSL 3 (Ubuntu 24.04) rend le code 0 même quand la signature est fausse : seul le message fait foi
    rc, out, err = openssl(["req", "-inform", "DER", "-noout", "-verify"], der)
    if rc != 0 or "verify OK" not in (out + err) or "failure" in (out + err):
        raise ValueError("la signature de la demande de certificat n'est pas valide (preuve de possession de la clé refusée)")
    rc, text, _ = openssl(["req", "-inform", "DER", "-noout", "-text"], der)
    if rc != 0:
        raise ValueError("demande de certificat illisible")
    if "rsaEncryption" in text:
        m = re.search(r"Public-Key:\s*\((\d+) bit\)", text)
        bits = int(m.group(1)) if m else 0
        if bits not in RSA_BITS:
            raise ValueError("clé RSA de %d bits refusée (admis : %s)" % (bits, ", ".join(str(b) for b in RSA_BITS)))
        return "RSA", str(bits)
    if "id-ecPublicKey" in text:
        m = re.search(r"ASN1 OID:\s*(\S+)", text)
        curve = m.group(1) if m else ""
        if curve not in EC_CURVES:
            raise ValueError("courbe %s refusée (admises : %s)" % (curve or "inconnue", ", ".join(EC_CURVES)))
        return "EC", curve
    raise ValueError("type de clé refusé (admis : RSA 2048 / 3072 / 4096, ECDSA P-256 / P-384)")


def cmd_deposit(argv):
    # deposit SRC DEST KIND [MAXCERTS] ; KIND = certs | crl | csr
    src, dest, kind = argv[0], argv[1], argv[2]
    maxc = int(argv[3]) if len(argv) > 3 else 1
    try:
        data = read_deposit(src)
    except (OSError, ValueError) as e:
        print("ERR\t%s" % e)
        return 1
    info = "1"
    try:
        if kind == "certs":
            ders = parse_certs(data)
            if len(ders) > maxc:
                raise ValueError("%d certificat(s) au plus attendu(s)" % maxc)
            if not all(cert_ok(d) for d in ders):
                raise ValueError("un certificat n'est pas lisible par openssl")
            payload = "".join(pem_of(d) for d in ders).encode()
            info = str(len(ders))
        elif kind == "csr":
            der = csr_der(data)
            alg, detail = csr_check(der)
            payload = pem_of(der, "CERTIFICATE REQUEST").encode()
            info = "%s\t%s" % (alg, detail)
        elif kind == "crl":
            if data[:1] == b"\x30":
                der = data
            else:
                m = CRL_RE.search(data.decode("ascii", "replace"))
                if not m or CRL_RE.sub("", data.decode("ascii", "replace")).strip():
                    raise ValueError("la CRL doit être au format DER ou PEM (X509 CRL)")
                der = base64.b64decode("".join(m.group(1).split()), validate=True)
            rc, _, _ = openssl(["crl", "-inform", "DER", "-noout"], der)
            if rc != 0:
                raise ValueError("CRL illisible")
            payload = der
        else:
            raise ValueError("type de dépôt inconnu")
    except ValueError as e:
        print("ERR\t%s" % e)
        return 1
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(payload)
    print("OK\t%s" % info)
    return 0


# ---------- contrôles avant import ----------
def x509_text(pem_path):
    rc, out, _ = openssl(["x509", "-in", pem_path, "-noout", "-text"])
    return out if rc == 0 else ""


def x509_field(pem_path, flag):
    rc, out, _ = openssl(["x509", "-in", pem_path, "-noout", flag, "-nameopt", "RFC2253"])
    return out.strip().split("=", 1)[1].strip() if rc == 0 and "=" in out else ""


def pubkey_of(kind, path):
    rc, out, _ = openssl([kind, "-in", path, "-noout", "-pubkey"])
    return out.strip() if rc == 0 else ""


def cmd_check_issued(argv):
    # check-issued CSR CERT CHAIN : le certificat rendu par la racine correspond-il à notre demande ?
    csr, cert, chain = argv[0], argv[1], argv[2]
    err = None
    text = x509_text(cert)
    pk_c, pk_r = pubkey_of("x509", cert), pubkey_of("req", csr)
    rc_r, subj_r, _ = openssl(["req", "-in", csr, "-noout", "-subject", "-nameopt", "RFC2253"])
    subj_c = x509_field(cert, "-subject")
    subj_r = subj_r.strip().split("=", 1)[1].strip() if rc_r == 0 and "=" in subj_r else ""
    if not text:
        err = "certificat illisible"
    elif not pk_c or pk_c != pk_r:
        err = "la clé publique du certificat ne correspond pas à la demande de certificat de cette autorité"
    elif not subj_c or subj_c.lower() != subj_r.lower():
        err = "le nom du certificat (%s) diffère de celui de la demande (%s)" % (subj_c, subj_r)
    elif "CA:TRUE" not in text:
        err = "le certificat n'est pas un certificat d'autorité (basicConstraints CA:TRUE absent)"
    elif re.search(r"Key Usage:[^\n]*\n\s*([^\n]*)", text) and "Certificate Sign" not in re.search(r"Key Usage:[^\n]*\n\s*([^\n]*)", text).group(1):
        err = "le certificat n'autorise pas la signature de certificats (keyCertSign absent)"
    else:
        rc, _, e = openssl(["verify", "-CAfile", chain, "-untrusted", chain, cert])
        if rc != 0:
            err = "la chaîne ne valide pas ce certificat : %s" % (e.strip().splitlines()[-1] if e.strip() else "refusé")
        else:
            rc1, _, _ = openssl(["x509", "-in", cert, "-noout", "-checkend", "86400"])
            if rc1 != 0:
                err = "le certificat expire dans moins d'un jour (ou est déjà expiré)"
            else:
                m = re.search(r"Not Before\s*:\s*(.+)", text)
                if m:
                    try:
                        nb = calendar.timegm(time.strptime(re.sub(r"\s+", " ", m.group(1).strip()).replace(" GMT", ""), "%b %d %H:%M:%S %Y"))
                        if nb - time.time() > 86400:
                            err = "le certificat n'est pas encore valable (début : %s)" % m.group(1).strip()
                    except ValueError:
                        pass
    if err:
        print("ERR\t%s" % err)
        return 1
    print("OK")
    return 0


def leaf_der(raw):
    """Le certificat rendu par la CLI d'EJBCA : des lignes « Subject: » / « Issuer: » précèdent le bloc PEM. Un seul bloc PEM est exigé, rien d'autre après lui."""
    text = raw.decode("ascii", "replace")
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----", text)
    if len(blocks) != 1:
        raise ValueError("un seul certificat est attendu dans le fichier rendu par EJBCA (%d trouvé(s))" % len(blocks))
    rest = re.sub(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", "", text, flags=re.S)
    if any(l.strip() and not re.match(r"(Subject|Issuer):", l.strip()) for l in rest.splitlines()):
        raise ValueError("le fichier rendu par EJBCA contient autre chose qu'un certificat")
    try:
        return base64.b64decode("".join(blocks[0].split()), validate=True)
    except Exception:
        raise ValueError("certificat illisible (base64)")


def issued_by_first(cert_path, bundle_path):
    """L'émetteur du certificat final est-il le sujet du premier certificat du lot (l'autorité demandée), et non une autre autorité de la même chaîne ?"""
    try:
        first = parse_certs(open(bundle_path, "rb").read())[0]
    except (OSError, ValueError, IndexError):
        return False
    want = describe_cert(first)["subject"].lower()
    rc, out, _ = openssl(["x509", "-in", cert_path, "-noout", "-issuer", "-nameopt", "RFC2253"])
    got = out.partition("=")[2].strip().lower() if rc == 0 else ""
    return bool(want) and want == got


def cmd_check_leaf(argv):
    # check-leaf CSR CERT BUNDLE OUT : le certificat émis par EJBCA correspond-il à la demande (même clé) et remonte-t-il à une racine par BUNDLE
    # (certificat de l'autorité + sa chaîne, racine auto-signée en dernier) ? OUT reçoit le certificat en PEM canonique.
    # Sortie : OK, série (hex), SHA-256, début, fin, sujet
    csr, cert, bundle, out_path = argv[0], argv[1], argv[2], argv[3]
    try:
        der = leaf_der(read_deposit(cert))
    except (OSError, ValueError) as e:
        print("ERR\t%s" % e)
        return 1
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem_of(der).encode())
    text = x509_text(out_path)
    err = None
    pk_c, pk_r = pubkey_of("x509", out_path), pubkey_of("req", csr)
    if not text:
        err = "certificat illisible"
    elif not pk_c or pk_c != pk_r:
        err = "la clé publique du certificat ne correspond pas à la demande"
    elif "CA:FALSE" not in text:
        err = "le certificat émis n'est pas un certificat final (CA:FALSE absent) : refusé"
    elif not issued_by_first(out_path, bundle):
        err = "le certificat n'a pas été signé par l'autorité demandée (premier certificat du lot)"
    else:
        rc, _, e = openssl(["verify", "-CAfile", bundle, out_path])
        if rc != 0:
            err = "la chaîne ne valide pas le certificat émis : %s" % (e.strip().splitlines()[-1] if e.strip() else "refusé")
        elif openssl(["x509", "-in", out_path, "-noout", "-checkend", "60"])[0] != 0:
            err = "le certificat émis est déjà expiré"
    if err:
        print("ERR\t%s" % err)
        return 1
    rc, out, _ = openssl(["x509", "-in", out_path, "-noout", "-serial", "-fingerprint", "-sha256", "-subject", "-nameopt", "RFC2253"])
    serial = sha = subject = ""
    for line in out.splitlines():
        k, _, v = line.partition("=")
        if k == "serial":
            serial = v.strip().upper().lstrip("0") or "0"
        elif k.lower().endswith("fingerprint"):
            sha = v.replace(":", "").lower()
        elif k == "subject":
            subject = v.strip()
    info = describe_cert(der)
    print("OK\t%s\t%s\t%s\t%s\t%s" % (serial, sha, info["notBefore"], info["notAfter"], subject))
    return 0


# ---------- PKCS#12 d'une autorité existante ----------
KEY_RE = re.compile(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----\s*[A-Za-z0-9+/=\s]+?\s*-----END \1-----")


def write_secret(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def secret_tmpdir():
    """Dossier temporaire 0700 en mémoire (tmpfs) quand c'est possible : la clé n'y reste que le temps du contrôle."""
    for base in ("/dev/shm", None):
        try:
            return tempfile.TemporaryDirectory(dir=base)
        except OSError:
            continue
    raise OSError("aucun dossier temporaire")


def p12_dump(p12, pw):
    """Contenu du PKCS#12 en PEM sans chiffrement (clé comprise). Le mot de passe ne passe que par l'environnement d'openssl."""
    env = dict(os.environ, DDI_P12PW=pw)
    for extra in ([], ["-legacy"]):   # anciens fichiers (RC2-40, 3DES) : openssl 3 demande le fournisseur « legacy »
        p = subprocess.run(["openssl", "pkcs12", "-in", p12, "-passin", "env:DDI_P12PW", "-nodes"] + extra,
                           capture_output=True, env=env, timeout=30)
        if p.returncode == 0:
            return p.stdout.decode("ascii", "replace")
        err = p.stderr.decode("utf-8", "replace").lower()
        if "mac verify" in err or "invalid password" in err:
            raise ValueError("mot de passe du fichier PKCS#12 incorrect")
    raise ValueError("fichier PKCS#12 illisible (format ou chiffrement non pris en charge)")


def p12_alg(info):
    if info["keyAlg"] == "RSA" and info["keyBits"] in RSA_BITS:
        return "rsa%d" % info["keyBits"]
    if info["keyAlg"] == "EC" and info["curve"] in EC_CURVES:
        return {"prime256v1": "ecp256", "secp384r1": "ecp384"}[info["curve"]]
    return None


def cmd_p12_check(argv):
    # p12-check P12 PWFILE OUT_DIR CHAIN_OUT : OUT_DIR/ca.p12 = fichier rhabillé (mot de passe aléatoire), OUT_DIR/root.pem = racine (si l'autorité n'est pas auto-signée),
    # CHAIN_OUT = chaîne publique (intermédiaires puis racine). Sortie : OK<TAB>mot de passe à usage unique<TAB>root|issuing<TAB>alg<TAB>sha8 racine ou -<TAB>sujet<TAB>fin de validité<TAB>sujet de la racine ou -
    p12_path, pw_path, out_dir, chain_out = argv[0], argv[1], argv[2], argv[3]
    try:
        raw = read_deposit(p12_path, MAX_P12)
        pw_raw = read_deposit(pw_path, MAX_P12_PW)
    except (OSError, ValueError) as e:
        print("ERR\t%s" % e)
        return 1
    if raw[:1] != b"\x30":
        print("ERR\tle fichier n'est pas un PKCS#12 (.p12 / .pfx) : format binaire attendu")
        return 1
    try:
        pw = pw_raw.decode("utf-8")
    except UnicodeDecodeError:
        print("ERR\tmot de passe refusé : UTF-8 attendu")
        return 1
    if not pw or len(pw) > 128 or any(ord(c) < 0x20 or ord(c) == 0x7f for c in pw):
        print("ERR\tmot de passe du fichier PKCS#12 absent ou refusé (1 à 128 caractères, sans caractère de contrôle)")
        return 1
    try:
        with secret_tmpdir() as td:
            src = os.path.join(td, "in.p12")
            write_secret(src, raw)
            dump = p12_dump(src, pw)
            os.unlink(src)
            keys = [m.group(0) for m in KEY_RE.finditer(dump)]
            if len(keys) != 1:
                raise ValueError("le fichier doit contenir une seule clé privée (%d trouvée(s))" % len(keys))
            ders, seen = [], set()
            for m in CERT_RE.finditer(dump):
                try:
                    der = base64.b64decode("".join(m.group(1).split()), validate=True)
                except Exception:
                    raise ValueError("certificat du fichier illisible")
                if der and der[0] == 0x30 and len(der) <= 8192 and der not in seen:
                    seen.add(der)
                    ders.append(der)
            if not ders or len(ders) > 8:
                raise ValueError("le fichier doit contenir de 1 à 8 certificats (l'autorité, sa chaîne et sa racine)")
            keyp = os.path.join(td, "key.pem")
            write_secret(keyp, (keys[0] + "\n").encode())
            rc, pub, _ = openssl(["pkey", "-in", keyp, "-pubout"])
            if rc != 0 or not pub.strip():
                raise ValueError("clé privée illisible")
            paths, infos = [], []
            for i, der in enumerate(ders):
                if not cert_ok(der):
                    raise ValueError("un certificat du fichier n'est pas lisible par openssl")
                cp = os.path.join(td, "c%d.pem" % i)
                with open(cp, "w") as f:
                    f.write(pem_of(der))
                paths.append(cp)
                infos.append(describe_cert(der))
            mine = [i for i, p in enumerate(paths) if pubkey_of("x509", p) == pub.strip()]
            if not mine:
                raise ValueError("aucun certificat du fichier ne correspond à la clé privée")
            if len(mine) > 1:
                raise ValueError("plusieurs certificats du fichier portent la même clé : fournir seulement l'autorité et sa chaîne")
            li = mine[0]
            leaf, linfo = paths[li], infos[li]
            text = x509_text(leaf)
            if "CA:TRUE" not in text:
                raise ValueError("le certificat de la clé n'est pas un certificat d'autorité (basicConstraints CA:TRUE absent)")
            m = re.search(r"Key Usage:[^\n]*\n\s*([^\n]*)", text)
            if m and "Certificate Sign" not in m.group(1):
                raise ValueError("le certificat n'autorise pas la signature de certificats (keyCertSign absent)")
            alg = p12_alg(linfo)
            if not alg:
                raise ValueError("clé refusée (admis : RSA 2048 / 3072 / 4096, ECDSA P-256 / P-384)")
            rc, _, _ = openssl(["x509", "-in", leaf, "-noout", "-checkend", "86400"])
            if rc != 0:
                raise ValueError("le certificat de l'autorité est expiré ou expire dans moins d'un jour")
            mnb = re.search(r"Not Before\s*:\s*(.+)", text)
            if mnb:
                try:
                    nb = calendar.timegm(time.strptime(re.sub(r"\s+", " ", mnb.group(1).strip()).replace(" GMT", ""), "%b %d %H:%M:%S %Y"))
                    if nb - time.time() > 86400:
                        raise ValueError("le certificat de l'autorité n'est pas encore valable (début : %s)" % mnb.group(1).strip())
                except ValueError as e:
                    if "pas encore valable" in str(e):
                        raise
            subject = linfo["subject"]
            if not subject or len(subject) > 256 or any(ord(c) < 0x20 or ord(c) == 0x7f for c in subject):
                raise ValueError("nom distinctif de l'autorité refusé")
            # chaîne : de l'autorité jusqu'à une racine auto-signée, avec les seuls certificats du fichier
            chain_idx, cur, guard = [], linfo, 0
            while cur["subject"] != cur["issuer"]:
                nxt = [i for i, inf in enumerate(infos) if i != li and i not in chain_idx and inf["subject"].lower() == cur["issuer"].lower()]
                if not nxt or guard >= 5:
                    raise ValueError("chaîne incomplète : le fichier doit contenir tous les certificats jusqu'à la racine auto-signée")
                chain_idx.append(nxt[0])
                cur = infos[nxt[0]]
                guard += 1
            for i in chain_idx:
                if "CA:TRUE" not in x509_text(paths[i]):
                    raise ValueError("un certificat de la chaîne n'est pas un certificat d'autorité")
                rc, _, _ = openssl(["x509", "-in", paths[i], "-noout", "-checkend", "86400"])
                if rc != 0:
                    raise ValueError("un certificat de la chaîne est expiré ou expire dans moins d'un jour")
            if chain_idx:
                full = os.path.join(td, "all.pem")
                with open(full, "w") as f:
                    f.write("".join(pem_of(ders[i]) for i in [li] + chain_idx))
                rc, _, e = openssl(["verify", "-CAfile", paths[chain_idx[-1]], "-untrusted", full, leaf])
            else:
                rc, _, e = openssl(["verify", "-CAfile", leaf, leaf])
            if rc != 0:
                raise ValueError("la chaîne ne valide pas ce certificat : %s" % (e.strip().splitlines()[-1] if e.strip() else "refusé"))
            # fichier rhabillé : une seule clé, l'autorité et sa chaîne, mot de passe aléatoire que root seul connaît le temps de l'import
            alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            import secrets
            newpw = "".join(secrets.choice(alphabet) for _ in range(32))
            extra = os.path.join(td, "extra.pem")
            with open(extra, "w") as f:
                f.write("".join(pem_of(ders[i]) for i in chain_idx))
            cmd = ["openssl", "pkcs12", "-export", "-inkey", keyp, "-in", leaf]
            if chain_idx:
                cmd += ["-certfile", extra]
            cmd += ["-name", "ddi-ca", "-passout", "env:DDI_P12NEW", "-out", os.path.join(out_dir, "ca.p12")]
            r = subprocess.run(cmd, capture_output=True, env=dict(os.environ, DDI_P12NEW=newpw), timeout=30)
            if r.returncode != 0:
                raise ValueError("fichier PKCS#12 impossible à reconstruire")
            os.chmod(os.path.join(out_dir, "ca.p12"), 0o600)
            rootsha, rootsubj = "-", "-"
            if chain_idx:
                root_der = ders[chain_idx[-1]]
                rootsubj = infos[chain_idx[-1]]["subject"]
                rootsha = hashlib.sha256(root_der).hexdigest()[:8]
                write_secret(os.path.join(out_dir, "root.pem"), pem_of(root_der).encode())
                fd = os.open(chain_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
                with os.fdopen(fd, "w") as f:
                    f.write("".join(pem_of(ders[i]) for i in chain_idx))
            print("OK\t%s\t%s\t%s\t%s\t%s\t%s\t%s" % (newpw, "issuing" if chain_idx else "root", alg, rootsha, subject, linfo["notAfter"], rootsubj))
            return 0
    except ValueError as e:
        print("ERR\t%s" % e)
        return 1
    except (OSError, subprocess.SubprocessError):
        print("ERR\tfichier PKCS#12 refusé (lecture ou contrôle impossible)")
        return 1



def dn_key(dn):
    """Nom distinctif → clé comparable quel que soit l'ordre des éléments (EJBCA garde CN,O,C ; openssl affiche l'ordre d'encodage) et la casse."""
    parts, cur, esc = [], [], False
    for c in dn:
        if esc:
            cur.append(c)
            esc = False
        elif c == "\\":
            cur.append(c)
            esc = True
        elif c == ",":
            parts.append("".join(cur).strip().lower())
            cur = []
        else:
            cur.append(c)
    parts.append("".join(cur).strip().lower())
    return tuple(sorted(p for p in parts if p))


def cmd_dn_find(argv):
    # dn-find DN : stdin = lignes « nom<TAB>nom distinctif » (cadata) ; sortie = nom de la première autorité qui porte ce nom distinctif
    want = dn_key(argv[0])
    for line in sys.stdin:
        name, _, dn = line.rstrip("\n").partition("\t")
        if name and dn and dn_key(dn) == want:
            print(name)
            return 0
    return 0


def cmd_hex2dec(argv):
    if len(argv) != 1 or not SERIAL_RE.fullmatch(argv[0]):
        return 1
    print(int(argv[0], 16))
    return 0


def cmd_check_chain(argv):
    # check-chain CHAIN.pem ROOT_OUT.pem : chaîne de l'autorité qui signera (émettrices éventuelles puis racine AUTO-SIGNÉE en dernier)
    try:
        ders = parse_certs(read_deposit_path(argv[0]))
    except (OSError, ValueError) as e:
        print("ERR\t%s" % e)
        return 1
    if not ders or len(ders) > 5:
        print("ERR\tla chaîne doit contenir de 1 à 5 certificats (racine comprise)")
        return 1
    with tempfile.TemporaryDirectory() as td:
        paths = []
        for i, der in enumerate(ders):
            p = os.path.join(td, "c%d.pem" % i)
            with open(p, "w") as f:
                f.write(pem_of(der))
            paths.append(p)
        infos = [describe_cert(d) for d in ders]
        for i, (inf, p) in enumerate(zip(infos, paths)):
            if "CA:TRUE" not in x509_text(p):
                print("ERR\tle certificat %d de la chaîne n'est pas un certificat d'autorité" % (i + 1))
                return 1
            rc, _, _ = openssl(["x509", "-in", p, "-noout", "-checkend", "86400"])
            if rc != 0:
                print("ERR\tle certificat %d de la chaîne est expiré ou expire dans moins d'un jour" % (i + 1))
                return 1
        if infos[-1]["subject"] != infos[-1]["issuer"]:
            print("ERR\tle dernier certificat de la chaîne doit être la racine (auto-signée)")
            return 1
        for i, inf in enumerate(infos[:-1]):
            if inf["subject"] == inf["issuer"]:
                print("ERR\tle certificat %d de la chaîne est auto-signé mais n'est pas le dernier : une seule racine, placée en dernier" % (i + 1))
                return 1
        full = os.path.join(td, "all.pem")
        with open(full, "w") as f:
            f.write("".join(pem_of(d) for d in ders))
        # chaque maillon doit remonter, par les suivants, jusqu'à la racine finale (et pas seulement le premier)
        for i, p in enumerate(paths[:-1]):
            rc, _, e = openssl(["verify", "-CAfile", paths[-1], "-untrusted", full, p])
            if rc != 0:
                print("ERR\tla chaîne n'est pas cohérente (certificat %d) : %s" % (i + 1, e.strip().splitlines()[-1] if e.strip() else "refusée"))
                return 1
        with open(argv[1], "w") as f:
            f.write(pem_of(ders[-1]))
        os.chmod(argv[1], 0o600)
        print("OK\t%s\t%d\t%s" % (hashlib.sha256(ders[-1]).hexdigest()[:8], len(ders), infos[-1]["subject"]))
    return 0


def cmd_check_crl(argv):
    # check-crl ROOTCERT CRLDER : signée par la racine et pas encore périmée
    cert, crl = argv[0], argv[1]
    rc, out, e = openssl(["crl", "-inform", "DER", "-in", crl, "-noout", "-CAfile", cert, "-verify", "-nextupdate", "-issuer", "-nameopt", "RFC2253"])
    if rc != 0 or "verify OK" not in (out + e):
        print("ERR\tla CRL n'est pas signée par cette racine")
        return 1
    m = re.search(r"nextUpdate=(.+)", out)
    if not m:
        print("ERR\tCRL sans date de prochaine mise à jour")
        return 1
    try:
        nxt = calendar.timegm(time.strptime(re.sub(r"\s+", " ", m.group(1).strip()).replace(" GMT", ""), "%b %d %H:%M:%S %Y"))
    except ValueError:
        print("ERR\tdate de CRL illisible")
        return 1
    if nxt < time.time():
        print("ERR\tla CRL est déjà périmée")
        return 1
    print("OK\t%d" % int(nxt))
    return 0


# ---------- publication de l'état ----------
def enc_dn(dn):
    return urllib.parse.quote(dn, safe="")


def public_urls(host, port, dn):
    base = "http://%s:%d/ejbca/publicweb/webdist/certdist?cmd=" % (host, port)
    return {"crl": base + "crl&issuer=" + enc_dn(dn), "cert": base + "cacert&issuer=" + enc_dn(dn)}


def cmd_b64pem(argv):
    # b64pem : certificat DER en base64 sur l'entrée standard → PEM (rien si vide ou illisible)
    der = der_of_b64(sys.stdin.read().strip())
    if der and der[0] == 0x30:
        sys.stdout.write(pem_of(der))
    return 0


def cmd_urls(argv):
    u = public_urls(argv[0], int(argv[1]), argv[2])
    print(u["crl"])
    print(u["cert"])
    return 0


def der_of_b64(s):
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return b""


def describe_cert(der):
    """Champs lisibles d'un certificat d'autorité (openssl), sans jamais échouer."""
    pem = pem_of(der).encode()
    rc, text, _ = openssl(["x509", "-noout", "-text"], pem)
    rc2, names, _ = openssl(["x509", "-noout", "-subject", "-issuer", "-serial", "-nameopt", "RFC2253"], pem)
    d = {"subject": "", "issuer": "", "serial": "", "notBefore": "", "notAfter": "", "keyAlg": "", "keyBits": 0, "curve": "", "sigAlg": "", "pathLen": None}
    if rc2 == 0:
        for line in names.splitlines():
            k, _, v = line.partition("=")
            if k == "subject":
                d["subject"] = v.strip()
            elif k == "issuer":
                d["issuer"] = v.strip()
            elif k == "serial":
                d["serial"] = v.strip().lower()
    if rc == 0:
        def f(rx):
            m = re.search(rx, text)
            return m.group(1).strip() if m else ""
        for key, rx in (("notBefore", r"Not Before\s*:\s*(.+)"), ("notAfter", r"Not After\s*:\s*(.+)")):
            raw = f(rx)
            try:
                t = time.strptime(re.sub(r"\s+", " ", raw).replace(" GMT", ""), "%b %d %H:%M:%S %Y")
                d[key] = time.strftime("%Y-%m-%dT%H:%M:%SZ", t)
            except ValueError:
                d[key] = raw
        d["keyAlg"] = {"rsaEncryption": "RSA", "id-ecPublicKey": "EC"}.get(f(r"Public Key Algorithm:\s*(\S+)"), f(r"Public Key Algorithm:\s*(\S+)"))
        m = re.search(r"Public-Key:\s*\((\d+) bit\)", text)
        d["keyBits"] = int(m.group(1)) if m else 0
        d["curve"] = f(r"ASN1 OID:\s*(\S+)")
        d["sigAlg"] = f(r"Signature Algorithm:\s*(\S+)")
        m = re.search(r"pathlen:(\d+)", text)
        d["pathLen"] = int(m.group(1)) if m else None
    return d


def load_meta(ca_dir, name):
    try:
        with open(os.path.join(ca_dir, name, "meta.json")) as f:
            m = json.load(f)
        return m if isinstance(m, dict) else {}
    except Exception:
        return {}


def atomic_write(path, data, mode=0o644):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".pki.")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_tsv(path):
    rows = []
    if not path or not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line:
                rows.append(line.split("\t"))
    return rows


def cmd_publish_cas(argv):
    # publish-cas CAS.tsv CRLS.tsv CA_DIR RUN_DIR HOST PORT
    cas_tsv, crls_tsv, ca_dir, run_dir, host, port = argv[0], argv[1], argv[2], argv[3], argv[4], int(argv[5])
    rows = read_tsv(cas_tsv)       # name, status, subjectdn, caid, base64cert
    crl_rows = read_tsv(crls_tsv)  # issuerdn, crlnumber, thisupdate(ms), nextupdate(ms), base64crl
    certs = {}                     # sujet (RFC 2253, minuscules) -> {der, pem}
    cas = []
    for r in rows:
        # une ligne mal formée (base64 coupé par un retour à la ligne, nom hors format) n'est jamais interprétée comme une autorité
        if len(r) != 5 or not r[1].lstrip("-").isdigit() or not r[3].lstrip("-").isdigit():
            continue
        name, status, dn, _caid, b64 = r[:5]
        if name in RESERVED_NAMES:
            continue
        der = der_of_b64(b64) if b64 else b""
        info = describe_cert(der) if der and cert_ok(der) else None
        if info:
            certs[info["subject"].lower()] = {"der": der, "pem": pem_of(der)}
        cas.append({"name": name, "status": int(status) if status.lstrip("-").isdigit() else -1, "dn": dn, "der": der, "info": info})
    crls = {}
    for r in crl_rows:
        if len(r) != 5 or not r[1].isdigit():
            continue
        iss, num, this, nxt, b64 = r[:5]
        crls[iss.lower()] = {"number": int(num) if num.isdigit() else 0, "this": int(this) if this.isdigit() else 0,
                             "next": int(nxt) if nxt.isdigit() else 0, "der": der_of_b64(b64)}
    # l'émetteur est affiché avec le nom distinctif d'EJBCA de l'autorité qui l'a émis quand elle est connue (même ordre que « dn »)
    by_subject = {ca["info"]["subject"].lower(): ca["dn"] for ca in cas if ca["info"] and ca["dn"]}
    out_dir = os.path.join(run_dir, "pki-ca")
    os.makedirs(out_dir, mode=0o755, exist_ok=True)
    os.chmod(out_dir, 0o755)   # la console (sans privilège) lit ces dossiers : le umask de root ne doit pas les fermer
    listing, keep = [], set()
    for ca in cas:
        name, st, info = ca["name"], ca["status"], ca["info"]
        meta = load_meta(ca_dir, name)
        kind = meta.get("kind")
        if st == 6:
            kind = "extroot"
        elif kind not in ("root", "issuing"):
            kind = "root" if info and info["subject"] == info["issuer"] else ("issuing" if info else "unknown")
        state = "active" if st == 1 else "waiting" if st == 2 else "external" if st == 6 else "other"
        item = {"name": name, "kind": kind, "state": state, "status": st, "dn": ca["dn"], "signedBy": meta.get("signedBy"),
                "alg": meta.get("alg"), "createdAt": meta.get("createdAt"), "imported": bool(meta.get("imported")), "extRoot": meta.get("extRoot") if re.fullmatch(r"ExtRoot-[0-9a-f]{8}", str(meta.get("extRoot") or "")) else None,
                "files": {"cert": False, "chain": False, "csr": False, "crl": False}}
        if info:
            item.update({"issuer": by_subject.get(info["issuer"].lower(), info["issuer"]), "selfSigned": info["subject"] == info["issuer"], "serial": info["serial"],
                         "notBefore": info["notBefore"], "notAfter": info["notAfter"], "keyAlg": info["keyAlg"], "keyBits": info["keyBits"],
                         "curve": info["curve"], "sigAlg": info["sigAlg"], "pathLen": info["pathLen"],
                         "sha256": hashlib.sha256(ca["der"]).hexdigest()})
        # EJBCA indexe ses CRL et attend l'adresse de publication avec SON nom distinctif (cadata.subjectdn : CN=…,O=…,C=…), pas avec l'ordre d'openssl
        ejdn = ca["dn"] or (info["subject"] if info else "")
        if ejdn:
            u = public_urls(host, port, ejdn)
            item["crlUrl"], item["certUrl"] = u["crl"], u["cert"]
        crl = crls.get(ejdn.lower()) if ejdn else None
        if crl and crl["der"]:
            item["crl"] = {"number": crl["number"], "thisUpdate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(crl["this"] / 1000)) if crl["this"] else "",
                           "nextUpdate": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(crl["next"] / 1000)) if crl["next"] else "", "bytes": len(crl["der"])}
        # fichiers publics (certificat, chaîne, demande, CRL) : seulement pour un nom sûr comme nom de dossier
        if NAME_RE.fullmatch(name) and not name.startswith("."):
            d = os.path.join(out_dir, name)
            os.makedirs(d, mode=0o755, exist_ok=True)
            os.chmod(d, 0o755)
            keep.add(name)
            wanted = {}
            if info:
                chain, cur, seen = [], info, set()
                wanted["cert.pem"] = certs[info["subject"].lower()]["pem"].encode()
                while cur and cur["issuer"] != cur["subject"] and cur["issuer"].lower() in certs and cur["issuer"].lower() not in seen:
                    seen.add(cur["issuer"].lower())
                    p = certs[cur["issuer"].lower()]
                    chain.append(p["pem"])
                    cur = describe_cert(p["der"])
                ext = os.path.join(ca_dir, name, "chain.pem")
                if not chain and os.path.isfile(ext) and not os.path.islink(ext):
                    with open(ext, "rb") as f:
                        chain.append(f.read().decode("ascii", "replace"))
                wanted["chain.pem"] = ("".join(chain)).encode() if chain else b""
            csr = os.path.join(ca_dir, name, "csr.pem")
            if state == "waiting" and os.path.isfile(csr) and not os.path.islink(csr):
                with open(csr, "rb") as f:
                    wanted["csr.pem"] = f.read(8192)
            if crl and crl["der"]:
                wanted["crl.der"] = crl["der"]
            for fn in ("cert.pem", "chain.pem", "csr.pem", "crl.der"):
                p = os.path.join(d, fn)
                if fn in wanted and wanted[fn]:
                    atomic_write(p, wanted[fn])
                    item["files"][fn.split(".")[0]] = True
                elif os.path.lexists(p):
                    os.unlink(p)
        listing.append(item)
    if os.path.isdir(out_dir):
        for n in os.listdir(out_dir):
            if n not in keep and NAME_RE.fullmatch(n):
                p = os.path.join(out_dir, n)
                if os.path.isdir(p) and not os.path.islink(p):
                    for fn in os.listdir(p):
                        os.unlink(os.path.join(p, fn))
                    os.rmdir(p)
    doc = {"at": int(time.time()), "ok": True, "hostname": host, "port": port, "cas": listing}
    atomic_write(os.path.join(run_dir, "pki-cas.json"), (json.dumps(doc, ensure_ascii=False) + "\n").encode())
    return 0


# ---------- 0.14.5 : sauvegarde des secrets et du volume de la PKI (lot chiffré par la clé PUBLIQUE de récupération) ----------
# Le lot (archive tar.gz) contient les secrets d'EJBCA (ejbca.env, instance.json), les métadonnées des autorités (ca/) et le volume du conteneur (persistent/, sans work/).
# root le chiffre avec le certificat de récupération (openssl cms) : la clé privée correspondante n'existe jamais sur l'appliance. À la restauration, tout ce qui sort du lot
# est traité comme hostile : types de fichiers, noms, tailles et contenu des deux fichiers de secrets sont revalidés avant que quoi que ce soit ne soit installé.
BUNDLE_FORMAT = 1
BUNDLE_MAX_PLAIN = 64 << 20        # 64 Mio de données avant compression, au total
BUNDLE_MAX_FILE = 32 << 20
BUNDLE_MAX_FILES = 5000
RECOVERY_MIN_BITS = 3072
RECOVERY_MIN_LEFT = 365 * 86400    # le certificat de récupération doit rester valable au moins un an
ENV_SECRET_RE = re.compile(r"[A-Za-z0-9]{20,64}")
ENV_LINE_RE = re.compile(r"([A-Z][A-Z0-9_]{0,63})=([A-Za-z0-9._:/@+-]{0,200})")
ENV_REQUIRED = ("PASSWORD_ENCRYPTION_KEY", "CA_KEYSTOREPASS", "EJBCA_CLI_DEFAULTPASSWORD", "DATABASE_USER", "DATABASE_PASSWORD", "DATABASE_JDBC_URL", "HTTPSERVER_HOSTNAME", "TLS_SETUP_ENABLED")
ENV_SECRETS = ("PASSWORD_ENCRYPTION_KEY", "CA_KEYSTOREPASS", "EJBCA_CLI_DEFAULTPASSWORD", "DATABASE_PASSWORD")
CA_DIR_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,47}")
CA_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
PERSIST_PART_RE = re.compile(r"[^\x00-\x1f\x7f/\\]{1,200}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
TAG_RE = re.compile(r"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}")


def validate_env(text):
    """ejbca.env restauré : mêmes formes que celles que ddibuntu-pki écrit ; sinon ValueError. Retourne le dictionnaire."""
    d = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        m = ENV_LINE_RE.fullmatch(line)
        if not m:
            raise ValueError("ejbca.env : ligne illisible")
        if m.group(1) in d:
            raise ValueError("ejbca.env : clé en double (%s)" % m.group(1))
        d[m.group(1)] = m.group(2)
    for k in ENV_REQUIRED:
        if k not in d:
            raise ValueError("ejbca.env : %s manquante" % k)
    for k in ENV_SECRETS:
        if not ENV_SECRET_RE.fullmatch(d[k]):
            raise ValueError("ejbca.env : %s invalide" % k)
    if d["DATABASE_USER"] != "ejbca" or d["DATABASE_JDBC_URL"] != "jdbc:postgresql://127.0.0.1:5432/ejbca" or d["TLS_SETUP_ENABLED"] != "true":
        raise ValueError("ejbca.env : réglages de base inattendus")
    if not (HOST_RE.fullmatch(d["HTTPSERVER_HOSTNAME"]) and not re.search(r"\.[0-9]+$", d["HTTPSERVER_HOSTNAME"])):
        raise ValueError("ejbca.env : nom public invalide")
    return d


def validate_instance(text):
    try:
        d = json.loads(text)
    except Exception:
        raise ValueError("instance.json illisible")
    if not isinstance(d, dict):
        raise ValueError("instance.json invalide")
    host, tag, dig, nets = d.get("hostname"), d.get("tag"), d.get("digest"), d.get("nets", "")
    if not (isinstance(host, str) and HOST_RE.fullmatch(host) and not re.search(r"\.[0-9]+$", host)):
        raise ValueError("instance.json : nom public invalide")
    if not (isinstance(tag, str) and TAG_RE.fullmatch(tag)):
        raise ValueError("instance.json : version invalide")
    if not (isinstance(dig, str) and (dig == "" or DIGEST_RE.fullmatch(dig))):
        raise ValueError("instance.json : empreinte invalide")
    if not (isinstance(nets, str) and len(nets) <= 4096 and all(NET_RE.fullmatch(n) for n in nets.split(",") if n)):
        raise ValueError("instance.json : réseaux invalides")
    return d


def _bundle_sources(petc, pdata):
    """(chemin source, nom dans le lot, type) ; ni lien symbolique ni fichier spécial. Le dossier d'échange de la CLI (persistent/work) n'est jamais sauvegardé."""
    out, skipped = [], 0
    for n in ("ejbca.env", "instance.json"):
        p = os.path.join(petc, n)
        st = os.lstat(p) if os.path.lexists(p) else None
        if st is None:
            if n == "ejbca.env":
                raise ValueError("ejbca.env absent : rien à sauvegarder")
            continue
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("%s n'est pas un fichier ordinaire" % n)
        out.append((p, "etc/" + n, "f"))
    for sub in ("ca", "persistent"):
        base = os.path.join(pdata, sub)
        if not os.path.isdir(base) or os.path.islink(base):
            continue
        out.append((base, "data/" + sub, "d"))
        for root, dirs, files in os.walk(base, followlinks=False):
            if sub == "persistent" and os.path.normpath(root) == os.path.normpath(base):
                dirs[:] = [x for x in dirs if x != "work"]
            dirs.sort()
            for x in list(dirs):
                p = os.path.join(root, x)
                if os.path.islink(p):
                    dirs.remove(x)
                    skipped += 1
                    continue
                out.append((p, "data/" + sub + "/" + os.path.relpath(p, base).replace(os.sep, "/"), "d"))
            for x in sorted(files):
                p = os.path.join(root, x)
                st = os.lstat(p)
                if not stat.S_ISREG(st.st_mode):
                    skipped += 1
                    continue
                out.append((p, "data/" + sub + "/" + os.path.relpath(p, base).replace(os.sep, "/"), "f"))
    return out, skipped


def cmd_bundle_pack(argv):
    # bundle-pack SORTIE.tgz PETC PDATA → JSON de synthèse sur la sortie standard (ERR<TAB>message et code 1 en cas d'échec)
    import tarfile
    out, petc, pdata = argv[0], argv[1], argv[2]
    try:
        items, skipped = _bundle_sources(petc, pdata)
        files = [i for i in items if i[2] == "f"]
        if len(items) > BUNDLE_MAX_FILES:
            raise ValueError("trop de fichiers (%d)" % len(items))
        total = 0
        for p, _, _ in files:
            sz = os.lstat(p).st_size
            if sz > BUNDLE_MAX_FILE:
                raise ValueError("fichier trop gros : %s" % os.path.basename(p))
            total += sz
        if total > BUNDLE_MAX_PLAIN:
            raise ValueError("volume trop gros (%d Mio ; limite %d)" % (total >> 20, BUNDLE_MAX_PLAIN >> 20))
        inst = {}
        try:
            with open(os.path.join(petc, "instance.json"), encoding="utf-8") as f:
                inst = json.load(f)
        except (OSError, ValueError):
            pass
        if not isinstance(inst, dict):
            inst = {}
        cas = sorted(n for n in (os.listdir(os.path.join(pdata, "ca")) if os.path.isdir(os.path.join(pdata, "ca")) else []) if CA_DIR_RE.fullmatch(n))
        manifest = {"format": BUNDLE_FORMAT, "createdAt": int(time.time()), "hostname": str(inst.get("hostname", ""))[:253], "tag": str(inst.get("tag", ""))[:24],
                    "cas": cas[:200], "files": len(files), "bytes": total}
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz", compresslevel=6) as tf:
            data = (json.dumps(manifest) + "\n").encode()
            ti = tarfile.TarInfo("MANIFEST.json")
            ti.size, ti.mode, ti.mtime = len(data), 0o600, manifest["createdAt"]
            tf.addfile(ti, io.BytesIO(data))
            for p, arc, kind in items:
                ti = tf.gettarinfo(p, arc)
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                ti.mode &= 0o777
                if kind == "d":
                    tf.addfile(ti)
                else:
                    with open(p, "rb") as f:
                        tf.addfile(ti, f)
        manifest["skipped"] = skipped
        print(json.dumps(manifest))
        return 0
    except (OSError, ValueError, tarfile.TarError) as e:
        print("ERR\t%s" % e)
        return 1


def _bundle_name_ok(name):
    parts = name.split("/")
    if name == "MANIFEST.json":
        return "manifest"
    if name in ("etc/ejbca.env", "etc/instance.json"):
        return "secret"
    if len(parts) >= 2 and parts[0] == "etc":
        return None
    if parts[:1] == ["data"] and len(parts) >= 2 and parts[1] in ("ca", "persistent"):
        if len(parts) > 14 or any(p in ("", ".", "..") for p in parts):
            return None
        if parts[1] == "ca":
            if len(parts) == 2:
                return "dir"
            if not CA_DIR_RE.fullmatch(parts[2]) or len(parts) > 4:
                return None
            if len(parts) == 4 and not CA_FILE_RE.fullmatch(parts[3]):
                return None
            return "ca"
        if parts[2:3] == ["work"]:
            return None
        return "persist" if all(PERSIST_PART_RE.fullmatch(p) for p in parts[2:]) else None
    return None


def cmd_bundle_extract(argv):
    # bundle-extract ARCHIVE.tgz DEST : revalide chaque entrée, extrait sous DEST (etc/ et data/), valide les secrets ; imprime le manifeste (JSON) ou ERR<TAB>message
    import tarfile
    src, dest = argv[0], argv[1]
    manifest = None
    try:
        total = count = 0
        with tarfile.open(src, mode="r:gz") as tf:
            members = []
            for m in tf:
                count += 1
                if count > BUNDLE_MAX_FILES + 8:
                    raise ValueError("lot refusé : trop d'entrées")
                if not (m.isfile() or m.isdir()):
                    raise ValueError("lot refusé : entrée de type interdit (%s)" % m.name[:60])
                kind = _bundle_name_ok(m.name)
                if kind is None or (m.isdir() and kind in ("manifest", "secret")) or (m.isfile() and kind == "dir"):
                    raise ValueError("lot refusé : nom inattendu (%s)" % m.name[:60])
                if m.isfile():
                    if m.size > BUNDLE_MAX_FILE:
                        raise ValueError("lot refusé : fichier trop gros")
                    total += m.size
                    if total > BUNDLE_MAX_PLAIN + (1 << 20):
                        raise ValueError("lot refusé : volume excessif")
                members.append(m)
            names = [m.name for m in members]
            if len(set(names)) != len(names):
                raise ValueError("lot refusé : entrées en double")
            if "MANIFEST.json" not in names or "etc/ejbca.env" not in names:
                raise ValueError("lot incomplet (manifeste ou ejbca.env absent)")
            os.makedirs(dest, mode=0o700, exist_ok=True)
            dmodes = []
            for m in members:
                target = os.path.join(dest, m.name)
                if m.isdir():
                    os.makedirs(target, mode=0o700, exist_ok=True)
                    dmodes.append((target, m.mode & 0o777))
                    continue
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as f:
                    r = tf.extractfile(m)
                    left = m.size
                    while left > 0:
                        chunk = r.read(min(left, 1 << 20))
                        if not chunk:
                            raise ValueError("lot tronqué")
                        f.write(chunk)
                        left -= len(chunk)
                os.chmod(target, m.mode & 0o777)
            for t, mode in reversed(dmodes):
                os.chmod(t, mode | 0o700)   # root doit pouvoir descendre partout ; les modes d'origine sont rétablis à l'installation
        with open(os.path.join(dest, "MANIFEST.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        if not isinstance(manifest, dict) or manifest.get("format") != BUNDLE_FORMAT:
            raise ValueError("format de lot inconnu (%s) : cette version ne sait relire que le format %d" % (str(manifest.get("format"))[:8] if isinstance(manifest, dict) else "?", BUNDLE_FORMAT))
        with open(os.path.join(dest, "etc/ejbca.env"), encoding="utf-8") as f:
            env = validate_env(f.read())
        ip = os.path.join(dest, "etc/instance.json")
        if os.path.exists(ip):
            with open(ip, encoding="utf-8") as f:
                inst = validate_instance(f.read())
            if inst["hostname"] != env["HTTPSERVER_HOSTNAME"]:
                raise ValueError("le nom public d'instance.json ne correspond pas à celui d'ejbca.env")
        out = {k: manifest.get(k) for k in ("format", "createdAt", "hostname", "tag", "cas", "files", "bytes")}
        out["hasInstance"] = os.path.exists(ip)
        print(json.dumps(out))
        return 0
    except (OSError, ValueError, tarfile.TarError, EOFError, json.JSONDecodeError) as e:
        print("ERR\t%s" % e)
        return 1


def _recovery_facts(der):
    """Certificat de récupération (DER) → (empreinte SHA-256, bits RSA, fin de validité en secondes, sujet) ; ValueError s'il ne convient pas."""
    rc, text, _ = openssl(["x509", "-inform", "DER", "-noout", "-text"], der)
    if rc != 0:
        raise ValueError("certificat illisible")
    if "rsaEncryption" not in text:
        raise ValueError("clé RSA attendue (la clé de récupération est une clé RSA de %d bits au moins)" % RECOVERY_MIN_BITS)
    m = re.search(r"Public-Key:\s*\((\d+) bit\)", text)
    bits = int(m.group(1)) if m else 0
    if bits < RECOVERY_MIN_BITS:
        raise ValueError("clé RSA de %d bits refusée (%d bits au moins)" % (bits, RECOVERY_MIN_BITS))
    rc, out, _ = openssl(["x509", "-inform", "DER", "-noout", "-enddate"], der)
    mm = re.search(r"notAfter=(.+)", out)
    try:
        end = calendar.timegm(time.strptime(mm.group(1).strip(), "%b %d %H:%M:%S %Y %Z")) if mm else 0
    except ValueError:
        end = 0
    if end <= 0:
        raise ValueError("date de fin de validité illisible")
    rc, sub, _ = openssl(["x509", "-inform", "DER", "-noout", "-subject", "-nameopt", "RFC2253"], der)
    subject = "".join(ch for ch in sub.strip().replace("subject=", "", 1) if ch.isprintable())[:100]
    return hashlib.sha256(der).hexdigest(), bits, end, subject


def cmd_recovery_check(argv):
    # recovery-check SRC DEST : le dépôt de la console doit être UN certificat RSA (3072 bits au moins, valable un an au moins) avec lequel openssl sait chiffrer ; écrit le PEM canonique
    src, dest = argv[0], argv[1]
    try:
        data = read_deposit(src, 8192)
        ders = parse_certs(data)
        if len(ders) != 1:
            raise ValueError("un seul certificat est attendu")
        fp, bits, end, subject = _recovery_facts(ders[0])
        if end - time.time() < RECOVERY_MIN_LEFT:
            raise ValueError("le certificat expire dans moins d'un an")
        pem = pem_of(ders[0])
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "c.pem")
            write_secret(p, pem.encode())
            rc, _, err = openssl(["cms", "-encrypt", "-aes256", "-binary", "-outform", "DER", "-recip", p, "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256"], b"ddibuntu-recovery-test")
            if rc != 0:
                raise ValueError("ce certificat ne permet pas de chiffrer")
        write_secret(dest, pem.encode())
        print("OK\t%s\t%d\t%d" % (fp, bits, end))
        return 0
    except (OSError, ValueError) as e:
        print("ERR\t%s" % e)
        return 1


def cmd_recovery_info(argv):
    # recovery-info CERT.pem → JSON {fingerprint, bits, notAfter, subject, registeredAt} ; code 1 s'il est absent ou illisible
    try:
        with open(argv[0], "rb") as f:
            ders = parse_certs(f.read(8192))
        fp, bits, end, subject = _recovery_facts(ders[0])
        at = int(os.stat(argv[0]).st_mtime)
    except (OSError, ValueError, IndexError):
        return 1
    print(json.dumps({"fingerprint": fp, "bits": bits, "notAfter": end, "subject": subject, "registeredAt": at}))
    return 0


# ---- Mises à jour de l'image d'EJBCA (0.14.7) ----
VER_RE = re.compile(r"([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,3})")
DOCS_BASE = "https://docs.keyfactor.com/ejbca/latest/"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
JOB_STATES = ("idle", "running", "pending", "validated", "failed", "rolled_back")
JOB_KEYS_STR = ("state", "step", "from", "to", "fromDigest", "toDigest", "message", "backup", "reason")
JOB_KEYS_INT = ("startedAt", "finishedAt", "updatedAt", "certsAtBackup", "casAtBackup", "backupBytes")


def ver(t):
    m = VER_RE.fullmatch(t) if isinstance(t, str) else None
    return tuple(int(x) for x in m.groups()) if m else None


def update_policy(cur, dbtag, target):
    """« ok » ou le motif du refus. La base ne se rouvre jamais avec une image plus ancienne que celle qui l'a migrée ; un saut de version
    majeure n'est pas essayé (le DDI ne valide que les mises à jour à l'intérieur d'une série, par exemple 9.3.7 → 9.6.3)."""
    c, t = ver(cur), ver(target)
    d = ver(dbtag) or c
    if not (c and d and t):
        return "invalid"
    if t == c:
        return "same"
    if t < d:
        return "older_than_db"
    if t < c:
        return "older"
    if t[0] != c[0]:
        return "major_jump"
    return "ok"


def notes_of(t):
    v = ver(t)
    if not v:
        return {}
    return {"release": "%sejbca-%d-%d-release-notes" % (DOCS_BASE, v[0], v[1]), "upgrade": "%sejbca-%d-%d-upgrade-notes" % (DOCS_BASE, v[0], v[1])}


def kind_of(cur, target):
    c, t = ver(cur), ver(target)
    return "major" if t[0] != c[0] else ("minor" if t[1] != c[1] else "patch")


def _atomic_json(path, obj):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".upd.", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, ensure_ascii=False)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json(path):
    try:
        with open(path, "rb") as f:
            d = json.loads(f.read(1 << 20).decode("utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def cmd_update_policy(argv):
    if len(argv) != 3:
        return 2
    r = update_policy(argv[0], argv[1], argv[2])
    print(r)
    return 0 if r == "ok" else 1


def cmd_update_cmp(argv):
    a, b = (ver(x) for x in argv[:2]) if len(argv) == 2 else (None, None)
    if not (a and b):
        return 2
    print((a > b) - (a < b))
    return 0


def cmd_update_check_write(argv):
    # update-check-write FICHIER COURANTE ÉTIQUETTE_DE_LA_BASE (TAGS.json | --error CODE) : écrit la recherche ; une erreur garde la dernière liste connue
    if len(argv) != 4:
        return 2
    path, cur, dbtag, src = argv
    old = _read_json(path)
    out = {"checkedAt": int(time.time()), "error": "", "latest": old.get("latest"), "available": old.get("available", [])}
    if src == "--error":
        return 2
    if src.startswith("--error="):
        out["error"] = re.sub(r"[^a-z_]", "", src[8:])[:40] or "error"
    else:
        try:
            with open(src, "rb") as f:
                d = json.loads(f.read(4 << 20).decode("utf-8"))
            rows = d["results"]
            if not isinstance(rows, list):
                raise ValueError("results n'est pas une liste")
        except (OSError, ValueError, KeyError):
            out["error"] = "bad_answer"
            _atomic_json(path, out)
            return 0
        seen, items = set(), []
        for r in rows[:200]:
            if not isinstance(r, dict):
                continue
            t = r.get("name")
            if not (isinstance(t, str) and ver(t)) or t in seen or ver(t) <= (ver(cur) or (0, 0, 0)):
                continue
            seen.add(t)
            why = update_policy(cur, dbtag, t)
            dg = r.get("digest")
            at = r.get("last_updated")
            items.append({"tag": t, "pushedAt": at[:10] if isinstance(at, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}.*", at) else "",
                          "kind": kind_of(cur, t), "allowed": why == "ok", "reason": "" if why == "ok" else why,
                          "digest": dg if isinstance(dg, str) and DIGEST_RE.fullmatch(dg) else "", "notes": notes_of(t)})
        items.sort(key=lambda i: ver(i["tag"]), reverse=True)
        out["available"] = items[:20]
        ok = [i for i in items if i["allowed"]]
        out["latest"] = ok[0]["tag"] if ok else None
    _atomic_json(path, out)
    return 0


def cmd_update_job(argv):
    # update-job FICHIER init DE VERS EMPREINTE ÉTAPE… | set clé=valeur… | step ÉTAPE ÉTAT | check ID OK(true|false) DÉTAIL | steps ÉTAPE…
    if len(argv) < 2:
        return 2
    path, op, args = argv[0], argv[1], argv[2:]
    job = _read_json(path)
    now = int(time.time())
    if op == "init":
        if len(args) < 4 or not (ver(args[0]) and ver(args[1])):
            return 2
        job = {"state": "running", "step": args[3], "from": args[0], "to": args[1], "fromDigest": args[2], "toDigest": "", "message": "", "backup": "",
               "startedAt": now, "finishedAt": 0, "updatedAt": now, "certsAtBackup": -1, "casAtBackup": -1, "backupBytes": 0, "reason": "",
               "steps": [{"id": x, "status": "todo"} for x in args[3:]], "checks": []}
    elif op == "set":
        for kv in args:
            k, _, v = kv.partition("=")
            if k in JOB_KEYS_STR:
                if k == "state" and v not in JOB_STATES:
                    return 2
                if k in ("fromDigest", "toDigest") and v and not DIGEST_RE.fullmatch(v):
                    return 2
                job[k] = re.sub(r"[\x00-\x1f\x7f]", " ", v)[:300]
            elif k in JOB_KEYS_INT and re.fullmatch(r"-?[0-9]{1,12}", v):
                job[k] = int(v)
            else:
                return 2
    elif op == "steps":
        job["steps"] = [{"id": x, "status": "todo"} for x in args if re.fullmatch(r"[a-z_]{1,24}", x)]
        job["checks"] = []
        if job["steps"]:
            job["step"] = job["steps"][0]["id"]
    elif op == "step":
        if len(args) != 2 or args[1] not in ("todo", "running", "done", "failed") or not re.fullmatch(r"[a-z_]{1,24}", args[0]):
            return 2
        steps = job.setdefault("steps", [])
        row = next((x for x in steps if x.get("id") == args[0]), None)
        if row is None:
            row = {"id": args[0], "status": "todo"}
            steps.append(row)
        row["status"] = args[1]
        if args[1] == "running":
            job["step"] = args[0]
    elif op == "check":
        if len(args) < 2 or args[1] not in ("true", "false") or not re.fullmatch(r"[a-z_]{1,24}", args[0]):
            return 2
        checks = [c for c in job.get("checks", []) if c.get("id") != args[0]]
        checks.append({"id": args[0], "ok": args[1] == "true", "detail": re.sub(r"[\x00-\x1f\x7f]", " ", " ".join(args[2:]))[:200]})
        job["checks"] = checks
    else:
        return 2
    job["updatedAt"] = now
    _atomic_json(path, job)
    return 0


def cmd_update_publish(argv):
    # update-publish RECHERCHE.json TÂCHE.json COURANTE ÉTIQUETTE_DE_LA_BASE NOMBRE_DE_CERTIFICATS_ACTUEL (-1 si illisible) : JSON public
    if len(argv) != 5:
        return 2
    chk, jobp, cur, dbtag, certs = argv
    c, job = _read_json(chk), _read_json(jobp)
    try:
        certs_now = int(certs)
    except ValueError:
        certs_now = -1
    keep = ("state", "step", "from", "to", "fromDigest", "toDigest", "message", "backup", "startedAt", "finishedAt", "updatedAt", "certsAtBackup", "casAtBackup",
            "backupBytes", "reason", "steps", "checks")
    pub = {k: job[k] for k in keep if k in job}
    can_rollback = bool(job.get("backup")) and job.get("state") in ("pending", "failed", "running")
    pub["rollbackAvailable"] = can_rollback
    since = None
    if can_rollback and certs_now >= 0 and isinstance(job.get("certsAtBackup"), int) and job["certsAtBackup"] >= 0:
        since = max(0, certs_now - job["certsAtBackup"])
    # la liste de Docker Hub date de la dernière recherche : elle est rejugée ici par rapport à la version installée AUJOURD'HUI (après une mise à jour,
    # ce qui est devenu ancien disparaît sans attendre la recherche suivante, et le motif de refus suit la nouvelle base)
    avail = []
    for it in c.get("available", []):
        t = it.get("tag") if isinstance(it, dict) else None
        if not (isinstance(t, str) and ver(t) and ver(cur) and ver(t) > ver(cur)):
            continue
        why = update_policy(cur, dbtag or cur, t)
        it = dict(it, kind=kind_of(cur, t), allowed=why == "ok", reason="" if why == "ok" else why)
        avail.append(it)
    ok_tags = [i["tag"] for i in avail if i["allowed"]]
    out = {"at": int(time.time()), "current": cur, "dbTag": dbtag or cur, "checkedAt": c.get("checkedAt", 0), "checkError": c.get("error", ""),
           "latest": ok_tags[0] if ok_tags else None, "available": avail, "job": pub if pub.get("state") else None, "certsSince": since,
           "docs": {"upgrading": DOCS_BASE + "ejbca-upgrade-notes"}}
    print(json.dumps(out, ensure_ascii=False))
    return 0


def cmd_update_digest(argv):
    # update-digest RECHERCHE.json ÉTIQUETTE → empreinte (sha256:…) annoncée par Docker Hub ; rien si elle est inconnue
    if len(argv) != 2 or not ver(argv[1]):
        return 2
    for it in _read_json(argv[0]).get("available", []):
        if isinstance(it, dict) and it.get("tag") == argv[1] and isinstance(it.get("digest"), str) and DIGEST_RE.fullmatch(it["digest"]):
            print(it["digest"])
    return 0


def cmd_update_crl_urls(argv):
    # update-crl-urls PKI-CAS.json PORT : une adresse locale (127.0.0.1) par CRL d'autorité active ; l'adresse publique, elle, dépend du DNS
    if len(argv) != 2 or not re.fullmatch(r"[0-9]{2,5}", argv[1]):
        return 2
    d = _read_json(argv[0])
    for ca in d.get("cas", []):
        u = ca.get("crlUrl") if ca.get("state") == "active" else None
        if not (isinstance(u, str) and u.startswith("http")):
            continue
        r = urllib.parse.urlsplit(u)
        if r.path.startswith("/ejbca/") and "\n" not in u and "\t" not in u:
            print("%s\thttp://127.0.0.1:%s%s?%s" % (ca.get("name", ""), argv[1], r.path, r.query))
    return 0


def cmd_scep_pw(argv):
    # scep-pw FICHIER : lit le mot de passe à usage unique déposé par la console (lien symbolique refusé) ; imprime le mot de passe, ou « ERR<TAB>motif »
    if len(argv) != 1:
        return 2
    try:
        raw = read_deposit(argv[0], 256)
        pw = raw.decode("ascii").strip()
    except (OSError, ValueError, UnicodeDecodeError) as e:
        print("ERR\tmot de passe d'enregistrement absent ou illisible (%s)" % e.__class__.__name__)
        return 1
    if not SCEP_PW_RE.fullmatch(pw):
        print("ERR\tmot de passe d'enregistrement refusé : 16 à 64 lettres ou chiffres attendus")
        return 1
    print(pw)
    return 0


def _clean(v, n=300):
    return re.sub(r"[\x00-\x1f\x7f]", "", v or "")[:n]


def cmd_scep_publish(argv):
    # scep-publish ACTIVÉ(0|1) JOURS HÔTE PORT < TSV : pki-scep.json (données publiques). TSV = une ligne par équipement préenregistré (voir scep_publish)
    if len(argv) != 4:
        return 2
    enabled, days, host, port = argv[0] == "1", int(argv[1]) if argv[1].isdigit() else 7, argv[2], argv[3]
    now = int(time.time())
    offers = []
    for line in sys.stdin:
        f = line.rstrip("\n").split("\t")
        if len(f) < 12 or not SCEP_CN_RE.fullmatch(f[0]):
            continue
        cn, st = f[0], int(f[1]) if f[1].lstrip("-").isdigit() else -1
        created, modified = (int(x) // 1000 if x.isdigit() else 0 for x in (f[2], f[3]))
        exp = modified + days * 86400
        cert = None
        if f[8].isdigit():
            na = int(f[9]) // 1000 if f[9].isdigit() else 0
            cert = {"serial": "%X" % int(f[8]), "notAfter": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(na)) if na else "",
                    "revoked": f[10] == "40", "sha1": f[11] if re.fullmatch(r"[0-9a-f]{40}", f[11]) else ""}
        if st in (10, 11):
            state = "failed" if st == 11 else ("expired" if exp <= now else "waiting")
        elif st == 40:
            state = "issued"
        elif st in (50, 60):
            state = "revoked"
        else:
            state = "other"
        pid = int(f[5]) if f[5].isdigit() else 0
        offers.append({"cn": cn, "state": state, "status": st, "ca": _clean(f[4], 48), "profile": SCEP_PROFILE_OF.get(pid, ""), "dn": _clean(f[6]), "san": _clean(f[7]),
                       "createdAt": created, "modifiedAt": modified, "expiresAt": exp if st in (10, 11) else None, "cert": cert})
    path = "/ejbca/publicweb/apply/scep/%s/pkiclient.exe" % SCEP_ALIAS
    print(json.dumps({"at": now, "enabled": enabled, "alias": SCEP_ALIAS, "path": path, "port": int(port) if port.isdigit() else 8080,
                      "url": "http://%s:%s%s" % (host, port, path) if host else "", "offerDays": days, "offers": offers}, ensure_ascii=False))
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    args = sys.argv[2:]
    if cmd == "parse-request":
        return parse_request()
    if cmd == "deposit":
        return cmd_deposit(args)
    if cmd == "check-issued":
        return cmd_check_issued(args)
    if cmd == "check-leaf":
        return cmd_check_leaf(args)
    if cmd == "hex2dec":
        return cmd_hex2dec(args)
    if cmd == "check-chain":
        return cmd_check_chain(args)
    if cmd == "p12-check":
        return cmd_p12_check(args)
    if cmd == "dn-find":
        return cmd_dn_find(args)
    if cmd == "check-crl":
        return cmd_check_crl(args)
    if cmd == "publish-cas":
        return cmd_publish_cas(args)
    if cmd == "urls":
        return cmd_urls(args)
    if cmd == "b64pem":
        return cmd_b64pem(args)
    if cmd == "bundle-pack":
        return cmd_bundle_pack(args)
    if cmd == "bundle-extract":
        return cmd_bundle_extract(args)
    if cmd == "recovery-check":
        return cmd_recovery_check(args)
    if cmd == "recovery-info":
        return cmd_recovery_info(args)
    if cmd == "update-policy":
        return cmd_update_policy(args)
    if cmd == "update-cmp":
        return cmd_update_cmp(args)
    if cmd == "update-check-write":
        return cmd_update_check_write(args)
    if cmd == "update-job":
        return cmd_update_job(args)
    if cmd == "update-publish":
        return cmd_update_publish(args)
    if cmd == "update-digest":
        return cmd_update_digest(args)
    if cmd == "update-crl-urls":
        return cmd_update_crl_urls(args)
    if cmd == "scep-pw":
        return cmd_scep_pw(args)
    if cmd == "scep-publish":
        return cmd_scep_publish(args)
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
