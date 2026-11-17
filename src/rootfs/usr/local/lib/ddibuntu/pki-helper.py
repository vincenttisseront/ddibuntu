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
"""
import base64
import calendar
import hashlib
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
    if a in ("start", "stop", "restart", "status", "uninstall", "reset"):
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
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
