#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ddibuntu-cluster : test de bascule guidé (pré-contrôles, bascule mesurée, rapport).

Lancé par « ddibuntu-cluster drill | drill-check » (root, nœud de données). Aucun secret n'est lu ni écrit ici : la configuration arrive par
l'environnement DRILL_* ; les appels à l'API Patroni utilisent le certificat du nœud (TLS mutuel). La bascule elle-même est confiée à
« ddibuntu-cluster switchover » (la seule voie qui parle à patronictl).

  check : pré-contrôles → un JSON {ok, leader, candidate, candidates[], checks[]}
  run   : pré-contrôles, puis bascule(s) mesurée(s). Sortie : des lignes JSON {"type":"live",…} pendant le test, puis {"type":"report",…}.

Mesures (échantillonnage de l'API Patroni de chaque nœud de données, toutes les DDI_DRILL_POLL secondes, 0,5 par défaut) :
  fenêtre sans primaire, promotion, rétrogradation et réintégration de l'ancien primaire, rattrapage de la réplication, ligne de temps,
  continuité de la position WAL (aucune perte), état du quorum etcd, de Kea HA et de l'adresse virtuelle de CE nœud.
Limite assumée : la précision est celle de l'échantillonnage (indiquée dans le rapport) ; l'écriture applicative n'est pas simulée (la sonde
« primaire » de Patroni — PostgreSQL hors récupération — fait foi).
"""
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

NAME = re.compile(r"^[a-z][a-z0-9-]{1,30}$")
ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")


def env(k, d=""):
    return os.environ.get(k, d)


def fenv(k, d):
    try:
        return float(os.environ.get(k, d))
    except ValueError:
        return float(d)


POLL = max(0.1, fenv("DDI_DRILL_POLL", "0.5"))
SETTLE = fenv("DDI_DRILL_SETTLE", "150")              # délai maximal pour retrouver un cluster stable après une bascule (s)
CMD_TIMEOUT = fenv("DDI_DRILL_CMD_TIMEOUT", "120")     # délai maximal de la commande de bascule (s)
PAUSE = fenv("DDI_DRILL_PAUSE", "5")                   # pause entre la bascule et le retour (s)
MAX_LAG = int(fenv("DDI_DRILL_MAX_LAG", "1048576"))    # retard de réplication toléré avant la bascule (octets)
CATCHUP_LAG = int(fenv("DDI_DRILL_CATCHUP_LAG", "16384"))   # « rattrapé » : retard inférieur à ceci (octets)
GAP_OK, GAP_WARN = fenv("DDI_DRILL_GAP_OK_MS", "15000"), fenv("DDI_DRILL_GAP_WARN_MS", "30000")        # fenêtre sans primaire (ms)
PROMO_OK, PROMO_WARN = fenv("DDI_DRILL_PROMO_OK_MS", "30000"), fenv("DDI_DRILL_PROMO_WARN_MS", "60000")  # promotion (ms)
REJOIN_OK, REJOIN_WARN = fenv("DDI_DRILL_REJOIN_OK_MS", "90000"), fenv("DDI_DRILL_REJOIN_WARN_MS", "150000")  # réintégration (ms)
LEADER_RE = {"master": "leader", "primary": "leader", "standby_leader": "leader", "replica": "replica"}


def now_ms():
    return int(time.time() * 1000)


def clip(s, n):
    return "".join(c for c in str(s) if c.isprintable())[:n]


def peers():
    out = []
    for p in env("DRILL_PEERS").split():
        m = re.fullmatch(r"([a-z][a-z0-9-]{1,30})=([0-9.]+):(data|witness)", p)
        if m:
            out.append({"name": m.group(1), "ip": m.group(2), "role": m.group(3)})
    return out


def jenv(k):
    try:
        return json.loads(env(k) or "null")
    except ValueError:
        return None


def health_map():
    """DRILL_HEALTH_RAW = sortie JSON d'« etcdctl get --prefix » : un enregistrement de santé par nœud (chacun jugé seul)."""
    import base64
    out = {}
    try:
        kvs = json.loads(env("DRILL_HEALTH_RAW") or "{}").get("kvs", [])[:64]
    except ValueError:
        return out
    for kv in kvs:
        try:
            name = base64.b64decode(kv["key"]).decode().rsplit("/", 1)[-1]
            raw = base64.b64decode(kv.get("value", ""))
            if NAME.match(name) and len(raw) <= 4096:
                h = json.loads(raw)
                if isinstance(h, dict) and h.get("node") == name:
                    out[name] = h
        except Exception:
            continue
    return out


# ---------------------------------------------------------------- API Patroni
class Patroni:
    def __init__(self):
        pki = env("DRILL_PKI")
        self.ctx = ssl.create_default_context(cafile=os.path.join(pki, "ca.crt"))
        self.ctx.load_cert_chain(os.path.join(pki, "node.crt"), os.path.join(pki, "node.key"))
        self.port = int(env("DRILL_PORT", "8008") or 8008)

    def get(self, ip, path, timeout=1.5):
        try:
            c = http.client.HTTPSConnection(ip, self.port, context=self.ctx, timeout=timeout)
            c.request("GET", path)
            r = c.getresponse()
            body = r.read(200000)
            c.close()
            try:
                return r.status, json.loads(body)
            except ValueError:
                return r.status, None
        except Exception:
            return None, None


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def norm(d):
    """Réponse de /patroni → échantillon normalisé (toute valeur inattendue est ignorée)."""
    if not isinstance(d, dict):
        return {"up": False}
    x = d.get("xlog") if isinstance(d.get("xlog"), dict) else {}
    tags = d.get("tags") if isinstance(d.get("tags"), dict) else {}
    return {"up": True, "role": LEADER_RE.get(d.get("role"), "other"), "state": clip(d.get("state", ""), 20), "tl": _int(d.get("timeline")),
            "lsn": _int(x.get("location")), "recv": _int(x.get("received_location")), "replay": _int(x.get("replayed_location")),
            "rstate": clip(d.get("replication_state", ""), 20), "pending": d.get("pending_restart") is True, "nofailover": tags.get("nofailover") is True}


def sample(api, pool, nodes):
    futs = {n["name"]: pool.submit(api.get, n["ip"], "/patroni") for n in nodes}
    return {name: norm(f.result()[1]) for name, f in futs.items()}


def leaders(s):
    return [n for n, x in s.items() if x.get("up") and x.get("role") == "leader" and x.get("state") == "running"]


def streaming(x):
    return bool(x.get("up") and x.get("role") == "replica" and x.get("rstate") == "streaming")


def lag_of(s, leader, name):
    a, b = s.get(leader, {}).get("lsn"), s.get(name, {}).get("replay")
    return max(0, a - b) if a is not None and b is not None else None


# ---------------------------------------------------------------- pré-contrôles
def local_vip_held():
    vip, iface = (env("DRILL_VIP").split("|") + [""])[:2]
    if not vip or not iface:
        return None
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", iface], capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return None
    return vip in [f.split() [3] for f in out.splitlines() if len(f.split()) > 3]


def check(api, pool, nodes, want):
    me = env("DRILL_NODE")
    s = sample(api, pool, nodes)
    cks = []

    def add(i, st, detail):
        cks.append({"id": i, "status": st, "detail": clip(detail, 200)})

    ld = leaders(s)
    down = [n["name"] for n in nodes if not s[n["name"]].get("up")]
    if len(nodes) < 2:
        add("topology", "fail", "moins de deux nœuds de données : aucune bascule possible")
    elif down:
        add("topology", "fail", "nœud injoignable : " + ", ".join(down))
    elif len(ld) != 1:
        add("topology", "fail", "aucun primaire" if not ld else "plusieurs primaires : " + ", ".join(ld))
    else:
        add("topology", "ok", "primaire : %s ; %d nœuds de données joignables" % (ld[0], len(nodes)))
    leader = ld[0] if len(ld) == 1 else None
    # état global (pause, bascule déjà planifiée) lu sur un nœud joignable
    cluster, config = {}, {}
    for n in sorted(nodes, key=lambda n: n["name"] != me):
        if s[n["name"]].get("up"):
            cluster = api.get(n["ip"], "/cluster")[1] or {}
            config = api.get(n["ip"], "/config")[1] or {}
            break
    paused = cluster.get("pause") is True or config.get("pause") is True
    pending_sw = bool(cluster.get("scheduled_switchover") or cluster.get("failover"))
    if paused:
        add("pause", "fail", "Patroni est en pause (restauration en cours ?) : reprendre avant de basculer")
    elif pending_sw:
        add("pause", "fail", "une bascule est déjà planifiée ou en attente")
    else:
        add("pause", "ok", "Patroni actif, aucune bascule en attente")
    maxlag = _int(config.get("maximum_lag_on_failover")) or MAX_LAG
    # candidats
    cands = []
    for n in nodes:
        nm = n["name"]
        if nm == leader:
            continue
        x, issues, lag = s[nm], [], lag_of(s, leader, nm) if leader else None
        if not x.get("up"):
            issues.append("injoignable")
        else:
            if x.get("role") != "replica":
                issues.append("n'est pas un secondaire")
            if x.get("rstate") != "streaming":
                issues.append("réplication non en continu (%s)" % (x.get("rstate") or x.get("state") or "?"))
            if x.get("nofailover"):
                issues.append("étiquette nofailover")
            if lag is not None and lag > min(maxlag, MAX_LAG):
                issues.append("retard de %d octets" % lag)
        cands.append({"name": nm, "ok": not issues, "lagBytes": lag, "issues": issues})
    cand = want if want else next(iter(sorted([c for c in cands if c["ok"]], key=lambda c: (c["lagBytes"] or 0, c["name"]))), {}).get("name")
    cobj = next((c for c in cands if c["name"] == cand), None)
    if want and cobj is None:
        add("candidate", "fail", "le candidat « %s » n'est pas un nœud de données secondaire" % clip(want, 31))
    elif cobj is None:
        add("candidate", "fail", "aucun secondaire apte à devenir primaire")
    elif not cobj["ok"]:
        add("candidate", "fail", "%s : %s" % (cand, " ; ".join(cobj["issues"])))
    else:
        add("candidate", "ok", "%s : secondaire en réplication continue" % cand)
    lag = cobj["lagBytes"] if cobj else None
    if lag is None:
        add("lag", "fail" if cobj else "skip", "retard de réplication inconnu")
    elif lag > min(maxlag, MAX_LAG):
        add("lag", "fail", "retard de %d octets (limite %d)" % (lag, min(maxlag, MAX_LAG)))
    else:
        add("lag", "ok", "retard de %d octets" % lag)
    others = [c for c in cands if c["name"] != cand and not c["ok"]]
    add("replicas", "warn" if others else "ok",
        ("secondaire(s) non sains : " + ", ".join(c["name"] for c in others)) if others else "tous les autres secondaires sont en réplication continue")
    pend = [n for n, x in s.items() if x.get("pending")]
    add("pending", "warn" if pend else "ok", ("redémarrage en attente sur : " + ", ".join(pend)) if pend else "aucun redémarrage en attente")
    q = jenv("DRILL_QUORUM")
    if not isinstance(q, dict):
        add("quorum", "warn", "état du quorum etcd illisible")
    elif not q.get("hasQuorum"):
        add("quorum", "fail", "le quorum etcd est perdu")
    elif (q.get("tolerance") or 0) < 1:
        add("quorum", "warn", "quorum etcd sans marge (%s/%s voix saines) : la perte d'un nœud le ferait tomber" % (q.get("healthy"), q.get("voters")))
    else:
        add("quorum", "ok", "quorum etcd : %s/%s voix saines, tolérance %s" % (q.get("healthy"), q.get("voters"), q.get("tolerance")))
    kea = jenv("DRILL_KEA")
    if not isinstance(kea, dict):
        add("kea", "skip", "Kea ne répond pas sur ce nœud (ou pas de DHCP)")
    elif not kea.get("ha"):
        add("kea", "skip", "haute disponibilité DHCP non configurée")
    else:
        st = (kea.get("local") or {}).get("state")
        add("kea", "ok" if st in ("hot-standby", "load-balancing") else "warn", "Kea HA : état local « %s »" % clip(st, 30))
    held = local_vip_held()
    if held is None:
        add("vip", "skip", "pas d'adresse virtuelle configurée")
    elif held == (leader == me):
        add("vip", "ok", "l'adresse virtuelle est %s sur ce nœud, comme attendu" % ("portée" if held else "absente"))
    else:
        add("vip", "warn", "l'adresse virtuelle est %s sur ce nœud alors que le primaire est %s" % ("portée" if held else "absente", leader or "inconnu"))
    health = health_map()
    if not health:
        add("services", "skip", "santé des nœuds non disponible")
    else:
        probs = []
        for n in nodes:
            h = health.get(n["name"])
            if not isinstance(h, dict) or not isinstance(h.get("at"), int):
                probs.append("%s : santé inconnue" % n["name"])
            elif time.time() - h["at"] > 300:
                probs.append("%s : santé périmée" % n["name"])
            else:
                bad = [sv.get("name") for sv in (h.get("services") or []) if isinstance(sv, dict) and sv.get("expected") and sv.get("state") != "active"]
                if bad:
                    probs.append("%s : service(s) %s" % (n["name"], ", ".join(clip(b, 20) for b in bad)))
        add("services", "warn" if probs else "ok", "; ".join(probs) if probs else "services attendus actifs sur tous les nœuds de données")
    act = jenv("DRILL_ACTIVE")
    # la marque posée par CE test (même identifiant) n'est pas « un autre test »
    if isinstance(act, dict) and isinstance(act.get("at"), int) and 0 <= time.time() - act["at"] < 1200 and (not env("DRILL_ID") or act.get("id") != env("DRILL_ID")):
        add("active", "fail", "un test de bascule est déjà en cours (%s, nœud %s)" % (clip(act.get("id"), 20), clip(act.get("node"), 31)))
    else:
        add("active", "ok", "aucun autre test en cours")
    return {"ok": not any(c["status"] == "fail" for c in cks), "at": int(time.time()), "leader": leader, "candidate": cand if cobj else None,
            "candidates": cands, "checks": cks, "samples": s}


# ---------------------------------------------------------------- moniteur
class Monitor(threading.Thread):
    def __init__(self, api, pool, nodes, t0):
        super().__init__(daemon=True)
        self.api, self.pool, self.nodes, self.t0 = api, pool, nodes, t0
        self.samples, self.events, self.stop = [], [], threading.Event()
        self.lock = threading.Lock()

    def ev(self, t, kind, node, detail):
        if len(self.events) < 600:
            self.events.append({"t": t, "kind": kind, "node": node, "detail": clip(detail, 120)})

    def run(self):
        prev = None
        while not self.stop.is_set():
            c0 = time.monotonic()
            s = sample(self.api, self.pool, self.nodes)
            t = now_ms() - self.t0
            with self.lock:
                self.samples.append((t, s))
                if prev is not None:
                    self.diff(t, prev, s)
            prev = s
            self.stop.wait(max(0.0, POLL - (time.monotonic() - c0)))

    def diff(self, t, a, b):
        for n in b:
            x, y = a.get(n, {}), b[n]
            if x.get("up") and not y.get("up"):
                self.ev(t, "node_down", n, "API Patroni injoignable")
            elif not x.get("up") and y.get("up"):
                self.ev(t, "node_up", n, "API Patroni de nouveau joignable")
            if x.get("up") and y.get("up"):
                if x.get("role") != y.get("role"):
                    self.ev(t, "role", n, "%s → %s" % (x.get("role"), y.get("role")))
                if x.get("state") != y.get("state"):
                    self.ev(t, "state", n, "%s → %s" % (x.get("state") or "?", y.get("state") or "?"))
                if x.get("rstate") != y.get("rstate") and y.get("role") == "replica":
                    self.ev(t, "repl", n, "réplication : %s → %s" % (x.get("rstate") or "?", y.get("rstate") or "?"))
                if x.get("tl") != y.get("tl") and y.get("tl") is not None:
                    self.ev(t, "timeline", n, "ligne de temps %s → %s" % (x.get("tl"), y.get("tl")))
        la, lb = leaders(a), leaders(b)
        if la != lb:
            self.ev(t, "leader", ",".join(lb) or "-", ("primaire : " + ", ".join(lb)) if lb else "plus aucun primaire")

    def snapshot(self):
        with self.lock:
            return list(self.samples), list(self.events)

    def last(self):
        with self.lock:
            return self.samples[-1][1] if self.samples else {}


# ---------------------------------------------------------------- analyse d'une phase
def verdict(v, ok, warn):
    if v is None:
        return "fail"
    return "ok" if v <= ok else ("warn" if v <= warn else "fail")


def analyse(samples, t_cmd, old, new, data_names):
    win = [(t, s) for t, s in samples if t >= t_cmd]
    base = [(t, s) for t, s in samples if t < t_cmd and leaders(s) == [old]]
    tl_before = next((s[old].get("tl") for t, s in reversed(base)), None)
    res = {"noPrimaryMs": 0, "resolutionMs": 0, "promotionMs": None, "demotionMs": None, "rejoinMs": None, "catchUpMs": None,
           "timeline": [tl_before, None], "lagMaxBytes": 0, "lsnContinuity": None}
    if not win:
        return res
    ts = [t for t, _ in win]
    res["resolutionMs"] = max([b - a for a, b in zip(ts, ts[1:])] + [int(POLL * 1000)])
    t_new = next((t for t, s in win if leaders(s) == [new]), None)
    res["promotionMs"] = None if t_new is None else t_new - t_cmd
    res["demotionMs"] = next((t - t_cmd for t, s in win if old not in leaders(s)), None)
    # fenêtre sans primaire : du dernier échantillon avec primaire au premier qui en retrouve un
    last_with, gap_start, gap = None, None, 0
    for t, s in [(t, s) for t, s in samples if t >= t_cmd - int(POLL * 2000)]:
        if leaders(s):
            if gap_start is not None:
                gap = max(gap, t - gap_start)
                gap_start = None
            last_with = t
        elif gap_start is None and last_with is not None:
            gap_start = last_with
    res["noPrimaryMs"] = None if gap_start is not None else gap
    if t_new is not None:
        tl_new = next((s[new].get("tl") for t, s in win if t == t_new), None)
        res["timeline"][1] = tl_new
        res["rejoinMs"] = next((t - t_cmd for t, s in win if t >= t_new and streaming(s.get(old, {})) and s[old].get("tl") == tl_new), None)
        others = [n for n in data_names if n != new]
        res["catchUpMs"] = next((t - t_new for t, s in win if t >= t_new and leaders(s) == [new] and all(
            streaming(s.get(n, {})) and (lag_of(s, new, n) is not None and lag_of(s, new, n) <= CATCHUP_LAG) for n in others)), None)
        old_lsn = max([s[old]["lsn"] for t, s in win if s.get(old, {}).get("role") == "leader" and s[old].get("lsn") is not None] +
                      [s[old]["lsn"] for t, s in base if s[old].get("lsn") is not None] or [None], key=lambda v: -1 if v is None else v)
        new_lsn = next((s[new]["lsn"] for t, s in win if t == t_new), None)
        if old_lsn is not None and new_lsn is not None:
            res["lsnContinuity"] = new_lsn >= old_lsn
    lm = 0
    for t, s in win:
        ld = leaders(s)
        if len(ld) == 1:
            for n in data_names:
                if n != ld[0]:
                    lg = lag_of(s, ld[0], n)
                    if lg is not None:
                        lm = max(lm, lg)
    res["lagMaxBytes"] = lm
    return res


def settled(s, target, names):
    return leaders(s) == [target] and all(streaming(s.get(n, {})) for n in names if n != target)


# ---------------------------------------------------------------- exécution
OUT_LOCK = threading.Lock()


def emit(o):
    with OUT_LOCK:
        sys.stdout.write(json.dumps(o, ensure_ascii=False, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def self_json(sub):
    try:
        out = subprocess.run([env("DRILL_SELF"), sub], capture_output=True, text=True, timeout=20).stdout
        return json.loads(out)
    except Exception:
        return None


def run():
    nodes = [n for n in peers() if n["role"] == "data"]
    names = [n["name"] for n in nodes]
    me = env("DRILL_NODE")
    did = env("DRILL_ID")
    if not ID.match(did) or not NAME.match(me):
        emit({"type": "error", "message": "identifiant de test invalide"})
        return 2
    want = env("DRILL_CAND") or None
    if want and not NAME.match(want):
        emit({"type": "error", "message": "candidat invalide"})
        return 2
    back = env("DRILL_BACK") == "1"
    api = Patroni()
    pool = ThreadPoolExecutor(max_workers=max(2, len(nodes)))
    t0 = now_ms()
    started = int(time.time())
    steps = []

    cur = {"phase": "checks"}

    def beat():
        emit({"type": "live", "id": did, "node": me, "phase": cur["phase"], "startedAt": started, "at": int(time.time()), "elapsedMs": now_ms() - t0, "steps": steps[-12:]})

    def live(phase, note):
        cur["phase"] = phase
        steps.append({"t": now_ms() - t0, "text": clip(note, 140)})
        beat()

    hb_stop = threading.Event()

    def heartbeat():      # un signe de vie toutes les 3 s (la console juge « en cours » d'après l'âge de la dernière ligne)
        while not hb_stop.wait(3):
            beat()
    threading.Thread(target=heartbeat, daemon=True).start()

    live("checks", "pré-contrôles")
    pre = check(api, pool, nodes, want)
    pre_s = pre.pop("samples")
    report = {"v": 1, "id": did, "cluster": env("DRILL_CLUSTER"), "node": me, "by": env("DRILL_BY", "cli"), "startedAt": started, "back": back,
              "from": pre["leader"], "to": pre["candidate"], "pre": {"ok": pre["ok"], "checks": pre["checks"], "candidates": pre["candidates"]},
              "phases": [], "events": [], "resolutionMs": int(POLL * 1000)}
    if not pre["ok"]:
        hb_stop.set()
        report.update(outcome="refused", message="pré-contrôles non satisfaits : aucune bascule n'a été effectuée")
        return finish(report, t0, [], [])
    old, new = pre["leader"], pre["candidate"]
    quorum0, kea0 = self_json("_quorum"), self_json("_kea")
    mon = Monitor(api, pool, nodes, t0)
    mon.start()
    t_wait = time.time() + 5
    while time.time() < t_wait and not mon.last():
        time.sleep(0.1)
    plan = [("switch", old, new)] + ([("back", new, old)] if back else [])
    failed = False
    try:
        for ph, a, b in plan:
            if failed:
                break
            live(ph, "bascule %s → %s" % (a, b))
            tc = now_ms() - t0
            mon.ev(tc, "step", a, "commande de bascule vers %s" % b)
            out, rc = "", None
            try:
                p = subprocess.run([env("DRILL_SELF"), "switchover", "--candidate", b], capture_output=True, text=True, timeout=CMD_TIMEOUT)
                out, rc = (p.stdout + "\n" + p.stderr), p.returncode
            except subprocess.TimeoutExpired:
                out, rc = "délai dépassé", 124
            cmd_ms = now_ms() - t0 - tc
            lines = [l for l in out.splitlines() if l.strip()]
            mon.ev(now_ms() - t0, "step", a, "commande terminée (code %s) en %d ms" % (rc, cmd_ms))
            phase = {"name": ph, "from": a, "to": b, "cmdRc": rc, "cmdMs": cmd_ms, "output": clip(lines[-1] if lines else "", 200)}
            live(ph, "attente de la stabilisation du cluster")
            end = time.time() + SETTLE
            good = 0
            while time.time() < end:
                s = mon.last()
                good = good + 1 if settled(s, b, names) else 0
                if rc == 0 and good >= 2:
                    break
                if rc != 0 and time.time() > end - SETTLE + 10:
                    break      # la commande a échoué : on ne patiente pas (le cluster est resté en l'état)
                time.sleep(POLL)
            samples, _ = mon.snapshot()
            m = analyse(samples, tc, a, b, names)
            m["settleMs"] = now_ms() - t0 - tc if good >= 2 else None
            phase["metrics"] = m
            v = {"noPrimary": verdict(m["noPrimaryMs"], GAP_OK, GAP_WARN), "promotion": verdict(m["promotionMs"], PROMO_OK, PROMO_WARN),
                 "rejoin": verdict(m["rejoinMs"], REJOIN_OK, REJOIN_WARN),
                 "catchUp": "ok" if m["catchUpMs"] is not None else "fail",
                 "timeline": "ok" if (m["timeline"][0] is not None and m["timeline"][1] == m["timeline"][0] + 1) else "fail",
                 "lsn": "ok" if m["lsnContinuity"] else ("warn" if m["lsnContinuity"] is None else "fail")}
            if rc != 0:
                v = {k: "fail" for k in v}
            phase["verdicts"] = v
            post = []
            s = mon.last()

            def padd(i, st, d):
                post.append({"id": i, "status": st, "detail": clip(d, 200)})
            ld = leaders(s)
            padd("leader", "ok" if ld == [b] else "fail", ("primaire : " + b) if ld == [b] else "primaire attendu %s, observé : %s" % (b, ", ".join(ld) or "aucun"))
            bad = [n for n in names if n != b and not streaming(s.get(n, {}))]
            padd("replicas", "ok" if not bad else "fail", "tous les secondaires en réplication continue" if not bad else "pas en réplication continue : " + ", ".join(bad))
            q = self_json("_quorum")
            if isinstance(q, dict) and isinstance(quorum0, dict):
                okq = q.get("hasQuorum") and (q.get("healthy") or 0) >= (quorum0.get("healthy") or 0)
                padd("quorum", "ok" if okq else "fail", "quorum etcd : %s/%s voix saines (avant : %s)" % (q.get("healthy"), q.get("voters"), quorum0.get("healthy")))
            else:
                padd("quorum", "warn", "quorum etcd non relu")
            kea = self_json("_kea")
            if isinstance(kea0, dict) and kea0.get("ha"):
                st = ((kea or {}).get("local") or {}).get("state") if isinstance(kea, dict) else None
                padd("kea", "ok" if st in ("hot-standby", "load-balancing") else "warn", "Kea HA : état local « %s » (avant : %s)" % (clip(st, 30), clip((kea0.get("local") or {}).get("state"), 30)))
            held0 = local_vip_held()
            if held0 is not None:
                t_v = time.time() + 25
                while time.time() < t_v and local_vip_held() != (b == me):
                    time.sleep(0.5)
                okv = local_vip_held() == (b == me)
                padd("vip", "ok" if okv else "warn", "adresse virtuelle %s sur ce nœud comme attendu" % ("portée" if b == me else "absente") if okv else "adresse virtuelle pas encore convergée sur ce nœud")
            phase["post"] = post
            phase["ok"] = rc == 0 and not any(x == "fail" for x in v.values()) and not any(c["status"] == "fail" for c in post)
            report["phases"].append(phase)
            if rc != 0 or good < 2:
                failed = True
            live(ph, "phase terminée : " + ("conforme" if phase["ok"] else "écarts constatés"))
            if ph == "switch" and back and not failed:
                time.sleep(PAUSE)
    finally:
        mon.stop.set()
        hb_stop.set()
    samples, events = mon.snapshot()
    fails = sum(1 for p in report["phases"] for x in list(p["verdicts"].values()) + [c["status"] for c in p["post"]] if x == "fail")
    warns = sum(1 for p in report["phases"] for x in list(p["verdicts"].values()) + [c["status"] for c in p["post"]] if x == "warn")
    report["outcome"] = "failed" if (fails or failed or not report["phases"]) else ("warning" if warns else "success")
    return finish(report, t0, events, samples)


def finish(report, t0, events, samples):
    key = {"step": 0, "leader": 1, "timeline": 2, "role": 3, "node_down": 4, "node_up": 4, "state": 5, "repl": 6}
    ev = sorted(events, key=lambda e: e["t"])
    if len(ev) > 150:      # on garde d'abord ce qui compte, dans l'ordre du temps
        keep = sorted(sorted(ev, key=lambda e: (key.get(e["kind"], 9), e["t"]))[:150], key=lambda e: e["t"])
        ev = keep
    report["events"] = ev
    report["finishedAt"] = int(time.time())
    report["durationMs"] = now_ms() - t0
    report["thresholds"] = {"noPrimaryMs": [GAP_OK, GAP_WARN], "promotionMs": [PROMO_OK, PROMO_WARN], "rejoinMs": [REJOIN_OK, REJOIN_WARN], "catchUpLagBytes": CATCHUP_LAG, "maxLagBytes": MAX_LAG}
    emit({"type": "report", "report": report})
    return 0 if report.get("outcome") in ("success", "warning") else 1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "check":
        nodes = [n for n in peers() if n["role"] == "data"]
        api, pool = Patroni(), ThreadPoolExecutor(max_workers=max(2, len(nodes)))
        want = env("DRILL_CAND") or None
        if want and not NAME.match(want):
            want = None
        r = check(api, pool, nodes, want)
        r.pop("samples", None)
        print(json.dumps(r, ensure_ascii=False))
        return 0 if r["ok"] else 1
    if cmd == "run":
        return run()
    sys.stderr.write("usage : cluster-drill.py check|run\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
