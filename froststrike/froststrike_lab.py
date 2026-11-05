#!/usr/bin/env python3
"""
FROSTBOX Lab — Synthetic refrigeration-supervisory controller, adversary emulation,
detection engine and write-protecting guard proxy.

Purpose
-------
Reference lab accompanying the technical report on the October/November 2026
European supermarket refrigeration sabotage campaign (Intermarché and other
retailers, Danfoss AK-SM / Copeland-Dixell XWEB class of devices).

Design constraints (deliberate):
- 100% Python 3 standard library. No third-party dependencies.
- The ONLY target is a synthetic controller created by this file, bound to
  loopback by default. The attack module refuses any non-loopback target
  (ScopeError), mirroring safe-lab practice.
- No real vendor endpoint, protocol detail, firmware path, password algorithm
  or CVE exploit chain of any manufacturer is reproduced. The "daily service
  code" variant implements a generic, self-defined predictable-code scheme to
  emulate the *class* of authentication-bypass weaknesses publicly discussed
  in connection with the campaign (e.g. CVE-2025-41450, CVE-2025-6519) without
  reproducing any vendor's algorithm.
- All actors are fictional. No real supermarket, vendor or network is involved.

Usage
-----
  python3 froststrike_lab.py serve  [--host 127.0.0.1] [--port 8080] [--sim-time "2026-11-02T02:30:00"]
  python3 froststrike_lab.py attack [--port 8080] [--variant h1|h2] [--target 127.0.0.1]
  python3 froststrike_lab.py detect  --audit <audit.jsonl> --alerts <alerts.jsonl>
  python3 froststrike_lab.py guard   [--listen 8081] [--upstream 8080]
  python3 froststrike_lab.py demo    [--evidence-dir evidence]

MITRE ATT&CK mapping (see report):
  Enterprise T1596 (Search Open Technical Databases, Shodan/Censys recon)
  Enterprise T1078.001 (Valid Accounts: Default Accounts)
  Enterprise T1190 / ICS T0819 (Exploit Public-Facing Application — auth-bypass variant)
  ICS T0883 (Internet Accessible Device)
  ICS T1692.001 (Unauthorized Message: Command Message, ATT&CK v20)
  ICS T0879 (Damage to Property)
License: Apache-2.0 (lab code). See the LICENSE file and the report's usage notice.

Changelog
---------
v1.4 (2026-11-05): license metadata only — the docstring license line now states
  Apache-2.0, matching the repository LICENSE file (it previously said MIT,
  a leftover from the initial release). No behavioral change: detection
  engine, guard and CLI are untouched, and the full regression re-run passes
  with identical numbers.
v1.3 (2026-11-05): operator patient-attack validation (patient_probe.py)
  confirmed the predicted threshold evasion: a valid-credential actor touching
  only 2 cases at a time, spacing pairs >5 min apart, evaded the burst
  correlation and (measured with a paced 6-case audit) could defrost the whole
  fleet with zero CRIT alerts at night (direct access; through the guard the
  night window rule blocks everything, and daytime forwarded defrosts still
  hit D-DEFROST-UNSCHEDULED). D-MULTI-CASE now runs a dual horizon: burst
  >=3 cases/5 min (as before) or patient >=3 cases/1 h, both requiring the
  v1.2 secondary anomaly signal. Documented floor: a total of <=2 cases is
  below any case-count correlation by design (covered by out-of-window WARN
  pre-damage, reactive plant alarms, and the guard fleet ceiling).
v1.2 (2026-11-05): operator false-positive validation (fp_probe.py) scoped
  D-MULTI-CASE: the correlation now requires a secondary anomaly signal on
  each counted event (out-of-band setpoint, off-schedule defrost, alarm
  suppression, or out-of-maintenance-window operation). Legitimate in-window,
  in-band multi-case maintenance no longer raises CRIT. Known limits added
  to the report: single-log-source dependency (a compromised controller can
  suppress the audit), reactive (not pre-impact) detection against valid-
  credential adversaries (H3), and threshold evasion by patient actors.
v1.1 (2026-11-05): adversarial validation by the operator (probe.py /
  improved_detect.py) closed three gaps found in v1.0: (1) controller ALARM
  events were ignored -> new rule D-PROCESS-ALARM; (2) the >=3-cases/5-min/
  actor correlation existed only as a KQL hunt -> engine rule D-MULTI-CASE;
  (3) D-OUT-OF-WINDOW covered only setpoint writes -> now covers every http
  config/command event. The guard gained a fleet-anomaly ceiling on defrost
  commands (G-DEFROST-FLEET-ANOMALY) so in-window fleet-wide defrosts no
  longer pass freely.
v1.0 (2026-11-05): initial release.
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Scope guard
# ---------------------------------------------------------------------------

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class ScopeError(Exception):
    """Raised when an action would leave the authorized lab scope."""


def assert_loopback(host: str):
    if host not in LOOPBACK:
        raise ScopeError(
            "target %r is outside lab scope: FROSTBOX attacks may only run "
            "against loopback (127.0.0.1/::1) synthetic targets" % host
        )


# ---------------------------------------------------------------------------
# Clock: real time drives MTTD measurement, sim time drives scenario logic
# ---------------------------------------------------------------------------

_SIM_TIME = None  # ISO string, set by --sim-time


def set_sim_time(iso: str):
    global _SIM_TIME
    _SIM_TIME = iso


def now_real_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def now_sim() -> datetime:
    if _SIM_TIME:
        return datetime.fromisoformat(_SIM_TIME)
    return datetime.now(timezone.utc).replace(tzinfo=None)


def now_sim_iso() -> str:
    return now_sim().strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Plant model
# ---------------------------------------------------------------------------

CASE_TYPES = {
    "FZ": {"label": "freezer", "min_sp": -30.0, "max_sp": -15.0, "start_sp": -20.0},
    "CH": {"label": "chilled", "min_sp": 0.0, "max_sp": 6.0, "start_sp": 3.0},
}

MAINTENANCE_WINDOW = (8, 18)   # writes allowed 08:00-17:59 (sim time)
DEFROST_WINDOW = (2, 5)        # legit scheduled defrost 02:00-04:59 (sim time)


class Case:
    """One refrigerated display case / freezer with a heating-based defrost."""

    def __init__(self, cid: str, ctype: str):
        self.id = cid
        self.type = ctype
        cfg = CASE_TYPES[ctype]
        self.setpoint = cfg["start_sp"]
        self.temp = cfg["start_sp"] + 0.5     # measured product temp
        self.defrost_on = False
        self.defrost_until = None            # sim datetime
        self.alarm_enabled = True
        self.alarm_high = -10.0 if ctype == "FZ" else 8.0
        self.alarm_fired = False

    def step(self, sim_now: datetime):
        """Advance physics one tick toward setpoint; defrost heaters add heat."""
        if self.defrost_on:
            if self.defrost_until and sim_now >= self.defrost_until:
                self.defrost_on = False
            else:
                self.temp = min(self.temp + 0.8, 60.0)   # defrost heating
                return
        # pull toward setpoint, ambient leakage toward +21C
        pull = (self.setpoint - self.temp) * 0.10
        leak = (21.0 - self.temp) * 0.002
        self.temp = self.temp + pull + leak

    def check_alarm(self) -> bool:
        if self.alarm_enabled and self.temp > self.alarm_high:
            if not self.alarm_fired:
                self.alarm_fired = True
                return True
        elif self.temp <= self.alarm_high:
            self.alarm_fired = False
        return False


def default_cases():
    return {
        "FZ-01": Case("FZ-01", "FZ"),
        "FZ-02": Case("FZ-02", "FZ"),
        "FZ-03": Case("FZ-03", "FZ"),
        "CH-01": Case("CH-01", "CH"),
        "CH-02": Case("CH-02", "CH"),
        "CH-03": Case("CH-03", "CH"),
    }


# ---------------------------------------------------------------------------
# Audit log (JSONL) — the lab's telemetry source
# ---------------------------------------------------------------------------

class Audit:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        open(path, "w").close()

    def emit(self, event: str, **fields):
        rec = {
            "ts": now_real_iso(),        # real clock: MTTD math
            "sim_ts": now_sim_iso(),     # scenario clock: window logic
            "device": "FROSTBOX-01",
            "event": event,
        }
        rec.update(fields)
        with self.lock:
            with open(self.path, "a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------

WEAK_CREDS = [("admin", "admin123"), ("admin", "123456"), ("supervisor", "supervisor")]
SERVICE_HEADER = "X-Service-Code"
DEVICE_SERIAL = "FRB-4402-X"


def daily_service_code(sim_now: datetime) -> str:
    """
    GENERIC, SELF-DEFINED predictable daily code. Emulates the *class* of
    "code-of-the-day" hidden authentication documented by researchers for
    certain refrigeration controllers. This is our own synthetic algorithm
    for our own synthetic device; it is not derived from any vendor scheme.
    """
    day = sim_now.strftime("%Y%m%d")
    seed = "FROSTBOX-SERVICECODE:%s:%s" % (day, DEVICE_SERIAL)
    return hashlib.sha256(seed.encode()).hexdigest()[:8].upper()


class FrostboxController:
    def __init__(self, audit: Audit):
        self.audit = audit
        self.cases = default_cases()
        self.sessions = {}
        self.users = {"admin": "admin123",     # default password, never rotated
                     "tech": "Tq9x!Lm2#vZp7"}  # hardening: strong per-user credential
        self.lock = threading.Lock()
        self._sim_tick = 0

    # -- physics loop ----------------------------------------------------
    def step(self):
        sim_now = now_sim() + timedelta(seconds=self._sim_tick)
        with self.lock:
            for c in self.cases.values():
                c.step(sim_now)
                if c.check_alarm():
                    self.audit.emit("ALARM", case=c.id, temp=round(c.temp, 2),
                                    threshold=c.alarm_high, source="plant")
        self._sim_tick += 5

    # -- auth ------------------------------------------------------------
    def login(self, user, password):
        ok = self.users.get(user) == password
        self.audit.emit("AUTH_LOGIN", actor=user, outcome="success" if ok else "failure",
                        source="http")
        if ok:
            tok = secrets.token_hex(16)
            self.sessions[tok] = user
            return tok
        return None

    def service_auth(self, code):
        """Hidden 'service' authentication path (the sanitized H2 variant)."""
        ok = secrets.compare_digest(code, daily_service_code(now_sim()))
        self.audit.emit("AUTH_SERVICE_CODE", actor="service",
                        outcome="success" if ok else "failure", source="http")
        if ok:
            tok = secrets.token_hex(16)
            self.sessions[tok] = "service"
            return tok
        return None

    def authed(self, token):
        return token in self.sessions

    # -- control actions ---------------------------------------------------
    def set_setpoint(self, cid, value, actor):
        if cid not in self.cases:
            return None, 404
        c = self.cases[cid]
        old = c.setpoint
        c.setpoint = float(value)
        self.audit.emit("CFG_SETPOINT", case=cid, actor=actor,
                        old=old, new=c.setpoint, source="http")
        return c.setpoint, 200

    def force_defrost(self, cid, actor):
        if cid not in self.cases:
            return 404
        c = self.cases[cid]
        c.defrost_on = True
        c.defrost_until = now_sim() + timedelta(minutes=30)
        self.audit.emit("CMD_DEFROST", case=cid, actor=actor, source="http")
        return 200

    def alarm_config(self, cid, enabled, high, actor):
        if cid not in self.cases:
            return 404
        c = self.cases[cid]
        c.alarm_enabled = bool(enabled)
        if high is not None:
            c.alarm_high = float(high)
        self.audit.emit("CFG_ALARM", case=cid, actor=actor,
                        enabled=c.alarm_enabled, high=c.alarm_high, source="http")
        return 200

    def status(self):
        with self.lock:
            return {
                "device": "FROSTBOX-01",
                "serial": DEVICE_SERIAL,
                "fw": "1.0.0-lab",
                "cases": [
                    {"id": c.id, "type": c.type, "setpoint": c.setpoint,
                     "temp": round(c.temp, 2), "defrost": c.defrost_on,
                     "alarm_enabled": c.alarm_enabled,
                     "alarm_high": c.alarm_high}
                    for c in self.cases.values()
                ],
            }


def make_handler(ctrl: FrostboxController):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence default stderr noise
            pass

        def _json(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                try:
                    return json.loads(self.rfile.read(n).decode())
                except Exception:
                    return None
            return {}

        def _token(self):
            auth = self.headers.get("Authorization", "")
            return auth[7:] if auth.startswith("Bearer ") else None

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/":
                ctrl.audit.emit("HTTP_GET", path="/", outcome=200, source="http")
                self._json(200, {"product": "FrostBox Refrigeration Supervisor (SYNTHETIC LAB DEVICE)",
                                 "serial": DEVICE_SERIAL})
            elif path == "/api/status":
                ctrl.audit.emit("HTTP_GET", path="/api/status", outcome=200, source="http")
                self._json(200, ctrl.status())   # unauthenticated read (mirrors real misconfiguration)
            else:
                ctrl.audit.emit("HTTP_GET", path=path, outcome=404, source="http")
                self._json(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            body = self._body()
            if path == "/api/login":
                tok = ctrl.login(str(body.get("user", "")), str(body.get("pass", "")))
                self._json(200 if tok else 401,
                           {"token": tok} if tok else {"error": "invalid credentials"})
                return
            # hidden service-code path (sanitized H2 emulation)
            if path == "/api/service/login":
                code = self.headers.get(SERVICE_HEADER, "")
                tok = ctrl.service_auth(code)
                self._json(200 if tok else 401,
                           {"token": tok} if tok else {"error": "invalid service code"})
                return
            if not ctrl.authed(self._token()):
                ctrl.audit.emit("AUTHZ_DENIED", path=path, outcome=401, source="http")
                self._json(401, {"error": "unauthorized"})
                return
            if path.startswith("/api/case/") and path.endswith("/setpoint"):
                cid = path.split("/")[3]
                val, code = ctrl.set_setpoint(cid, body.get("value"), ctrl.sessions[self._token()])
                self._json(code, {"case": cid, "setpoint": val} if code == 200 else {"error": "unknown case"})
            elif path.startswith("/api/case/") and path.endswith("/defrost"):
                cid = path.split("/")[3]
                self._json(ctrl.force_defrost(cid, ctrl.sessions[self._token()]), {"case": cid, "defrost": "forced"})
            elif path == "/api/alarm/config":
                cid = body.get("case")
                code = ctrl.alarm_config(cid, body.get("enabled", True),
                                         body.get("high_threshold"), ctrl.sessions[self._token()])
                self._json(code, {"ok": True} if code == 200 else {"error": "unknown case"})
            else:
                ctrl.audit.emit("HTTP_POST", path=path, outcome=404, source="http")
                self._json(404, {"error": "not found"})

    return H


def serve(args):
    set_sim_time(args.sim_time) if args.sim_time else None
    audit = Audit(args.audit)
    ctrl = FrostboxController(audit)
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(ctrl))

    def tick():
        while True:
            time.sleep(0.25)
            ctrl.step()

    threading.Thread(target=tick, daemon=True).start()
    print("[serve] FROSTBOX synthetic controller on %s:%d (sim time: %s)"
          % (args.host, args.port, now_sim_iso()))
    print("[serve] audit log: %s" % audit.path)
    httpd.serve_forever()


# ---------------------------------------------------------------------------
# HTTP client (stdlib only)
# ---------------------------------------------------------------------------

def http_req(method, host, port, path, body=None, headers=None, timeout=5):
    import http.client
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    payload = json.dumps(body).encode() if body is not None else None
    conn.request(method, path, body=payload, headers=hdrs)
    r = conn.getresponse()
    data = r.read()
    conn.close()
    try:
        return r.status, json.loads(data.decode() or "{}")
    except Exception:
        return r.status, {}


# ---------------------------------------------------------------------------
# Adversary emulation (H1 / H2) — loopback only
# ---------------------------------------------------------------------------

def attack(args):
    assert_loopback(args.target)
    set_sim_time(args.sim_time) if args.sim_time else None
    host, port = args.target, args.port
    steps = []

    def record(phase, action, detail):
        steps.append({"ts": now_real_iso(), "sim_ts": now_sim_iso(),
                      "phase": phase, "action": action, "detail": detail})
        print("  [%s] %s — %s" % (phase, action, detail))

    print("[attack] variant=%s target=%s:%d" % (args.variant, host, port))

    # P1 — Recon: fingerprint the exposed interface (Shodan/Censys analogue)
    st, banner = http_req("GET", host, port, "/")
    record("recon", "fingerprint", "GET / -> %d %s" % (st, banner.get("serial", "?")))
    st, status = http_req("GET", host, port, "/api/status")
    record("recon", "unauth_status", "GET /api/status -> %d (%d cases)"
           % (st, len(status.get("cases", []))))

    # P2 — Access
    token = None
    if args.variant == "h1":
        # Default / weak credential access (ANSSI-attributed class for the
        # October wave: exposed admin interfaces, unchanged default passwords)
        for u, p in WEAK_CREDS:
            st, resp = http_req("POST", host, port, "/api/login", {"user": u, "pass": p})
            record("credential_access", "login_try", "%s/<weak> -> %d" % (u, st))
            if st == 200 and resp.get("token"):
                token = resp["token"]
                record("credential_access", "login_success", "session as %r via weak credential" % u)
                break
    else:
        # H2 (sanitized): hidden predictable daily service code
        code = daily_service_code(now_sim())
        st, resp = http_req("POST", host, port, "/api/service/login", None,
                            {SERVICE_HEADER: code})
        record("credential_access", "service_code_auth",
               "predictable daily code -> %d" % st)
        if st == 200:
            token = resp.get("token")
    if not token:
        print("[attack] ACCESS FAILED — attack chain stops (initial access not achieved)")
        return steps, None

    # P3 — Sabotage: raise setpoints, force defrost, silence alarms
    hdr = {"Authorization": "Bearer " + token}
    first_action_ts = None
    for c in status.get("cases", []):
        cid = c["id"]
        st, _ = http_req("POST", host, port, "/api/case/%s/setpoint" % cid,
                         {"value": 50.0}, hdr)
        if first_action_ts is None:
            first_action_ts = now_real_iso()
        record("sabotage", "setpoint_50C", "%s -> %d (was %.1f)" % (cid, st, c["setpoint"]))
        st, _ = http_req("POST", host, port, "/api/case/%s/defrost" % cid, {}, hdr)
        record("sabotage", "forced_defrost", "%s -> %d" % (cid, st))
        st, _ = http_req("POST", host, port, "/api/alarm/config",
                         {"case": cid, "enabled": False, "high_threshold": 60.0}, hdr)
        record("sabotage", "alarm_suppress", "%s -> %d" % (cid, st))
        time.sleep(0.4)   # pacing so the detector pipeline shows real latency
    return steps, first_action_ts


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

ALERT_LEVELS = {"INFO": 10, "WARN": 20, "CRIT": 30}


class Detector:
    # v1.1 — adversarial validation by the operator (probe.py) closed three
    # gaps in the original engine: (1) controller ALARM events were ignored
    # (rule A), (2) the >=3-cases/5-min/actor correlation existed only as a KQL
    # hunt, not in the engine (rule B), and (3) D-OUT-OF-WINDOW covered only
    # CFG_SETPOINT, leaving defrost-only night attacks undetected.
    CONFIG_EVENTS = ("CFG_SETPOINT", "CMD_DEFROST", "CFG_ALARM")
    CORR_WINDOW_S = 300      # operator rule B / KQL hunt #4
    CORR_CASES_MIN = 3
    CORR_SLOW_WINDOW_S = 3600   # v1.3: patient-actor horizon (operator patient_probe)

    def __init__(self):
        self.alerts = []
        self._seen = set()
        self._actor_events = defaultdict(list)

    def alert(self, rule, level, msg, ts, **ctx):
        key = (rule, json.dumps(ctx, sort_keys=True))
        if key in self._seen:
            return
        self._seen.add(key)
        self.alerts.append({
            "ts": ts,                      # event time (audit record)
            "det_ts": now_real_iso(),      # detection time (when the rule fired)
            "sim_ts": ctx.get("sim_ts", ""),
            "rule": rule, "level": level, "msg": msg,
            "context": {k: v for k, v in ctx.items() if k != "sim_ts"}})

    def scan(self, rec):
        ev = rec.get("event")
        sim_ts = rec.get("sim_ts", "")
        hour = int(sim_ts[11:13]) if len(sim_ts) >= 13 else -1

        if ev == "AUTH_LOGIN" and rec.get("outcome") == "success":
            if rec.get("actor") in ("admin", "supervisor"):
                # 'tech' carries a strong rotated credential and is not flagged
                self.alert("D-WEAK-LOGIN", "CRIT",
                            "Login success with vendor-default account '%s'" % rec["actor"],
                            rec["ts"], actor=rec.get("actor"), sim_ts=sim_ts)
        if ev == "AUTH_SERVICE_CODE":
            self.alert("D-SERVICE-AUTH", "CRIT",
                       "Use of hidden service-code authentication path", rec["ts"],
                       outcome=rec.get("outcome"), sim_ts=sim_ts)
        if ev == "ALARM":
            # operator rule A: plant-level alarms are telemetry too
            self.alert("D-PROCESS-ALARM", "WARN",
                       "Plant alarm on %s: temp %.2f above threshold %.2f"
                       % (rec.get("case"), rec.get("temp", 0), rec.get("threshold", 0)),
                       rec["ts"], case=rec.get("case"), temp=rec.get("temp"),
                       threshold=rec.get("threshold"), sim_ts=sim_ts)
        if ev == "CFG_SETPOINT":
            cid = rec.get("case", "")
            ctype = "FZ" if cid.startswith("FZ") else "CH"
            new = float(rec.get("new", 0))
            lo, hi = CASE_TYPES[ctype]["min_sp"], CASE_TYPES[ctype]["max_sp"]
            if new < lo or new > hi:
                self.alert("D-SETPOINT-RANGE", "CRIT",
                           "Setpoint %.1f°C on %s outside allowed band [%.0f, %.0f]°C"
                           % (new, cid, lo, hi), rec["ts"], case=cid, value=new, sim_ts=sim_ts)
        if ev == "CMD_DEFROST":
            if hour >= 0 and not (DEFROST_WINDOW[0] <= hour < DEFROST_WINDOW[1]):
                self.alert("D-DEFROST-UNSCHEDULED", "CRIT",
                           "Forced defrost on %s outside scheduled defrost window" % rec.get("case"),
                           rec["ts"], case=rec.get("case"), sim_ts=sim_ts)
        if ev == "CFG_ALARM" and (rec.get("enabled") is False or rec.get("high", 0) > 40):
            self.alert("D-ALARM-MUTE", "CRIT",
                       "Alarm suppression on %s (enabled=%s, high=%s)"
                       % (rec.get("case"), rec.get("enabled"), rec.get("high")),
                       rec["ts"], case=rec.get("case"), sim_ts=sim_ts)
        if ev in self.CONFIG_EVENTS:
            # v1.1: generalized to every http-source config/command event,
            # not just setpoint writes (probe finding: defrost-only night
            # attacks used to pass silently)
            in_window = (hour >= 0
                         and (MAINTENANCE_WINDOW[0] <= hour < MAINTENANCE_WINDOW[1]))
            if hour >= 0 and not in_window:
                self.alert("D-OUT-OF-WINDOW", "WARN",
                           "%s at %02d:xx outside maintenance window %02d-%02d"
                           % (ev, hour, *MAINTENANCE_WINDOW),
                           rec["ts"], case=rec.get("case"), event=ev, sim_ts=sim_ts)
            # v1.2 (operator fp_probe finding): D-MULTI-CASE counted cases per
            # actor with no regard to context, so a legitimate technician
            # doing seasonal multi-case maintenance inside the window and
            # inside the band raised a CRIT false positive. Correlation now
            # requires a SECONDARY ANOMALY SIGNAL on the event itself:
            # out-of-band setpoint, off-schedule defrost, alarm suppression,
            # or any config/command event outside the maintenance window.
            # In-window, in-band, alarm-preserving writes are therefore
            # invisible to the rule (legitimate maintenance by definition);
            # a credential-thief who only does that is indistinguishable
            # from maintenance and remains covered by D-DEFROST-
            # UNSCHEDULED and G-DEFROST-FLEET-ANOMALY for defrost operations.
            anomalous = not in_window
            if ev == "CFG_SETPOINT":
                anomalous = anomalous or (new < lo or new > hi)
            elif ev == "CMD_DEFROST":
                anomalous = anomalous or (hour < 0 or not
                                         (DEFROST_WINDOW[0] <= hour < DEFROST_WINDOW[1]))
            elif ev == "CFG_ALARM":
                anomalous = anomalous or (rec.get("enabled") is False
                                          or float(rec.get("high", 0) or 0) > 40)
            # v1.1: operator rule B — correlated multi-case activity
            # v1.2: only events with a secondary signal feed the correlation
            try:
                t = datetime.strptime(rec["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
            except (KeyError, ValueError):
                t = None
            if t is not None and anomalous:
                actor = rec.get("actor")
                evs = self._actor_events[actor]
                evs.append((t, rec.get("case")))
                # v1.3 (operator patient_probe finding): keep history for the
                # slow horizon, not just the burst window. A patient actor
                # spacing operations >CORR_WINDOW_S apart (e.g. 2 cases every
                # 10+ min) evaded the burst correlation entirely; a shift-scale
                # horizon (1 h) now catches the same pattern at the 3rd case.
                # Both horizons feed the same rule and dedup on actor only.
                slow = [(tt, cc) for (tt, cc) in evs
                        if tt >= t - self.CORR_SLOW_WINDOW_S]
                self._actor_events[actor] = slow
                n_fast = len({cc for (tt, cc) in slow
                              if tt >= t - self.CORR_WINDOW_S})
                n_slow = len({cc for (_, cc) in slow})
                if n_fast >= self.CORR_CASES_MIN or n_slow >= self.CORR_CASES_MIN:
                    horizon = self.CORR_WINDOW_S if n_fast >= self.CORR_CASES_MIN \
                        else self.CORR_SLOW_WINDOW_S
                    # dedup on actor only: one alert per correlated pattern
                    self.alert("D-MULTI-CASE", "CRIT",
                               "Correlated sabotage pattern: actor '%s' touched %d+ "
                               "distinct cases within %d s%s"
                               % (actor, max(n_fast, n_slow), horizon,
                                  "" if horizon == self.CORR_WINDOW_S
                                  else " (patient-actor horizon)"),
                               rec["ts"], actor=actor, sim_ts=sim_ts)

    def mttd(self, first_attack_ts):
        """First time-to-detect from the first unauthorized SABOTAGE action to
        the first CRIT alert at or after it (login-phase alerts are earlier
        and are reported separately as detect-before-impact)."""
        if not first_attack_ts or not self.alerts:
            return None
        crits = sorted([a["det_ts"] for a in self.alerts
                        if a["level"] == "CRIT" and a["det_ts"] >= first_attack_ts])
        if not crits:
            return None
        t0 = datetime.strptime(first_attack_ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        t1 = datetime.strptime(crits[0], "%Y-%m-%dT%H:%M:%S.%fZ")
        return (t1 - t0).total_seconds()

    def detect_before_impact(self, first_attack_ts):
        """True if any CRIT alert fired strictly before the first sabotage
        action (e.g. weak-credential login or hidden service auth detected
        during the access phase)."""
        if not first_attack_ts:
            return False
        return any(a["level"] == "CRIT" and a["ts"] < first_attack_ts
                   for a in self.alerts)


def tail_detect(audit_path, alerts_path, poll_s=1.0, max_s=30, first_attack_ts=None,
                quiet=False):
    """Continuously tail the audit log like a SIEM pipeline and emit alerts."""
    det = Detector()
    alerts = Audit(alerts_path)
    pos = 0
    deadline = time.time() + max_s
    while time.time() < deadline:
        with open(audit_path) as fh:
            fh.seek(pos)
            for line in fh:
                if line.strip():
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    before = len(det.alerts)
                    det.scan(rec)
                    for a in det.alerts[before:]:
                        alerts.emit("ALERT", **a)
                        if not quiet:
                            print("  [ALERT %s] %s: %s" % (a["level"], a["rule"], a["msg"]))
            pos = fh.tell()
        if first_attack_ts and det.mttd(first_attack_ts) is not None:
            break
        time.sleep(poll_s)
    return det


def detect_cli(args):
    det = tail_detect(args.audit, args.alerts, max_s=args.max_s, quiet=False)
    print("[detect] %d alerts, MTTD(from file start unavailable) — see demo for MTTD" % len(det.alerts))


# ---------------------------------------------------------------------------
# Guard proxy — the prevention artifact
# ---------------------------------------------------------------------------

class GuardConfig:
    def __init__(self):
        self.allow_sources = LOOPBACK | {"10.10.50.0/24"}     # maintenance network
        self.block_creds = {("admin", "admin123"), ("admin", "123456"),
                            ("supervisor", "supervisor")}
        self.strip_headers = {SERVICE_HEADER.lower()}
        self.read_only_paths = {"/", "/api/status"}
        self.write_paths = {"/api/login", "/api/case/setpoint", "/api/case/defrost"}
        self.quarantine_token = None
        # v1.1 (operator probe finding): in-window writes were fully allowed,
        # so a fleet-wide forced defrost inside the maintenance window passed
        # the guard. Fleet-anomaly ceiling: after DEFROST_FLEET_LIMIT distinct
        # cases defrosted through this proxy within DEFROST_FLEET_WINDOW_S,
        # further defrost commands are blocked.
        self.defrost_fleet_limit = 2
        self.defrost_fleet_window_s = 600


def make_guard_handler(audit: Audit, upstream_port: int):
    cfg = GuardConfig()
    fleet_state = {"defrost": []}       # [(epoch, case)] forwarded defrost commands
    import http.client

    class G(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _reply(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _guard_alert(self, rule, msg, **ctx):
            rec = {"rule": rule, "msg": msg}
            rec.update(ctx)
            audit.emit("GUARD_BLOCK", **rec)
            print("  [GUARD BLOCK] %s: %s" % (rule, msg))

        def _hour(self):
            return now_sim().hour

        def _route(self):
            path = urlparse(self.path).path
            hour = self._hour()
            in_maint = MAINTENANCE_WINDOW[0] <= hour < MAINTENANCE_WINDOW[1]

            # strip the hidden service-code path at the perimeter
            for h in [k for k in self.headers if k.lower() in cfg.strip_headers]:
                self._guard_alert("G-HIDDEN-AUTH-STRIPPED",
                                  "service-code header stripped at perimeter",
                                  header=h)
                del self.headers[h]

            if path == "/api/service/login":
                self._guard_alert("G-HIDDEN-AUTH-BLOCKED",
                                  "request to hidden service authentication path blocked")
                self._reply(403, {"error": "forbidden by guard"})
                return None

            # authentication is always routed to inspection (credential policy);
            # non-read paths other than login are writes subject to the window
            if path == "/api/login":
                return path
            if not in_maint and path not in ("/", "/api/status"):
                self._guard_alert("G-OUT-OF-WINDOW",
                                  "write outside maintenance window blocked (%02d:xx)" % hour,
                                  path=path)
                self._reply(403, {"error": "writes allowed only in maintenance window"})
                return None

            return path

        def _forward(self, method, body=None):
            path = urlparse(self.path).path
            n = int(self.headers.get("Content-Length") or 0)
            payload = self.rfile.read(n) if n else None
            conn = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=5)
            hdrs = {k: v for k, v in self.headers.items()
                    if k.lower() not in cfg.strip_headers | {"Host", "Content-Length"}}
            if payload is not None:
                hdrs["Content-Length"] = str(len(payload))
            conn.request(method, path, body=payload, headers=hdrs)
            r = conn.getresponse()
            data = r.read()
            code = r.status
            ctype = r.getheader("Content-Type") or "application/json"
            conn.close()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return code, data

        def _inspect(self):
            """Content inspection: credential blocklist + setpoint clamping +
            fleet-anomaly ceiling on defrost commands."""
            path = urlparse(self.path).path
            # v1.1: fleet-wide forced defrost is never a legitimate remote
            # maintenance pattern, even inside the write window
            if path.endswith("/defrost"):
                now_t = time.time()
                fleet_state["defrost"] = [
                    (t, c) for (t, c) in fleet_state["defrost"]
                    if t >= now_t - cfg.defrost_fleet_window_s]
                recent = {c for (_, c) in fleet_state["defrost"]}
                if len(recent) >= cfg.defrost_fleet_limit:
                    self._guard_alert("G-DEFROST-FLEET-ANOMALY",
                                      "forced defrost on further cases blocked: "
                                      "%d distinct cases already defrosted within %d s"
                                      % (len(recent), cfg.defrost_fleet_window_s),
                                      cases=len(recent))
                    self._reply(403, {"error": "fleet-wide defrost anomaly blocked by guard"})
                    return None
            n = int(self.headers.get("Content-Length") or 0)
            if not n:
                return None
            raw = self.rfile.read(n)
            try:
                body = json.loads(raw.decode())
            except Exception:
                self._reply(400, {"error": "bad json"})
                return None
            if path == "/api/login":
                pair = (str(body.get("user", "")), str(body.get("pass", "")))
                if pair in cfg.block_creds:
                    self._guard_alert("G-DEFAULT-CRED-BLOCKED",
                                      "login attempt with vendor-default credential '%s' blocked"
                                      % pair[0], actor=pair[0])
                    self._reply(403, {"error": "credential rejected by guard policy"})
                    return None
                return raw
            if path.endswith("/setpoint"):
                cid = path.split("/")[3]
                ctype = "FZ" if cid.startswith("FZ") else "CH"
                lo, hi = CASE_TYPES[ctype]["min_sp"], CASE_TYPES[ctype]["max_sp"]
                try:
                    val = float(body.get("value"))
                except (TypeError, ValueError):
                    self._reply(400, {"error": "bad setpoint"})
                    return None
                if not (lo <= val <= hi):
                    self._guard_alert("G-SETPOINT-CLAMP",
                                      "setpoint %.1f°C for %s outside [%.0f, %.0f]°C blocked"
                                      % (val, cid, lo, hi), case=cid, value=val)
                    self._reply(403, {"error": "setpoint outside guarded band"})
                    return None
            if path == "/api/alarm/config" and (
                    body.get("enabled") is False or
                    (body.get("high_threshold") or 0) > 40):
                self._guard_alert("G-ALARM-MUTE-BLOCKED",
                                  "alarm suppression request blocked", case=body.get("case"))
                self._reply(403, {"error": "alarm muting not permitted via remote interface"})
                return None
            if path.endswith("/defrost"):
                # record the forwarded command for the fleet-anomaly ceiling
                fleet_state["defrost"].append((time.time(), path.split("/")[3]))
            return raw

        def do_GET(self):
            if self._route() is None:
                return
            self._forward("GET")

        def do_POST(self):
            if self._route() is None:
                return
            path = urlparse(self.path).path
            if path in ("/", "/api/status"):
                self._reply(405, {"error": "read-only path"})
                return
            raw = self._inspect()
            if raw is None:
                return
            # re-dispatch body upstream without re-reading
            import http.client
            hdrs = {k: v for k, v in self.headers.items()
                    if k.lower() not in cfg.strip_headers | {"Host", "Content-Length"}}
            hdrs["Content-Length"] = str(len(raw))
            conn = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=5)
            conn.request("POST", path, body=raw, headers=hdrs)
            r = conn.getresponse()
            data = r.read()
            conn.close()
            self.send_response(r.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return G


def guard(args):
    set_sim_time(args.sim_time) if args.sim_time else None
    audit = Audit(args.audit)
    httpd = ThreadingHTTPServer((args.host, args.listen), make_guard_handler(audit, args.upstream))
    print("[guard] FROSTBOX guard proxy on %s:%d -> upstream 127.0.0.1:%d (sim time: %s)"
          % (args.host, args.listen, args.upstream, now_sim_iso()))
    print("[guard] policy: maintenance window %02d-%02d, setpoint clamps, default-cred blocklist, "
          "service-auth stripped, alarm-mute blocked" % MAINTENANCE_WINDOW)
    httpd.serve_forever()


# ---------------------------------------------------------------------------
# Demo: full end-to-end evidence run
# ---------------------------------------------------------------------------

def run_controller_in_thread(port, audit_path, sim_time):
    set_sim_time(sim_time)
    audit = Audit(audit_path)
    ctrl = FrostboxController(audit)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(ctrl))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def tick():
        while True:
            time.sleep(0.25)
            ctrl.step()

    threading.Thread(target=tick, daemon=True).start()
    return httpd, ctrl, audit


def demo(args):
    ev_dir = args.evidence_dir
    os.makedirs(ev_dir, exist_ok=True)
    night = "2026-11-02T02:30:00"     # campaign window: night, store closed
    results = {"generated": now_real_iso(), "sim_time": night, "scenarios": []}

    for variant, audit_f, alerts_f in [
        ("h1", "audit_h1.jsonl", "alerts_h1.jsonl"),
        ("h2", "audit_h2.jsonl", "alerts_h2.jsonl"),
    ]:
        print("\n=== SCENARIO %s (night %s) ===" % (variant.upper(), night))
        audit_path = os.path.join(ev_dir, audit_f)
        alerts_path = os.path.join(ev_dir, alerts_f)
        httpd, ctrl, audit = run_controller_in_thread(8080, audit_path, night)

        from types import SimpleNamespace
        A = SimpleNamespace(target="127.0.0.1", port=8080, variant=variant, sim_time=night)

        # streaming detection: a poller tails the audit log concurrently with
        # the attack, like an agent forwarding events into a SIEM pipeline
        det = Detector()
        stop = threading.Event()

        def emit_alerts(alerts, before):
            for a in det.alerts[before:]:
                alerts.emit("ALERT", **a)

        def stream_detect():
            alerts = Audit(alerts_path)
            pos = 0
            while not stop.is_set():
                with open(audit_path) as fh:
                    fh.seek(pos)
                    for line in fh:
                        if line.strip():
                            try:
                                rec = json.loads(line)
                            except Exception:
                                continue
                            before = len(det.alerts)
                            det.scan(rec)
                            emit_alerts(alerts, before)
                    pos = fh.tell()
                time.sleep(0.25)

        t_det = threading.Thread(target=stream_detect)
        t_det.start()
        steps, first_ts = attack(A)      # runs while the detector polls
        time.sleep(0.75)                  # let the last records flow
        stop.set()
        t_det.join(timeout=5)

        mttd = det.mttd(first_ts)
        dbi = det.detect_before_impact(first_ts)
        crit = [a for a in det.alerts if a["level"] == "CRIT"]
        print("[demo] %s: %d actions, %d alerts (%d CRIT), MTTD(sabotage->alert) %.2fs, "
              "detect-before-impact: %s"
              % (variant.upper(), len(steps), len(det.alerts), len(crit),
                 mttd if mttd is not None else -1, dbi))
        results["scenarios"].append({
            "variant": variant, "actions": steps, "attack_start": first_ts,
            "alerts": det.alerts, "mttd_seconds": mttd,
            "detect_before_impact": dbi,
            "final_state": ctrl.status(),
        })
        httpd.shutdown()
        httpd.server_close()

    # --- Negative case: legitimate maintenance, zero alerts expected --------
    print("\n=== NEGATIVE CASE — legitimate maintenance (sim 10:15) ===")
    day = "2026-11-02T10:15:00"
    audit_path = os.path.join(ev_dir, "audit_negative.jsonl")
    alerts_path = os.path.join(ev_dir, "alerts_negative.jsonl")
    httpd, ctrl, audit = run_controller_in_thread(8080, audit_path, day)

    st, resp = http_req("POST", "127.0.0.1", 8080, "/api/login",
                        {"user": "tech", "pass": "Tq9x!Lm2#vZp7"})
    tok = resp.get("token") if st == 200 else None
    hdr = {"Authorization": "Bearer " + tok} if tok else {}
    http_req("POST", "127.0.0.1", 8080, "/api/case/FZ-01/setpoint",
             {"value": -22.0}, hdr)      # within freezer band [-30,-15]
    http_req("GET", "127.0.0.1", 8080, "/api/status")
    time.sleep(0.5)
    det = tail_detect(audit_path, alerts_path, poll_s=0.2, max_s=1.5, quiet=True)
    crit_neg = [a for a in det.alerts if a["level"] in ("CRIT", "WARN")]
    print("[demo] negative case: %d alerts total, %d CRIT/WARN (expected: 0 / 0)"
          % (len(det.alerts), len(crit_neg)))
    results["negative_case"] = {
        "scenario": "legitimate technician, maintenance window, in-band setpoint",
        "alerts": det.alerts,
        "crit_or_warn": len(crit_neg),
        "pass": len(crit_neg) == 0,
    }
    httpd.shutdown()
    httpd.server_close()

    # --- Guarded run: same attack through the prevention artifact -----------
    print("\n=== SCENARIO H1 THROUGH GUARD (prevention artifact) ===")
    guard_audit = os.path.join(ev_dir, "audit_guard.jsonl")
    httpd, ctrl, ctrl_audit = run_controller_in_thread(8080, guard_audit, night)
    set_sim_time(night)
    g_audit = Audit(os.path.join(ev_dir, "guard_blocks.jsonl"))
    ghttpd = ThreadingHTTPServer(("127.0.0.1", 8081),
                                 make_guard_handler(g_audit, 8080))
    threading.Thread(target=ghttpd.serve_forever, daemon=True).start()

    from types import SimpleNamespace
    A2 = SimpleNamespace(target="127.0.0.1", port=8081, variant="h1", sim_time=night)
    steps, first_ts = attack(A2)
    time.sleep(1.0)
    blocks = [json.loads(l) for l in open(g_audit.path)]
    print("[demo] guard blocked %d actions; attack reached sabotage phase: %s"
          % (len(blocks), any(s["phase"] == "sabotage" for s in steps)))
    results["guarded_run"] = {
        "actions": steps, "guard_blocks": blocks,
        "controller_audit_records": sum(1 for _ in open(ctrl_audit.path)),
        "sabotage_reached": any(s["phase"] == "sabotage" for s in steps),
        "final_state": ctrl.status(),   # should be unchanged setpoints
    }
    ghttpd.shutdown()
    ghttpd.server_close()
    httpd.shutdown()
    httpd.server_close()

    out = os.path.join(ev_dir, "summary.json")
    with open(out, "w") as fh:
        json.dump(results, fh, indent=2)
    print("\n[demo] evidence written to %s" % ev_dir)
    print("[demo] summary: %s" % out)
    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="FROSTBOX lab (see report for context)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--audit", default="audit.jsonl")
    s.add_argument("--sim-time", default=None, help='ISO datetime, e.g. "2026-11-02T02:30:00"')
    s.set_defaults(fn=serve)

    a = sub.add_parser("attack")
    a.add_argument("--target", default="127.0.0.1")
    a.add_argument("--port", type=int, default=8080)
    a.add_argument("--variant", choices=["h1", "h2"], default="h1")
    a.add_argument("--sim-time", default=None)
    a.set_defaults(fn=lambda args: (attack(args), print("[attack] chain complete")))

    d = sub.add_parser("detect")
    d.add_argument("--audit", required=True)
    d.add_argument("--alerts", required=True)
    d.add_argument("--max-s", type=float, default=10)
    d.set_defaults(fn=detect_cli)

    g = sub.add_parser("guard")
    g.add_argument("--host", default="127.0.0.1")
    g.add_argument("--listen", type=int, default=8081)
    g.add_argument("--upstream", type=int, default=8080)
    g.add_argument("--audit", default="guard_blocks.jsonl")
    g.add_argument("--sim-time", default=None)
    g.set_defaults(fn=guard)

    m = sub.add_parser("demo")
    m.add_argument("--evidence-dir", default="evidence")
    m.set_defaults(fn=demo)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
