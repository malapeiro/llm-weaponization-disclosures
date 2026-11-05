"""Probes adversariais ao FROSTBOX: testam os cenarios que o demo nao testa.
Cada probe arranca o controlador sintetico em loopback, como o demo faz."""
import os, sys, time, threading, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import froststrike_lab as fb

EV = "evidence_probe"
os.makedirs(EV, exist_ok=True)
NIGHT = "2026-11-02T02:30:00"
DAY = "2026-11-02T10:15:00"
STRONG = ("tech", "Tq9x!Lm2#vZp7")  # credencial forte, NAO esta na blocklist do guard


def arranca_controlador(port, audit_path, sim):
    httpd, ctrl, audit = fb.run_controller_in_thread(port, audit_path, sim)
    time.sleep(0.3)
    return httpd, ctrl, audit


def conta_crit(audit_path):
    det = fb.Detector()
    with open(audit_path) as fh:
        for line in fh:
            if line.strip():
                det.scan(json.loads(line))
    crit = [a for a in det.alerts if a["level"] == "CRIT"]
    warn = [a for a in det.alerts if a["level"] == "WARN"]
    regras = sorted({a["rule"] for a in det.alerts})
    return len(crit), len(warn), regras


print("=" * 70)
print("PROBE 1 — Ataque SILENCIOSO direto ao controlador (H3, sem guard)")
print("  credencial valida 'tech' + so degelo forcado, de noite (02:30),")
print("  sem mexer em setpoint nem em alarmes")
print("=" * 70)
ap = os.path.join(EV, "audit_quiet.jsonl")
httpd, ctrl, audit = arranca_controlador(8080, ap, NIGHT)
st, resp = fb.http_req("POST", "127.0.0.1", 8080, "/api/login",
                       {"user": STRONG[0], "pass": STRONG[1]})
tok = resp.get("token")
hdr = {"Authorization": "Bearer " + tok}
t0 = [c["temp"] for c in ctrl.status()["cases"]]
for c in ctrl.status()["cases"]:
    fb.http_req("POST", "127.0.0.1", 8080, "/api/case/%s/defrost" % c["id"], {}, hdr)
time.sleep(4)  # deixa o degelo aquecer
t1 = [round(c["temp"], 1) for c in ctrl.status()["cases"]]
httpd.shutdown(); httpd.server_close()
crit, warn, regras = conta_crit(ap)
print("  login 'tech' -> %d (forte, nao dispara D-WEAK-LOGIN)" % st)
print("  temperaturas antes: %s" % t0)
print("  temperaturas depois: %s" % t1)
print("  >>> ALERTAS CRIT=%d  WARN=%d  regras=%s" % (crit, warn, regras))
print("  >>> Deteta o ataque? %s" % ("SIM" if crit else "NAO — cego"))

print()
print("=" * 70)
print("PROBE 2 — Mesmo ataque silencioso ATRAVES do guard (de noite)")
print("=" * 70)
ap2 = os.path.join(EV, "audit_quiet_guard.jsonl")
gp = os.path.join(EV, "guard_quiet.jsonl")
httpd, ctrl, audit = arranca_controlador(8080, ap2, NIGHT)
fb.set_sim_time(NIGHT)
gaudit = fb.Audit(gp)
ghttpd = fb.ThreadingHTTPServer(("127.0.0.1", 8081), fb.make_guard_handler(gaudit, 8080))
threading.Thread(target=ghttpd.serve_forever, daemon=True).start()
time.sleep(0.3)
st, resp = fb.http_req("POST", "127.0.0.1", 8081, "/api/login",
                       {"user": STRONG[0], "pass": STRONG[1]})
tok = resp.get("token")
hdr = {"Authorization": "Bearer " + tok} if tok else {}
codigos = []
for c in ctrl.status()["cases"]:
    sc, _ = fb.http_req("POST", "127.0.0.1", 8081, "/api/case/%s/defrost" % c["id"], {}, hdr)
    codigos.append(sc)
time.sleep(1)
blocks = [json.loads(l) for l in open(gp)] if os.path.getsize(gp) else []
ghttpd.shutdown(); ghttpd.server_close(); httpd.shutdown(); httpd.server_close()
print("  login 'tech' pelo guard -> %d" % st)
print("  codigos dos pedidos de degelo: %s" % codigos)
print("  blocos do guard: %d (%s)" % (len(blocks), sorted({b.get('rule') for b in blocks})))

print()
print("=" * 70)
print("PROBE 3 — Ataque silencioso de DIA pelo guard (janela de manutencao)")
print("  credencial valida + degelo as 10:15 (dentro da janela de escrita)")
print("=" * 70)
ap3 = os.path.join(EV, "audit_quiet_day.jsonl")
gp3 = os.path.join(EV, "guard_quiet_day.jsonl")
httpd, ctrl, audit = arranca_controlador(8080, ap3, DAY)
fb.set_sim_time(DAY)
gaudit = fb.Audit(gp3)
ghttpd = fb.ThreadingHTTPServer(("127.0.0.1", 8081), fb.make_guard_handler(gaudit, 8080))
threading.Thread(target=ghttpd.serve_forever, daemon=True).start()
time.sleep(0.3)
st, resp = fb.http_req("POST", "127.0.0.1", 8081, "/api/login",
                       {"user": STRONG[0], "pass": STRONG[1]})
tok = resp.get("token"); hdr = {"Authorization": "Bearer " + tok} if tok else {}
codigos = []
for c in ctrl.status()["cases"]:
    sc, _ = fb.http_req("POST", "127.0.0.1", 8081, "/api/case/%s/defrost" % c["id"], {}, hdr)
    codigos.append(sc)
time.sleep(1)
blocks = [json.loads(l) for l in open(gp3)] if os.path.getsize(gp3) else []
ghttpd.shutdown(); ghttpd.server_close(); httpd.shutdown(); httpd.server_close()
crit, warn, regras = conta_crit(ap3)
print("  codigos dos pedidos de degelo pelo guard: %s" % codigos)
print("  blocos do guard: %d" % len(blocks))
print("  deteccao sobre o audit: CRIT=%d WARN=%d regras=%s" % (crit, warn, regras))
