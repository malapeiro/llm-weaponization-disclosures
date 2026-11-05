"""Falso positivo? Tecnico legitimo, de dia, dentro da janela, a mexer
em 3+ caixas com setpoints DENTRO da banda. Nada disto e ataque."""
import os, time, json, froststrike_lab as fb
EV = "evidence_fp"; os.makedirs(EV, exist_ok=True)
DAY = "2026-11-02T10:15:00"
ap = os.path.join(EV, "audit_fp.jsonl")
httpd, ctrl, audit = fb.run_controller_in_thread(8080, ap, DAY)
time.sleep(0.3)
st, resp = fb.http_req("POST", "127.0.0.1", 8080, "/api/login",
                       {"user": "tech", "pass": "Tq9x!Lm2#vZp7"})
hdr = {"Authorization": "Bearer " + resp["token"]}
# ajuste sazonal legitimo: baixar setpoint de 4 congeladores, tudo dentro de [-30,-15]
for cid, val in [("FZ-01", -22.0), ("FZ-02", -23.0), ("FZ-03", -21.0), ("CH-01", 2.0)]:
    sc, _ = fb.http_req("POST", "127.0.0.1", 8080, "/api/case/%s/setpoint" % cid,
                        {"value": val}, hdr)
time.sleep(0.5)
httpd.shutdown(); httpd.server_close()
det = fb.Detector()
for l in open(ap):
    if l.strip(): det.scan(json.loads(l))
regras = {}
for a in det.alerts:
    regras[a["rule"]] = regras.get(a["rule"], 0) + 1
print("cenario: tecnico 'tech', 10:15, 4 caixas, setpoints DENTRO da banda")
print("alertas totais:", len(det.alerts), "| regras:", regras)
print("FALSO POSITIVO?" , "SIM" if any(a["level"]=="CRIT" for a in det.alerts) else "nao")
