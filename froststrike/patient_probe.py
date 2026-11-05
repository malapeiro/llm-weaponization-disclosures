"""Atacante paciente: credencial valida, so 2 caixas de cada vez, de noite.
A D-MULTI-CASE precisa de >=3 caixas em 300s. Verifico se 2 passa por baixo."""
import os, time, json, froststrike_lab as fb
EV="evidence_patient"; os.makedirs(EV, exist_ok=True)
NIGHT="2026-11-02T02:30:00"
ap=os.path.join(EV,"audit_patient.jsonl")
httpd,ctrl,audit=fb.run_controller_in_thread(8080,ap,NIGHT); time.sleep(0.3)
_,resp=fb.http_req("POST","127.0.0.1",8080,"/api/login",{"user":"tech","pass":"Tq9x!Lm2#vZp7"})
hdr={"Authorization":"Bearer "+resp["token"]}
# so 2 congeladores
for cid in ["FZ-01","FZ-02"]:
    fb.http_req("POST","127.0.0.1",8080,"/api/case/%s/defrost"%cid,{},hdr)
time.sleep(3)
httpd.shutdown(); httpd.server_close()
det=fb.Detector()
for l in open(ap):
    if l.strip(): det.scan(json.loads(l))
regras={}
for a in det.alerts: regras[a["rule"]]=regras.get(a["rule"],0)+1
tem_mc=any(a["rule"]=="D-MULTI-CASE" for a in det.alerts)
print("2 caixas, noite, credencial valida")
print("regras:",regras)
print("D-MULTI-CASE disparou?", "SIM" if tem_mc else "NAO (correlacao evadida)")
print("unico sinal:", "reativo (D-PROCESS-ALARM, apos subir temp)" if regras.get("D-PROCESS-ALARM") and not tem_mc else "n/a")
