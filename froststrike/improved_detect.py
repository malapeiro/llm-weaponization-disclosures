import json, sys, collections
from datetime import datetime

audit = sys.argv[1]
recs = [json.loads(l) for l in open(audit) if l.strip()]

# --- Regra A: handler de ALARM do controlador (falta no Detector do lab) ---
alarms = [r for r in recs if r.get("event") == "ALARM"]

# --- Regra B: correlacao estilo KQL #4 (>=3 casos / 5 min / ator) ---
WIN = 300
by_actor = collections.defaultdict(list)
for r in recs:
    if r.get("event") in ("CFG_SETPOINT", "CMD_DEFROST", "CFG_ALARM"):
        t = datetime.strptime(r["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").timestamp()
        by_actor[r.get("actor")].append((t, r.get("case")))

corr_hits = []
for actor, evs in by_actor.items():
    evs.sort()
    for i, (t0, _) in enumerate(evs):
        janela = [c for (t, c) in evs if t0 <= t < t0 + WIN]
        if len(set(janela)) >= 3:
            corr_hits.append((actor, len(set(janela))))
            break

print("Regra A (ALARM do controlador): %d alertas  -> %s" % (
    len(alarms), "DISPARA" if alarms else "silencio"))
print("Regra B (correlacao >=3 casos/5min/ator): %s  -> %s" % (
    corr_hits, "DISPARA" if corr_hits else "silencio"))
