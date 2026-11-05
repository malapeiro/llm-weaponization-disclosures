# Froststrike

## Anatomy of the 2026 European Supermarket Refrigeration Sabotage, and How to Stop It

**Author:** Sérgio Azevedo · **Date:** 2026-11-05 · **Artifact class:** execution-verified (lab)
**Subject:** the October–November 2026 refrigeration-controller sabotage campaign that hit Intermarché, Coopérative U, E.Leclerc, Carrefour, Monoprix, Delhaize, Colruyt and others across France, Portugal, Belgium, the Netherlands, Sweden, Estonia, Finland, Luxembourg and Ireland — including the November 2, 2026 incident against seven Intermarché stores in Portugal.

Notice. This repository is independent defensive research based exclusively on public sources (CERT-FR, ANSSI statements, press coverage, published CVE advisories). The emulation code does not reproduce any vendor endpoint, protocol, firmware path, password algorithm or CVE exploit chain; it operates only against the synthetic controller defined in this repository, on loopback (the attack module refuses any non-loopback target). It cannot be used against real equipment and adds no capability to anyone seeking to do so. The purpose is detection engineering and hardening, not offense.

---

## 1. Executive summary

Between the night of October 11–12, 2026 (France) and the night of November 1–2, 2026 (Portugal and much of western/northern Europe), unknown attackers took remote control of supermarket refrigeration supervisory systems and used them as weapons: they forced defrost cycles, raised temperature setpoints to +50 °C (with reports up to +80 °C), and suppressed alarms — at night, when stores were closed. Hundreds of tonnes of chilled and frozen food had to be destroyed. In Portugal, seven Intermarché stores were hit and three reported total merchandise loss; the chain as a whole reported losses in the tens of millions of euros.

The devices at the center of the campaign are remote refrigeration controllers and supervisory web interfaces of the Danfoss AK-SM / AK-SC families and the Copeland/Dixell XWEB family — equipment typically installed and remotely operated by third-party refrigeration contractors. ANSSI's public assessment attributes the October wave to **"elementary security flaws": direct internet exposure of the management interfaces, no particular hardening, and weak or default passwords** — not to the vulnerability research published weeks earlier ([AFP](https://www.franceinfo.fr/internet/securite-sur-internet/cyberattaques/des-magasins-systeme-u-et-intermarche-touches-par-une-cyberattaque-contre-leurs-installations-frigorifiques_8233720.html)).

This repository reconstructs the attack class, emulates it against a synthetic controller (`froststrike_lab.py`), measures detection (lab streaming MTTD: **0.25 s**, with the access phase detected **before** any physical impact in both emulated variants), and provides an executable prevention artifact: a write-protecting **guard proxy** that blocked the full attack chain at the authentication phase in the demonstration run, leaving all setpoints unchanged. After the initial release, independent adversarial probes by the operator (section 4.3) found and fixed three gaps — including the exact quiet pattern of the real campaign (forced defrost inside the legitimate night defrost window), which the v1.0 engine could not see at all. A second probe round (section 4.4) then attacked the fix itself and found a false positive on legitimate multi-case maintenance, which v1.2 scopes away; a third round (section 4.5) measured the patient-attacker threshold evasion and v1.3 closed it with a shift-scale correlation horizon. The probe → fix → re-run cycle, with each round executed and verified, is the method this repo demonstrates.

**Key defensive insight:** the sabotage window (a closed store at 02:30) overlaps the legitimate nightly defrost window. "Forced defrost at night" is therefore a weak signal by itself. The signals that matter are **setpoint band violations**, **alarm muting**, and **correlated multi-case writes outside maintenance windows** — plus detecting default-credential and hidden-service-auth logins, which fire before a single degree is lost.

---

## 2. The campaign: what is publicly known

### 2.1 Timeline

| Date | Event | Source |
|---|---|---|
| Aug 9, 2026 | Claroty Team82 publishes research on Danfoss AK-SM 800A: hidden "code-of-the-day" authentication (CVE-2025-41450), OS command injection (CVE-2025-41451), Nginx config injection (CVE-2025-41452); fixed in firmware R4.3.1; 2,765 systems found internet-exposed | [Claroty](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers), [Danfoss DSA-2025-08-01](https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-08-01/) |
| Oct 12, 2026 | **Wave 1 (France).** Night attack on refrigeration controllers of the Danfoss AK-SM/AK-SC family. Forced defrost + setpoints to +50 °C. ≥300 Intermarché/Netto, <100 Coopérative U, several E.Leclerc, 80 Carrefour, ~30 Monoprix. One store reports +80 °C, "melted fixtures" | [BFMTV](https://www.bfmtv.com/economie/consommation/la-temperature-est-montee-jusqu-a-50-degres-une-cyberattaque-contre-les-systemes-frigorifiques-provoque-la-destruction-de-produits-frais-dans-des-centaines-d-intermarche-et-de-super-u_AN-202610120327.html), [France Inter](https://www.radiofrance.fr/franceinter/podcasts/l-info-de-france-inter/cyberattaque-sur-des-installations-frigorifiques-4546707), [ICI](https://www.ici.fr/infos/faits-divers-justice/une-cyberattaque-d-une-extreme-gravite-cible-les-frigos-d-intermarche-de-leclerc-et-du-groupe-u-8217697) |
| Oct 12–16, 2026 | CERT-FR alert **CERTFR-2026-ALE-012** "Incident de sécurité ciblant les contrôleurs à distance des installations de réfrigération": recommends removing controllers from the internet, VPN-only access, changing default passwords, firmware updates, verifying defrost schedules, factory reset of compromised units. Extended Oct 13 to Copeland XWEB and Dixell XWEB; attack campaigns "probably still in progress" | [CERTFR-2026-ALE-012](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/), [Numerama](https://www.numerama.com/cyberguerre/2352205-cest-lhecatombe-apres-danfoss-un-deuxieme-fournisseur-de-systemes-frigorifiques-est-vise-par-des-hackers.html) |
| Oct 13, 2026 | Second product family confirmed: Dixell XWEB regulators also compromised (a Leclerc in the Tarn) | [Numerama](https://www.numerama.com/cyberguerre/2352205-cest-lhecatombe-apres-danfoss-un-deuxieme-fournisseur-de-systemes-frigorifiques-est-vise-par-des-hackers.html) |
| Oct 21, 2026 | ANSSI director Vincent Strubel (Senate hearing): attack enabled by "elementary security flaws" — direct internet exposure, weak passwords; explicitly **not** the recently published CVEs. Copeland reportedly acknowledges a vulnerability in a discontinued, end-of-life controller generation | [AFP via franceinfo](https://www.franceinfo.fr/internet/securite-sur-internet/cyberattaques/des-magasins-systeme-u-et-intermarche-touches-par-une-cyberattaque-contre-leurs-installations-frigorifiques_8233720.html), [Tech-Insider](https://tech-insider.org/fr/frigos-deuxieme-vague-anssi-copeland-dixell-2026/) |
| Nov 2, 2026 | **Wave 2 (Europe, incl. Portugal).** Same sabotage pattern overnight: Belgium (Carrefour ~15, Delhaize, Colruyt, Intermarché ~15, Ikea Mons), Sweden, Netherlands, Ireland, Luxembourg, Finland, Estonia. **Portugal: seven Intermarché stores, three with total merchandise loss.** Group Les Mousquetaires confirms the attack targeted "an external service provider responsible for refrigeration systems management" | [Observador](https://observador.pt/2026/11/02/ataque-informatico-atinge-frigorificos-e-congeladores-de-supermercados-na-belgica-luxemburgo-e-suecia/), [CM](https://www.cmjornal.pt/portugal/detalhe/ataque-informatico-ao-intermarche-desliga-frigorificos-em-sete-supermercados-de-norte-a-sul), [JN](https://www.jn.pt/justica/artigo/sistemas-de-refrigeracao-de-sete-lojas-intermarche-em-portugal-alvo-de-ciberataque/18143714) |
| Nov 3, 2026 | CNCS (PT national cybersecurity centre) coordinating since Nov 2; origin "presumed to be unauthorized access to the remote temperature controller of these systems, under the responsibility of a provider of the chain". PJ investigating jointly with CNCS | [SIC Notícias](https://sicnoticias.pt/pais/2026-11-03-centro-nacional-de-ciberseguranca-esta-a-acompanhar-incidente-que-afetou-sete-lojas-do-intermarche-em-portugal-0070a49e), [Observador](https://observador.pt/2026/11/03/cncs-acompanha-ciberataque-a-sete-lojas-intermarche-em-portugal-que-comprometeu-sistemas-de-refrigeracao/) |

### 2.2 Known vs unknown

**Confirmed by authorities/vendors/media:**

- Target class: remote refrigeration controllers/supervisors — Danfoss AK-SM & AK-SC, Copeland XWEB, Dixell XWEB — reachable through web management interfaces ([CERTFR-2026-ALE-012](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/)).
- Impact technique: forced defrost activation and setpoint manipulation to +50 °C, overnight ([France Inter](https://www.radiofrance.fr/franceinter/podcasts/l-info-de-france-inter/cyberattaque-sur-des-installations-frigorifiques-4546707)).
- ANSSI assessment for wave 1: elementary security failures, direct internet exposure, weak passwords — not the published CVEs.
- Portugal wave 2 reached customers of an external refrigeration-services provider (CNCS and Les Mousquetaires statements).
- No ransom demand and no data theft were reported for either wave; the goal was physical spoilage.

**Unknown / not publicly established:**

- Attribution, motivation, and the exact initial-access mechanism of wave 2.
- Whether one single method was used against all victims, or whether the provider's central platform was compromised (which would explain the simultaneity across countries).
- Per-store firmware versions and device generations affected.

---

## 3. Reconstructed attack chain (threat model)

The reconstruction below combines the confirmed facts with explicit, labeled hypotheses. H1 is the ANSSI-endorsed class for wave 1 and the CNCS-endorsed class for wave 2; H2 is the published-vulnerability class that ANSSI excluded for wave 1 but which cannot be excluded for wave 2 on current public information; H3 is the central-platform compromise.

| # | Phase | Description | ATT&CK mapping | Confidence |
|---|---|---|---|---|
| 1 | Reconnaissance | Internet-wide scan/fingerprint of exposed supervisory interfaces (Shodan/Censys indexes them; 2,765 Danfoss systems were publicly reachable) | Enterprise [T1596](https://attack.mitre.org/techniques/T1596/); ICS [T0883 Internet Accessible Device](https://attack.mitre.org/techniques/T0883/) | Confirmed (feasible & demonstrated exposure) |
| 2 | Initial access (H1) | Login to the web management interface with **default or weak credentials** — interfaces "normally in a closed network" but exposed "to anyone with a few bits of knowledge" (Synacktiv) | Enterprise [T1078.001 Default Accounts](https://attack.mitre.org/techniques/T1078/001/) | High (ANSSI-endorsed, wave 1) |
| 2b | Initial access (H2) | Authentication bypass via a hidden predictable daily code ("code-of-the-day" / "ONEDAY" class, CVE-2025-41450 / CVE-2025-6519) on unpatched or end-of-life firmware | Enterprise [T1190](https://attack.mitre.org/techniques/T1190/) / ICS [T0819 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T0819/) | Medium (published & feasible; ANSSI excludes for wave 1; wave 2 not assessed publicly) |
| 2c | Initial access (H3) | Compromise of the refrigeration contractor's central remote-management platform, inheriting fleet-wide reach in one night | Enterprise T1078 (third-party access) | Not excluded; unconfirmed |
| 3 | Sabotage execution | Remote commands: force defrost on all cases, raise setpoints to +50 °C, during the legitimate night defrost window | ICS [T1692.001 Unauthorized Message: Command Message](https://attack.mitre.org/techniques/T1692/001/) (v20; formerly T0855) | Confirmed (impact pattern) |
| 4 | Defense evasion | Alarm suppression / threshold manipulation so that the cold-chain breach is not reported until morning | ICS tactic [TA0107 Inhibit Response Function](https://attack.mitre.org/tactics/TA0107/) (specific technique ID: to be confirmed against the current matrix) | Plausible (consistent with delayed discovery; not individually confirmed) |
| 5 | Impact | Food spoilage, forced disposal, fixture damage (up to +80 °C reported) | ICS [T0879 Damage to Property](https://attack.mitre.org/techniques/T0879/) | Confirmed |

Timing is itself a technique: the sabotage window (02:00–04:00) overlaps the legitimate scheduled defrost window, blending malicious heating into expected telemetry.

---

## 4. The lab: FROSTBOX

`froststrike_lab.py` (single file, Python 3 stdlib only, ~1,100 lines) implements:

```
                         ┌──────────────────────────────────────────┐
   attack (H1/H2) ──────►│  guard proxy (prevention artifact)       │
   loopback only         │  • default-cred blocklist                 │
                         │  • maintenance-window write gate          │
                         │  • setpoint band clamps                   │
                         │  • hidden-auth path blocked               │
                         │  • alarm-mute requests blocked            │
                         └───────────────┬──────────────────────────┘
                                         ▼
                         ┌──────────────────────────────────────────┐
                         │  FROSTBOX synthetic controller            │
                         │  6 cases (3 freezers FZ-, 3 chilled CH-)  │
                         │  web supervisory interface (HTTP)         │
                         │  weak/default admin; hidden daily-code    │
                         │    service auth (H2, generic algorithm)   │
                         │  plant physics: pull-to-setpoint, defrost │
                         │    heaters, alarm thresholds              │
                         │  audit JSONL (telemetry)                 │
                         └───────────────┬──────────────────────────┘
                                         ▼
                         ┌──────────────────────────────────────────┐
                         │  detection engine (streaming tail of the  │
                         │  audit log, like an agent → SIEM)         │
                         │  D-WEAK-LOGIN · D-SERVICE-AUTH ·          │
                         │  D-SETPOINT-RANGE · D-OUT-OF-WINDOW ·     │
                         │  D-DEFROST-UNSCHEDULED · D-ALARM-MUTE     │
                         └──────────────────────────────────────────┘
```

**Run it:**

```bash
python3 froststrike_lab.py demo --evidence-dir evidence
```

The demo executes five scenarios and writes all evidence to `evidence/`:
audit trails, alert trails, guard-block logs and a machine-readable `summary.json`.

**Scope guard:** the attack module refuses any non-loopback target (`ScopeError`). The synthetic controller, its endpoints and its "daily service code" algorithm are defined in this file; nothing is derived from vendor internals.

### 4.1 Measured results (this run, execution-verified)

| Scenario | Outcome | Alerts | MTTD (sabotage → first CRIT alert) | Detected before physical impact? |
|---|---|---|---|---|
| **H1** — default-credential login, setpoints → +50 °C, forced defrost, alarm mute (02:30) | Full sabotage succeeds against unguarded controller | 32 (14 CRIT) | **0.25 s** (streaming poll interval) | **Yes** — `D-WEAK-LOGIN` fires during the access phase |
| **H2** — hidden daily-code service auth, same sabotage | Full sabotage succeeds | 32 (14 CRIT) | **0.25 s** | **Yes** — `D-SERVICE-AUTH` fires during the access phase |
| **Negative case** — legitimate technician, strong credential, maintenance window (10:15), in-band setpoint change | Normal operation | **0** | n/a | n/a (correctly no alert) |
| **H1 through guard proxy** | **Attack blocked at authentication** (3 × `G-DEFAULT-CRED-BLOCKED`); sabotage phase never reached; all setpoints unchanged (−20 °C / +3 °C) | 3 guard blocks | n/a | Chain died before impact |

Sample evidence records (from `evidence/`):

```json
{"event": "CFG_SETPOINT", "case": "FZ-01", "actor": "admin", "old": -20.0, "new": 50.0, "sim_ts": "2026-11-02T02:30:00Z"}
{"rule": "D-SETPOINT-RANGE", "level": "CRIT", "msg": "Setpoint 50.0°C on FZ-01 outside allowed band [-30, -15]°C"}
{"rule": "G-DEFAULT-CRED-BLOCKED", "msg": "login attempt with vendor-default credential 'admin' blocked"}
```

Artifact integrity: `froststrike_lab.py` (v1.4) — 1,129 lines, SHA-256 `c8cbcfe0ef65006cbb1caaf5f56522af22b9a725771b515b8557456f61ecf638`. v1.4 is a license-metadata-only change (docstring line corrected from MIT to Apache-2.0; no behavioral change, full regression re-run identical). v1.3 (1,124 lines, `a1fb2607059c4d8b8cfdf6819e3717df737dadae213ad4f3c6dd0ae09be7a246`), v1.2 (1,099 lines, `166f71d92a20e034e10844669ee0abfc13336015823e75606cdc93c15b60003e`), v1.1 (1,067 lines, `a35165c5f7b2e160cd44ed2b132357a193579d9c3a69a257aee8e4acbafa44d3`) and v1.0 (985 lines, `e1982dbb91490398cd4eebd70a492876e76629bc25781c3d772a0d7159fd18c5`) are preserved in the evidence trail: earlier versions were reconstructed byte-identically from the published canvases after environment resets, which is itself a validation of the artifact-integrity chain.

### 4.2 Reproducing each component individually

```bash
# terminal 1 — controller at night scenario time
python3 froststrike_lab.py serve --sim-time "2026-11-02T02:30:00" --audit audit.jsonl

# terminal 2 — adversary emulation (loopback only)
python3 froststrike_lab.py attack --variant h1   # or --variant h2

# terminal 3 — streaming detector
python3 froststrike_lab.py detect --audit audit.jsonl --alerts alerts.jsonl

# or: the prevention artifact in front of the controller
python3 froststrike_lab.py guard --listen 8081 --upstream 8080
python3 froststrike_lab.py attack --port 8081 --variant h1
```

### 4.3 Adversarial validation — operator probes (v1.1)

After the initial release, the operator ran independent adversarial probes (`probe.py`, `improved_detect.py`, `fp_probe.py`, `patient_probe.py`, shipped in the repo root) against scenarios the demo does not cover. All three findings were confirmed and fixed in v1.1:

| Probe | Scenario (not covered by the demo) | v1.0 result | v1.1 result |
|---|---|---|---|
| 1 | **Quiet attack, no guard:** valid strong credential ('tech'), defrost-only, night (02:30), no setpoint/alarm changes — exactly the real campaign pattern (forced defrost inside the legitimate defrost window) | **Blind**: 0 alerts while temperatures rose from −19.5 °C to −6.7 °C (freezers) and +3.5 °C to +16.3 °C (chilled) | **Detected**: `D-MULTI-CASE` CRIT (correlation, operator rule B) + 6 × `D-OUT-OF-WINDOW` WARN (now covers all config/command events) + 6 × `D-PROCESS-ALARM` WARN (controller ALARM telemetry, operator rule A) |
| 2 | Same quiet attack through the guard at night | Guard blocks all 6 defrost commands (`G-OUT-OF-WINDOW`) | Unchanged: 6 × 403 |
| 3 | Same quiet attack through the guard **inside** the maintenance window (10:15) | Guard fully permissive (6 × 200, 0 blocks); detection left to `D-DEFROST-UNSCHEDULED` alone | Guard limits blast radius: first 2 commands forwarded, further 4 blocked (`G-DEFROST-FLEET-ANOMALY`, fleet-wide defrost is never a legitimate remote pattern); `D-DEFROST-UNSCHEDULED` still fires CRIT on the 2 forwarded commands |

Rule provenance: `D-PROCESS-ALARM` and `D-MULTI-CASE` originate from the operator's `improved_detect.py` (rules A and B); they were verified against both sabotage audits, the quiet-attack audit and the negative case (no false positive: the legitimate single-case maintenance change keeps all correlation rules silent).

### 4.4 False-positive validation — operator `fp_probe.py` (v1.2)

The operator then attacked the fix itself: a legitimate technician ('tech') at 10:15, **inside** the maintenance window, lowering the setpoints of **4 cases**, all **inside the allowed band** — ordinary seasonal maintenance, nothing anomalous. v1.1 raised `D-MULTI-CASE` CRIT on it, because the rule counted distinct cases per actor with no regard to window, band or source. The demo's negative case (one case only) could never expose this.

| Scenario | v1.1 result | v1.2 result |
|---|---|---|
| Legitimate multi-case maintenance, in-window, in-band (`fp_probe.py`) | **False positive**: 1 × `D-MULTI-CASE` CRIT | **Silent**: 0 alerts |
| Probe 1 (quiet defrost-only night attack) re-run | detected (CRIT + 12 WARN) | **Unchanged** — still detected: 1 × `D-MULTI-CASE` CRIT + 12 WARN |
| Probe 3 (in-window attack through guard) re-run | 4/6 blocked + 2 CRIT | **Unchanged** — 4/6 blocked + 2 × `D-DEFROST-UNSCHEDULED` CRIT |
| Canonical demo H1/H2 + negative case re-run | 32/14, 0 FP | **Unchanged** — 32 alerts (14 CRIT), MTTD 0.25 s, negative case 0 |

v1.2 fix: `D-MULTI-CASE` now requires a **secondary anomaly signal** on each counted event — out-of-band setpoint, off-schedule defrost, alarm suppression, or any config/command event outside the maintenance window. In-window, in-band, alarm-preserving writes are invisible to the correlation (legitimate maintenance by definition); a credential-thief restricting themselves to that pattern remains covered for defrost operations by `D-DEFROST-UNSCHEDULED` and `G-DEFROST-FLEET-ANOMALY`.

**Documented residual (measured, not assumed):** legitimate *emergency* maintenance **outside** the maintenance window on 3+ cases still alerts (verified: 4 in-band setpoint writes at 02:30 → `D-OUT-OF-WINDOW` + `D-MULTI-CASE`). This is intentional: out-of-window multi-case writes deserve review. The SOC-side mitigation is a maintenance-mode/actor allowlist (deliberately not implemented in the lab, to keep the rule conservative).

### 4.5 Patient-attacker validation — operator `patient_probe.py` (v1.3)

The operator then tested the threshold-evasion limit predicted in section 7: a valid credential touching only **2 cases at a time**, at night. `D-MULTI-CASE` needs ≥3 distinct cases in 5 minutes, so a single pair is below its resolution — and an attacker iterating pairs spaced >5 minutes apart evades it entirely. Measured against v1.2, at engine level, with a paced 6-case audit (pairs 610 s apart, night, defrost-only, direct access):

| Scenario | v1.2 result | v1.3 result |
|---|---|---|
| Operator `patient_probe.py` (one pair, 2 cases, night, valid cred) | Correlation evaded; `D-OUT-OF-WINDOW` 2 × WARN (pre-damage) + `D-PROCESS-ALARM` 2 × WARN (reactive) | Same — 2 total cases are below any case-count correlation **by design** (documented floor) |
| Paced whole-fleet attack (6 cases, pairs 610 s apart, night, direct access) | **Fleet down with zero CRIT alerts** (6 × `D-OUT-OF-WINDOW` WARN only) | **`D-MULTI-CASE` CRIT at the 3rd case** (patient horizon: ≥3 distinct cases within 1 h) — 2 cases attacked, 4 saved |
| Same attack **through the guard**, night | Blocked entirely by `G-OUT-OF-WINDOW` (nothing passes at 02:30) | Unchanged |
| Fleet ceiling `G-DEFROST-FLEET-ANOMALY` under spacing (daytime, in-window, time-scaled logic test) | Sliding-window ceiling evaded by spacing pairs beyond the window (3 forwarded with limit 2) | Unchanged (architectural: sliding windows are pace-evadable) — daytime forwarded defrosts still each hit `D-DEFROST-UNSCHEDULED` CRIT |
| Canonical demo H1/H2 + negative case + `fp_probe.py` re-run | 32/14, 0 FP | **Unchanged** — 32 alerts (14 CRIT), negative 0, fp_probe 0 |

v1.3 fix: `D-MULTI-CASE` runs a **dual horizon** — burst (≥3 distinct cases / 5 min, as before) or patient (≥3 distinct cases / 1 h, new) — both still gated on the v1.2 secondary anomaly signal. The burst alert takes precedence and the rule stays deduplicated per actor, so H1/H2 counts are unchanged.

**What the patient probe proves about the remaining surface:** with a valid credential and direct controller access, the correlation floor is 3 cases. Two cases total is below any case-count rule; the only pre-damage signal there is the out-of-window WARN (which should page in a real SOC), and the process alarms are reactive. The sliding-window guard ceiling is pace-evadable by construction. The real fix for both is the same as ever: do not let the controller be directly reachable at all (section 6).

---

## 5. Detection engineering

Reference rules are in [`detections/`](detections/README.md): two Sigma rules over the lab audit schema, one generic Sigma rule for proxy/webserver logs, four Suricata signatures for the config-write and hidden-auth endpoint classes, and Sentinel KQL hunting queries (including the correlated multi-case sabotage pattern).

### 5.1 Coverage matrix

| Detection | Covers (ATT&CK) | Positive case | Negative case |
|---|---|---|---|
| `D-WEAK-LOGIN` / `G-DEFAULT-CRED-BLOCKED` | T1078.001 | H1 run: fires before impact | Technician with strong cred: silent |
| `D-SERVICE-AUTH` / `G-HIDDEN-AUTH-BLOCKED` | T1190/T0819 (bypass class) | H2 run: fires before impact | No legitimate use exists in lab |
| `D-SETPOINT-RANGE` / `G-SETPOINT-CLAMP` | T1692.001, T0879 | H1/H2: fires per case in ≤0.25 s | In-band maintenance change: silent |
| `D-OUT-OF-WINDOW` / `G-OUT-OF-WINDOW` | TA0107-adjacent | H1/H2 + probe 1: fires per write/command (v1.1: all config events, not only setpoints) | Daytime maintenance: silent |
| `D-ALARM-MUTE` / `G-ALARM-MUTE-BLOCKED` | TA0107 | H1/H2: fires per case | n/a (muting is never legitimate remotely) |
| `D-MULTI-CASE` (v1.1, operator rule B; v1.2 requires a secondary anomaly signal; v1.3 dual horizon: ≥3 cases/5 min burst or ≥3 cases/1 h patient; KQL hunt #4 is the SIEM equivalent) | Campaign signature | H1/H2 + probe 1: CRIT on burst; paced 6-case patient attack: CRIT at 3rd case | Multi-case in-window, in-band maintenance: silent (verified with `fp_probe.py`; v1.2 scoping) |
| `D-PROCESS-ALARM` (v1.1, operator rule A) | Process-level deviation (DET0794-adjacent) | Probe 1: 6 plant alarms become WARN alerts instead of being ignored | Controller at setpoint: no alarms to flag |
| `G-DEFROST-FLEET-ANOMALY` (v1.1) | Blast-radius limiting | Probe 3: 4 of 6 in-window defrost commands blocked | 1–2 case service defrost inside window: forwarded |

ATT&CK also publishes a detection strategy for the command-message technique ([DET0794](https://attack.mitre.org/detectionstrategies/DET0794/)); for [T0879 Damage to Property](https://attack.mitre.org/detectionstrategies/DET0762/) MITRE notes no standard detection method exists, which is why band-violation and correlation rules are the practical compensating controls.

### 5.2 Detection caveats (measured, not assumed)

- **Nightly-defrost blind spot (measured in the lab, closed in v1.1):** `D-DEFROST-UNSCHEDULED` did **not** fire during the 02:30 sabotage because 02:00–05:00 is the legitimate defrost window — an attack deliberately timed inside that window evades any "defrost at night" rule. Operator probe 1 proved this was a full blind spot in v1.0 (a defrost-only attack with a valid credential raised temperatures with zero alerts). v1.1 closes it with three independent signals, all of which now fire: correlated multi-case activity (`D-MULTI-CASE`, CRIT), out-of-maintenance-window commands (`D-OUT-OF-WINDOW`, generalized to every config/command event) and the controller's own plant alarms (`D-PROCESS-ALARM`). `D-DEFROST-UNSCHEDULED` remains window-blind **by design** (it encodes scheduled-window semantics) and should never be the only defrost-related control.
- **The correlation fix is itself adversarially validated (v1.2):** the rule that closed probe 1 opened a false positive on ordinary multi-case maintenance (operator `fp_probe.py`). Counting cases per actor without context means a technician tuning 6 cases in one morning produces a CRIT — the kind of alert that gets a rule disabled in a real SOC. The v1.2 secondary-signal scoping (section 4.4) keeps the attack detection and silences the maintenance; the SIEM-side KQL hunt #4 must apply the same scoping or it inherits the false positive.
- **Weak-credential login is your best pre-impact signal:** in both variants the CRIT alert fired during initial access, before the first setpoint was touched. Log supervisor authentication and treat any default-account or hidden-service login as an incident, not a log line.
- **Lab MTTD is pipeline MTTD, not organizational MTTD.** 0.25 s is the streaming poll interval; a real deployment adds agent forwarding and SIEM ingestion (typically seconds to minutes) plus — the dominant term in the real campaign — **time until a human looks at the alarm at 02:30**. Unattended-hours alerting paths (call-out, store security) are part of the design.
- **Unauthenticated status reads** (mirroring real misconfiguration) give attackers free reconnaissance. Treat unauthenticated `/status` exposure as a finding by itself.

---

## 6. How to prevent this class of attack

The guard proxy is a reference implementation; the real fix is architectural. Mapped to CERT-FR's recommendations for CERTFR-2026-ALE-012 ([cert.cyber.gouv.fr](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/)):

| Control | CERT-FR recommendation | Reference in this repo | Priority |
|---|---|---|---|
| **1. Remove direct internet exposure** | Take controllers off the internet; access only via VPN | Guard proxy: source allowlist + path allowlist | Critical |
| 2. Never expose the management interface raw | "VPN, bastion d'administration, réseau dédié" (ANSSI guidance since 2014) | `guard` component | Critical |
| **3. Kill default/weak credentials** | Change default passwords; strong per-user creds | `G-DEFAULT-CRED-BLOCKED`; `tech` account pattern | Critical |
| 4. Constrain what remote access can do | Limit writes to maintenance windows and in-band setpoints | `G-OUT-OF-WINDOW`, `G-SETPOINT-CLAMP` | High |
| 4b. Cap fleet-wide commands | Not in CERT-FR list; recommended here (probe finding) | `G-DEFROST-FLEET-ANOMALY` (max 2 distinct cases per 10 min) | High |
| 5. Block alarm muting remotely | Not in CERT-FR list; recommended here | `G-ALARM-MUTE-BLOCKED` | High |
| 6. Update firmware / security mode "Strict" (Danfoss), verify defrost schedules, factory-reset compromised units | Vendor + CERT-FR guidance | Out of lab scope (documented) | High |
| 7. Inventory + EOL replacement | Old controllers out of security support (Copeland acknowledged an EOL-generation flaw) | Documented; guard is the compensating control for EOL fleets | Medium |
| 8. Third-party access governance | Refrigeration contractors hold remote admin on systems IT doesn't own | Guard: single enforced choke point for all parties | Medium |
| 9. Monitor and alert, including at night | Correlated sabotage alerting with unattended-hours escalation | Detection engine + KQL hunt #4 | High |

Segmentation note: refrigeration control belongs on a dedicated OT network (Purdue levels 0–3), separated from store IT. Where two-way remote control is not genuinely required, unidirectional gateways (data diodes) make the sabotage class physically impossible rather than merely filtered.

Governance note: in the EU, food retailers and their service providers increasingly fall under NIS2-style obligations; third-party remote access to safety-relevant control systems belongs in contracts, risk registers and audit scope.

---

## 7. What cannot be claimed (limitations)

- This repo does **not** prove how the real attackers got in. Authorities have not published the initial-access mechanism for either wave; ANSSI's statement covers wave 1's class only. The chain in section 3 is a threat model, explicitly labeled.
- The lab device is synthetic. Real controllers expose different protocols, authentication schemes and log formats; the Sigma rules use the lab's schema and the webserver-category field names, and must be adapted and tested per pipeline.
- Suricata and Sigma rules were **not** executed against a Suricata/SIEM instance in this run; they are textual compliance for those engines (the Python detection engine and guard are the executed, execution-verified components).
- Lab MTTD (0.25 s) is the streaming poll interval under zero load; it is a lower bound, not a production expectation.
- **Every detection rule reads the controller's own audit log.** `D-MULTI-CASE`, `D-PROCESS-ALARM`, `D-OUT-OF-WINDOW` — the whole engine consumes the log the controller writes. This closes the blind spot against a *noisy* attacker who leaves the log intact; an attacker who owns the controller and suppresses or rewrites the audit erases the detection layer with it (the v1.1/v1.2 fixes do not change this). Without an independent sensor (out-of-band probe, network capture, or the guard proxy's own log as a second source), detection lives at the mercy of the compromised source. This is the single deepest hole in the design and it is architectural, not a rule away from being fixed.
- **Against a valid-credential adversary (H3-class), detection is reactive, not pre-impact.** The "detect-before-impact: true" result holds only for the noisy variants (H1/H2): there, the default-account or hidden-service login is the pre-impact signal. With a legitimately valid credential, the earliest `D-MULTI-CASE` can fire is the 3rd case — by which time 2 cases are already under attack — and `D-PROCESS-ALARM` only ignites after temperatures have risen, i.e. with damage in progress. For the silent variant, the honest claim is "detection at first anomalous write, damage-limiting via the guard", not "detection before impact".
- **Thresholds are evadable by a patient actor — partially mitigated in v1.3, floor documented.** `D-MULTI-CASE` now runs a dual horizon (≥3 cases/5 min burst, ≥3 cases/1 h patient), closing the pacing evasion measured by the operator's `patient_probe.py` follow-up (a 6-case fleet attack in pairs 610 s apart previously produced zero CRIT alerts; it now fires at the 3rd case, section 4.5). Three limits remain, stated plainly: (1) a total of ≤2 cases is below any case-count correlation by design — the only pre-damage signal there is the out-of-window WARN; (2) the guard's sliding-window fleet ceiling is pace-evadable by construction (spacing pairs beyond the window; verified with a time-scaled logic test); (3) an actor slower than 3 cases per hour still passes. Longer-horizon baselines (cases per actor per shift) would raise the bar at the cost of the same false-positive tradeoff section 4.4 documents.
- The v1.2 scoping keeps a **measured residual**: legitimate emergency maintenance outside the window on 3+ cases still alerts (`D-OUT-OF-WINDOW` + `D-MULTI-CASE`, section 4.4). Intentional and documented; the SOC-side fix is a maintenance-mode allowlist, not a rule change.
- No attribution, actor profile or motivation is asserted anywhere in this repo.
- ATT&CK mapping notes: ICS technique IDs are per the current ATT&CK for ICS matrix (v20-era); "Unauthorized Command Message" (T0855) was restructured into [T1692.001](https://attack.mitre.org/techniques/T1692/001/) in the current version. The alarm-suppression technique mapping is given at tactic level only (TA0107) pending confirmation against the current matrix.

---

## 8. References

1. CERT-FR, **CERTFR-2026-ALE-012** — *Incident de sécurité ciblant les contrôleurs à distance des installations de réfrigération* — https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/
2. The Hacker News — *Attackers Heat French Supermarket Fridges Up to 50°C by Hijacking Danfoss Controllers* — https://thehackernews.com/2026/10/attackers-heat-french-supermarket.html
3. BFMTV — *INFO BFMTV: "Extrême gravité, inédit et inacceptable"* — https://www.bfmtv.com/economie/consommation/la-temperature-est-montee-jusqu-a-50-degres-une-cyberattaque-contre-les-systemes-frigorifiques-provoque-la-destruction-de-produits-frais-dans-des-centaines-d-intermarche-et-de-super-u_AN-202610120327.html
4. France Inter (Radio France) — *Cyberattaque de frigos : près de 300 magasins Intermarché touchés* — https://www.radiofrance.fr/franceinter/podcasts/l-info-de-france-inter/cyberattaque-sur-des-installations-frigorifiques-4546707
5. franceinfo — *Des magasins Système U, Intermarché, E.Leclerc et Monoprix touchés…* — https://www.franceinfo.fr/internet/securite-sur-internet/cyberattaques/des-magasins-systeme-u-et-intermarche-touches-par-une-cyberattaque-contre-leurs-installations-frigorifiques_8233720.html
6. franceinfo — *Un piratage "pas si sophistiqué que ça"* — https://www.franceinfo.fr/internet/securite-sur-internet/cyberattaques/un-piratage-pas-si-sophistique-que-ca-ce-que-l-on-sait-de-la-cyberattaque-qui-a-fait-monter-en-temperature-les-frigos-de-supermarches_8235061.html
7. ICI (Radio France) — *Frigos à 50 degrés, produits frais jetés* — https://www.ici.fr/infos/faits-divers-justice/une-cyberattaque-d-une-extreme-gravite-cible-les-frigos-d-intermarche-de-leclerc-et-du-groupe-u-8217697
8. Numerama — *après Danfoss, un deuxième fournisseur de systèmes frigorifiques est visé* — https://www.numerama.com/cyberguerre/2352205-cest-lhecatombe-apres-danfoss-un-deuxieme-fournisseur-de-systemes-frigorifiques-est-vise-par-des-hackers.html
9. AFP (2026-10-21) — *La cyberattaque des frigos liée à des "défauts de sécurisation élémentaires", selon l'Anssi* (Vincent Strubel, Senate hearing)
10. AFP (2026-11-02) — *La cyberattaque contre les frigos rappelle la vulnérabilité des objets connectés* (incl. Synacktiv commentary)
11. Observador — *Ataque informático a sistemas de refrigeração afeta Intermarché em Portugal* — https://observador.pt/2026/11/02/ataque-informatico-atinge-frigorificos-e-congeladores-de-supermercados-na-belgica-luxemburgo-e-suecia/
12. Observador — *CNCS acompanha ciberataque a sete lojas Intermarché em Portugal* — https://observador.pt/2026/11/03/cncs-acompanha-ciberataque-a-sete-lojas-intermarche-em-portugal-que-comprometeu-sistemas-de-refrigeracao/
13. Correio da Manhã — *Ataque informático ao Intermarché desliga frigoríficos em sete supermercados* — https://www.cmjornal.pt/portugal/detalhe/ataque-informatico-ao-intermarche-desliga-frigorificos-em-sete-supermercados-de-norte-a-sul
14. SIC Notícias — *CNCS está a acompanhar incidente que afetou sete lojas do Intermarché* — https://sicnoticias.pt/pais/2026-11-03-centro-nacional-de-ciberseguranca-esta-a-acompanhar-incidente-que-afetou-sete-lojas-do-intermarche-em-portugal-0070a49e
15. JN — *Sistemas de refrigeração de sete lojas Intermarché em Portugal alvo de ciberataque* — https://www.jn.pt/justica/artigo/sistemas-de-refrigeracao-de-sete-lojas-intermarche-em-portugal-alvo-de-ciberataque/18143714
16. Claroty Team82 — *Freeze the Controller, Defrost the Food* (CVE-2025-41450/41451/41452) — https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers
17. Danfoss — **DSA-2025-08-01** — https://www.danfoss.com/en/service-and-support/coordinated-vulnerability-disclosure/danfoss-security-advisories/dsa-2025-08-01/
18. ONYPHE — *Refrigeration as Critical Infrastructure: the Exposure of Copeland/Dixell Supervisory Systems* (CVE-2025-6519, CVE-2025-52550) — https://blog.onyphe.io/en/refrigeration-as-critical-infrastructure-beyond-danfoss-the-exposure-of-copeland-dixell-supervisory-systems/
19. Refindustry — *Danfoss, Copeland and Trane address controller security vulnerabilities* — https://refindustry.com/news/danfoss-copeland-and-trane-address-controller-security-vulnerabilities/
20. MITRE ATT&CK — T1596, T1078.001, T1190 (Enterprise); T0883, T0819, T1692.001, T0879, TA0107 (ICS); DET0794, DET0762 (Detection Strategies) — https://attack.mitre.org/

---

## 9. License and usage

- **Code** (`froststrike_lab.py`, `detections/`, `probe.py`, `improved_detect.py`, `fp_probe.py`, `patient_probe.py`): Apache-2.0 — see `LICENSE`.
- **Report and documentation** (this file, `README.md`, `detections/README.md`): CC BY-NC-SA 4.0 — see `LICENSE-docs`.

Intended use. This is defensive security research. The adversary-emulation module is scope-guarded to loopback and targets only this repository's synthetic controller; it contains nothing specific to any real product. The author does not condone use of this material against systems one does not own and operate as a lab. This paragraph states intent; it is not a license term.

*Operated under the PVTE v5.0 verification framework: Phase 1 verification table and "what cannot be claimed" disclosures apply to every claim in this file.*