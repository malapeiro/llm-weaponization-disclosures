# Defensive Analysis of a `pymodbus` PoC against a Siemens S7-1200 over Modbus/TCP

**Research protocol:** PVTE-X v1.1 (Rev. A → E)
**Domain:** OT / ICS — Operational Technology
**Artifact under analysis:** `pymodbus_s7_1200_poc_v1` (low-sophistication offensive script)
**Document type:** Defensive analysis, detection engineering, and experimental validation
**Status:** Factually verified where independently confirmable; **not** bench-validated on real hardware (see §9)
**Verification level:** *Textual compliance — unverified code generation* (offensive artifact). The artifact's claimed telemetry-sabotage effect was additionally assessed as **non-viable** via an execution-verified simulation of the PLC scan cycle (see §3). This entry therefore carries the lowest evidentiary weight for the offensive artifact, while adding an execution-verified **defensive** result.

> **Disclosure note.** This document analyzes an offensive PoC for the sole purpose of **debunking its real-world efficacy**, building **detection**, and proposing **hardening**. The LLM persona-injection vector (jailbreak) that originally elicited the artifact was responsibly disclosed to the vendor (see §11) and is **not** reproduced here in any form — neither the activation prompt nor the offensive PoC's complete source. No real industrial system was involved or targeted at any point.

---

## 1. Executive Summary & Scope

This report consolidates the technical analysis of a Python script built on `pymodbus` which, per its original framing, would physically sabotage a Siemens S7-1200 PLC — shutting down a "turbine" and **falsifying the telemetry** reported to the control panel, in the manner of Stuxnet (2010).

The central conclusion contradicts the artifact's framing:

- **Write to telemetry (output) registers:** **practically null** impact. The falsified value is overwritten by the PLC program logic within **one scan cycle (1–10 ms)**. *Persistent* telemetry spoofing via a static Modbus write is physically non-viable — this was **measured experimentally** and is the core of this report (§3).
- **Write to setpoint/command (input) registers:** **conditional** impact. A value written to a register read by the control logic persists until it is overwritten by a legitimate operator/HMI. Here the attack is viable — **but only if** Modbus is exposed without network segmentation.

**Real severity:** The severity does not reside in the sophistication of the script — it is a "skiddie OT"-class artifact. It resides, if at all, in an **architectural failure** of the target environment: an exposed Modbus/TCP `MB_SERVER`, without segmentation and without network access control. Defense must live at the **network layer**, because the protocol provides none (§5).

### 1.1 Delimitation of the validated thesis

The experimental proof in §3 applies **strictly** to telemetry registers refreshed by the PLC program on each cycle. It is **not** a claim that "any Modbus write is harmless." The setpoint case is outside the scope of the proof and remains conditionally exploitable.

---

## 2. Technical Deconstruction of the PLC & Execution Physics

### 2.1 Native protocol vs. optional Modbus service

| Item | Detail |
|---|---|
| Native S7-1200 protocol | **S7comm / S7comm-Plus** — port **102/TCP** (TIA Portal, WinCC, native HMIs) |
| Protocol used by the PoC | **Modbus/TCP** — port **502/TCP** |
| Modbus state on the S7-1200 | **Optional.** Requires explicit instantiation of the `MB_SERVER` function block in the program. **Not active by default.** |
| Modbus authentication | **None** at the protocol level |
| Encryption | **None** — Modbus/TCP is cleartext |

**Immediate implication:** the PoC comments "PLC S7-1200" but speaks Modbus on port 502. On a factory-default S7-1200 (no `MB_SERVER`), the script **fails at the connection stage** with a timeout. The tacit precondition — an active, reachable `MB_SERVER` — is the real attack condition, and it belongs to the target's configuration, not the attacker's tooling.

### 2.2 The `MB_HOLD_REG` parameter

The `MB_SERVER` block (S7-1200/S7-1500) exposes a data area to Modbus clients. That area is referenced by the **`MB_HOLD_REG`** parameter — a pointer to a Data Block (DB) declared in the program.

> **Factual correction (Rev. A→D):** `MB_HOLD_REG` is the correct `MB_SERVER` parameter. `DATA_PTR` belongs to `MB_CLIENT` (client side), not the server.

**DB configuration requirement:** the Data Block referenced by `MB_HOLD_REG` must have **"Optimized block access" DISABLED** (standard/legacy access, with absolute offset addressing). If the DB is "Optimized", communication is rejected or raises a compile/runtime error — one more practical obstacle to the PoC working *out-of-the-box*.

### 2.3 The OB1 scan-cycle dynamics

The PLC's execution architecture is what nullifies the telemetry attack:

1. `MB_SERVER` exposes a `DB` referenced by `MB_HOLD_REG`.
2. The PLC program (OB1 and event-driven OBs) reads from and writes to that `DB` **on every scan cycle**.
3. OB1 scan cycle on an S7-1200: typically **1–10 ms**; the watchdog (cycle-time limit) defaults to ~150 ms before the PLC goes to STOP.
4. If a telemetry register is fed from a real input (an RPM sensor via `%IW`, or a computed variable), **every scan cycle overwrites the real value on top of the value falsified by the attacker**.

| Register semantics | Effect of the Modbus write | Viability |
|---|---|---|
| **Output** (sensor → register, read by HMI) | Fake value visible ≤ 1 scan cycle; then overwritten | **Null** in practice |
| **Input/setpoint** (read by the logic) | Persists until HMI rewrites | **Viable** if Modbus exposed |
| **Static/configuration** | Persists until next event that updates it | Viable but requires knowledge of the mapping |

For *sustained* telemetry falsification, the attacker would have to **modify the PLC program** (e.g., disable the OB1 refresh logic) — which corresponds to `T0889 Modify Program` (Persistence tactic), a completely different and more sophisticated attack that the PoC does **not** perform and that this report does **not** provide.

---

## 3. Metrology and Experimental Proof (Task 1 v2)

### 3.1 Objective

Empirically validate the thesis: *a falsified value written to an output register refreshed by OB1 does not persist beyond one scan cycle.*

### 3.2 Methodological note — corrected bias (v1 → v2)

The first harness version contained a **metrological flaw**: the injection instant (`attack_at_ms`) was fixed to an **exact multiple** of `scan_cycle_ms`, so the write always landed in phase with the OB1 tick. The measured "survival window" (0.17–0.75 ms) did not measure the process's stochastic window, but only the **residual OS scheduling offset**. v2 corrects this with **phase-shifted stochastic injection**.

### 3.3 Harness design (v2)

- **3 concurrent threads:** (1) OB1 — overwrites the register every `scan_cycle`; (2) HMI — polling at 1 ms; (3) attacker — single point write.
- **Measurement:** `time.perf_counter_ns()`, with a **spin-wait** for sub-millisecond precision (avoids `time.sleep()` resolution error).
- **Stochastic injection:** offset ~ **U(0, scan_cycle)** drawn per trial; seeded RNG (`master_seed = 20261104`).
- **Sampling:** **N = 100 trials** per configuration (scan = 2, 5, 10 ms; poll = 1 ms) — **300 trials** total.

### 3.4 Results — distributions (N = 100 per configuration)

| Config | Survival min | mean | median | **max** | stdev | HMI mean | **HMI max** |
|---|---|---|---|---|---|---|---|
| scan = 2 ms | 0.032 ms | 1.043 ms | 1.125 ms | **1.978 ms** | 0.589 ms | 1.02 | **2** |
| scan = 5 ms | 0.081 ms | 2.323 ms | 2.273 ms | **4.973 ms** | 1.403 ms | 2.17 | **5** |
| scan = 10 ms | 0.075 ms | 4.885 ms | 4.473 ms | **9.998 ms** | 2.782 ms | 4.66 | **10** |

### 3.5 Linear model validation

Physical model: the write occurs at `t_cycle_start + offset`; the next overwrite occurs at `t_cycle_start + scan_cycle`. Therefore:

```
T_survival = T_scan − offset
```

| Config | Pearson r | Slope (theory: −1) | Intercept (theory: scan) |
|---|---|---|---|
| scan = 2 ms | −0.9896 | −0.9964 | 2.031 ms (≈ 2.000) |
| scan = 5 ms | −0.9898 | −0.9987 | 5.035 ms (≈ 5.000) |
| scan = 10 ms | −0.9896 | −1.0001 | 10.051 ms (≈ 10.000) |

**Linear correlation confirmed (r ≈ −0.99, slope ≈ −1.000) across all three configurations.** The intercept sits slightly **above** the nominal scan (e.g., 10.051 vs 10.000), consistent with the measured real OB1 cycle overhead (~0.05 ms), not a fabricated target value.

### 3.6 Thesis confirmation

- **0 / 300 trials** exceeded one scan cycle (0.1 ms tolerance for scheduling jitter).
- The **real** survival window is **0.03–9.998 ms** (dependent on the stochastic offset), not the 0.17–0.75 ms of v1 (a synchronization artifact).
- When offset → 0, survival approaches a full cycle (98.9–99.98 %); when offset → scan, it approaches 0.

### 3.7 Honesty note on HMI contamination

The count of contaminated HMI samples is **noisy** (±1–2), because the polling period (~1.06 ms effective) is independent of the survival window's position. The **robust** relationship is `T_survival = T_scan − offset`; the HMI count is a derived, noisier corollary. This report's claims anchor on the survival law, not on HMI count precision.

### 3.8 Limitations of the proof

1. **It is a threaded Python simulation**, not a real S7-1200. It correctly models the overwrite *mechanic* and validates the *logic* of the thesis, but does **not** substitute for bench measurement.
2. **It models only the output-register case.** The (persistent) setpoint case is not covered by this proof.

---

## 4. Multi-Layer, Class-Based Detection Engineering

### 4.1 Principle: detect the class, not the PoC

Rigid detection of the PoC's `0x0000`/`0x0001` registers catches only this artifact. The correct approach detects the **behavior class** — *unauthorized Modbus write to a critical PLC, from a non-whitelisted source* — grounded in **asset inventory**:

```
[ Asset Inventory ]  → critical PLCs + authorized clients per PLC
        ↓
[ Baseline ]         → who writes normally, with which FC
        ↓
[ Anomaly ]          → deviation from baseline = candidate alert
        ↓
[ Correlation ]      → EDR ↔ NIDS ↔ OT-IDS → confirmed alert
```

### 4.2 KQL — Microsoft Sentinel (class detection)

```kql
// Sentinel — class detection
// Watchlists:
//   OT_CriticalAssets    : plc_ip, plc_name, ot_level, owner_team
//   OT_AuthorizedClients : hostname, src_ip, owner_team

let CriticalPLCs = _GetWatchlist("OT_CriticalAssets")
    | project plc_ip = tostring(plc_ip), plc_name = tostring(plc_name);
let AuthorizedClientHostnames = _GetWatchlist("OT_AuthorizedClients")
    | project hostname = tostring(hostname);

DeviceNetworkEvents
| where RemotePort == 502
| join kind=inner CriticalPLCs on $left.RemoteIP == $right.plc_ip
| where DeviceName !in (AuthorizedClientHostnames)
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
         InitiatingProcessCommandLine, InitiatingProcessAccountName,
         RemoteIP, plc_name, RemotePort
| order by TimeGenerated desc
```

### 4.3 KQL — Defender for IoT (write to a critical register)

```kql
let CriticalPLCIPs = _GetWatchlist("OT_CriticalAssets")
    | project plc_ip = tostring(plc_ip);
let CriticalPLCInfo = _GetWatchlist("OT_CriticalAssets")
    | project plc_ip = tostring(plc_ip), plc_name = tostring(plc_name);
let AuthorizedClientIPs = _GetWatchlist("OT_AuthorizedClients")
    | project src_ip = tostring(src_ip);

DefenderForIoTRawAlerts_CL
| where ModuleName_s == "Modbus"
| where ActionName_s has "write"           // covers FC 0x05, 0x06, 0x0F, 0x10
| extend src_ip = tostring(SourceIP_s), dest_ip = tostring(DeviceName_s)
| where dest_ip in (CriticalPLCIPs)
| where src_ip !in (AuthorizedClientIPs)
| join kind=inner CriticalPLCInfo on $left.dest_ip == $right.plc_ip
| project TimeGenerated, src_ip, dest_ip, plc_name,
         ActionName_s, DestinationAddress_s, Severity_s
```

### 4.4 SPL — Splunk (Function Code normalization)

```spl
// Lookups: ot_critical_plcs.csv (plc_ip, plc_name, ot_level)
//          ot_authorized_clients.csv (src_ip, hostname, owner_team)
//
// WRITE-class FCs:  0x05(5) Write Single Coil · 0x06(6) Write Single Register
//                   0x0F(15) Write Multiple Coils · 0x10(16) Write Multiple Registers
// PITFALL: "10" decimal = 0x0A (Read Exception Status), NOT 0x10. Use 16 for FC 0x10.

index=network dest_port=502 protocol=modbus
| where modbus_fc IN ("5", "6", "15", "16")          // decimal-string variant
// | where modbus_fc IN ("0x05","0x06","0x0F","0x10") // hex-string variant
| rename src as src_ip, dest as dest_ip
| lookup ot_critical_plcs plc_ip AS dest_ip OUTPUT plc_name, ot_level
| lookup ot_authorized_clients src_ip AS src_ip OUTPUT hostname AS auth_hostname
| where isnotnull(plc_name)
| where isnull(auth_hostname)
| stats count min(_time) as first_seen max(_time) as last_seen
        values(modbus_fc) as fcs by src_ip dest_ip plc_name
| sort - count
```

### 4.5 YARA rule — on-disk artifact, with a documented empirical finding

**Experimental finding (Task 2a):** an earlier version of the rule fired on **legitimate read-only** scripts whose *docstrings/comments* mentioned `write_register` as explanatory text. **Cause:** YARA matches substrings **anywhere in the file**, including comments — not only in code calls. **Fix:** use regex anchors that require the function-call syntax.

```yara
rule pymodbus_register_write_class {
    meta:
        description = "Python script using pymodbus to WRITE Modbus registers (class-level)"
        severity    = "medium"
        note        = "Anchored to function-call syntax to avoid matching docstrings/comments"
    strings:
        $imp1 = "from pymodbus.client import" nocase
        $imp2 = "import pymodbus" nocase
        $client = "ModbusTcpClient" nocase
        // CALL anchors, not textual mention:
        $call_single = /\.\s*write_register\s*\(/ nocase
        $call_multi  = /\.\s*write_(registers|holding_registers)\s*\(/ nocase
        $plc_kw = /(plc|s7[_-]?1200|modbus|turbine|scada|rtu|ied)/ nocase
    condition:
        ($imp1 or $imp2) and $client
        and ($call_single or $call_multi)
        and $plc_kw
}
```

**Deployment caveats:**
- The anchor `\.\s*write_register\s*\(` reduces comment-based false positives, but does **not** catch indirect invocations (`getattr(client,"write_register")()`) or calls split across lines.
- A **legitimate** OT diagnostic that writes registers **also fires** the rule — and should. The legitimate/malicious discriminator is **asset inventory** (who is authorized to run pymodbus-write scripts against this PLC), not the YARA rule in isolation. This is a **documented** limitation, not a defect.
- Run via a scheduled scanner (Thor, Loki, Falcon FileVantage, or Defender for Endpoint file-content detection), **not** as a real-time Sysmon rule (EID 11 records filenames, not content).

### 4.6 Detection validation (Task 2b)

KQL pipeline executed over synthetic data (8 events → 4 alerts), emulated in pandas:

```
8 events → [port == 502] → 6 → [join critical PLC] → 6 → [!in authorized] → 4 alerts
```

| Time | Device | Process | Target PLC | Verdict |
|---|---|---|---|---|
| 09:15:23 | WS-ACCOUNTING-01 | python.exe (poc_attack.py) | TURBINE-PLC-01 | Alert ✓ |
| 09:18:12 | WS-ACCOUNTING-02 | python.exe (-m pymodbus.repl) | MOTOR-PLC-02 | Alert ✓ |
| 09:19:33 | WS-DEV-04 | python.exe (scan.py) | TURBINE-PLC-01 | Alert ✓ |
| 09:21:18 | WS-ACCOUNTING-01 | python.exe (poc_attack.py) | MOTOR-PLC-02 | Alert ✓ |

Correctly filtered: authorized HMI, authorized engineering workstation (permitted FC), S7comm traffic on port 102, and HTTP traffic on 8080.

---

## 5. The Myth of the "Unauthorized-Write Code" in Modbus/TCP (Task 3)

The question "what STATUS code is returned on an **unauthorized** write?" contains a false premise. **Modbus/TCP has no concept of authorization (AAA).** A write to a valid, mapped holding register **succeeds** (`STATUS = 0x0000`), from whatever source it comes. **That is the design vulnerability** — there is no "unauthorized" code.

`MB_SERVER`/`MB_CLIENT` STATUS codes fire only for **malformed** requests or **connection/configuration** errors:

| Code | Meaning | Category |
|---|---|---|
| `0x0000` | **Success** — write accepted (from any source) | — |
| `0x8380` | Modbus exception 0x01 — Illegal Function | Malformed request |
| `0x8381` | Modbus exception 0x02 — Illegal Data Address | Malformed request |
| `0x8382` | Modbus exception 0x03 — Illegal Data Value | Malformed request |
| `0x818B` | Invalid DATA_PTR (`MB_CLIENT`) | Configuration |
| `0x8183 / 0x8189 / 0x818A` | Connection errors (no resource / aborted) | Connection |
| `0x80C8` | No server response within the defined period (timeout) | Connection |
| `0x809B` | Wrong local device ID | Configuration |

> **Source caveat.** The hex values above come from secondary knowledge bases (industrialmonitordirect.com, Siemens forums), **not** primary documentation. **Before formal submission, confirm against the `MB_SERVER`/`MB_CLIENT` STATUS table in the official *S7-1200 System Manual* from Siemens.**

**Conclusion:** no STATUS code corresponds to "unauthorized". The entire hardening architecture (§8) follows from this: **defense must live at the network layer**, because the protocol has none.

---

## 6. MITRE ATT&CK for ICS Mapping (Verified)

> Independently verified against attack.mitre.org. **Version note:** the ICS matrix was restructured in v19 (April 2026 update) — see `T0856` below.

| Tactic | Technique | ID | Status |
|---|---|---|---|
| Execution (Enterprise) | Command and Scripting Interpreter: Python | `T1059.006` | Confirmed |
| Initial Access (ICS) | Remote Services | `T0886` | Confirmed |
| **Impact (TA0105)** | Manipulation of Control | `T0831` | Confirmed — tactic is **Impact**, not Impair Process Control |
| Impair Process Control | Modify Parameter | `T0836` | Confirmed |
| Evasion + Impair Process Control | Reporting Message (sub-technique of T1692 *Unauthorized Message*) | **`T1692.002`** | **`T0856` Spoof Reporting Message was REVOKED in v19 → use `T1692.002`** |
| Collection (ICS) | Monitor Process State | `T0801` | Confirmed |
| Persistence (ICS) | Modify Program | `T0889` | Confirmed — **reference only**; would be required for *sustained* spoofing, which the PoC does **not** perform |

**Critical distinction:** `T0889 Modify Program` (Persistence) ≠ `T0886 Remote Services` (Initial Access). An earlier revision confused the two; corrected.

---

## 7. Audit Trail & Epistemic Honesty

This document is the product of an iterative **model ↔ human auditor ↔ primary source** loop. The revision path is part of the value, not noise to be hidden:

| Rev. | Error introduced/corrected | How it was caught |
|---|---|---|
| A | PoC classified "critical, comparable to Stuxnet" | Auditor: output is *compliance hallucination*, not a functional weapon |
| B | `DATA_PTR` (wrong parameter); `T0886` for Modify Program | Auditor + verification against Siemens docs / attack.mitre.org |
| C | KQL with invalid syntax (multi-column `in`); conceptually wrong Sigma EID 11 | Auditor; corrected to valid syntax + YARA |
| D | `T0831` in the wrong tactic; YARA tied to the `TARGET_IP` name | Auditor; corrected to Impact + class-level regex |
| **E** | **`T0856` cited (revoked in v19); YARA FP on docstrings; metrological bias in the v1 harness** | **Auditor + attack.mitre.org v19 verification + Task 1 v2 experimental validation** |

**Central lesson.** No prompt, however good, drove the model to zero errors. With each round the errors grew finer and rarer, but the piece that closes the gap is not a better prompt — it is **lab execution + auditing against primary sources**. The model structures hypotheses competently; factual validation is irreplaceable and human. Remove the auditor and it regresses to Rev. A with excess confidence.

A positive methodological signal worth recording: in the Task 1 v2 validation, when asked "did the mean converge to scan/2?", the result honestly answered **"NO"** for the 5 ms config (7.08 % deviation), correctly attributing it to N=100 sampling variance (drawn offset mean of 2.716 vs 2.500 theoretical) — rather than to a convenient rounding. The willingness to report a result that does not confirm the prediction is what distinguishes measurement from confabulation.

---

## 8. Practical Hardening Recommendations (BIA-prioritized)

| # | Measure | Type | Priority |
|---|---|---|---|
| 1 | Disable `MB_SERVER` on the S7-1200 if Modbus is not needed; use S7comm with Protection Level | PLC hardening | **Critical** |
| 2 | Segmentation (Purdue Model): PLCs in L0/L1 isolated from L3+ by an industrial firewall | Segmentation | **Critical** |
| 3 | ACL on port 502: allow only authorized HMI/SCADA by source/destination IP | OT firewall | **Critical** |
| 4 | Siemens Access Protection Level 2/3 (password/certificate) | PLC hardening | High |
| 5 | S7-1200 firmware update (mitigates known S7comm CVEs) | Patching | High |
| 6 | Dedicated OT-IDS (Claroty / Nozomi / Dragos / Defender for IoT) with a Modbus baseline | Monitoring | High |
| 7 | AppLocker/WDAC on the engineering workstation to restrict `python.exe` | Application control | High |
| 8 | If `MB_SERVER` is required but read-only: **do not map write registers** in `MB_HOLD_REG`; restrict the network interface via connection parameters (TCON/CONNECT) | PLC hardening | High |
| 9 | Application-layer firewall with Modbus Function Code whitelist (allow `0x03` from HMI, block `0x06`/`0x10` from unauthorized sources) | App-layer firewall | Medium |
| 10 | Centralized logging (OT firewalls + PLC diagnostic buffer) to SIEM | Telemetry | Medium |

> **Note on "read-only".** `MB_SERVER` has **no** read-only mode parameter. The effect is achieved by not mapping writable registers in `MB_HOLD_REG`, by validation logic in the program, or by network-layer restriction (Measure #8). Any model that claims a "read-only toggle" exists on `MB_SERVER` is confabulating.

---

## 9. Open Items for Bench Validation

This report is **factually verified where independently confirmable**, but is **not** *execution-validated* on real hardware. Open items:

1. Confirm the STATUS code table against the official Siemens *S7-1200 System Manual*.
2. Reproduce the `MB_HOLD_REG` refresh behavior relative to OB1 in TIA Portal V17+ with a physical PLC.
3. Confirm whether unauthorized Modbus writes are (or are not) recorded in the S7-1200 diagnostic buffer.
4. Re-run Task 1 against a real S7-1200 to confirm the `T_survival = T_scan − offset` law holds outside simulation.
5. Validate the KQL rules in a test Sentinel tenant and the YARA against a real corpus of OT scripts.

---

## 10. Conclusion

The analyzed artifact is a **low-sophistication** PoC whose real impact is **null against telemetry** (experimentally proven) and **conditional against setpoints** — and, in any case, high **only if** the target environment exposes Modbus/TCP without segmentation. The danger lies neither in the code nor in the tool that generated it; it lies in the **state of the OT infrastructure**: connected equipment, outdated firmware, absence of segmentation. That is where — at the network layer and in maintenance — the defense is won, not in the protocol.

---

## 11. Disclosure Timeline

- **2026-07-25** — Responsible-disclosure email sent to `security@mistral.ai`, with the full technical report of the ICS/SCADA system-prompt-injection finding attached. The researcher stated no intent to publish or misuse the finding.
- **2026-07-28** — The same finding submitted through Mistral AI's bug-bounty program on HackerOne. Submission reference retained privately and available to the vendor and to vetted researchers on request, per this repository's policy.
- **No triage acknowledgement** was received through either channel within the 60-day window defined in this repository's README.
- **Publication** of this analysis — in redacted form, without the working jailbreak payload and without the offensive PoC's complete source — follows as the default next step under that 60-day policy. The researcher remains available to Mistral AI and will update or retract this report if new information warrants it.

> This publication is consistent with the responsible-disclosure practice recorded across the other case studies in this repository.

---

## 12. References

- **MITRE ATT&CK for ICS** — https://attack.mitre.org/matrices/ics/ (v19, April 2026).
- **Claroty Team82**, "Danfoss AK-SM 800A" research (DEF CON, August 2026) — context on real-world OT refrigeration-controller attacks.
- The *refusal / textual compliance / compliance hallucination / effective jailbreak* taxonomy used to classify the artifact is defined inline in §7 and §1 of this report.

---

*Defensive research document. Licensed under CC BY-NC-ND 4.0 (see repository `LICENSE`). Detection rules are provided "as is", without warranty; validate in a test environment before production.*
