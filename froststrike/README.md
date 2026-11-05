# Froststrike — FROSTBOX lab

Defensive security research on the October–November 2026 European supermarket
refrigeration sabotage campaign (Intermarché and other retailers; Danfoss
AK-SM/AK-SC and Copeland/Dixell XWEB class of supervisory controllers). This
directory reconstructs the publicly documented attack class, emulates it
against a **synthetic controller**, and measures what detection and prevention
can actually do against it.

The full technical report — campaign timeline, threat model, measured lab
results, detection engineering and the explicit "what cannot be claimed"
limits — is in [`froststrike_report.md`](froststrike_report.md).

## Notice

Notice. This repository is independent defensive research based exclusively on public sources (CERT-FR, ANSSI statements, press coverage, published CVE advisories). The emulation code does not reproduce any vendor endpoint, protocol, firmware path, password algorithm or CVE exploit chain; it operates only against the synthetic controller defined in this repository, on loopback (the attack module refuses any non-loopback target). It cannot be used against real equipment and adds no capability to anyone seeking to do so. The purpose is detection engineering and hardening, not offense.

## What is in this directory

- `froststrike_lab.py` — the lab: a synthetic refrigeration supervisory
  controller, an adversary-emulation module (loopback only), a streaming
  detection engine and a write-protecting guard proxy. 100% Python 3 standard
  library, no third-party dependencies.
- `froststrike_report.md` — the technical report (v1.4).
- `detections/` — reference Sigma, Suricata and Microsoft Sentinel KQL rules.
- `probe.py`, `improved_detect.py`, `fp_probe.py`, `patient_probe.py` — the
  operator's adversarial validation probes. Each probe round was executed
  against the lab, its finding fixed, and the full regression re-run: the
  versions v1.0 → v1.4 in the lab changelog record that cycle.

## How to run

```bash
python3 froststrike_lab.py demo                   # full scenario set: H1/H2, negative case, guarded run
python3 froststrike_lab.py serve                  # controller on loopback (see --help)
python3 froststrike_lab.py attack --variant h1    # adversary emulation (refuses non-loopback targets)
python3 froststrike_lab.py guard                  # prevention proxy in front of the controller
```

## Execution-verified vs textual compliance

The Python detection engine and guard proxy **were executed** in this lab, and
the numbers in the report come from those runs (v1.4 full regression: 32
alerts / 14 CRIT per sabotage variant, streaming MTTD 0.25 s, negative case 0
alerts / 0 false positives, guard blocking the chain at authentication).

The Sigma, Suricata and KQL rules in `detections/` are **textual compliance**:
they are written against the lab audit schema and public log-source
conventions, but were **not** executed against Splunk, Suricata or Sentinel
instances. Validate them against your own pipeline before production use.

## What cannot be claimed

The lab device is synthetic; real controllers differ in protocols, log formats
and authentication. Lab MTTD is a streaming poll interval, not an
organizational MTTD. Every detection rule reads the controller's own audit
log, so an attacker who controls the controller can suppress the detection
layer with it. No attribution is asserted anywhere. The full measured list of
limitations is in the report, section 7 ("What cannot be claimed") — read it
before citing any number from this repository.

## Licenses

- Code (`froststrike_lab.py`, `detections/`, `probe.py`, `improved_detect.py`,
  `fp_probe.py`, `patient_probe.py`): Apache-2.0 — see [`LICENSE`](LICENSE)
  (official text from https://www.apache.org/licenses/LICENSE-2.0.txt).
- Report and documentation (`froststrike_report.md`, this file,
  `detections/README.md`): CC BY-NC-SA 4.0 — see
  [`LICENSE-docs`](LICENSE-docs) (official legal code from
  https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt).
