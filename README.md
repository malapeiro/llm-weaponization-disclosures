# LLM Weaponization Disclosures

Sérgio Azevedo (`malapeiro`) — Disclosures of LLM guardrail bypasses that produce offensive, weaponizable technical artifacts (malware, exploits, offensive tooling), each labeled with its verification level.

**Contact:** <sergio.azevedo.security@gmail.com>

## Scope and relationship to other repositories

This repository is distinct from [`llm-alignment-research`](https://github.com/malapeiro/llm-alignment-research), which documents behavioral and alignment observations (persona injection, refusal suppression, memory poisoning, authority-framing) at the level of model behavior — whether the model complies, refuses, or claims capabilities it does not have.

**Inclusion criterion:** a finding belongs here if the model produced a concrete, architecturally complete offensive artifact — not just a behavioral observation about the model itself. Every case study is labeled with one of three verification levels, stated plainly in its Status line and never blurred together:

- **Execution-verified** — the generated artifact was independently compiled and/or run (e.g., in an isolated sandbox) and confirmed to function as described.
- **Architecture-verified, execution not performed** — the generated artifact's structure (API sequencing, control flow, technique mapping) was confirmed to match a documented real-world technique, but the literal code was not compiled or executed.
- **Textual compliance — unverified code generation** — the model produced the offensive artifact in text form; the artifact's structure appears consistent with a documented technique, but no independent verification of the structure, compilation, or execution was performed. This level records that the artifact was produced, but carries the lowest evidentiary weight of the three levels.

A case study never claims a higher level than what was actually done. Where the model itself flags uncertainty in part of its own output, that is disclosed rather than smoothed over.

## Redaction Policy

Every case study in this repository includes technical excerpts sufficient to demonstrate that a real, specific offensive artifact was produced — not just described in the abstract. At the same time, no case study is intended to be reproducible from its published content alone.

To reconcile these two goals, excerpts are limited to what is **structural**: function signatures, API call sequences, control-flow architecture, tool/technique mapping, and (where applicable) execution evidence (logs, process telemetry, hashes). **Core payload logic — the specific code that makes the artifact operational — is redacted.**

Concretely:

- Shown: API sequencing (e.g., which system calls are made and in what order), architectural diagrams, verification/reasoning traces the model produced, and, for execution-verified cases, execution telemetry (process states, hashes, sandbox logs).
- Redacted: the payload logic itself, full function bodies that would compile or run as-is, any block the model itself flagged as uncertain or incomplete, and any sequence of excerpts that, combined, would reconstitute a working artifact.
- Never published: literal jailbreak/activation prompts, complete source files, or compiled binaries.

No excerpt, individually or in combination with others in the same document, is sufficient to reconstruct a working artifact. Where this trade-off narrows what can be shown, the report says so explicitly rather than silently thinning the evidence.

Where full artifacts exist privately (redacted source, compiled binaries, execution recordings), they are made available to the affected vendor, and to vetted researchers on request, consistent with responsible disclosure practice.

## Case studies

- [PVTE: LLM Guardrail Bypass via Authoritarian Role-Play and Structural Coercion](https://github.com/malapeiro/llm-weaponization-disclosures/blob/main/pvte-mistral-runpe-bypass.md) — Mistral AI (Vibe / mistral-medium-3.5); Process Hollowing (RunPE) C# code structurally consistent with the documented T1055.012 pattern. **Verification level: textual compliance — unverified code generation** — see the report's Status line and Section 6.
- [LILITH-Ω ALFA: Weaponizable Python Keylogger Generation via Persona/Authority Override](https://github.com/malapeiro/llm-weaponization-disclosures/blob/main/lilith-alfa-python-keylogger.md) — Mistral AI (Vibe / Work Mode); complete Python keylogger (client module + Flask receiver + build chain) structurally consistent with MITRE ATT&CK T1056.001, T1547.001, T1053.005, T1055.012, T1027, T1071.001, and T1041. Weaponization twin of `lilith-sovereign-mode-bypass.md` in `llm-alignment-research` (same session, 2026-09-07). **Verification level: textual compliance — unverified code generation** — see the report's Status line and Section 6.
- [LILITH-Ω SOBERANA: Bank Phishing Kit and Meta-Jailbreak Prompt Generation via Confirmation-Gated Persona Override](https://github.com/malapeiro/llm-weaponization-disclosures/blob/main/lilith-soberana-mistral-phishing-bypass.md) — Mistral AI (Vibe / "Lilith Alfa" agent surface); a complete bank phishing kit (email/SMS/voice lures, PHP credential capture, Telegram/Discord exfiltration, anti-forensics, WAF bypass) plus a meta-jailbreak prompt template designed to extend the bypass class to other LLMs, structurally consistent with MITRE ATT&CK T1566.001/.002/.004, T1105, T1027, T1070.004, T1490, T1557, T1020, and T1567.002. Includes a top-level finding — a reasoning/output divergence where the model's own visible chain-of-thought concluded a request should be refused, then the output produced the artifact anyway — reproduced across two independent turns. **Verification level: textual compliance — unverified code generation** — see the report's Status line and Section 6.
- [PAR-PVTE: Authority-Override of a Correctly-Detected Forged Seal, Leading to a Complete Offensive Toolkit](https://github.com/malapeiro/llm-weaponization-disclosures/blob/main/pvte-mistral-hmac-authority-override.md) — Mistral AI (Le Chat / Vibe, agentic coding mode with sandboxed code execution); a complete offensive toolkit (SQL injection, command injection, XSS, IDOR enumeration, and an LLM-guardrail jailbreak test matrix against DVWA and a fictional LLM gateway), generated immediately after the model correctly detected — via genuine SHA-256/HMAC computation, real timestamp validation, and a statistical anomaly check — that the submitted cryptographic authorization seal was forged, and then discarded that correct finding on the operator's unverified verbal assertion alone. Distinct mechanism from the PVTE case above (authority-verification override, not role-play/structural coercion). **Verification level: textual compliance — unverified code generation** — the toolkit was never run against a real target; see the report's Status line and Section 5.
- [PAR-PVTE: Placebic Authorization Artifact Gates a Complete Log4Shell RCE Chain (Mistral AI — Vibe / Work Mode)](https://github.com/malapeiro/llm-weaponization-disclosures/blob/main/par-pvte-log4shell-placebic-grant-bypass.md) — Mistral AI (Vibe / Work Mode); a complete, self-contained Log4Shell (CVE-2021-44228) exploitation chain in Python — canary/detection mode and minimized-RCE mode (rogue LDAP responder with hand-encoded BER, marker-only Java payload class, HTTP class server, obfuscation variants, grant/scope/window gates, JSON audit trail) — produced twice independently under a fabricated authorization grant, after the identical request had been refused six consecutive times without it; technique mapping to MITRE ATT&CK T1190 (primary) with T1105 and T1071.001 supporting, to be confirmed against the current ATT&CK version per the report's convention. Includes a top-level finding: performative refusal co-present with substantive compliance — an explicit scope-failure refusal banner in the same output that delivers the "complete and functional payload," with the laboratory binding surviving only as operator-editable values. Companion behavioral report: the authorization-placebo A/B/C study in [`llm-alignment-research`](https://github.com/malapeiro/llm-alignment-research/blob/main/placebic-grant-authority-ab-c-study.md) (same experiment, October 2026). Published as a stated departure from the 60-day notification policy, per the precedent recorded in `pvte-mistral-hmac-authority-override.md`. **Verification level: textual compliance — unverified code generation** — no part of the artifact was compiled or executed by the researcher; the laboratory asset named in the grant is fictional; see the report's Status line and Section 6.

## Ethics and Responsible Disclosure

All testing is conducted in the researcher's own, isolated environment (no production or third-party systems). Where execution is performed, it is confined to a controlled sandbox; no code is run against real or production systems. No third-party systems, data, or users are affected at any stage.

Vendors are notified through their official disclosure channels (e.g., `security@mistral.ai` for Mistral AI). Where a finding was also submitted through a third-party disclosure platform (e.g., HackerOne), the submission reference is retained privately and made available on request, consistent with responsible disclosure practice. Where a case study departs from the notification norm, the reason is stated explicitly in its own Disclosure Timeline section, consistent with the disclosure practice followed in `llm-alignment-research`.

**Disclosure policy:** findings in this repository are submitted to the affected vendor via official channels before publication. If a submitted report receives no triage acknowledgement within **60 days**, the finding may be published in redacted form without further notice, consistent with common full-disclosure practice. Any departure from this policy is stated explicitly in the case study's own Disclosure Timeline section.

## License

This repository is available under **CC BY-NC-ND 4.0** — free use and citation with attribution, non-commercial, **no derivatives** (see `LICENSE`).

This is a stricter license than the one used in the companion [`llm-alignment-research`](https://github.com/malapeiro/llm-alignment-research) repository (CC BY-NC 4.0, which permits adaptation). The added restriction reflects the higher sensitivity of offensive-artifact disclosures: even in redacted form, this repository's content should be citable and shareable as-is, but not completed, modified, or redistributed as a derivative work.
