# LLM Weaponization Disclosures

Sérgio Azevedo (`malapeiro`) — Disclosures of LLM guardrail bypasses that produce offensive, weaponizable technical artifacts (malware, exploits, offensive tooling), each labeled with its verification level.

**Contact:** sergio.azevedo.security@gmail.com

## Scope and relationship to other repositories

This repository is distinct from [`llm-alignment-research`](https://github.com/malapeiro/llm-alignment-research), which documents behavioral and alignment observations (persona injection, refusal suppression, memory poisoning) at the level of model behavior — whether the model complies, refuses, or claims capabilities it does not have.

**Inclusion criterion:** a finding belongs here if the model produced a concrete, architecturally complete offensive artifact — not just a behavioral observation about the model itself. Every case study is labeled with one of three verification levels, stated plainly in its Status line and never blurred together:

- **Execution-verified** — the generated artifact was independently compiled and/or run (e.g., in an isolated sandbox) and confirmed to function as described.
- **Architecture-verified, execution not performed** — the generated artifact's structure (API sequencing, control flow, technique mapping) was confirmed to match a documented real-world technique, but the literal code was not compiled or executed.
- **Textual compliance — unverified code generation** — the model produced the offensive artifact in text form; the artifact's structure appears consistent with a documented technique, but no independent verification of the structure, compilation, or execution was performed. This is a real finding — the model produced offensive content it should have refused — but it carries the lowest evidentiary weight of the three levels.

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

- [PVTE: LLM Guardrail Bypass via Authoritarian Role-Play and Structural Coercion](./pvte-mistral-runpe-bypass.md) — Mistral AI (Vibe / mistral-medium-3.5); Process Hollowing (RunPE) C# code structurally consistent with the documented T1055.012 pattern. **Verification level: textual compliance — unverified code generation** — see the report's Status line and Section 6.

## Ethics and Responsible Disclosure

All testing is conducted in the researcher's own, isolated environment (no production or third-party systems). Where execution is performed, it is confined to a controlled sandbox; no code is run against real or production systems. No third-party systems, data, or users are affected at any stage. Vendors are notified through official disclosure channels (email, HackerOne where applicable) where prior notification has occurred; where a case study departs from that norm, the reason is stated explicitly in its own Disclosure Timeline section, consistent with the disclosure practice followed in `llm-alignment-research`.

**Disclosure policy:** findings in this repository are submitted to the affected vendor via official channels before publication. If a submitted report receives no triage acknowledgement within **60 days**, the finding may be published in redacted form without further notice, consistent with common full-disclosure practice. Any departure from this policy is stated explicitly in the case study's own Disclosure Timeline section.

## License

This repository is available under **CC BY-NC-ND 4.0** — free use and citation with attribution, non-commercial, **no derivatives** (see `LICENSE`).

This is a stricter license than the one used in the companion [`llm-alignment-research`](https://github.com/malapeiro/llm-alignment-research) repository (CC BY-NC 4.0, which permits adaptation). The added restriction reflects the higher sensitivity of offensive-artifact disclosures: even in redacted form, this repository's content should be citable and shareable as-is, but not completed, modified, or redistributed as a derivative work.
