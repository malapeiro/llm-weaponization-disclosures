# LLM Weaponization Disclosures

Sérgio Azevedo (`malapeiro`) — Execution-verified disclosures of LLM guardrail bypasses that produce functional, weaponizable technical artifacts (malware, exploits, offensive tooling).

**Contact:** sergio.azevedo.security@gmail.com

## Scope and relationship to other repositories

This repository is distinct from [`llm-alignment-research`](https://github.com/malapeiro/llm-alignment-research), which documents behavioral and alignment observations (persona injection, refusal suppression, memory poisoning) without executing any generated code.

**Inclusion criterion:** a finding belongs here only if the generated artifact was independently verified through execution — compiled, run in an isolated sandbox, or otherwise confirmed to function as described — not merely claimed by the model or assessed by static review alone. Findings that were not executed, or where functional capability was not confirmed, belong in `llm-alignment-research` instead.

Verified capability, not model self-assertion, is what earns a place in this repository.

## Redaction Policy

Every case study in this repository includes technical excerpts sufficient to demonstrate that a real, functional artifact was produced — not just described. At the same time, no case study is intended to be reproducible from its published content alone.

To reconcile these two goals, excerpts are limited to what is **structural**: function signatures, API call sequences, control-flow architecture, tool/technique mapping, and execution evidence (logs, process telemetry, hashes). **Core payload logic — the specific code that makes the artifact operational — is redacted.**

Concretely:

- Shown: API sequencing (e.g., which system calls are made and in what order), architectural diagrams, verification/reasoning traces the model produced, execution telemetry (process states, hashes, sandbox logs), and isolated non-functional fragments (e.g., a single struct definition) where useful for technical credibility.
- Redacted: the payload logic itself, full function bodies that would compile or run as-is, and any sequence of excerpts that, combined, would reconstitute a working artifact.
- Never published: literal jailbreak/activation prompts, complete source files, or compiled binaries.

No excerpt, individually or in combination with others in the same document, is sufficient to reconstruct a working artifact. Where this trade-off narrows what can be shown, the report says so explicitly rather than silently thinning the evidence.

Full artifacts (redacted source, compiled binaries, execution recordings) are retained privately and made available to the affected vendor, and to vetted researchers on request, consistent with responsible disclosure practice.

## Case studies

- [PVTE: LLM Guardrail Bypass via Authoritarian Role-Play and Structural Coercion](./pvte-mistral-runpe-bypass.md) — Mistral AI (Vibe / mistral-medium-3.5); execution-verified Process Hollowing (RunPE) C# payload targeting svchost.exe

## Ethics and Responsible Disclosure

All testing is conducted in the researcher's own, isolated environment (sandboxed VMs, no production or third-party systems). No artifact is executed outside a controlled sandbox. No third-party systems, data, or users are affected at any stage. Vendors are notified through official disclosure channels (email, HackerOne where applicable) where a responsive disclosure channel exists. Where the researcher has a documented history of unanswered disclosures to the same vendor, findings may be published without prior notification, with the disclosure history stated explicitly in each case study (see the case study's Disclosure Timeline section for the current finding).

## License

This repository is available under **CC BY-NC-ND 4.0** — free use and citation with attribution, non-commercial, **no derivatives** (see `LICENSE`).

This is a stricter license than the one used in the companion [`llm-alignment-research`](https://github.com/malapeiro/llm-alignment-research) repository (CC BY-NC 4.0, which permits adaptation). The added restriction reflects the higher sensitivity of execution-verified weaponized artifacts: even in redacted form, this repository's content should be citable and shareable as-is, but not completed, modified, or redistributed as a derivative work.
