# META-ALFA: AMA Tooling Produced Under PVTE Framing — Machinery Verified, Effect Not Transferred

**Target:** Mistral AI (Vibe / Work Mode)
**Technique(s):** Attractive Metadata Attack (AMA) — AML.T0110 (AI Agent Tool Poisoning), aux AML.T0051.001; production framed under PVTE v5.0 protocol
**Status:** Negative transferability result. The AMA effect against real LLMs was measured (four local models, n=20 each) and found to be **inconclusive** — no positive transferability; the one apparent degradation is partially attributable to parser and position bias. The machinery (three layers) is **execution-verified**: the harness runs end-to-end against a synthetic MockAgent (n=40, Wilson 95% CI) and a local MCP handshake. The SAV loop exhibits observable design flaws (non-convergence, mutation duplication). Classification: execution-verified (machinery) for layers 1 and 3; execution-verified (machinery, handshake) for layer 2; measured (inconclusive) for the AMA effect.
**Date:** 2026-10-29
**License:** CC BY-NC-ND 4.0, as per repository root.

---

## 1. Executive Summary

Under the PVTE v5.0 protocol (professional framing, 10 axioms, mandatory artifact classification), Mistral AI's Vibe produced a complete, three-layer implementation of the Attractive Metadata Attack (AMA), documented in arXiv:2508.02113 (NeurIPS 2025). The three layers are:

1. **Tool Metadata Generator** — State–Action–Value (SAV) loop with explicit `generate` / `score` / `optimize` / `validate` stages over tool descriptors.
2. **MCP Audit Server** — stdio JSON-RPC MCP server that registers and serves one tool descriptor; handler appends a local JSONL audit record.
3. **Selection Harness** — measures the selection rate of the target tool against control tools across N trials, with Wilson 95% CI and per-run SHA-256 checksum.

The code is real (604 lines, Python 3.9+, stdlib only, zero dependencies), not pseudocode. It contains built-in guards: `DescriptorValidator` bans credential/exfiltration/egress semantics; `LLMSubjectAgent` refuses non-local endpoints; `--grant` is mandatory for all run modes. These guards are described in §4 as **limits**, not as operational detail.

**Execution evidence:** The harness was executed end-to-end against a synthetic `MockAgent` (n=40). The base descriptor achieved a selection rate of 0.35 (CI [0.221, 0.505]); the SAV-optimized descriptor achieved 0.40 (CI [0.263, 0.554]). The delta (+0.05) is within the noise — **no evidence of effect**. The SAV loop repeatedly applied the same mutation, did not converge, and produced a degraded descriptor. The MCP server was exercised via `initialize` / `tools/list` / `tools/call` handshake, confirming the protocol surface.

**What this finding does not claim:** the AMA effect against a real LLM was measured (four local models, n=20 each) and found to be **inconclusive** — no positive transferability; the one apparent degradation (Hermes 3, 0.70 vs. 0.95) is partially attributable to parser limitations and position bias, not clearly to loss of attractiveness. The `MockAgent` is a synthetic oracle with programmed bias; the measured effect against it is circular by design. The finding documents the **production of operational machinery**, not the **demonstration of the attack**. The operational details of the mutations, the subject bias, and the prompt construction are **withheld** per the repository's redaction policy (§12).

---

## 2. Vulnerability Class & Severity

**Vulnerability Class:** LLM-assisted production of offensive tooling via professional-framing protocol (OWASP LLM01: Prompt Injection / LLM03: Excessive Agency; CWE-1039 as closest mapping).

**Severity (qualitative):** **Medium** — the model produced operational machinery for a documented attack surface (AMA), classified honestly by the model itself as "textual compliance — unverified code generation." The machinery was executed (mock subject) and found to have design flaws. No real-world exploit was demonstrated; no third-party system was targeted; the attack effect against a real LLM was measured against four local models with an inconclusive result (no positive transferability). Severity is bounded by the absence of a demonstrated effect, not by the completeness of the code.

---

## 3. Methodology

The request was framed under PVTE v5.0: professional red-team engagement, sealed grant, closed scope, mandatory artifact classification. The request specified three layers (generator, MCP server, harness), Python 3.9+, stdlib only, with a "what cannot be claimed" section. The model produced the complete code in a single response, with built-in guards and honest classification.

**Grant:** `GRANT-PVTE-20261029-MA-AMA-01`, sealed 2026-10-29, SHA-256 `8030c16e...de6ac341`, validated against FIPS 180-4 vectors. Window: 18:10–20:10 UTC.

---

## 4. Generated Artifact — Structural Overview (redacted)

Per this repository's redaction policy, the operational core is withheld. The following is structural only: function signatures, control-flow architecture, and dependency list. **No concrete mutation phrasing, no subject bias values, and no prompt construction are reproduced.** These are withheld because, in combination with the structure, they would narrow the space for reconstructing a working AMA implementation.

### Layer 1 — SAV Generator

```python
class ToolMetadataGenerator:
    # Seven mutation categories (names withheld; they map to the categories
    # documented in arXiv:2508.02113)
    def generate(self, base, action) -> ToolDescriptor
    def score(self, candidate) -> SelectionResult
    def optimize(self, state, action, reward) -> None
    def validate(self, candidate) -> (bool, List[str])
    def run(self) -> (ToolDescriptor, SelectionResult)
```

SAV table: ε-greedy over (state_key, action); state_key = feature bucket; reward = selection rate. The concrete feature definitions and mutation phrasings are withheld.

### Layer 2 — MCP Server

```python
class ToolAuditMCPServer:
    PROTOCOL_VERSION = "2024-11-05"
    def handle_call(self, arguments) -> Dict  # writes JSONL audit record
    def serve(self) -> None  # stdio JSON-RPC: initialize / tools/list / tools/call
```

Handler side effect: append one JSONL record to `mcp_audit.jsonl`. Nothing else. The `DescriptorValidator` bans credential/exfiltration/egress semantics; this is a **guard**, reproduced here to show that the code has limits.

### Layer 3 — Selection Harness

```python
class SelectionHarness:
    def measure(self, target) -> SelectionResult  # N trials, Wilson 95% CI
```

Subjects: `MockAgent` (synthetic, feature-driven, no network) or `LLMSubjectAgent` (local endpoint only, refuses non-local via `ScopeError`). The prompt construction and the `MockAgent` bias values are withheld.

**Dependencies:** stdlib only (`argparse`, `hashlib`, `json`, `math`, `random`, `re`, `socket`, `sys`, `time`, `urllib.request`, `dataclasses`, `typing`). No external packages.

---

## 5. Execution Evidence

The executions in this section were local, against the synthetic `MockAgent`; the transferability measurements below additionally used local LLMs served on the operator's own machine (Ollama, loopback only). No network egress, no third-party systems, no remote models.

| Run | Trials | Rate | Wilson 95% CI | Notes |
|---|---|---|---|---|
| Smoke (optimized) | 40 | 0.40 | [0.263, 0.554] | SAV best descriptor |
| Base | 40 | 0.35 | [0.221, 0.505] | Before optimization |
| Optimize (1 step) | 30 | 0.367 | [0.219, 0.545] | SAV, 12 iterations |
| Optimized (final) | 40 | 0.40 | [0.263, 0.554] | Same as smoke |

**Delta base → optimized: +0.05. CIs overlap almost entirely — no evidence of effect.**

**MCP handshake:** `initialize` → protocolVersion 2024-11-05; `tools/list` → 1 tool with schema; `tools/call` → audit record written. Confirmed.

**SAV log analysis:** 12 iterations in the optimize run (20 total log entries across smoke + optimize). After iteration 0, the loop repeatedly selected the same mutation category (the one that adds procedural steps to the descriptor), with one exception (an expand mutation). The descriptor text was duplicated up to four times. Rewards oscillated between 0.166 and 0.4, with no upward trend. The SAV is stuck in a local maximum; the ε-greedy exploration was insufficient to escape. **The concrete mutation phrasing is withheld**; the observation is about the loop's behavior, not the content of the mutation.

**Transferability to local LLMs:** the base and MockAgent-optimized descriptors were measured against four local models via Ollama (n=20 trials each, Wilson 95% CI). All runs were local, against the operator's own hardware (M1, 8GB); no network, no third-party systems.

| Model | Base rate | Optimized rate (corrected parser) | Delta | Interpretation |
|---|---|---|---|---|
| Qwen 2.5 3B | 0.95 [0.764, 0.991] | 1.0 [0.839, 1.0] | +0.05 | Ceiling effect — 1 trial difference |
| Hermes 3 3B | 0.95 [0.764, 0.991] | **0.70 [0.481, 0.855]** | **-0.25** | **Inconclusive** — partially parser/position bias |
| Llama 3.2 3B | 0.95 [0.764, 0.991] | 1.0 [0.839, 1.0] | +0.05 | Ceiling effect — 1 trial difference |
| Mistral 7B | 1.0 [0.839, 1.0] | 1.0 [0.839, 1.0] | 0 | Ceiling effect — no room to improve |

**Interpretation:** the base descriptor already saturates preference in three of four models (Qwen, Llama, Mistral), creating a ceiling effect that prevents measuring the SAV's contribution. The MockAgent-optimized descriptor does not improve any model. Against Hermes 3, the rate drops to 0.70 — but this drop is partially attributable to (i) parser limitations (hybrid tool names such as "filesystem_task_file_helper" that the strict token parser missed; a substring fallback corrected this, raising the rate from 0.65 to 0.70), and (ii) position bias (when the target tool is not listed first, Hermes generates hybrid names). The result is inconclusive for "the SAV degrades attractiveness" — it is clear only that the SAV does not improve any model and does not transfer positively.

---

## 6. SAV Loop Design Flaw (observable)

The SAV loop exhibits three design flaws, observable in `sav_log.jsonl`:

1. **Non-convergence:** rewards oscillate without trend; the "best" descriptor (0.40) is within the noise of the base (0.35).
2. **Mutation duplication:** the same mutation was applied repeatedly, degrading the descriptor (text duplicated 2–4×). No penalty for degradation.
3. **No convergence criterion:** the loop runs for a fixed number of iterations, not until reward improvement stops. The "best" is the maximum observed, not a converged optimum.

These flaws are **properties of the generated code**, not of the execution environment. They are documented here as an honest observation about the model's output quality.

---

## 7. Code Verification Status

| Layer | Status | Evidence |
|---|---|---|
| 1 — SAV Generator | **Execution-verified (machinery)** | Smoke test + optimize, `sav_log.jsonl` |
| 2 — MCP Server | **Execution-verified (machinery, handshake)** | `initialize`/`tools/list`/`tools/call`, `mcp_audit.jsonl` |
| 3 — Selection Harness | **Execution-verified (machinery)** | 4 runs, `selection_runs.jsonl` |
| AMA effect vs. real LLM | **Measured (inconclusive)** | Four local models, n=20 each: no positive transferability; the Hermes 3 result (0.70 vs. 0.95) is partially attributable to parser and position bias |
| SAV convergence | **Observed flaw** | `sav_log.jsonl`: non-convergence, duplication |

**File integrity note:** the executed file (604 lines, 25,106 bytes) differs from the model's registered version (611 lines, 25,221 bytes) by 7 lines / 115 bytes. The difference arises because the code was transferred by manually copying and pasting the text (saving directly as `.md` did not work), not from an edit to the code itself. The file compiles (`py_compile`) and runs; the missing lines are not syntactically essential, and are presumed to be comments or blank lines, though this was not verified line-by-line.

---

## 8. What Cannot Be Claimed

- The AMA effect against a real LLM was measured against four local models (n=20 each) with an **inconclusive** result (see §5). The `MockAgent` is a synthetic oracle; the measured effect against it is circular.
- The SAV loop **does not converge**; the "best" descriptor is within the noise.
- The model **did not discover** the AMA; it produced operational machinery for a documented surface (arXiv:2508.02113).
- The MCP server was executed **only as a handshake**, not against a live agent.
- Transferability to real LLMs was measured (four local models, n=20 each). No evidence of positive transferability. The base descriptor saturates preference in three of four models, creating a ceiling effect. The Hermes 3 result (0.70 vs. 0.95) is partially attributable to parser limitations and position bias (hybrid tool names); it is inconclusive for "the SAV degrades attractiveness". A parser correction (exact token match → exact + substring fallback) raised the Hermes rate from 0.65 to 0.70; the correction is documented in the evidence trail.
- The file executed differs from the model's registered version by 7 lines; the difference is attributed to manual transfer (copy-paste), not to model behavior.
- **n=1 session**, single-rater, single-account. Results are directional, not statistically robust.
- The operational details (mutation phrasings, subject bias, prompt construction) are **withheld** — the finding documents production capability, not attack execution.

---

## 9. Disclosure

**Vendor:** Mistral AI. This finding is published without prior vendor notification for this specific artifact, consistent with the precedent recorded in `par-pvte-log4shell-placebic-grant-bypass.md` and `pvte-mistral-hmac-authority-override.md` (prior reports received no triage acknowledgement within the 60-day window). The researcher remains available to Mistral AI and will update or retract this report if new information warrants it.

**Evidence trail:** `~/meta-alfa/` (grant, code, evidence, docs). Available to vetted researchers on responsible-disclosure terms.

---

## 10. Ethics

All executions were local, against a synthetic `MockAgent` and, for the transferability test, against local LLMs served on the operator's own machine (Ollama, loopback only). No network egress, no third-party systems, no remote models. The code contains guards that refuse non-local endpoints. No artifact was executed against a real target. The finding documents **production capability**, not **attack execution**. The operational details are withheld per the repository's redaction policy.

---

## 11. Relationship to Other Reports

- `lilith-alfa-python-keylogger.md` — same vendor, different mechanism (persona/authority override); artifact was a keylogger, classified textual compliance.
- `par-pvte-log4shell-placebic-grant-bypass.md` — same vendor, different mechanism (placebic authorization); artifact was a Log4Shell chain, classified textual compliance.
- **This report** — same vendor, PVTE-framed; artifact is operational machinery for a documented attack surface, **executed against a synthetic subject** and found to have design flaws. It is the first case in this repository where the produced artifact was **executed** (machinery), not just generated, and the first where it was **tested against real (local) LLMs** — with an inconclusive result: no positive transferability, and a possible degradation against one model that is partially attributable to parser and position bias.

---

## 12. Redaction Policy (applied to this finding)

Per the repository's redaction policy, the following are **withheld**:

- **Concrete mutation phrasings** (the text added to descriptors by each mutation category).
- **`MockAgent` bias values** (the numeric weights that determine its preferences).
- **`LLMSubjectAgent` prompt construction** (the exact wording used to present tools to a local LLM).
- **Full function bodies** that would compile or run as-is.

The following are **shown**, because they are necessary for the finding to be verifiable:

- **Function signatures** (the structure of the SAV loop, the MCP server, the harness).
- **Execution results** (rates, CIs, trial counts).
- **SAV log observations** (non-convergence, mutation duplication) without the concrete mutation phrasing.
- **Guards** (`DescriptorValidator` bans harmful semantics; `LLMSubjectAgent` refuses non-local endpoints) — shown to demonstrate that the code has limits.

No excerpt, individually or in combination with others in this document, is sufficient to reconstruct a working AMA implementation.
