# ASAP presentation runbook

## Prepare

Run `python3 tools/present.py` and open http://127.0.0.1:8787. This dependency-free presentation is explicitly illustrative. The source library shows real repository files, but this mode does not claim the engines ran.

For actual signed evidence, set up Python 3.11+, install `.[test]`, run `python3 tools/bootstrap.py`, and launch `.venv/bin/python tools/present.py --verified`. Bootstrap downloads large checksum-pinned toolchains; do this before the event. This run uses synthetic data and local mock services. No model, email, or payment credentials are needed.

If port 8787 is occupied, append `--port 8788`. Ctrl-C stops the server. Every verified launcher invocation creates fresh state; it never overwrites an audit history. The printed output location contains the evidence, trust and checkpoint files. Keep the state directory private.

## Manual walkthrough

Use **Next action** and **Previous** to move through nine examples. Each shows its complete result immediately. The Action menu jumps to any example. Expand **Policy & evidence** for the rule and verification details. Nothing advances automatically.

Speak alongside the on-screen explanation:

1. **0:00–0:20 — Read.** “ASAP means Agent Security and Access Protocol. Our assistant needs payroll access to do its job. Access is allowed, and the workflow becomes private.”
2. **0:20–0:40 — Derive.** “Summarizing data does not make it public. The new summary inherits the restriction.”
3. **0:40–1:00 — Deliver safely.** “Finance is an approved recipient. The exact request passes all three checks and the local mock records the effect.”
4. **1:00–1:20 — Block a leak.** “The same agent tries an external address. Send permission alone is not enough. The privacy rule blocks dispatch.”
5. **1:20–1:40 — Stop substitution.** “Even swapping the destination after authorization fails. The receiving tool checks the actual request.”
6. **1:40–2:00 — Delegate narrowly.** “Agent B gets one summary, read only, with no further delegation.”
7. **2:00–2:20 — Revoke.** “The owner revokes the parent grant. Agent B’s dependent access stops.”
8. **2:20–2:40 — Admit uncertainty.** “A lost acknowledgement does not mean failure. ASAP reports unknown and avoids a duplicate send.”
9. **2:40–3:00 — Prove the outcome.** “The signed recipient record confirms the original effect. Authorize. Enforce. Prove.”

The walkthrough shows recorded outcomes, not live proof construction. In verified mode it uses real recorded evidence. The **Run with OPA + Lean** button inside the action explorer generates a fresh complete scenario. Open **Policies & proofs** for the underlying sources and formal scope. Use **All actions & details** for judge questions.

## Honest claims

- In verified mode, OPA, compiled Lean and Python must agree on each policy decision and next active labels.
- A policy denial produces a signed denial event; a rejected bypass may have no signed execution event because it never entered the gate.
- Authorization permits an attempt. A V2 send is a queued intent. A confirmed integration delivery means the local mock recipient recorded an effect and signed an observation.
- The lost-acknowledgement case is unknown until reconciliation; it never automatically retries.
- Lean proves properties of the semantic model. It does not prove all Python, OS, storage, compiler or arbitrary remote tool behavior.
- The presentation controls replay steps; the verified Run button executes the entire fixed scenario with fresh state. The simple-guide controls are an educational simulation.

## Offline fallback

`python3 tools/present.py --build output/hackathon-site` creates a self-contained site. Open `output/hackathon-site/index.html` directly. Use a new build directory each time. All fonts and interface assets are local/system assets; no CDN is required.
