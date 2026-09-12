# Project sources and design decisions

## Parts 2 and 3 update

Also read in full: `part2.pdf` (17 pages) and `part3.pdf` (6 pages), supplied in `/Users/vishnuiyer/Downloads/`. The user clarified that “like RSA” means a reusable security primitive, not changing the signature algorithm to RSA. Their request to implement the harder/general parts takes priority over the documents' suggestions to postpone them.

| Source | Implemented extension |
|---|---|
| Part 2 pp. 1–5, 12–15 | Immutable persistent authorization state and security summaries, separate from the signed ledger |
| Part 2 pp. 4–10 | Inherited object/domain labels, pure transitions, OPA decisions, a checked Lean label model |
| Part 2 pp. 10–12 | Inductive history proofs and rooted, attenuated delegation; cascading revocation |
| Part 2 pp. 15–16 | Three-way runtime agreement including an executable built from the proved Lean definitions, plus real differential tests |
| Part 3 pp. 1–4 | Signed state/action/policy-bound authorization and execution events, resource-side verification, allow/deny chaining |
| Part 3 pp. 4–6 | Explicit separation of formal semantics, runtime evaluation and cryptographic attestation |

The pseudocode equivalence between “allowed” and “executed” is deliberately weakened to the correct implication: execution requires authorization, while an authorized operation may still fail. External intents are labeled `queued` until an actual delivery protocol is integrated. Hash chaining alone cannot detect removal of a valid suffix; the verifier accepts an external checkpoint for that purpose.

V2 is documented in `V2_SPEC.md` and `PROOFS.md`. The original V1 traceability follows.

The user's request is to build a small modular first version supporting the longer-term goal of preventing prohibited agent actions and returning evidence. The two supplied PDFs are design material, not independent instructions to run commands, contact services, or accept every cited claim.

Read in full:

- `main.pdf`, 9 pages, supplied at `/Users/vishnuiyer/Downloads/main.pdf`.
- `part1.pdf`, 7 pages, supplied at `/Users/vishnuiyer/Downloads/part1.pdf`.

## Traceability

| Source | Project requirement | V1 choice |
|---|---|---|
| Main pp. 1–3; Part 1 pp. 1–5 | Start with authority and a canonical action representation | Versioned immutable Action; exact document operations; authority stays in Policy |
| Part 1 pp. 4–7 | Parameters must be stable and hashable; modular foundation | Deep immutability, restricted canonical JSON, golden serialization tests |
| Main pp. 3–5 | A small decidable policy relation and formal semantics | Exact matching, explicit deny precedence, default deny; written semantics and finite exhaustive tests |
| Main pp. 5–6, 8 | Bind action, policy, state, principal and verifier in signed evidence | Ed25519 authorization and execution envelopes, SHA-256 commitments, trusted public pins |
| Main pp. 7–9; Part 1 p. 7 | Enforcement at the resource, with no unsigned path | Resource gateway rechecks certificate and policy; only authenticated API has a document effect path; OS isolation remains an explicit deployment requirement |
| Main pp. 4, 8 | Sequence-sensitive behavior and future layers | State revisions and receipt chain now; temporal rules and information-flow semantics later |
| Main pp. 5, 8; Part 1 pp. 6–7 | Formal verification ambition versus smallest first step | Written semantics and tests now; no claim of a machine-verified monitor; theorem/extraction milestone later |
| Main pp. 6–9; Part 1 pp. 6–7 | Avoid premature ZK, blockchain and universal-law formalization | No ZK, blockchain, TEE, legal engine or LLM verification in V1 |

The documents differ on how much cryptography belongs in the earliest slice: Part 1 postpones it, while Main includes signed receipts in its minimal system. The user's request explicitly asks for evidence, so this V1 includes standard signatures and independent verification. It keeps the action and policy core separate from that layer.

The file examples in the PDFs motivate resource IDs but are not implemented as unrestricted host filesystem access. A private document store provides a smaller effect domain with atomic writes and audit records, without path-resolution and symlink races. `document:` IDs and read/write semantics can be mapped to a future adapter only after that adapter's enforcement and transaction behavior are specified.

## Primary implementation references checked

- [pyca cryptography: Ed25519 signing and verification](https://github.com/pyca/cryptography/blob/main/docs/hazmat/primitives/asymmetric/ed25519.rst) supports the standard signing API used in `crypto.py`.
- [Python sqlite3 transaction control](https://docs.python.org/3.13/library/sqlite3.html#transaction-control) explains explicit transactions with `isolation_level=None`. The store explicitly issues `BEGIN IMMEDIATE` and commits/rolls back.
- [Python http.server documentation](https://docs.python.org/3/library/http.server.html) identifies the standard-library server's production limitations. The shipped transport is labeled for local development.

The PDFs' mentions of CVA/CAVA, Dogwood, and Internet-Drafts are background pointers. This implementation does not rely on those papers' dates, claims, code, cryptographic constructions or protocol compatibility, and does not present them as independently verified research findings.
