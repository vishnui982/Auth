# Grow by strengthening one claim at a time

**Update after Parts 2 and 3:** stateful grants, revocation, domain/object labels, budgets, OPA, an executable Lean semantic checker and several checked history/authority theorems are now implemented in protocol V2. See `V2_SPEC.md` and `PROOFS.md` for exact scope. The following is the preserved original V1 plan, not a claim that all its milestones remain unfinished. Deployment containment, production transport, lifecycle migration and confirmed external delivery are still separate integration work.

## V1 delivered: a complete authorization slice

Immutable canonical actions, finite exact-match policies, credential-derived identity, signed short-lived authorization, resource-side checks, transactional document effects, durable receipt chains, public-key verification and adversarial tests. The document adapter is small enough to audit and does not require a model subscription or live external credentials.

Start by running the demo and reading a verified receipt. Then configure one narrowly scoped pilot agent to access only its own test documents. A successful pilot is an independently verified receipt for an intended action plus rejected bypass attempts at the gateway boundary, with the required deployment isolation separately demonstrated.

## V1.1: establish the deployment boundary

Before giving a hostile agent real access, deploy the gateway separately and test that the agent cannot read its key/database, invoke the underlying store, reach unintended network destinations, or run code inside the service. Replace the development HTTP transport with a hardened authenticated TLS service. Add credential lifecycle management, resource quotas and receipt reconciliation after lost responses.

Exit criterion: an automated containment test from the actual agent environment demonstrates that the controlled resource is reachable only through the gateway. This is the most valuable next security milestone; adding a more elaborate proof does not establish this boundary.

## V2: trusted context and lifecycle

Introduce explicit immutable `EvaluationContext` and versioned policy epochs, with administrators authenticated separately from agents. Add narrow revocation semantics: revoking a grant or identity must invalidate already-issued authority as well as future requests. Retain historical public keys, policies and source manifests so past receipts remain verifiable.

Add one stateful rule such as a per-agent write budget, with check, update and receipt in the same transaction. Extend the formal relation and exhaustive tests before changing runtime behavior. Replace global invalidation with resource-scoped versions only after defining cross-resource dependencies.

Exit criteria: a budget cannot be overspent by concurrent calls; a revoked certificate cannot execute; a verifier can audit a history across policy/key epochs.

## V3: one external adapter and information flow

Define an adapter contract that binds the complete operation payload, resource identity, trusted state preconditions, idempotency key and observed outcome. Add one service whose side effects can be confirmed and deduplicated. External APIs cannot share a SQLite transaction: use an outbox/pending/confirmed/unknown state machine and reconcile ambiguous outcomes. Do not issue an `executed` receipt merely because a request was attempted.

Next, track one explicit sensitivity label and prohibit an external send after reading protected data. The system needs trusted label provenance and a definition of which derived outputs inherit that label; the model's self-report is insufficient.

Exit criteria: substituted bodies and destinations fail; crash/retry behavior is demonstrated against the actual service; a read-then-send policy is enforced across the whole sequence.

## V4: machine-checked policy soundness

Translate the finite semantics in `SPEC.md` into Lean, Coq or another selected proof environment. Prove the evaluator's allow result implies the formal authorization relation. Prefer extracting the runtime evaluator or proving a narrowly defined compiler correspondence, rather than maintaining an unrelated theorem beside unverified code.

Keep the action canonicalization, credential boundary, adapter execution, storage and cryptography assumptions explicit in the theorem's trusted base. Formal verification of a policy predicate alone does not prove complete mediation or faithful execution.

Exit criterion: CI checks the theorem and the runtime is demonstrably connected to that proved artifact.

## V5 and beyond: attestations, privacy, legal rules

External checkpoints/transparent logs can strengthen history completeness and rollback detection. Hardware attestation can narrow trust in the runtime. Selective disclosure or zero-knowledge proofs can hide private policy inputs once there is a concrete privacy requirement and a stable relation worth proving.

Legal-rule modules come after the authority system has a dependable execution boundary. Start with one reviewed rule set in one defined domain and jurisdiction. Separate rule interpretation, factual evidence/provenance and authorization. Unknown or contradictory required facts should produce a defined deny/review outcome. Version the legal source and interpretation alongside the policy commitment.

The eventual claim should identify the exact rule set, facts, assumptions, tools, period and jurisdiction covered. Universal “the agent never does anything illegal” remains outside what a receipt about a finite policy can establish.

## Extension discipline

For each feature, write the new semantic relation, identify newly trusted facts/components, define the receipt fields that bind those facts, and demonstrate an adversarial failure case. Add only the required adapter or rule type. Preserve historical schema versions and public verification material. Avoid building generic plugin frameworks, policy compilers, blockchains or prover infrastructure before a concrete feature requires them.
