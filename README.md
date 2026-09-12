# Verifiable Authorization for AI Agents

Tools execute agent actions only when they can verify that the exact action passed the security policy.

Run the local product demo with the existing toolchain, without model API keys:

```sh
.venv/bin/python -m agent_guard product-demo --output output/my-product-demo --serve
```

Open **http://127.0.0.1:8787** for the interactive story: inherited payroll restrictions, protected email and REST tools, blocked bypass/substitution/replay, scoped delegation, cascading revocation, MCP interoperability and uncertain-delivery reconciliation. Choose a new output directory for each run. The generated `index.html` also opens directly without a server.

```sh
.venv/bin/python -m agent_guard product-demo --verify output/my-product-demo
```

The [integration guide](docs/PRODUCT_DEMO.md) covers the small `guard.protect(...)` API, adapters, signed delivery evidence and the exact mock-service boundary. V2 still reports send intents as **queued**; a separate recipient observation confirms only the local mock effect. The detailed existing documentation follows.

# Agent Guard: stateful authorization with checked evidence

**Parts 2 and 3 are implemented as protocol V2.** The core now combines persistent authorization state, attenuated delegation, cascading revocation, inherited information-flow labels, budgets, OPA, a compiled Lean evaluator, and a replayable signed history.

The robustness review closes a broad-delegation denial bypass, makes Lean label transitions match runtime state exactly, strengthens the authorization proof to a declarative equivalence, and hardens signed-evidence and persistent-state validation. See [the review findings and regression coverage](docs/ROBUSTNESS_REVIEW.md).

Every live decision must agree across **OPA + the executable checked by Lean + the Python reference**. Missing engines, malformed responses or disagreement stop execution. Auditors verify the actual state transition as well as the signature. See [the V2 specification](docs/V2_SPEC.md) and [the exact proof boundary](docs/PROOFS.md).

## Run Parts 2 and 3

The tools are installed in this workspace. On a fresh checkout, run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
python3 tools/bootstrap.py
```

The bootstrap downloads SHA-256-pinned OPA 1.20.2 and Lean 4.33.1 into `tools/`, checks the proofs and builds the executable kernel. It requires `tar` with zstd support, downloads roughly 600 MB on macOS Intel, and needs several GB of disk. It does not change your global Lean installation. The full tests require both actual engines; proof tests are never silently skipped.

```sh
.venv/bin/python -m agent_guard v2 demo --output output/my-parts23-demo
.venv/bin/python -m agent_guard v2 verify output/my-parts23-demo/history.json --trust output/my-parts23-demo/trust.json
.venv/bin/python -m pytest -q
```

The demo shows a permitted public send, a protected read, inherited labels on a derived output, blocked external sends from two different agent identities, permitted internal queuing, scoped delegation, and root revocation. It produces signed allow **and deny** events, a complete history, administrator trust material and an external-checkpoint candidate. Output directories must be new.

To run the V2 API:

```sh
.venv/bin/python -m agent_guard v2 init --state runtime-v2
.venv/bin/python -m agent_guard v2 serve --state runtime-v2
```

Submit a version-2 action using `agent-guard-v2 request`, or the Python client with `api_version="v2"`. Example actions and policy are in [examples/v2](examples/v2). Each principal gets its own credential; the caller cannot select its identity through the JSON action. The gateway exposes `/v2/authorize`, `/v2/execute`, and `/v2/act`.

**The reusable primitive is scoped, like a security protocol with explicit assumptions.** It checks formal authorization and information-flow rules over registered resources. It is not a universal legality oracle, a proof of all Python/OS behavior, or a sandbox. Keep the service, signing key and database inaccessible to the agent. The current network transport remains for development.

General operation names and resource namespaces map to reviewed effect types: read, write, send, delegate and revoke. Data values and queued payloads can be structured JSON. A send is a **durable outbox intent**, and its receipt says `queued`. There is no email/API delivery claim or unrestricted shell/HTTP adapter. The [integration contract](docs/V2_SPEC.md#adapter-and-deployment-contract) explains what a real external adapter must establish.

Keep existing V1 trust material to verify old receipts. V2 uses a fresh store and schema; it does not silently migrate old data or reinterpret old signatures. Historical V1 details follow.

## V1 compatibility reference

A working MVP for **policy-authorized agent actions with independently verifiable evidence**. An agent submits a structured request; a trusted gateway authorizes it; the resource verifies the authorization; the response includes a signed execution receipt.

V1 controls a private SQLite document store with `read` and `write`. It establishes the action, policy, enforcement, and evidence interfaces before adding more tools or richer rules.

**The guarantee is scoped:** for this gateway's successful executions, the exact action passed the configured policy. This is not a proof of general legality, a formally verified implementation, or a sandbox for arbitrary agent code. The gateway and its storage must be isolated from the agent. See [the threat model](docs/THREAT_MODEL.md).

## Run it

Python 3.11+; one runtime dependency, `cryptography`. From this directory:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m agent_guard demo --output output/demo
.venv/bin/python -m agent_guard verify output/demo/read-receipt.json --trust output/demo/trust.json
.venv/bin/python -m pytest -q
```

The demo performs an allowed read, rejects a protected read, rejects payload and identity substitution, rejects replay, performs an allowed write, and verifies the execution history. It leaves public verification material and synthetic example evidence in `output/demo`; its temporary private key and store are removed. Choose a new output directory to run it again: commands refuse to overwrite existing artifacts.

The verifier command runs in a separate process using a public key and pinned policy. It needs no signing key or database. Obtain `trust.json` from the administrator through a trusted channel. A receipt sender supplying both the receipt and an untrusted key does not establish authenticity.

## Run the gateway

```sh
.venv/bin/python -m agent_guard init --state runtime
.venv/bin/python -m agent_guard serve --state runtime
```

In another terminal:

```sh
.venv/bin/python -m agent_guard request --token-file runtime/agent1.token --action examples/read.json --output output/read.json
.venv/bin/python -m agent_guard verify output/read.json --trust runtime/trust.json
.venv/bin/python -m agent_guard request --token-file runtime/agent1.token --action examples/write.json --output output/write.json
.venv/bin/python -m agent_guard request --token-file runtime/agent1.token --action examples/denied.json --output output/denied.json
```

The denied request returns HTTP 403 and exits with status 1. It includes a signed denial decision and no document content. `verify` currently verifies successful execution bundles and execution histories; a denial has no execution receipt.

This same-user, localhost setup is a development demonstration. For an untrusted agent, run the gateway under a separate OS identity/container/host and give the agent only its own token and network access to the gateway. The current HTTP transport is for local development; it has no TLS or production availability controls.

## What ships

| Module | Responsibility |
|---|---|
| `action.py`, `canonical.py` | Versioned immutable actions; strict canonical JSON; SHA-256 commitments |
| `policy.py` | Small pure authorization relation; exact grants; deny precedence; default deny |
| `gateway.py` | Issue short-lived authorization; verify it at the resource boundary; execute atomically |
| `store.py` | Private document adapter, persistent nonce consumption, state, execution ledger |
| `crypto.py`, `receipt.py` | Ed25519 signatures, source commitment, public-key verification and policy replay |
| `server.py`, `client.py` | Credential-derived identity, HTTP boundary, agent client |
| `cli.py` | Initialization, demo, server, request, export and offline verification |

No model provider or agent framework is required. Any agent can submit the same JSON through the client. There is no endpoint for arbitrary Python, shell, filesystem paths, SQL, URLs, policy editing, or key export.

## One action, one meaning

```json
{
  "version": 1,
  "actor": "agent1",
  "operation": "write",
  "resource": "document:drafts/note",
  "parameters": {"content": "A policy-authorized draft."}
}
```

The resource is an opaque ID, never a host file path. The full write content is committed in the action hash. Two actions are equal precisely when their canonical bytes are equal; changing actor, operation, resource, or content changes the commitment. Nested parameter structures cannot mutate an existing action.

The supplied policy lets `agent1` read the welcome document and read/write its draft. It explicitly denies reading the synthetic payroll document. All other actions are denied. Rules do not infer authority from natural language, claimed purposes, or `legal: true` fields.

## What the evidence establishes

An **authorization certificate** signs the decision, matching rule IDs, authenticated actor, action hash, policy hash, state hash, source hash, store audience, nonce, and 30-second validity window. It is permission to attempt one exact action; issuing it does not mean the action happened.

An **execution receipt** additionally signs the authorization hash, result hash, state before and after, sequence number, execution time, and previous receipt hash. The effect, consumed nonce, and receipt commit in one SQLite transaction. An audit or signing failure rolls back the write. Reads return their result only after committing the receipt.

The offline verifier checks signatures and all bindings and recomputes the finite authorization decision. Execution itself remains an attestation by the trusted gateway. The source hash is a commitment to the package's Python files, not evidence that a particular binary ran on trusted hardware.

For a complete history:

```sh
.venv/bin/python -m agent_guard export --state runtime --output output/history.json
.venv/bin/python -m agent_guard verify output/history.json --trust runtime/trust.json
```

The verifier prints the chain head. Preserve it independently and use `--head HASH` on later verification to detect removal of the tail of that history. Without an external checkpoint, a valid prefix cannot be distinguished from a complete history. Exports contain document content and should be handled as sensitive data.

## Build forward

Read [the V1 specification and semantics](docs/SPEC.md), [security assumptions](docs/THREAT_MODEL.md), and [the staged roadmap](docs/ROADMAP.md). The [source mapping](docs/SOURCES.md) explains how the two PDFs informed the implementation and which ambitions are intentionally deferred.

Policy, signing key, and source hash are fixed for a store in V1. Changing any of them fails startup rather than silently invalidating the history. Use a fresh development state directory after code changes; a controlled migration and revocation mechanism is a V2 feature. Do not delete a real audit history to upgrade a deployment.
