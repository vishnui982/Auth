# Product demo and protected tools

The integration layer sits above protocol V2. Canonical `Action` remains the central abstraction. The demo is entirely local, uses synthetic data and requires no model API keys or new Python dependencies.

## Run

From the repository root with the existing virtualenv, OPA and Lean toolchain installed:

```sh
.venv/bin/python -m agent_guard product-demo --output output/my-product-demo --serve
```

Open `http://127.0.0.1:8787`. The command runs the story and then serves the local demo lab. Choose a new output directory for each run; existing evidence is never overwritten. In the lab, **Run verified demo** executes the complete fixed local scenario again, writes it beneath the original output directory, and opens its fresh report. It does not execute text edited in the action inspector or accept arbitrary tool requests. Omit `--serve` to finish after generating `index.html`, which also works when opened directly; direct-file playback cannot rerun the scenario. The UI server exposes only `index.html` and `technical.html` reports, never a private state directory.

Verify the signed evidence again in a separate process:

```sh
.venv/bin/python -m agent_guard product-demo --verify output/my-product-demo
```

This checks the V2 chain, state transitions, delivery chain, signed recipient observations and both saved checkpoint heads. Distribute `trust.json` and the checkpoint through an independently trusted channel. A sender providing their own untrusted public key does not establish authenticity. A local checkpoint shipped alongside evidence does not by itself establish independent history completeness.

## Story

Agent A reads public information, reads payroll, and writes a derived summary. Existing V2 state acquires `PAYROLL_PRIVATE`, and the derived object inherits that label. Internal mail to finance succeeds; mail to the external destination is denied before dispatch. Actual HTTP calls demonstrate missing evidence and body/path substitutions failing at the receiving endpoint. Replay fails without another effect.

Agent B initially lacks a grant to the summary. A narrow delegation enables the read, and parent revocation disables it. An MCP `tools/call` uses the same V2 authorization machinery. Finally, a simulated lost acknowledgement produces `unknown`; reconciliation reads the already recorded signed observation and confirms it without resending.

The demo lab displays the principal, an editable inspection copy of the proposed action, the fundamental policy conditions, three-way checker agreement, decision, active/derived labels, grant parent links, revocations, action/policy/state commitments, event status and predecessor hash. For bypass attempts rejected before evaluation it says “Not evaluated,” rather than inventing checker results. The technical-notes page describes the adapter and evidence boundary. The only executable UI control runs the complete fixed demo; the lab is not an interface for dispatching arbitrary tools.

## Integration API

The embedding application provisions identity and trusted destinations. Applications do not call OPA, Lean, hashing, signing or nonce handling themselves:

```python
from agent_guard.integration import AgentGuard, EmailAdapter, ResourceVerifier

resource = ResourceVerifier(existing_v2_gateway)
guard = AgentGuard(existing_v2_gateway, actor="agent1", resource=resource)
email = guard.protect(EmailAdapter())
result = email.send(to="finance@company.com", body="A derived summary")
assert result["status"] == "confirmed"
```

For split workflows, use `prepared = email.prepare(...)`, followed by `email.dispatch(prepared)`. Preparation snapshots the full request and retains the signed V2 authorization. `Denied` contains the signed denial event. Never take the `actor` argument from an unauthenticated request: the mock HTTP server derives it from its bearer credential, and the MCP stdio server binds it to a provisioned credential for the session.

The adapters normalize exact effect-bearing fields:

| Adapter | Bound request | Recipient |
|---|---|---|
| Email | Exact recipient, body, service and method | Local mock mailbox |
| HTTP | Full loopback origin, path, POST method and complete JSON body | Actual local `/payments` and `/documents` REST endpoints |
| MCP | Server identity, `tools/call`, tool name and complete arguments | Local mock document service |

Unknown fields, methods and destinations are rejected. Email classification uses exact administrator-defined recipients, not a caller-provided label or an email suffix guess. The demo policy is defined in `integration/demo.py`. HTTP accepts no redirects or arbitrary network destinations. Filesystem-like reads/writes remain the existing private V2 document adapter; no host filesystem or shell access is added.

## Recipient boundary and lifecycle

`ResourceVerifier.invoke` reconstructs an action from the actual authenticated request and reuses V2 `Gateway._execute` inside the gateway's transaction. This is the integration layer's narrow, tested coupling to V2 internals. It does not copy cryptography, grant evaluation, nonce checks or transitions. The recipient rejects absent/forged evidence, substituted actions or actors, stale state, expiry, replay, mismatched policy/engine pins and revoked authority.

The controlled mock's effect is its durable `product_effects` database record. That record, its signed observation, V2 queued intent and nonce consumption commit together in the **recipient's local SQLite transaction**. Revocation or a competing action is serialized against this admission. This atomicity claim applies only to the supplied local mock, never to an arbitrary remote service. The verifier intentionally accepts no unrestricted side-effect callback.

The caller's separate signed delivery journal records:

| State | Meaning |
|---|---|
| `authorized` | An actual issued V2 allow certificate binds this request; no delivery claimed |
| `dispatching` | The caller durably reserved one transport attempt before invoking it |
| `confirmed` | A valid recipient observation confirms the mock record |
| `rejected` | Direct recipient invocation definitively refused the operation |
| `unknown` | Transport, acknowledgement or process outcome is uncertain |

The journal permits `authorized → dispatching → confirmed/rejected/unknown`, and `unknown → confirmed` through reconciliation. It rejects redispatch of any reserved attempt, including concurrent calls. Network exceptions and unverifiable acknowledgements conservatively produce `unknown`, even if an HTTP error seems to indicate rejection. No automatic retry creates a new authorization.

Call `email.reconcile(prepared)` after an uncertain or interrupted attempt. It reads the mock recipient's signed observation without executing the tool. An interrupted `dispatching` attempt first becomes `unknown`. Absence of a confirmation remains unknown; it is not proof of rejection. A crash between authorization and journal reservation can leave unused V2 authority, but cannot have dispatched a tool. As in V2, at-most-once applies to a certificate, not to the same semantic intention submitted for fresh authorization.

## Evidence and code boundaries

- `adapters.py`: request normalization contract and the three adapters.
- `resource.py`: recipient-side V2 reuse and the transactional mock observation.
- `runtime.py`: developer API and durable delivery lifecycle.
- `http.py`, `mcp.py`: optional transport examples.
- `evidence.py`: offline cross-verification against V2 history and product trust.
- `demo.py`, `ui.html`: scenario, CLI and playback UI.

V2 sends still have status `queued`. Product observations use a separate signed envelope, `mock_tool_observation`; delivery journal entries use `tool_delivery`. Offline verification binds every confirmed observation to its exact V2 queue event, request, actor, nonce and adapter source manifest, and every delivery attempt to an issued V2 authorization. Both chains have checkpoints.

Product code has a separately pinned source manifest. Core Python/OPA/Lean/state semantics remain unchanged, apart from CLI routing to the optional product command. Existing stores are not migrated; new demo state is created privately under the requested output directory. Detailed V2 security documentation remains in [V2_SPEC.md](V2_SPEC.md) and [PROOFS.md](PROOFS.md).

The new adapter layer is tested, not formally verified by the existing Lean theorems. Its trusted code, recipient provisioning, shared development signing key, clock, operating system and private database must be protected. Reconciliation in this demo uses trusted local database access; a real remote recipient needs an authenticated lookup protocol and its own independently pinned verification key. Actual SMTP delivery, real payments, production TLS/availability, arbitrary external idempotency and OS containment are outside this demo.

## Optional MCP stdio example

After generating a demo state, an MCP client can launch:

```sh
.venv/bin/python -m agent_guard.integration.mcp \
  --state output/my-product-demo/state \
  --token-file output/my-product-demo/state/agent1.token
```

This is a minimal example supporting MCP revision `2025-11-25`, `initialize`, `notifications/initialized`, `ping`, `tools/list` and `tools/call`. It uses newline-delimited JSON-RPC over stdio. Each call includes its previously issued V2 certificate in `params._meta["org.agentguard/authorization"]`; this is an application-specific authorization convention, not a claim of MCP OAuth support. `MCPAdapter.normalize` produces the canonical action to authorize. Notifications cannot execute tools. No MCP SDK is imported by the core.

Protocol references: [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) and [initialization lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

## Tests

```sh
.venv/bin/python -m pytest tests/test_integration.py -q
.venv/bin/python -m pytest -q
```

The integration tests exercise real OPA and compiled Lean, the actual loopback REST endpoint, MCP request handling, all requested evidence substitution attacks, concurrency/replay, cascading revocation, protected information flow, rollback, uncertain outcomes, restart/reconciliation and independent evidence verification.
