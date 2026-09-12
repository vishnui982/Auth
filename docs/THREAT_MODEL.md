# Security boundary and honest claims

## What V1 protects

Assume an agent controls every byte of its HTTP request. It can invent actor names, change operation/resource/content after authorization, submit malformed JSON, call the resource endpoint directly, copy receipts, replay requests, and race multiple requests. It knows its own bearer credential and sees responses to its requests.

Within this model, a document read or write succeeds only after the resource gateway checks authorization for the exact request under the pinned policy. A signature alone is insufficient: the resource also replays the policy decision, checks state and audience, and consumes the nonce atomically with the effect.

Prompt injection does not give request content any extra authority. Content is never executed or interpreted as policy. However, a malicious prompt can still persuade an agent to make an undesirable request that its policy permits. Rules must be chosen to match the intended authority.

## What must be trusted

- The administrator's policy and identity provisioning. An allow rule is an authority grant, not evidence that the administrator owns a resource or that the action is legally permitted.
- Gateway code, Python, cryptography/OpenSSL, SQLite, the operating system, random number generator and clock.
- The signing key and the gateway's exclusive access to the private database.
- The distribution of the public key, policy, source hash and store ID to auditors.
- SQLite's transaction/durability behavior and storage integrity under the deployment's normal failure model.

The implementation does not resist compromise of those components. A source hash identifies files; it does not attest the loaded process, dependencies, configuration provenance or hardware. Public signatures authenticate statements by the key holder; they do not independently witness external reality.

## Required deployment boundary

The gateway process is a privileged resource service. The untrusted agent must have **no filesystem, process-memory, debugging, administration or credential path** to the gateway's state or signing key. Do not execute agent-generated Python in the gateway process.

For a real pilot, use a separate OS user, an appropriately confined container, or a separate host for the gateway. Provision `runtime/` as the gateway user. Transfer only the agent's individual bearer credential to the agent. Transfer `trust.json` independently to the auditor. Do not mount the state directory, Docker socket, host credentials or signing key into the agent environment. Give the agent no underlying document-store credentials or alternate resource endpoint.

For a claim about all agent effects, the agent's network and tool access must also be restricted so that all consequential effects in the claimed domain pass through a gate. This repository implements the document gateway, **not an OS/network sandbox or a universal tool interceptor**. Adding it to an existing agent while retaining unrestricted shell, browser, filesystem or API access does not establish complete mediation.

The supplied localhost quickstart runs as one OS user for convenience. File modes are defense in depth against other users; they do not isolate a malicious process running as the same user. The self-contained demo uses trusted test calls. Neither setup demonstrates adversarial host containment.

## Transport and credentials

The bundled standard-library HTTP server is a local development transport. It has payload bounds, strict framing for supported POST requests, request timeouts and no permissive CORS behavior. It does not include TLS, rate limiting, thread quotas, distributed authentication or production denial-of-service defenses. Do not expose it to the public internet. For a networked pilot, use an authenticated TLS boundary and production transport after reviewing trusted-proxy behavior; preserve all request and identity checks.

Bearer credentials prove possession of a secret, not a human identity. Theft of an agent's credential lets the thief exercise that agent's grants. Keys and tokens are unencrypted private files protected by directory/file permissions in V1. There is no key-management service or runtime key/token rotation protocol. Identity map changes take effect when the service restarts. Remove a credential and restart to stop its future authenticated requests; authorization expiry alone is not a full revocation mechanism.

## Receipts, history and recovery

Execution receipts are durable and hash-linked. Signed denied decisions are returned but are not persisted in the execution ledger. Malformed requests and operational failures do not have signed execution receipts. This is an execution history, not a complete log of every attempted request.

Successful database writes, nonce consumption and receipts share a transaction. A process crash before commit leaves no committed write; a crash or lost response after commit can leave the caller unsure whether the write happened. Reusing that certificate will be rejected. Export/reconcile the execution ledger using the authorization hash or nonce before deciding to issue a new request. V1 has no public idempotency lookup API. Never treat a network error as proof that no action happened.

At-most-once execution applies to one certificate. Sending `/v1/act` again creates another authorization and may execute again. The current write operation replaces content, but future payments or email cannot inherit these transaction guarantees automatically.

An attacker who can restore the entire database to an earlier snapshot can also restore the nonce table. Database rollback, fork detection, trusted time rollback, and an administrator deleting/replacing the ledger are outside V1's local enforcement guarantee. External receipt-head checkpoints detect missing suffixes for auditors; protecting replay state against rollback requires stronger storage/anchoring. A valid isolated receipt proves neither completeness of the history nor that the agent used no other tools.

Receipt bundles contain raw action parameters and read results. They can disclose sensitive data. Content and policy hashes may also enable guessing low-entropy secrets. Export only to authorized auditors; later selective disclosure or ZK work needs a separate privacy threat model.

## Operational constraints

One fixed policy, source commitment, and signing key governs each store. A restart with different pins fails closed. Use a new store for development changes. A production migration must preserve historical trust epochs and outstanding-authority revocation; it is intentionally not improvised here.

Reads and writes serialize on SQLite and each success invalidates every previously issued certificate for that store. State commitments scan the small document inventory. The ledger grows without retention/compaction, and local history verification is capped at 32 MiB. These are acceptable MVP limits, not a multi-tenant performance design.

Policy allows arbitrary permitted document content. There is no data classification, consent database, purpose verification, sequence-dependent information-flow rule, jurisdiction resolution, or legal interpretation. An authorized action may still be unlawful or harmful. Legal-rule modules will require verified facts, scoped legal interpretation, and explicit handling of uncertainty, beyond this authorization kernel.
