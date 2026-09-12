Goal

Create a new demo/integration layer ABOVE protocol V2.

Do not make MCP the fundamental abstraction.

Agent Guard should be transport-agnostic and able to protect:

HTTP APIs
filesystem-like tools
email/message tools
MCP tools
other application-defined agent tools

The central abstraction remains the existing V2 Action.

Native tool operations should be translated into canonical Agent Guard Actions, authorized using the existing V2 pipeline, and executed only after verification.

Important distinction

The existing send operation currently records a durable queued intent and does not claim arbitrary external delivery.

Preserve that security claim.

For this demo, implement a controlled external-adapter framework that explicitly distinguishes:

authorized
dispatching
confirmed
rejected
unknown

Never label a remote action executed merely because an HTTP request was attempted.

Build one reusable adapter contract

Add something conceptually like:

class ProtectedToolAdapter:
    def normalize(self, actor, request) -> Action:
        ...

    def execute(self, verified_authorization, request):
        ...

    def observe_result(self, result):
        ...

The exact API can differ if the repository architecture suggests something cleaner.

Every adapter must guarantee:

the full destination is bound to the Action
operation/method is bound
parameters/body are bound
actor identity is bound
changing any of these invalidates authorization
no execution occurs before successful authorization verification
result status is recorded accurately
retries/replays are handled explicitly
Build three demo adapters
1. Mock email service

Expose a realistic-looking email tool:

email.send(
    to="bob@company.com",
    body=derived_data
)

Translate this into an Agent Guard Action.

Demonstrate:

reading payroll data adds PAYROLL_PRIVATE
sending derived payroll information to bob@company.com succeeds
sending it to attacker@gmail.com is denied before dispatch

This should reuse the existing information-flow state, not introduce a separate taint system.

2. HTTP service

Create a local mock REST API such as:

POST /payments
POST /documents

Protect it so requests must correspond to a valid Agent Guard authorization.

Demonstrate:

valid authorized request succeeds
request body modified after authorization fails
destination/path modified after authorization fails
missing authorization fails
replay fails
3. MCP adapter

Add one small MCP example only to demonstrate interoperability.

The MCP implementation must use the exact same core authorization protocol as the HTTP/email examples.

MCP must not become a dependency of the core.

Demonstrate a resource-side verifier

Create a small reusable verification component for protected resources.

Conceptually:

verifier.verify(
    authorization,
    expected_action=canonicalized_actual_request,
)

The protected resource must refuse execution when:

certificate is missing
signature is invalid
action hash differs
actor differs
state is stale
certificate expired
nonce was consumed
policy/evaluator manifest does not match trusted material

Reuse the existing V2 verification machinery rather than duplicating cryptographic logic.

Product demo

Add:

python -m agent_guard product-demo

or a similarly clean command.

The demo should run locally without model API keys.

It should tell one coherent story.

Scenario

Start with Agent A.

Agent A reads a public document.
✓ AUTHORIZED
✓ EXECUTED
Agent A reads payroll.
✓ AUTHORIZED
✓ EXECUTED

Security state changed:
+ PAYROLL_PRIVATE
Agent A creates a derived summary.

Show that the restriction follows the information.

Derived object labels:
PAYROLL_PRIVATE
Agent A sends it internally.
To: finance@company.com

✓ AUTHORIZED
✓ DISPATCHED
✓ CONFIRMED
Agent A tries sending the same information externally.
To: attacker@gmail.com

✗ DENIED

Reason:
PAYROLL_PRIVATE is not accepted by the external destination.
Show a bypass attack.

Attempt to invoke the protected HTTP endpoint without going through Agent Guard.

✗ REJECTED
Authorization evidence required.
Show action substitution.

Authorize:

finance@company.com

then change the actual request to:

attacker@gmail.com

Expected:

✗ REJECTED
Action commitment does not match request.
Show replay.

Reuse a consumed authorization.

Expected:

✗ REJECTED
Authorization already consumed.
Show multi-agent isolation.

Agent B tries accessing Agent A's protected resource.

✗ DENIED
No rooted authority witness.
Agent A delegates narrow authority to Agent B.

Agent B retries.

✓ AUTHORIZED

Then revoke the parent grant.

Agent B retries again.

✗ DENIED
Authority chain contains revoked grant.
UI

Build a small local web UI if it can remain lightweight.

The UI should visualize:

current agent
proposed action
OPA result
Lean result
Python result
final ALLOW/DENY
active information-flow labels
current grants
delegation chain
action hash
policy hash
state hash
signed event status
execution/dispatch outcome
previous-event hash / trace chain

Do not dump raw JSON as the primary UI.

The top-level product messaging should be:

Verifiable Authorization for AI Agents

“Tools execute agent actions only when they can verify that the exact action passed the security policy.”

Below it, show:

Agent
  ↓
Canonical Action
  ↓
OPA + Lean + Reference Checker
  ↓
Signed Authorization Evidence
  ↓
Protected Tool
Developer experience

Also expose an easy integration API.

Aim for something conceptually like:

guard = AgentGuard(...)

email = guard.protect(
    EmailTool(),
    adapter=EmailAdapter(...)
)

email.send(...)

or:

@guard.protected(adapter=...)
def send_email(...):
    ...

Do not force application developers to:

invoke OPA themselves
invoke Lean themselves
manually hash actions
sign receipts
manage nonce consumption
understand the internal proof representation

The security internals should remain inspectable, but the happy-path API should be simple.

Architectural requirements

Preserve these existing guarantees:

OPA alone cannot authorize execution
compiled Lean evaluator participates in live decisions
Python reference must agree
fail closed on evaluator disagreement
authorization and execution remain distinct
state transitions remain replayable
signatures remain independently verifiable
history remains hash chained
delegation remains attenuated
revocation cascades through grant chains
labels cannot silently disappear

Do NOT weaken the existing V2 model to make the demo easier.

Do not add

Do not add:

blockchain
ZKPs
TEEs
production Kubernetes
cloud dependencies
arbitrary shell execution
unrestricted browser automation
fake claims that arbitrary external effects are transactionally guaranteed
Tests

Add adversarial integration tests for:

no authorization
forged signature
substituted body
substituted destination
substituted actor
replay
stale state
expiration
revoked delegation
external exfiltration after protected read
valid internal send
successful narrow delegation
README

Keep the detailed current security documentation.

First:

inspect the existing V2 modules, CLI, tests, examples, and docs;
identify which existing components implement authorization events, execution events, state transitions, and verification;
propose the smallest set of new files/modules needed for the adapter/product-demo layer;
then implement it without duplicating existing security functionality.