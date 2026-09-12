"""Small integration API and durable attempt lifecycle above V2."""
from dataclasses import dataclass

from agent_guard.canonical import canonical, digest, loads, fields
from agent_guard.crypto import sign, verify
from agent_guard.errors import GuardError
from agent_guard.v2.audit import require, validate_payload
from agent_guard.v2.model import Action

STEPS = {None: {"authorized"}, "authorized": {"dispatching"},
         "dispatching": {"confirmed", "rejected", "unknown"}, "unknown": {"confirmed"},
         "confirmed": set(), "rejected": set()}


class Denied(GuardError):
    def __init__(self, event):
        super().__init__("authorization_denied")
        self.event = event


@dataclass(frozen=True)
class Prepared:
    request_bytes: bytes
    event_bytes: bytes

    @property
    def request(self):
        return loads(self.request_bytes)

    @property
    def event(self):
        return loads(self.event_bytes)

    @property
    def authorization(self):
        return self.event["receipt"]

    @property
    def action(self):
        return Action.from_dict(self.event["action"])


class DeliveryJournal:
    def __init__(self, gateway):
        self.gateway = gateway
        with gateway.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS product_delivery (sequence INTEGER PRIMARY KEY, envelope TEXT NOT NULL)")

    def events(self):
        with self.gateway.transaction() as db:
            return [loads(r[0]) for r in db.execute("SELECT envelope FROM product_delivery ORDER BY sequence")]

    def append(self, prepared, status, observation=None, reason=None):
        with self.gateway.transaction() as db:
            self.gateway._check_materialized(db)
            certificate = prepared.authorization
            auth = verify(certificate, self.gateway.key.public_key())
            validate_payload(auth)
            issued = db.execute('SELECT certificate FROM issued WHERE nonce=?', (auth['nonce'],)).fetchone()
            require(auth['kind'] == 'authorization' and auth['decision'] == 'allow' and
                    auth['action_hash'] == prepared.action.hash and
                    auth['actor'] == prepared.action.to_dict()['actor'] and
                    issued is not None and canonical(loads(issued[0])) == canonical(certificate),
                    'delivery_requires_issued_authorization')
            rows = [loads(r[0]) for r in db.execute("SELECT envelope FROM product_delivery ORDER BY sequence")]
            states = verify_journal(rows, self.gateway.key.public_key())
            nonce = prepared.authorization["payload"]["nonce"]
            old = states.get(nonce)
            require(status in STEPS[old["status"] if old else None], "delivery_not_retryable")
            p = {"version": 1, "kind": "tool_delivery", "sequence": len(rows)+1,
                 "previous": digest(rows[-1]) if rows else None, "attempt": nonce,
                 "action_hash": prepared.action.hash, "authorization_hash": digest(prepared.authorization),
                 "status": status, "observation": observation, "reason": reason}
            if old:
                require((old["action_hash"], old["authorization_hash"]) ==
                        (p["action_hash"], p["authorization_hash"]), "delivery_binding_mismatch")
            envelope = sign(p, self.gateway.key)
            db.execute("INSERT INTO product_delivery VALUES (?,?)", (p["sequence"], canonical(envelope).decode()))
        return envelope


def verify_journal(events, key, expected_head=None):
    states, previous = {}, None
    for i, envelope in enumerate(events, 1):
        p = verify(envelope, key)
        fields(p, {'version', 'kind', 'sequence', 'previous', 'attempt', 'action_hash',
                   'authorization_hash', 'status', 'observation', 'reason'})
        require(type(p["version"]) is int and p["version"] == 1 and p["kind"] == "tool_delivery" and
                type(p['sequence']) is int and p["sequence"] == i and p["previous"] == previous, "broken_delivery_history")
        old = states.get(p["attempt"])
        require(p["status"] in STEPS[old["status"] if old else None], "invalid_delivery_transition")
        if old:
            require((p["action_hash"], p["authorization_hash"]) ==
                    (old["action_hash"], old["authorization_hash"]), "delivery_binding_mismatch")
        require((p["status"] == "confirmed") == (p["observation"] is not None), "invalid_delivery_observation")
        states[p["attempt"]], previous = p, digest(envelope)
    if expected_head is not None:
        require(previous == expected_head, "delivery_checkpoint_mismatch")
    return states


class DirectTransport:
    def __init__(self, resource):
        self.resource = resource

    def send(self, adapter, actor, request, authorization):
        return self.resource.invoke(adapter, actor, request, authorization)


class AgentGuard:
    def __init__(self, gateway, actor, resource):
        self.gateway, self.actor, self.resource = gateway, actor, resource
        self.journal = DeliveryJournal(gateway)

    def protect(self, adapter, transport=None):
        return ProtectedTool(self, adapter, transport or DirectTransport(self.resource))


class ProtectedTool:
    def __init__(self, guard, adapter, transport):
        self.guard, self.adapter, self.transport = guard, adapter, transport

    def prepare(self, **request):
        raw = canonical(request)
        action = self.adapter.normalize(self.guard.actor, loads(raw))
        event = self.guard.gateway.authorize(action, self.guard.actor)
        if event["receipt"]["payload"]["decision"] != "allow":
            raise Denied(event)
        prepared = Prepared(raw, canonical(event))
        self.guard.journal.append(prepared, "authorized")
        return prepared

    def dispatch(self, prepared):
        require(self.adapter.normalize(self.guard.actor, prepared.request).hash == prepared.action.hash,
                "action_or_actor_mismatch")
        # Durable reservation before transport. One winner under concurrent calls.
        self.guard.journal.append(prepared, "dispatching")
        try:
            observation = self.transport.send(self.adapter, self.guard.actor, prepared.request, prepared.authorization)
        except GuardError as exc:
            # Only a direct recipient rejection is definitive. A network error,
            # malformed response or unverifiable evidence may follow a real effect.
            status = "rejected" if type(self.transport) is DirectTransport else "unknown"
            self.guard.journal.append(prepared, status, reason=exc.code)
            return {"status": status, "reason": exc.code}
        except Exception:
            self.guard.journal.append(prepared, "unknown", reason="transport_outcome_unknown")
            return {"status": "unknown", "reason": "transport_outcome_unknown"}
        try:
            self.guard.resource.verify_observation(observation, prepared.action, prepared.authorization)
        except Exception:
            self.guard.journal.append(prepared, "unknown", reason="unverifiable_observation")
            return {"status": "unknown", "reason": "unverifiable_observation"}
        self.guard.journal.append(prepared, "confirmed", observation=observation)
        return {"status": "confirmed", "observation": observation}

    def send(self, **request):
        return self.dispatch(self.prepare(**request))

    def reconcile(self, prepared):
        states = verify_journal(self.guard.journal.events(), self.guard.gateway.key.public_key())
        old = states.get(prepared.authorization["payload"]["nonce"])
        require(old is not None and old["status"] in {"dispatching", "unknown"}, "delivery_not_uncertain")
        if old["status"] == "dispatching":
            self.guard.journal.append(prepared, "unknown", reason="interrupted_dispatch")
        observation = self.guard.resource.lookup(self.guard.actor, prepared.action, prepared.authorization)
        if observation is None:
            return {"status": "unknown", "reason": "no_confirmed_observation"}
        self.guard.resource.verify_observation(observation, prepared.action, prepared.authorization)
        self.guard.journal.append(prepared, "confirmed", observation=observation)
        return {"status": "confirmed", "observation": observation}
