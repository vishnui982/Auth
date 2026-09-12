"""Recipient-owned verification and a transactional MOCK service, never a remote callback."""
from pathlib import Path

from agent_guard.canonical import canonical, digest, loads, fields
from agent_guard.crypto import sign, verify
from agent_guard.errors import GuardError
from agent_guard.v2.audit import require


def adapter_manifest():
    return {p.name: __import__('hashlib').sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(__file__).parent.glob('*.py'))}


class ResourceVerifier:
    """Reconstruct the actual request and reuse V2's resource gate in one transaction.

    Only the controlled SQLite mock effect belongs inside this transaction. A real
    external adapter must establish its own recipient boundary and delivery protocol.
    """
    def __init__(self, gateway):
        self.gateway = gateway
        self.manifest = adapter_manifest()
        self.adapter_hash = digest(self.manifest)
        with gateway.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS product_config (id INTEGER PRIMARY KEY, manifest TEXT NOT NULL)")
            row = db.execute("SELECT manifest FROM product_config WHERE id=1").fetchone()
            require(row is None or loads(row[0]) == self.manifest, "adapter_configuration_changed")
            db.execute("INSERT OR IGNORE INTO product_config VALUES (1,?)", (canonical(self.manifest).decode(),))
            db.execute("CREATE TABLE IF NOT EXISTS product_effects (nonce TEXT PRIMARY KEY, observation TEXT NOT NULL)")

    def invoke(self, adapter, actor, request, authorization):
        require(authorization is not None, "authorization_evidence_required")
        request, authorization = loads(canonical(request)), loads(canonical(authorization))
        action = adapter.normalize(actor, request)
        g = self.gateway
        with g.transaction() as db:
            g._check_materialized(db)
            # No separate copied signature/policy implementation. _execute rechecks
            # signature, identity, state, expiry, issuance, nonce and all three engines.
            queued = g._execute(db, action, actor, authorization)
            require(queued["receipt"]["payload"]["status"] == "queued", "adapter_requires_send_intent")
            nonce = authorization["payload"]["nonce"]
            result = {"record_id": nonce, "service": action.to_dict()["resource"],
                      "recorded_request": request, "outcome": "recorded_by_local_mock"}
            observation = sign({"version": 1, "kind": "mock_tool_observation", "status": "confirmed",
                                "actor": actor, "action_hash": action.hash, "nonce": nonce,
                                "queue_event_hash": digest(queued["receipt"]), "adapter_hash": self.adapter_hash,
                                "result": result}, g.key)
            # This row IS the mock mailbox/payment/document effect. It and the V2
            # queue receipt/nonce commit together. No network call occurs here.
            db.execute("INSERT INTO product_effects VALUES (?,?)", (nonce, canonical(observation).decode()))
        return observation

    def lookup(self, actor, action, authorization):
        """Read-only reconciliation; never resubmit or manufacture a fresh capability."""
        p = verify(authorization, self.gateway.key.public_key())
        require(p["actor"] == actor == action.to_dict()["actor"] and p["action_hash"] == action.hash,
                "action_or_actor_mismatch")
        with self.gateway.transaction() as db:
            self.gateway._check_materialized(db)
            row = db.execute("SELECT observation FROM product_effects WHERE nonce=?", (p["nonce"],)).fetchone()
        return loads(row[0]) if row else None

    def verify_observation(self, observation, action, authorization):
        p = verify(observation, self.gateway.key.public_key())
        fields(p, {'version', 'kind', 'status', 'actor', 'action_hash', 'nonce', 'queue_event_hash', 'adapter_hash', 'result'})
        require(p["kind"] == "mock_tool_observation" and type(p['version']) is int and p["version"] == 1 and p["status"] == "confirmed" and
                p["action_hash"] == action.hash and p["actor"] == action.to_dict()["actor"] and
                p["nonce"] == authorization["payload"]["nonce"] and p["adapter_hash"] == self.adapter_hash,
                "observation_binding_mismatch")
        return p

    def observations(self):
        with self.gateway.transaction() as db:
            return [loads(row[0]) for row in db.execute("SELECT observation FROM product_effects ORDER BY rowid")]
