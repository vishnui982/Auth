"""Decision gate and resource-side enforcement, sharing a local transaction."""

import secrets
import time

from .canonical import canonical, digest, loads
from .crypto import public_pem, sign, verifier_hash
from .errors import GuardError
from .receipt import require, verify_authorization


class ResourceGateway:
    def __init__(self, store, policy, key, source_hash, clock):
        self.store, self.policy, self.key = store, policy, key
        self.source_hash, self.clock = source_hash, clock

    def execute(self, db, action, actor, certificate):
        before = self.store.state(db)
        now = int(self.clock())
        p = verify_authorization(certificate, key=self.key.public_key(), action=action,
                                 policy=self.policy, actor=actor, audience=before["store_id"],
                                 expected_verifier=self.source_hash, state_hash=digest(before), now=now)
        require(db.execute("SELECT 1 FROM executions WHERE nonce = ?", (p["nonce"],)).fetchone() is None,
                "replayed_certificate")
        previous = db.execute("SELECT receipt_hash FROM executions ORDER BY sequence DESC LIMIT 1").fetchone()
        result = self.store.apply(db, action)
        db.execute("UPDATE meta SET value = ? WHERE key = 'revision'", (str(before["revision"] + 1),))
        after = self.store.state(db)
        receipt = sign({"kind": "execution", "version": 1,
                        "authorization_hash": digest(certificate), "action_hash": action.hash,
                        "policy_hash": self.policy.hash, "verifier_hash": self.source_hash,
                        "state_before_hash": digest(before), "state_after_hash": digest(after),
                        "result_hash": digest(result), "previous_receipt": previous[0] if previous else None,
                        "sequence": after["revision"], "executed_at": now, "status": "executed"}, self.key)
        bundle = {"action": action.to_dict(), "authorization": certificate, "receipt": receipt,
                  "result": result, "state_before": before, "state_after": after}
        # Signing/serialization/log failure rolls back the effect AND nonce consumption.
        self.store.record(db, p["nonce"], bundle)
        return bundle


class Gateway:
    def __init__(self, store, policy, key, clock=time.time):
        self.store, self.policy, self.key, self.clock = store, policy, key, clock
        self.source_hash = verifier_hash()
        self.resource = ResourceGateway(store, policy, key, self.source_hash, clock)
        # One fixed configuration per store in V1. Never silently run two policies
        # against the same state. Controlled policy migration belongs in V2.
        trust = {"policy_hash": policy.hash, "verifier_hash": self.source_hash,
                 "public_key_hash": digest(public_pem(key.public_key()).decode())}
        with store.transaction() as db:
            old = db.execute("SELECT value FROM meta WHERE key = 'trust'").fetchone()
            if old:
                require(loads(old[0]) == trust, "store_configuration_mismatch")
            else:
                db.execute("INSERT INTO meta VALUES ('trust', ?)", (canonical(trust).decode(),))

    def _authorize(self, db, action, actor):
        state = self.store.state(db)
        decision = self.policy.evaluate(action, actor)
        now = int(self.clock())
        return sign({"kind": "authorization", "version": 1, "actor": actor,
                     "action_hash": action.hash, "policy_hash": self.policy.hash,
                     "state_hash": digest(state), "verifier_hash": self.source_hash,
                     "audience": state["store_id"], "decision": "allow" if decision.allowed else "deny",
                     "reason": decision.reason, "rule_ids": list(decision.rule_ids),
                     "nonce": secrets.token_hex(32), "issued_at": now, "expires_at": now + 30}, self.key)

    def authorize(self, action, actor):
        with self.store.transaction() as db:
            return self._authorize(db, action, actor)

    def execute(self, action, actor, certificate):
        # Freeze an external mutable envelope before checking or using it.
        certificate = loads(canonical(certificate))
        with self.store.transaction() as db:
            return self.resource.execute(db, action, actor, certificate)

    def act(self, action, actor):
        with self.store.transaction() as db:
            certificate = self._authorize(db, action, actor)
            if certificate["payload"]["decision"] != "allow":
                return {"action": action.to_dict(), "authorization": certificate}
            return self.resource.execute(db, action, actor, certificate)
