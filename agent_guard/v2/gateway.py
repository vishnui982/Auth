"""A serializable, fail-closed stateful resource gate. All effects are local transactions."""
from contextlib import contextmanager
from pathlib import Path
import secrets
import sqlite3
import time

from agent_guard.canonical import canonical, digest, loads
from agent_guard.crypto import public_pem, sign, verify
from agent_guard.errors import GuardError
from .audit import PAYLOAD, require, verify_history
from .model import Action, AuthorizationState, initial_state, natural
from .semantics import query, transition


class Gateway:
    @classmethod
    def create(cls, path, policy, key, engines, values, clock=time.time):
        path = Path(path)
        state = initial_state(policy, secrets.token_hex(16), values)
        with path.open("xb"):
            pass
        path.chmod(0o600)
        with sqlite3.connect(path) as db:
            db.executescript("""
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE objects (resource TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE events (sequence INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, bundle TEXT NOT NULL);
                CREATE TABLE issued (nonce TEXT PRIMARY KEY, certificate TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE outbox (id TEXT PRIMARY KEY, intent TEXT NOT NULL);
            """)
            trust = {"version": 2, "policy": policy.to_dict(), "manifest": engines.manifest(),
                     "public_key": public_pem(key.public_key()).decode(), "genesis": state.to_dict()}
            db.executemany("INSERT INTO meta VALUES (?,?)", [("state", canonical(state.to_dict()).decode()),
                                                               ("trust", canonical(trust).decode())])
            db.executemany("INSERT INTO objects VALUES (?,?)", [(r, canonical(v).decode()) for r, v in values.items()])
        return cls(path, policy, key, engines, clock=clock, trust=trust)

    def __init__(self, path, policy, key, engines, clock=time.time, *, trust):
        self.path, self.policy, self.key = Path(path).resolve(), policy, key
        self.engines, self.clock = engines, clock
        self.manifest = engines.manifest()
        self.verifier_hash = digest(self.manifest)
        with self.transaction() as db:
            self.trust = loads(canonical(trust))
            stored_trust = loads(db.execute("SELECT value FROM meta WHERE key='trust'").fetchone()[0])
            require(stored_trust == self.trust, "stored_trust_mismatch")
            require(self.trust["policy"] == policy.to_dict() and self.trust["manifest"] == self.manifest and
                    self.trust["public_key"] == public_pem(key.public_key()).decode(), "store_configuration_mismatch")
            self.genesis = AuthorizationState(self.trust["genesis"])
            self.domain = self.genesis.to_dict()["domain"]
            # Replay all authenticated transitions at startup. Do not trust an
            # unverified materialized snapshot after a crash or disk corruption.
            events = [loads(r[0]) for r in db.execute("SELECT bundle FROM events ORDER BY sequence")]
            verified = verify_history(events, genesis=self.genesis, **self.verification_args())
            require(verified["state_hash"] == self.state(db).hash, "stored_state_mismatch")
            self._check_materialized(db)

    def verification_args(self):
        return dict(key=self.key.public_key(), policy=self.policy, verifier_hash=self.verifier_hash,
                    domain=self.domain, engines=self.engines)

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=30)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def state(self, db):
        return AuthorizationState(loads(db.execute("SELECT value FROM meta WHERE key='state'").fetchone()[0]))

    def _check_materialized(self, db):
        s = self.state(db).to_dict()
        stored_trust = loads(db.execute("SELECT value FROM meta WHERE key='trust'").fetchone()[0])
        require(digest(stored_trust) == digest(self.trust), "stored_trust_mismatch")
        objects = {r: digest(loads(v)) for r, v in db.execute("SELECT resource,value FROM objects")}
        require(objects == {r: x["value_hash"] for r, x in s["objects"].items()}, "resource_state_mismatch")
        outbox_hash = digest([])
        for rid, raw in db.execute("SELECT id,intent FROM outbox ORDER BY rowid"):
            intent = loads(raw)
            require(rid == intent["id"], "outbox_id_mismatch")
            outbox_hash = digest({"previous": outbox_hash, "intent": intent})
        require(outbox_hash == s["outbox_hash"], "outbox_state_mismatch")
        rows = {n: (loads(c), used) for n, c, used in db.execute("SELECT nonce,certificate,consumed FROM issued")}
        expected = {}
        previous, state_hash, last_time = None, self.genesis.hash, 0
        for i, (sequence, event_hash, raw) in enumerate(
                db.execute("SELECT sequence,hash,bundle FROM events ORDER BY sequence"), 1):
            b = loads(raw)
            p = verify(b["receipt"], self.key.public_key())
            require(sequence == p["sequence"] == i and event_hash == digest(b["receipt"]) and
                    p["previous"] == previous, "stored_history_mismatch")
            require(p["before_hash"] == state_hash == digest(b["before"]) and
                    p["after_hash"] == digest(b["after"]) and
                    p["action_hash"] == digest(b["action"]) and
                    p["result_hash"] == digest(b["result"]), "stored_event_binding_mismatch")
            require(p["time"] >= last_time, "nonmonotonic_history_time")
            if p["kind"] == "authorization":
                require(p["nonce"] not in expected, "duplicate_nonce")
                expected[p["nonce"]] = (b["receipt"], 0)
            else:
                require(p["kind"] == "execution" and
                        expected.get(p["nonce"]) == (b["authorization"], 0) and
                        p["authorization_hash"] == digest(b["authorization"]), "nonce_state_mismatch")
                expected[p["nonce"]] = (b["authorization"], 1)
            previous, state_hash, last_time = event_hash, p["after_hash"], p["time"]
        require(state_hash == digest(s), "stored_state_mismatch")
        require(rows == expected, "nonce_state_mismatch")

    def _now(self, db):
        now = int(self.clock())
        natural(now, 2**53 - 31)
        last = db.execute("SELECT bundle FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        require(last is None or now >= loads(last[0])["receipt"]["payload"]["time"], "clock_moved_backwards")
        return now

    def _record(self, db, action, actor, before, after, result, q, decision, nonce, expires, authorization=None):
        last = db.execute("SELECT sequence,hash FROM events ORDER BY sequence DESC LIMIT 1").fetchone()
        kind = "execution" if authorization else "authorization"
        status = ("queued" if q["effect"] == "send" else "executed") if authorization else (
            "authorized" if decision["allow"] else "denied")
        p = {"version": 2, "kind": kind, "sequence": last[0] + 1 if last else 1,
             "previous": last[1] if last else None, "policy_hash": self.policy.hash,
             "verifier_hash": self.verifier_hash, "domain": self.domain, "actor": actor,
             "action_hash": action.hash, "before_hash": before.hash, "after_hash": after.hash,
             "decision": "allow" if decision["allow"] else "deny", "query_hash": digest(q),
             "time": q["now"], "expires": expires, "nonce": nonce,
             "authorization_hash": digest(authorization) if authorization else None,
             "status": status, "result_hash": digest(result)}
        receipt = sign(p, self.key)
        bundle = {"action": action.to_dict(), "before": before.to_dict(), "after": after.to_dict(),
                  "result": result, "receipt": receipt, "authorization": authorization}
        db.execute("INSERT INTO events VALUES (?,?,?)", (p["sequence"], digest(receipt), canonical(bundle).decode()))
        return bundle

    def _authorize(self, db, action, actor):
        state = self.state(db)
        q = query(self.policy, state, action, actor, self._now(db))
        decision = self.engines.decide(q)
        bundle = self._record(db, action, actor, state, state, None, q, decision,
                              secrets.token_hex(32), q["now"] + 30)
        db.execute("INSERT INTO issued(nonce,certificate) VALUES (?,?)",
                   (bundle["receipt"]["payload"]["nonce"], canonical(bundle["receipt"]).decode()))
        return bundle

    def _execute(self, db, action, actor, certificate):
        from agent_guard.canonical import fields
        p = verify(certificate, self.key.public_key())
        fields(p, PAYLOAD)
        before = self.state(db)
        now = self._now(db)
        require(p["kind"] == "authorization" and p["decision"] == "allow" and p["version"] == 2, "invalid_authorization")
        require(p["actor"] == actor == action.to_dict()["actor"] and p["action_hash"] == action.hash, "action_or_actor_mismatch")
        require(p["domain"] == self.domain and p["policy_hash"] == self.policy.hash and
                p["verifier_hash"] == self.verifier_hash, "trust_mismatch")
        require(p["before_hash"] == before.hash and p["after_hash"] == before.hash, "stale_state")
        require(type(p["time"]) is int and type(p["expires"]) is int and
                p["time"] <= now < p["expires"] == p["time"] + 30, "expired_authorization")
        row = db.execute("SELECT certificate,consumed FROM issued WHERE nonce=?", (p["nonce"],)).fetchone()
        require(row is not None and row[1] == 0 and loads(row[0]) == certificate, "unissued_or_replayed_authorization")
        q = query(self.policy, before, action, actor, now)
        decision = self.engines.decide(q)
        require(decision["allow"], "authorization_no_longer_valid")
        a, s = action.to_dict(), before.to_dict()
        effect = q["effect"]
        if effect == "read":
            result = {"value": loads(db.execute("SELECT value FROM objects WHERE resource=?", (a["resource"],)).fetchone()[0])}
        elif effect == "write":
            db.execute("UPDATE objects SET value=? WHERE resource=?", (canonical(a["parameters"]["value"]).decode(), a["resource"]))
            result = {"written": True}
        elif effect == "send":
            item = {"id": digest({"domain": self.domain, "step": s["step"] + 1, "action": a}),
                    "actor": actor, "resource": a["resource"], "payload": a["parameters"]["payload"], "labels": s["active_labels"]}
            db.execute("INSERT INTO outbox VALUES (?,?)", (item["id"], canonical(item).decode()))
            result = {"status": "queued", "intent": item}
        elif effect == "delegate":
            result = {"delegated": q["child"]["id"]}
        elif effect == "revoke":
            result = {"revoked": q["target"]["id"]}
        else:
            raise GuardError("unsupported_effect")
        after = transition(self.policy, before, action, actor, now, result)
        require(after.to_dict()["active_labels"] == decision["nextLabels"], "transition_engine_disagreement")
        db.execute("UPDATE meta SET value=? WHERE key='state'", (canonical(after.to_dict()).decode(),))
        db.execute("UPDATE issued SET consumed=1 WHERE nonce=?", (p["nonce"],))
        return self._record(db, action, actor, before, after, result, q, decision, p["nonce"], p["expires"], certificate)

    def authorize(self, action, actor):
        with self.transaction() as db:
            self._check_materialized(db)
            return self._authorize(db, action, actor)

    def execute(self, action, actor, certificate):
        certificate = loads(canonical(certificate))
        with self.transaction() as db:
            self._check_materialized(db)
            return self._execute(db, action, actor, certificate)

    def act(self, action, actor):
        with self.transaction() as db:
            self._check_materialized(db)
            authorization = self._authorize(db, action, actor)
            if authorization["receipt"]["payload"]["decision"] == "deny":
                return authorization
            return self._execute(db, action, actor, authorization["receipt"])

    def export(self):
        with self.transaction() as db:
            self._check_materialized(db)
            return [loads(row[0]) for row in db.execute("SELECT bundle FROM events ORDER BY sequence")]
