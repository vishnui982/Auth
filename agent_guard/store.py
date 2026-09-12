"""Private SQLite resource adapter. No arbitrary file, shell, or network tool."""

from contextlib import contextmanager
from pathlib import Path
import sqlite3
import uuid

from .canonical import canonical, digest, loads
from .errors import GuardError


class DocumentStore:
    def __init__(self, path):
        self.path = Path(path).resolve()

    @classmethod
    def initialize(cls, path, documents):
        path = Path(path)
        # Exclusive creation prevents accidentally overwriting an existing store.
        with path.open("xb"):
            pass
        path.chmod(0o600)
        with sqlite3.connect(path) as db:
            db.executescript("""
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE documents (resource TEXT PRIMARY KEY, content TEXT NOT NULL);
                CREATE TABLE executions (
                    sequence INTEGER PRIMARY KEY, nonce TEXT NOT NULL UNIQUE,
                    receipt_hash TEXT NOT NULL UNIQUE, bundle TEXT NOT NULL
                );
            """)
            db.executemany("INSERT INTO meta VALUES (?, ?)",
                           [("store_id", str(uuid.uuid4())), ("revision", "0")])
            db.executemany("INSERT INTO documents VALUES (?, ?)", documents.items())
        return cls(path)

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                             isolation_level=None, timeout=5)
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
        metadata = dict(db.execute("SELECT key, value FROM meta"))
        rows = db.execute("SELECT resource, content FROM documents ORDER BY resource").fetchall()
        return {"version": 1, "store_id": metadata["store_id"],
                "revision": int(metadata["revision"]),
                "documents_hash": digest([[r, digest(c)] for r, c in rows])}

    def apply(self, db, action):
        row = db.execute("SELECT content FROM documents WHERE resource = ?", (action.resource,)).fetchone()
        if row is None:
            raise GuardError("resource_not_found", 404)
        if action.operation == "read":
            return {"content": row[0]}
        if action.operation == "write":
            db.execute("UPDATE documents SET content = ? WHERE resource = ?",
                       (action.parameters["content"], action.resource))
            return {"written": True}
        raise GuardError("unsupported_operation")

    def export(self):
        with self.transaction() as db:
            return [loads(row[0]) for row in db.execute("SELECT bundle FROM executions ORDER BY sequence")]

    def record(self, db, nonce, bundle):
        p = bundle["receipt"]["payload"]
        db.execute("INSERT INTO executions VALUES (?, ?, ?, ?)",
                   (p["sequence"], nonce, digest(bundle["receipt"]), canonical(bundle).decode()))
