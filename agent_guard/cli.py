import argparse
import hashlib
import json
from pathlib import Path
import secrets
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .action import Action
from .canonical import fields, loads
from .crypto import private_pem, public_pem
from .errors import GuardError
from .gateway import Gateway
from .policy import Policy
from .receipt import require, verify_bundle, verify_chain
from .store import DocumentStore

DEFAULT_POLICY = {"version": 1, "rules": [
    {"id": "read-welcome", "effect": "allow", "actor": "agent1", "operation": "read", "resource": "document:public/welcome"},
    {"id": "read-draft", "effect": "allow", "actor": "agent1", "operation": "read", "resource": "document:drafts/note"},
    {"id": "write-draft", "effect": "allow", "actor": "agent1", "operation": "write", "resource": "document:drafts/note"},
    {"id": "protect-payroll", "effect": "deny", "actor": "agent1", "operation": "read", "resource": "document:secret/payroll"},
]}


def read_json(path, *, max_bytes=131072):
    with Path(path).open("rb") as source:
        return loads(source.read(max_bytes + 1), max_bytes=max_bytes)


def write_file(path, data, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as out:
        out.write(data if isinstance(data, bytes) else data.encode())


def write_json(path, value, private=False):
    write_file(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n", private)


def initialize(path, policy_data=None):
    path = Path(path)
    policy = Policy(DEFAULT_POLICY if policy_data is None else policy_data)
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    key = Ed25519PrivateKey.generate()
    token = secrets.token_urlsafe(32)
    write_file(path / "signing-key.pem", private_pem(key), True)
    write_file(path / "agent1.token", token + "\n", True)
    write_json(path / "identities.json", {hashlib.sha256(token.encode()).hexdigest(): "agent1"}, True)
    write_json(path / "policy.json", policy.to_dict(), True)
    store = DocumentStore.initialize(path / "store.sqlite", {
        "document:public/welcome": "Welcome to Agent Guard.",
        "document:drafts/note": "An empty draft.",
        "document:secret/payroll": "Synthetic protected data. No real personal information.",
    })
    gateway = Gateway(store, policy, key)
    with store.transaction() as db:
        audience = store.state(db)["store_id"]
    trust = {"version": 1, "public_key": public_pem(key.public_key()).decode(),
             "policy": policy.to_dict(), "verifier_hash": gateway.source_hash, "audience": audience}
    write_json(path / "trust.json", trust)
    return gateway, token, trust


def load_gateway(path):
    path = Path(path)
    key = serialization.load_pem_private_key((path / "signing-key.pem").read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise GuardError("invalid_signing_key")
    return Gateway(DocumentStore(path / "store.sqlite"), Policy(read_json(path / "policy.json")), key)


def trust_arguments(value):
    fields(value, {"version", "public_key", "policy", "verifier_hash", "audience"})
    require(type(value["version"]) is int and value["version"] == 1, "unsupported_trust_version")
    key = serialization.load_pem_public_key(value["public_key"].encode())
    require(isinstance(key, Ed25519PublicKey), "invalid_public_key")
    return {"key": key, "policy": Policy(value["policy"]),
            "expected_verifier": value["verifier_hash"], "audience": value["audience"]}


def demo(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="agent-guard-") as temp:
        gateway, _, trust = initialize(Path(temp) / "state")
        read = Action("agent1", "read", "document:public/welcome")
        bundle = gateway.act(read, "agent1")
        verify_bundle(bundle, **trust_arguments(trust))
        write_json(output / "read-receipt.json", bundle)
        write_json(output / "trust.json", trust)
        print("PASS allowed read; signed receipt independently verified")
        denied = gateway.act(Action("agent1", "read", "document:secret/payroll"), "agent1")
        require(denied["authorization"]["payload"]["decision"] == "deny", "demo_failed")
        write_json(output / "denied.json", denied)
        print("PASS protected read denied")
        write = Action("agent1", "write", "document:drafts/note", {"content": "Approved draft."})
        certificate = gateway.authorize(write, "agent1")
        changed = Action("agent1", "write", "document:drafts/note", {"content": "Substituted payload."})
        for label, action, actor, cert in [
            ("changed payload", changed, "agent1", certificate),
            ("forged identity", write, "agent2", certificate),
            ("replayed receipt", read, "agent1", bundle["authorization"]),
        ]:
            try:
                gateway.execute(action, actor, cert)
            except GuardError:
                print(f"PASS {label} rejected")
            else:
                raise GuardError("demo_failed")
        gateway.execute(write, "agent1", certificate)
        history = gateway.store.export()
        head = verify_chain(history, **trust_arguments(trust))
        write_json(output / "history.json", history)
        write_json(output / "checkpoint.json", {"head": head, "count": len(history)})
        print("PASS authorized write and complete receipt chain verified")
        print(f"Evidence: {output.resolve()}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Agent Guard: policy-bound actions with verifiable receipts")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="create a fresh private demo store and credentials")
    init.add_argument("--state", default="runtime")
    init.add_argument("--policy")
    serve = commands.add_parser("serve", help="run the development gateway")
    serve.add_argument("--state", default="runtime")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    req = commands.add_parser("request", help="submit an action from an agent process")
    req.add_argument("--url", default="http://127.0.0.1:8765")
    req.add_argument("--token-file", required=True)
    req.add_argument("--action", required=True)
    req.add_argument("--output", required=True)
    check = commands.add_parser("verify", help="verify a receipt or full history against trusted pins")
    check.add_argument("file")
    check.add_argument("--trust", required=True)
    check.add_argument("--head", help="out-of-band checkpoint; requires a complete history array")
    export = commands.add_parser("export", help="administrator-only local history export")
    export.add_argument("--state", default="runtime")
    export.add_argument("--output", required=True)
    demo_parser = commands.add_parser("demo", help="run a self-contained adversarial demo")
    demo_parser.add_argument("--output", default="output/demo")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            initialize(args.state, read_json(args.policy) if args.policy else None)
            print(f"Initialized {args.state}. Keep state and signing key private; distribute trust.json separately.")
        elif args.command == "serve":
            from .server import make_server
            server = make_server(load_gateway(args.state), read_json(Path(args.state) / "identities.json"),
                                 args.host, args.port)
            print(f"Development gateway on http://{args.host}:{server.server_port}", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
        elif args.command == "request":
            from .client import request
            status, value = request(args.url, Path(args.token_file).read_text().strip(),
                                    {"action": read_json(args.action)})
            write_json(args.output, value, True)
            print(f"HTTP {status}; response saved to {args.output}")
            return 0 if status == 200 else 1
        elif args.command == "verify":
            # Local history files have a separate 32 MiB bound. Signature inputs
            # and network messages retain the smaller protocol bound.
            value = read_json(args.file, max_bytes=32 * 1024 * 1024)
            trust = trust_arguments(read_json(args.trust))
            if type(value) is list:
                head = verify_chain(value, expected_head=args.head, **trust)
                print(f"VALID: {len(value)} executions; head={head}")
            else:
                require(args.head is None, "head_requires_history")
                verify_bundle(value, **trust)
                print("VALID: signature, policy decision, request, state and result bindings")
        elif args.command == "export":
            write_json(args.output, DocumentStore(Path(args.state) / "store.sqlite").export(), True)
            print(f"Exported execution history to {args.output}")
        elif args.command == "demo":
            demo(args.output)
        return 0
    except (GuardError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
