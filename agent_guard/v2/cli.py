import argparse
import hashlib
from pathlib import Path
import secrets
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from agent_guard.canonical import digest, fields
from agent_guard.cli import read_json, write_file, write_json
from agent_guard.crypto import private_pem
from agent_guard.errors import GuardError
from .audit import require, verify_event, verify_history
from .engines import Engines
from .example import VALUES, example_policy
from .gateway import Gateway
from .model import Action, AuthorizationState, Policy


def initialize(directory, engines, policy_data=None, values=None):
    directory = Path(directory)
    policy = Policy(policy_data or example_policy())
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    key = Ed25519PrivateKey.generate()
    write_file(directory / "signing-key.pem", private_pem(key), True)
    identities = {}
    for actor in policy.to_dict()["principals"]:
        token = secrets.token_urlsafe(32)
        write_file(directory / (actor + ".token"), token + "\n", True)
        identities[hashlib.sha256(token.encode()).hexdigest()] = actor
    write_json(directory / "identities.json", identities, True)
    write_json(directory / "policy.json", policy.to_dict(), True)
    gateway = Gateway.create(directory / "store.sqlite", policy, key, engines, VALUES if values is None else values)
    write_json(directory / "trust.json", gateway.trust)
    return gateway


def load(directory, engines):
    directory = Path(directory)
    key = serialization.load_pem_private_key((directory / "signing-key.pem").read_bytes(), None)
    require(isinstance(key, Ed25519PrivateKey), "invalid_key_type")
    return Gateway(directory / "store.sqlite", Policy(read_json(directory / "policy.json")), key, engines,
                   trust=read_json(directory / "trust.json"))


def verification_args(trust, engines):
    fields(trust, {"version", "policy", "manifest", "public_key", "genesis"})
    require(type(trust["version"]) is int and trust["version"] == 2, "invalid_trust_version")
    key = serialization.load_pem_public_key(trust["public_key"].encode())
    require(isinstance(key, Ed25519PublicKey), "invalid_key_type")
    # Auditors need the pinned engine implementations. The manifest also records
    # gateway sources, but an auditor does not execute a remote gateway's code.
    require(trust["manifest"]["engines"] == engines.pins, "engine_trust_mismatch")
    genesis = AuthorizationState(trust["genesis"])
    return dict(key=key, policy=Policy(trust["policy"]), verifier_hash=digest(trust["manifest"]),
                domain=genesis.to_dict()["domain"], engines=engines)


def demo(output, engines):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="agent-guard-v2-") as tmp:
        g = initialize(Path(tmp) / "state", engines)
        actions = [
            ("public-send", Action("agent1", "message.send", "sink:external", {"payload": "Public message"}), True),
            ("private-read", Action("agent1", "data.read", "document:project/payroll"), True),
            ("derived-output", Action("agent1", "data.write", "document:project/summary", {"value": "Derived summary"}), True),
            ("blocked-leak", Action("agent1", "message.send", "sink:external", {"payload": "Derived summary"}), False),
            ("blocked-identity-laundering", Action("agent2", "message.send", "sink:external", {"payload": "Derived summary"}), False),
            ("internal-send", Action("agent1", "message.send", "sink:internal", {"payload": "Derived summary"}), True),
        ]
        for label, action, allowed in actions:
            event = g.act(action, action.to_dict()["actor"])
            require((event["receipt"]["payload"]["decision"] == "allow") == allowed, "demo_failed")
            write_json(output / (label + ".json"), event)
            print(f"PASS {label}: {event['receipt']['payload']['status']}", flush=True)
        grant = {"id": "child-read", "issuer": "agent1", "subject": "agent2", "operation": "data.read",
                 "resource": "document:project/public", "prefix": False, "remaining": 0,
                 "expires": 4102444800, "parent": "read-project"}
        delegated = g.act(Action("agent1", "authority.delegate", grant["resource"], {"grant": grant}), "agent1")
        require(delegated["receipt"]["payload"]["status"] == "executed", "demo_failed")
        child_read = Action("agent2", "data.read", grant["resource"])
        g.act(child_read, "agent2")
        stale = g.authorize(child_read, "agent2")
        g.act(Action("owner", "authority.revoke", "authority:grants", {"grant_id": "read-project"}), "owner")
        try:
            g.execute(child_read, "agent2", stale["receipt"])
        except GuardError:
            print("PASS revocation invalidates outstanding certificates", flush=True)
        else:
            raise GuardError("demo_failed")
        require(g.act(child_read, "agent2")["receipt"]["payload"]["decision"] == "deny", "demo_failed")
        print("PASS root revocation invalidates delegated descendants", flush=True)
        history = g.export()
        verified = verify_history(history, genesis=g.genesis, **g.verification_args())
        write_json(output / "history.json", history)
        write_json(output / "trust.json", g.trust)
        write_json(output / "checkpoint.json", verified)
        print(f"PASS OPA + Lean + reference agree; {verified['events']} signed events replayed", flush=True)
        print(f"Evidence: {output.resolve()}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Stateful Agent Guard with OPA and a checked Lean evaluator")
    parser.add_argument("--opa", default="tools/bin/opa")
    parser.add_argument("--lean", default="proof/.lake/build/bin/guard-kernel")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--state", default="runtime-v2")
    init.add_argument("--policy")
    init.add_argument("--values")
    serve = sub.add_parser("serve")
    serve.add_argument("--state", default="runtime-v2")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8766)
    request = sub.add_parser("request")
    request.add_argument("--url", default="http://127.0.0.1:8766")
    request.add_argument("--token-file", required=True)
    request.add_argument("--action", required=True)
    request.add_argument("--output", required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("file")
    verify_parser.add_argument("--trust", required=True)
    verify_parser.add_argument("--head")
    export = sub.add_parser("export")
    export.add_argument("--state", default="runtime-v2")
    export.add_argument("--output", required=True)
    demo_parser = sub.add_parser("demo")
    demo_parser.add_argument("--output", default="output/parts23")
    args = parser.parse_args(argv)
    try:
        if args.command == "request":
            from agent_guard.client import request as send
            status, result = send(args.url, Path(args.token_file).read_text().strip(),
                                  {"action": read_json(args.action)}, api_version="v2")
            write_json(args.output, result, True)
            print(f"HTTP {status}; {args.output}")
            return 0 if status == 200 else 1
        engines = Engines(args.opa, args.lean)
        if args.command == "init":
            initialize(args.state, engines, read_json(args.policy) if args.policy else None,
                       read_json(args.values) if args.values else None)
            print(f"Created private state in {args.state}")
        elif args.command == "serve":
            from agent_guard.server import make_server
            server = make_server(load(args.state, engines), read_json(Path(args.state) / "identities.json"),
                                 args.host, args.port, action_type=Action, api_version="v2", receipt_key="receipt")
            print(f"Development gateway on http://{args.host}:{server.server_port}", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
        elif args.command == "verify":
            trust = read_json(args.trust)
            data = read_json(args.file, max_bytes=128 * 1024 * 1024)
            kwargs = verification_args(trust, engines)
            if type(data) is list:
                print(verify_history(data, genesis=AuthorizationState(trust["genesis"]), expected_head=args.head, **kwargs))
            else:
                require(args.head is None, "head_requires_full_history")
                verify_event(data, **kwargs)
                print("VALID event: signatures, three evaluators, and state transition")
        elif args.command == "export":
            write_json(args.output, load(args.state, engines).export(), True)
        elif args.command == "demo":
            demo(args.output, engines)
        return 0
    except (GuardError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
