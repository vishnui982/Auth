import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import sys
import threading

import pytest

from agent_guard import Action
from agent_guard.canonical import loads
from agent_guard.client import request
from agent_guard.cli import initialize
from agent_guard.receipt import verify_bundle
from agent_guard.server import make_server


@pytest.fixture
def http_gateway(setup):
    g, token, trust = setup
    server = make_server(g, {hashlib.sha256(token.encode()).hexdigest(): "agent1"}, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield g, token, trust, f"http://127.0.0.1:{server.server_port}", server.server_port
    server.shutdown()
    server.server_close()
    thread.join()


def body():
    return {"action": Action("agent1", "read", "document:public/welcome").to_dict()}


def test_http_authenticated_action_and_separate_resource_check(http_gateway):
    g, token, trust, url, _ = http_gateway
    status, authorization = request(url, token, body(), "authorize")
    assert status == 200 and g.store.export() == []
    status, bundle = request(url, token, authorization, "execute")
    assert status == 200
    verify_bundle(bundle, **trust)
    assert request(url, token, authorization, "execute")[0] == 403


def test_http_forged_identity_and_missing_auth(http_gateway):
    g, token, _, url, _ = http_gateway
    assert request(url, "wrong", body())[0] == 401
    spoof = body()
    spoof["action"]["actor"] = "admin"
    status, value = request(url, token, spoof)
    assert status == 403
    assert value["authorization"]["payload"]["reason"] == "actor_mismatch"
    assert g.store.export() == []


def test_http_missing_proof_and_unknown_tool(http_gateway):
    g, token, _, url, _ = http_gateway
    assert request(url, token, {**body(), "authorization": {}}, "execute")[0] == 400
    unsupported = body()
    unsupported["action"]["operation"] = "execute"
    assert request(url, token, unsupported)[0] == 403
    assert g.store.export() == []


@pytest.mark.parametrize("raw,headers", [
    (b'{"action":{},"action":{}}', {}), (b'{"a":NaN}', {}),
    (json.dumps(body()).encode(), {"Origin": "https://untrusted.example"}),
    (json.dumps(body()).encode(), {"Content-Type": "text/plain"}),
    (b"{}", {"Transfer-Encoding": "chunked"}),
])
def test_http_malformed_inputs_fail_closed(http_gateway, raw, headers):
    g, token, _, _, port = http_gateway
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", "/v1/act", raw,
                 {"Authorization": "Bearer " + token, "Content-Type": "application/json", **headers})
    response = conn.getresponse()
    assert response.status in {400, 415}
    response.read()
    conn.close()
    assert g.store.export() == []


def test_http_internal_error_returns_no_success(http_gateway, monkeypatch):
    g, token, _, url, _ = http_gateway
    def fail(*_):
        raise OSError("simulated disk error")
    monkeypatch.setattr(g.store, "record", fail)
    status, value = request(url, token, body())
    assert status == 503 and value == {"error": "gateway_unavailable"}
    assert g.store.export() == []


def test_cli_demo_and_separate_verifier_process(tmp_path):
    output = tmp_path / "demo"
    run = subprocess.run([sys.executable, "-m", "agent_guard", "demo", "--output", str(output)],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert run.stdout.count("PASS") == 6
    verify = subprocess.run([sys.executable, "-m", "agent_guard", "verify", str(output / "history.json"),
                             "--trust", str(output / "trust.json"), "--head",
                             loads((output / "checkpoint.json").read_bytes())["head"]],
                            capture_output=True, text=True)
    assert verify.returncode == 0, verify.stderr
    bundle = loads((output / "read-receipt.json").read_bytes())
    bundle["result"]["content"] = "tampered"
    (output / "tampered.json").write_text(json.dumps(bundle))
    bad = subprocess.run([sys.executable, "-m", "agent_guard", "verify", str(output / "tampered.json"),
                          "--trust", str(output / "trust.json")], capture_output=True, text=True)
    assert bad.returncode == 1


def test_private_state_permissions_and_no_overwrite(tmp_path):
    path = tmp_path / "private"
    initialize(path)
    assert path.stat().st_mode & 0o777 == 0o700
    for name in ["signing-key.pem", "agent1.token", "identities.json", "store.sqlite"]:
        assert (path / name).stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        initialize(path)
