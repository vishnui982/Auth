"""Three-way runtime agreement. Engine failure is never interpreted as allow."""
import hashlib
from pathlib import Path
import subprocess

from agent_guard.canonical import canonical, digest, loads
from agent_guard.errors import GuardError
from .semantics import evaluate


class Engines:
    def __init__(self, opa, lean, rego=None):
        self.opa, self.lean = Path(opa).resolve(), Path(lean).resolve()
        self.rego = Path(rego or Path(__file__).with_name("agent.rego")).resolve()
        self.files = {"opa": self.opa, "lean": self.lean, "rego": self.rego}
        self.pins = {name: self.file_hash(path) for name, path in self.files.items()}

    @staticmethod
    def file_hash(path):
        h = hashlib.sha256()
        with path.open("rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()

    def manifest(self):
        root = Path(__file__).parent
        sources = {p.name: self.file_hash(p) for p in sorted(root.glob("*.py"))}
        for p in sorted(root.parent.glob("*.py")):
            sources["shared/" + p.name] = self.file_hash(p)
        proof = self.lean.parents[3]
        proof_sources = {name: self.file_hash(proof / name)
                         for name in ("AgentGuard.lean", "Main.lean", "lean-toolchain")
                         if (proof / name).is_file()}
        return {"protocol": 2, "engines": self.pins, "sources": sources, "proof_sources": proof_sources}

    def _run(self, command, data):
        try:
            r = subprocess.run(command, input=canonical(data) + b"\n", capture_output=True,
                               timeout=15, check=True)
            return loads(r.stdout)
        except (OSError, subprocess.SubprocessError, GuardError) as exc:
            raise GuardError("verification_engine_unavailable", 503) from exc

    def decide(self, q):
        # Correctness-first: rehash the actual executable and rules before every
        # check, rather than continuing after an on-disk replacement.
        try:
            if any(self.file_hash(path) != self.pins[name] for name, path in self.files.items()):
                raise GuardError("verification_engine_changed", 503)
        except OSError as exc:
            raise GuardError("verification_engine_unavailable", 503) from exc
        reference = evaluate(q)
        opa = self._run([str(self.opa), "eval", "--stdin-input", "--strict-builtin-errors",
                         "--format=json", "--data", str(self.rego), "data.agent_guard.v2.decision"], q)
        lean = self._run([str(self.lean)], q)
        try:
            opa = opa["result"][0]["expressions"][0]["value"]
            for result in (opa, lean):
                if type(result) is not dict or set(result) != {"allow", "nextLabels"}:
                    raise ValueError()
                if type(result["allow"]) is not bool or type(result["nextLabels"]) is not list:
                    raise ValueError()
                if not all(type(x) is str for x in result["nextLabels"]):
                    raise ValueError()
                if result["nextLabels"] != sorted(set(result["nextLabels"])):
                    raise ValueError()
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise GuardError("invalid_engine_result", 503) from exc
        if reference != opa or reference != lean:
            raise GuardError("verification_engine_disagreement", 503)
        return reference
