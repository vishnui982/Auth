# What is actually proved and executed

`proof/AgentGuard.lean` defines the semantic query, grant/scope checks, authorization predicate and label transition. `proof/Main.lean` compiles these same definitions into `proof/.lake/build/bin/guard-kernel`, which the live gate invokes for every decision. This is not a separate unused reference theorem.

Lean 4.33.1 checks the following statements:

| Theorem | Scope |
|---|---|
| `evaluator_sound` | An executable allow result satisfies `SpecAllowed`, including label acceptance for a send |
| `forbidden_flow_denied` | A send whose destination does not accept an active label is denied |
| `labels_monotone` | Existing active labels survive the transition |
| `read_inherits` | An accepted read adds the source object's labels |
| `chain_witness_sound` | A checked chain starts at an actual policy root, all grants are live, and all delegation edges satisfy attenuation |
| `delegation_attenuates` | Every accepted child has strictly less delegation depth and no later expiry |
| `revoked_grant_invalidates_chain` | Revoking any member makes that witness invalid |
| `history_preserves_labels` | Labels persist over every finite valid trace, independent of its length |
| `no_forbidden_send_over_history` | Every send in a valid trace accepts any label active at the trace's start |

Applying `read_inherits` at a protected read and the history theorem to the remaining trace establishes the modeled read-then-send restriction over arbitrarily long accepted workflows. `edges_sound` and `chain_has_authority_root` are supporting lemmas.

There are no unfinished proofs, `sorry`, `admit`, or project-defined axioms in the kernel. `proof/Check.lean` prints theorem dependencies. They use Lean's standard foundations (`propext`, `Classical.choice`, `Quot.sound`); none depends on `sorryAx`. These are machine-checked mathematical proofs, not only test assertions.

## The runtime bridge

Python validates typed Action/Policy/State and constructs a normalized query with candidate grant-chain witnesses. OPA evaluates the fixed Rego policy over that query. The compiled Lean evaluator independently checks the witnesses and computes allow plus next labels. The Python reference computes the same pair. The gate requires identical results and rejects engine errors or malformed results.

Thus a false OPA allow cannot alone cause execution: it must also pass the compiled semantic checker. This avoids pretending that differential tests constitute a formal proof of the entire Rego implementation. Actual differential tests still run across normal and adversarial inputs, including delegated grants, all two-label source/destination combinations and workflow cases.

The formal `SpecAllowed` includes the Boolean common/authority predicates and a propositional information-flow condition. The separate grant-path theorems establish structural properties of the executable authority witnesses. The proofs do not claim a mechanized correspondence between every Python schema/adapter/storage operation and a complete independently defined legal semantics.

## Boundaries that remain trusted

- Python's translation from authenticated input and current state to the semantic query.
- Correct resource/effect registration, initial label provenance and the definition of the protection domain.
- The relationship between the mathematical model and real tool behavior.
- Lean compilation and runtime execution, process loading, OPA, cryptography, storage, clock and OS behavior.
- Python's full state-transition and audit implementation. It is replayed and adversarially tested; the Lean history theorem specifically covers the label-state model and accepted semantic queries.

There is no claim that a compiler has been formally verified, that Python is memory-safe by theorem, that Rego and Lean are formally equivalent for every input, or that the host agent is sandboxed. The manifest and bootstrap bind checked sources and runtime artifacts under the administrator's build process; they are not a hardware attestation.

## Reproduce the checks

```sh
python3 tools/bootstrap.py
cd proof
../tools/bin/lake build
../tools/bin/lake env lean Check.lean
```

From the repository root, `python -m pytest tests/test_v2.py -q` exercises the actual OPA and compiled Lean binaries. Engine absence is a failure, not a skipped test. The generated event's verifier manifest includes hashes that auditors can pin; rebuilding on a different platform may change binary hashes and requires independently approved trust material for that build.

Primary references: [Lean toolchains and build tools](https://lean-lang.org/doc/reference/latest/Build-Tools-and-Distribution/) describe the proof/compiler toolchain; [OPA's CLI](https://www.openpolicyagent.org/docs/cli) and [built-in error handling](https://www.openpolicyagent.org/docs/policy-language) document the runtime evaluation interface and strict error behavior used here.
