# What is actually proved and executed

`proof/AgentGuard.lean` defines the semantic query, grant/scope checks, authorization predicate and label transition. `proof/Main.lean` compiles these same definitions into `proof/.lake/build/bin/guard-kernel`, which the live gate invokes for every decision. This is not a separate unused reference theorem.

Lean 4.33.1 checks the following statements:

| Theorem | Scope |
|---|---|
| `evaluator_correct`, `evaluator_sound`, `evaluator_complete` | Executable allow is equivalent to the declarative `SpecAllowed` relation: identity, budget, denials, rooted authority, delegation/revocation and send-label acceptance |
| `ordinary_authority_has_witness` | Every accepted non-revocation action has a rooted, live, attenuated grant witness |
| `delegation_cannot_cover_denied_resource` | A delegation whose child scope covers an explicitly denied resource is rejected |
| `forbidden_flow_denied` | A send whose destination does not accept an active label is denied |
| `labels_monotone` | Existing active labels survive the transition |
| `read_inherits` | An accepted read adds the source object's labels |
| `chain_witness_sound` | A checked chain starts at an actual policy root, all grants are live, and all delegation edges satisfy attenuation |
| `delegation_attenuates` | Every accepted child has strictly less delegation depth and no later expiry |
| `delegation_scope_contained` | Every resource covered by a child scope is covered by its parent scope |
| `revoked_grant_invalidates_chain` | Revoking any member makes that witness invalid |
| `history_preserves_labels` | Labels persist over every finite valid trace, independent of its length |
| `no_forbidden_send_over_history` | Every send in a valid trace accepts any label active at the trace's start |
| `protected_read_prevents_later_leak` | An accepted read forces every later send in a valid continuation to accept every source label |

`protected_read_prevents_later_leak` composes `read_inherits` with the history theorem to establish the modeled read-then-send restriction over arbitrarily long accepted workflows. `nextLabels` sorts and removes duplicates inside the Lean definition itself; Python no longer repairs the Lean output. Repeated reads therefore produce the same concrete label list used by the trace relation. `edges_sound` and `chain_has_authority_root` are supporting lemmas.

There are no unfinished proofs, `sorry`, `admit`, or project-defined axioms in the kernel. `proof/Check.lean` prints theorem dependencies. They use Lean's standard foundations (`propext`, `Classical.choice`, `Quot.sound`); none depends on `sorryAx`. These are machine-checked mathematical proofs, not only test assertions.

## The runtime bridge

Python validates typed Action/Policy/State and constructs a normalized query with candidate grant-chain witnesses. OPA evaluates the fixed Rego policy over that query. The compiled Lean evaluator independently checks the witnesses and computes allow plus next labels. The Python reference computes the same pair. The gate requires identical results and rejects engine errors or malformed results.

Thus a false OPA allow cannot alone cause execution: it must also pass the compiled semantic checker. This avoids pretending that differential tests constitute a formal proof of the entire Rego implementation. Actual differential tests still run across normal and adversarial inputs, including overlapping delegation denials, delegated grants, all two-label source/destination combinations and repeated-read workflows. The wrapper requires exact agreement, including sorted unique labels; malformed or noncanonical engine output fails closed.

The formal `SpecAllowed` is stated using declarative field equalities, inequalities, membership, scope coverage, rooted grant paths and explicit delegation/revocation cases. It does not define authorization as `common q = true` or `authority q = true`. Correspondence lemmas connect each executable predicate to those rules, and `evaluator_correct` proves both directions. `ScopeCovers` uses equality and the declarative prefix relation on character lists; the executable list-prefix check is proved equivalent, and scope containment is proved for every resource; resource names remain opaque identifiers. The proofs do not establish a mechanized correspondence between every Python schema/adapter/storage operation and the model, or a legal semantics.

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

From the repository root, `python -m pytest tests/test_v2.py -q` first rebuilds the proof artifact, checks theorem dependencies, and exercises the actual OPA and compiled Lean binaries. Engine absence is a failure, not a skipped test. The generated event's verifier manifest includes hashes that auditors can pin; rebuilding on a different platform may change binary hashes and requires independently approved trust material for that build.

Primary references: [Lean toolchains and build tools](https://lean-lang.org/doc/reference/latest/Build-Tools-and-Distribution/) describe the proof/compiler toolchain; [OPA's CLI](https://www.openpolicyagent.org/docs/cli) and [built-in error handling](https://www.openpolicyagent.org/docs/policy-language) document the runtime evaluation interface and strict error behavior used here.
