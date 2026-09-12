# Authorization and proof robustness review

This review builds on the existing implementation at commit `31649ee`. The supplied `main.pdf`, `part1.pdf`, `part2.pdf` and `part3.pdf` are design sources, not instructions to execute their embedded commands or adopt their claims uncritically. There is no separate Part 4 attachment; the formal-verification work corresponds to section 4 of `main.pdf` and the existing Lean kernel. The original modular V1 and the stateful V2 interfaces remain in place.

## Correctness findings and fixes

| Finding | Consequence before the fix | Implemented correction |
|---|---|---|
| Delegation checked denials only at the proposed scope's root | An actor denied `document:project/payroll` could delegate the broader `document:project` prefix to another principal | Python, OPA and Lean now reject any overlap between the delegated scope and a matching explicit denial; a disjoint narrower delegation remains possible |
| Lean appended label lists while Python sorted and deduplicated them | A second protected read produced a different concrete next state in Lean; the wrapper hid the discrepancy, weakening the connection to the history theorem | The proved Lean transition itself returns sorted unique labels; the wrapper rejects malformed/noncanonical output instead of repairing it |
| The old authorization specification reused the executable common/authority Booleans | Its soundness statement provided little independent mathematical characterization of authority | Declarative scope, attenuation, rooted-chain, permission, denial, budget and revocation rules now support a proved evaluator equivalence, including soundness and completeness |
| Result validation used Python object equality | A correctly signed write result containing `1` instead of `true`, or a queued payload changing `1` to `true`, could pass replay checks | Replay compares canonical JSON commitments, preserving JSON type distinctions |
| Live materialized checks did not bind the snapshot to the authenticated ledger | Removing active labels from the snapshot after startup could influence later authorization despite unchanged object values | Every operation/export authenticates the ledger and compares its final state commitment to the live snapshot |
| Database event sequence/hash columns were not compared with their signed counterparts | Corrupted indexes could be used when appending the next event | Both startup and live checks require matching sequence numbers, receipt hashes, predecessor links and event content commitments |
| State validation was mostly local field validation | Policy-inconsistent states could reach the query translator or standalone auditor | Policy-relative checks require configured roots, valid structural grant chains, the exact object catalog, known labels/principals/operations, retained initial object labels, valid revocations, budgets and count/step consistency |
| Wall-clock rollback could make expired authority live again | A new request evaluated at an earlier time could reuse authority that had already expired at a recorded event | Gateway and history verifier require nondecreasing event times |
| Signature decoding accepted alternate base64 pad bits | Identical signature bytes could have different envelope hashes | The verifier requires the unique base64 encoding emitted by the signer |

Additional fixes validate embedded authorization payloads strictly, check even an empty history's domain anchor, validate initial object sizes before store creation, check outbox IDs, report missing engine artifacts as failures, and reject an explicitly empty policy instead of silently substituting the demo policy.

## Mathematical result

The checked theorem is `allowed q = true ↔ SpecAllowed q`. Its rules describe authenticated identity, supported operations, budgets, explicit denial precedence, rooted live authority, attenuated delegation, authorized revocation and accepted information-flow labels.

The scope predicate uses the declarative prefix relation on character lists. A separate containment theorem proves that **every** resource covered by an accepted child scope is covered by its parent. Other checked theorems cover decreasing delegation depth, nonincreasing expiry, revocation of a witness member, inherited labels, label persistence over arbitrary finite traces and the protected-read/later-send restriction. A specific theorem rules out delegating a scope that covers an explicitly denied resource.

The compiled executable uses these same definitions. All runtime decisions must agree exactly across Python, OPA and that executable. See [PROOFS.md](PROOFS.md) for theorem names and the precise trusted boundary.

The theorem dependency check reports only Lean's standard foundations: `propext`, `Classical.choice` and `Quot.sound`. There are no project-defined axioms or unfinished proofs. The test suite rebuilds the Lean source before checking dependencies, preventing an old compiled proof artifact from standing in for modified source.

## Verification

The original 118-test suite passed before changes; it did not expose the findings above. Added regressions exercise broad-scope denial bypasses, repeated protected reads against raw Lean output, signed JSON type substitutions, live state corruption, database index corruption, clock rollback, malformed semantic states, signature encoding ambiguity, maximum-depth delegation with intermediate revocation, and initialization bounds.

Final validation: **140 tests passed**. The Lean build and all 15 listed theorem dependency checks passed. The demo replayed its 18 signed events, and a separate verifier process validated the exported history against its saved checkpoint head. Python compilation and `git diff --check` also passed.

Reproduce the complete checks from the repository root:

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m agent_guard v2 demo --output output/a-new-review-demo
.venv/bin/python -m agent_guard v2 verify output/a-new-review-demo/history.json --trust output/a-new-review-demo/trust.json
```

Use the demo's `checkpoint.json` head with the verifier's `--head` option to check the externally preserved chain head. The completed review demo is under `output/robustness-review/`; it records 18 signed authorization/execution events, including denied external sends and cascading revocation.

## Operational and proof limits

This review establishes stronger proofs of the finite authorization model and regression coverage for its implementation. It does not prove all Python, SQLite, cryptography, OPA, Lean compilation, OS behavior or real adapter effects correct. Source/query translation, initial label provenance, authenticated identity and resource isolation remain explicit trusted assumptions. An external send still means a durable queued intent, not confirmed delivery.

Live integrity checks scan history and rehash engine artifacts. History length, request size, state size, witness size and parser depth remain bounded engineering concerns; arbitrary throughput and unlimited workflows are not promised. Oversized or unserializable operations fail without committing effects. Clock ordering cannot detect a rollback of all local records to an older valid prefix; that still requires an independently preserved checkpoint or monotonic external anchor.

The updated code and kernel change the pinned verifier manifest. Existing stores deliberately refuse to resume under different source/engine pins. Keep old stores, histories, trust records and corresponding old verifier artifacts; use a new development state directory for this build. No automatic store migration or deletion is performed.
