<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Contributing

Thanks for your interest. This repository is an **independent, exploratory technical study** (not an official EU or standards-body deliverable — see the notices in the `README` and the specification). Contributions that sharpen the design, the conformance artefacts, or the documentation are welcome.

## Inbound = outbound

Contributions are accepted on an **inbound = outbound** basis: whatever license applies to a file is the license under which your contribution to that file is made.

- **Specification text and documentation** (the umbrella, the Internet-Draft, the TS-shaped binding, `docs/`, and the Markdown files) — **CC BY 4.0**.
- **Reference code and machine-readable artefacts** (`scripts/`, `tests/`, `schemas/`, `samples/`, `edd-resolver-openapi.yaml`, build/CI files) — **MIT**.

The canonical texts are in [`LICENSES/`](LICENSES/); the mapping is in [`LICENSE`](LICENSE).

## Patent commitment (what counts as a Contribution)

By making a **Contribution**, you agree that your Essential Patent Claims are subject to the project's **Royalty-Free (RAND-Z)** patent commitment in [`IPR.md`](IPR.md).

A **Contribution** is, deliberately narrowly:

> material that you **intentionally submit for inclusion** in the Specification or its companion artefacts **and** that is **actually incorporated** into them.

Consequently, a **bare issue, comment, review remark, or discussion post that is not incorporated is *not* a Contribution** and triggers **no** patent obligation. You can open issues and discuss freely without granting a patent license; the RAND-Z commitment attaches only when material you offered for inclusion is actually merged. This mirrors the definitions in [`IPR.md`](IPR.md) §2 and §5.

**Disclosing patents.** If you become aware of a patent or application you believe may be essential to a mandatory (MUST/SHALL/REQUIRED) part of the Specification — your own or a third party's — please disclose it via the *IPR disclosure* issue template or a row in [`IPR-DISCLOSURES.md`](IPR-DISCLOSURES.md). Late disclosures are welcome and do not remove a Contributor's own RAND-Z obligation ([`IPR.md`](IPR.md) §5).

By opening a pull request you represent that you have the right to contribute the material and to license it on these terms.

## How to contribute

1. **Open an issue first** for anything non-trivial, so the direction can be agreed before you invest effort.
2. **Keep changes in sync.** This repo maintains a hard invariant: spec set ↔ schemas ↔ samples ↔ mock ↔ linters ↔ tests ↔ CI. A change to a normative rule must update the schema/sample/lint/test that enforce it, with a negative test for each new rule.
3. **Set up, and run the checks** before submitting. **Use Python 3.11 for the full developer toolchain (the CI runtime); newer runtimes (e.g. 3.13) are not currently supported for dev-tools such as `reuse`.** The one-shot gate is `make conformance`; step by step:
   ```bash
   python3 -m venv .venv && . .venv/bin/activate
   pip install -r scripts/requirements.txt   # canonical test/conformance env
   make dev-tools                            # dev/CI tooling: reuse, pip-licenses
   cargo install cddl --version 0.9.5 --locked   # the CDDL gate is fail-closed without it
   make test        # dependency preflight + full pytest suite
   make schema      # sample schema-validation
   make lint        # evidence_lint + discovery_lint + bundle_lint (0 violations)
   make lint-demo   # the linters with demo-key seal verification
   make cddl-check  # CBOR/CDDL non-divergence gate — FAILS if the `cddl` tool is absent
   make versions    # version-matrix consistency vs versions.json
   make lint-catalogue # normative lint catalogue vs the reference tools
   make adr-index   # architecture decision records well-formed; decisions index current
   make id          # Internet-Draft structure check
   make reuse       # REUSE / SPDX compliance
   make doc-lint    # prose regression guard (part of the bar)
   make conformance # THE bar: versions + lint-catalogue + rule-ownership + adr-index + preflight + test +
                    #   schema-smoke + lint + lint-demo + cddl-check + openapi-validate + doc-lint + reuse
   make conformance-lite # the same gates, but tolerates a missing `cddl` tool — for contributors
                    #   without a Rust toolchain; NOT the release bar, and CI runs the full one
   ```
   **Changing a `LINT-*` rule?** The rule set is defined normatively in
   `docs/lint-catalogue.json` (rendered to `docs/lint-catalogue.md` — do not edit
   the Markdown by hand). Adding, removing or altering a rule in the reference
   linters REQUIRES updating that catalogue and a naming test in the same change:
   `make lint-catalogue` fails closed if a rule is emitted without a catalogue
   entry, and `tests/test_lint_catalogue.py` pins the exact set of rules still
   lacking a dedicated test (`coverage_gap`).
4. **License every new file.** Add an `SPDX-FileCopyrightText` and an `SPDX-License-Identifier` (inline where the format allows, otherwise via `REUSE.toml`) — `MIT` for code/machine-readable artefacts, `CC-BY-4.0` for documentation. `make reuse` must stay green. Do **not** hand-edit the sealed files under `samples/` (regenerate them with `python scripts/regen_samples.py`).
5. **Naming and drafting rules.** Never use the deprecated short-form name for Regulation (EU) No 910/2014; write "Regulation (EU) No 910/2014" or "the EUDI Regulation". Use RFC 2119 keywords in the Internet-Draft and ETSI modal verbs (SHALL, not MUST) in the TS-shaped binding. No normative requirement may be duplicated across the three specification documents: each rule family has one owning document, recorded in `docs/rule-ownership.md` (source `docs/rule-ownership.json`), and other documents may carry only informative summaries that reference the owner. `make rule-ownership` fails if a non-owner document restates an owned rule normatively, or if the Internet-Draft's deployment-defined-interface count disagrees with the interfaces it lists.

## Review invariants (earned, not theoretical)

Every deep design review of this study has found the same classes of defect
wearing different hats. The thirteen rules below are what those reviews earned;
each names the question to ask and, where one exists, the gate that asks it
mechanically. They apply to a change before it is submitted, and a reviewer
will apply them to it afterwards.

1. **A test that calls the same helper as the producer is not independent
   evidence.** Where a test asserts bytes, derive them from the specification,
   not from the code under test — `tests/test_mls_wire_kat.py` carries its own
   RFC 9420 reader for exactly this reason.
2. **A helper only its own test calls is not integrated.** After adding a
   helper, show a caller on a published path that passes the argument that
   makes the helper do its work. `docs/normative-helpers.json` lists the helpers
   that carry a normative obligation and `tests/test_helper_integration.py`
   fails when one has no such caller.
3. **When a fix supersedes a check, delete the superseded check.** An unused
   wrong path is one refactor away from being used again. After replacing a
   source of truth, grep every remaining reference to it and prove each
   survivor intentional, in a comment where the survivor lives.
4. **A fix that routes around a defect leaves the defect in place**, and a fix
   that lands in one of two paths leaves the other wrong. After fixing a rule,
   find every implementation of it and delete all but one; before claiming a
   capability, run the published path — not the helper — and assert on what
   that path produced.
5. **A fix is complete when the property holds, not when the reproduction
   fails.** After making a reproduction fail, enumerate the other members of
   its class — the other inputs to the same verdict, the other fields of the
   same tuple, the other callers of the same rule — and state for each whether
   it is covered. That is why `docs/required-properties.json` is a table the
   verifier iterates rather than a set of scattered call sites.
6. **A declared authority with no path to it is still a defect.** A schema
   that governs no value space, a record nobody produces, a signature over a
   transition nobody observed: the test to write is not "does the check exist"
   but *can I reach the accepting state without the server having observed
   anything?* Fail closed on an unrecognised declaration — a configuration the
   code cannot evaluate must stop the verification, never be treated as
   inapplicable.
7. **A value re-derived at a boundary is a second source of truth**, however
   faithfully the copy is then checked. Ask whether the value is carried by
   reference from the one place that owns it, or reconstructed here; where a
   parameter exists only to carry a value the server already holds, delete the
   parameter. Write the inventory of restatements before fixing the first one,
   and treat a delegation ("another rule establishes this") as a claim about a
   run, confirmed by which property that rule recorded.
8. **A value the public contract requires must be obtainable from the public
   contract**, by the component the contract obliges to use it. If the only way
   to obtain a value is to read the reference implementation, the contract is
   incomplete however rigorously the reference validates it. Name what travels
   on the wire — an inline schema is one nothing can reference; a gate that
   measures part of a surface reports on part of a surface; an absence is
   tolerable only when it carries its reason in a place a gate reads; and
   anything restated by hand drifts, so derive from the single source or add a
   check that the two agree.
9. **Verify where the value enters, and make the unverified form unusable.**
   Every path by which a value reaches a consumer must pass through its check
   first; the robust answer is structural — verify once, at ingress, and hand
   consumers a type only the verifier can produce (`authenticate_register`
   returns an `AuthenticatedRegister`, and nothing else is accepted). A check
   that runs after the act it governs is a report, not a gate; where the
   specification says *refuse*, the test asserts that nothing moved.
10. **A scoped value is never an identifier on its own — carry the scope,
    compare the whole.** A label unique within an entity, a member, a provider
    or a registry revision is half of an identifier; the other half comes from
    the same authenticated context as the label, never from a request field.
    Test the collisions the scopes permit, read a retained value with the
    dictionary it was written in, and name the event an instant dates.
11. **Build the world the way a participant would — a shortcut is where the
    composition's defect hides.** Of a composition test ask not *is the final
    state right* but *would a participant holding only the published contract
    have reached it this way?* Every input obtained through a published
    operation, no private ledger written, no party acting under another's
    credential, no step omitted because the state it produces could be set up
    directly. An identity that crosses a boundary crosses with its proof; an
    act is accepted for what it is about, not only for who made it; a
    historical decision is recomputed from all of its own inputs, or reported
    INCOMPLETE.
12. **An option no party can advertise and no party can refuse is not
    optional.** A sender's per-message choice that no discovery document
    advertises and no reason code can decline is every receiver's obligation,
    and a receiver that cannot meet it can only speak falsely or fall silent.
    Either close the set and make every member mandatory to implement, or
    advertise it and define the refusal; adding a hash mode reopens agenda
    question A11 for exactly this reason.

13. **A probe builds its world; it does not copy ours.** A test that copies
    this repository into a temporary directory and drives a rule against it
    asserts two things at once — that the rule works, and that the tree still
    says what it said the day the test was written. Only the first is the
    test's subject, and the second is what breaks: a fixture that wrote the
    current evidence version into its own README went stale at the next bump,
    and two probes that copied the live README could not run in this snapshot
    at all, where four tests failed on a correct tree. Build the smallest world
    the rule is about; where a test must read the real tree, assert a property
    and not a wording, and derive a generated value rather than spelling it.
    This is rule 11 turned toward the fixtures.

Two rules run through all thirteen: a fixture with one of everything cannot find
a defect that needs two, and a test that asserts a sentence exists is not a
test of the behaviour the sentence describes — where normative text requires a
value to be pinned, recorded or published, the test must find that value in the
artefact.

## Provenance (DCO — required)

Every commit **MUST** carry a `Signed-off-by` line (`git commit -s`) asserting the Developer Certificate of Origin (<https://developercertificate.org>) — a lightweight statement that you wrote, or have the right to submit, the contribution. CI enforces this: the **`dco`** job fails a pull request whose commits are not all signed off.

## Questions

See **Feedback** in the [`README`](README.md#feedback): technical feedback by issue, using the *Technical feedback* template; the maintainer is named there. For patent disclosures or clarification on the RAND-Z scope, see [`IPR.md`](IPR.md) — that route is separate from ordinary feedback.
