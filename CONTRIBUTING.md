<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Contributing

Thanks for your interest. This repository is an **independent, exploratory technical study** (not an official EU or standards-body deliverable — see the banners in the `README` and the specification). Contributions that sharpen the design, the conformance artefacts, or the documentation are welcome.

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
3. **Run the checks** before submitting. **Use Python 3.11 for the full developer toolchain (the CI runtime); newer runtimes (e.g. 3.13) are not currently supported for dev-tools such as `reuse`.** The one-shot gate is `make conformance`; step by step:
   ```bash
   pip install -r scripts/requirements.txt   # canonical test/conformance env
   make dev-tools                            # dev/CI tooling: reuse, pip-licenses
   make test        # dependency preflight + full pytest suite
   make schema      # sample schema-validation
   make lint        # evidence_lint + discovery_lint + bundle_lint (0 violations)
   make lint-demo   # the linters with demo-key seal verification
   make cddl-check  # CBOR/CDDL non-divergence gate — FAILS if the `cddl` tool is absent
                    #   (CI installs it: `cargo install cddl --version 0.9.5 --locked`)
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

Each deep design review has found the same class of defect wearing a
different hat. These rules live here, and not only in a batch plan that gets
archived, because a rule kept in a spent document is a rule that recurs.

**1. A test that calls the same helper as the producer is not independent
evidence.** An early GroupContext serializer emitted a double length prefix;
the producer, the fixtures and the tests shared it, agreed perfectly, and were
wrong together. Where a test asserts bytes, derive them from the specification
— `tests/test_mls_wire_kat.py` carries its own RFC 9420 reader and does not
import `scripts/mls_wire.py`.

**2. A helper only its own test calls is not integrated.** `as_of_resolve()`
was correct and passed its own tests for two rounds while no production path
called it. After adding a helper, show a caller. One review found five of these
at once, so the rule is now MECHANICAL: `docs/normative-helpers.json` lists
the helpers that carry a normative obligation and
`tests/test_helper_integration.py` fails when one has no caller outside its
own test — including when a caller exists but omits the argument that makes
the helper do its work (`check_certificate_binds_key` was being called without
`at=`, which is the whole check).

**3. When a fix supersedes a check, DELETE the superseded check.** One fix
added the act-time resolver *beside* the current-status map instead of
replacing it, and four rules kept deciding attribution from today's roster —
one of them under a comment saying the old behaviour was gone. An unused wrong
path is one refactor away from being used again. After replacing a source of
truth, grep every remaining reference to it and prove each survivor
intentional, in a comment where the survivor lives.

**4. A fix that ROUTES AROUND a defect leaves the defect in place and adds a
second code path.** The sharpest case: the same is true of a fix
that lands in ONE of two paths. A receipt-payload comparison went into
the retained verifier and not the live one, so the two disagreed about what a
receipt proves — and the live one was the path in production use. After fixing
a rule, find every implementation of it and delete all but one. Five found at once: a resolver whose result was discarded for
a symmetric recomputation; a validity check called without the instant to
check against; a decoder that lived inside a test; a helper with no caller; a
transaction that returned a dict *called* a sealed evidence object. Each was
correct in itself and reached nothing. Before claiming a capability, run the
PUBLISHED path — not the helper — and assert on what that path produced.

**5. A fix is complete when the PROPERTY holds, not when the reproduction
fails.** One review's whole family. After making a reproduction fail, enumerate
the other members of its class — the other inputs to the same verdict, the
other fields of the same tuple, the other callers of the same rule — and state
for each whether it is covered. A `[GAP]`/`[FAIL]` verdict added for one
required property must list every required property it governs; that is why
`docs/required-properties.json` is a table the code ITERATES rather than a set
of scattered call sites. One fix guarded an absent policy history and left an
absent GroupContext unguarded, in the same manifest, with the same machinery.
Another fixed `[]` for a truncated chain and left `[v1]`. A third corrected a
false `valid_until` sentence in the umbrella and left the identical sentence in
the code that implements it.

**6. A DECLARED AUTHORITY WITH NO PATH TO IT is still a defect.** One
review's whole family. A schema that governs no value space; a record required by the
endpoint that consumes it and rejected by the one that should produce it; a
signature over a state transition nobody observed; a registry whose entries the
code consults through a second, hidden map. Each artefact was correct and each
had nothing reaching it. The test to write is not "does the check exist" but
**"can I reach the accepting state without the server having observed
anything?"**

*Corollary.* **Fail closed on an unrecognised declaration.** A configuration
the code cannot evaluate must stop the verification, never be treated as
inapplicable. The first required-properties table returned "does not apply"
for any id its hard-coded map did not know, so an injected property was skipped
in silence and the output was byte-identical — the registry's own claim that
adding a property "fails closed until it is wired" was false.

**7. A VALUE RE-DERIVED AT A BOUNDARY IS A SECOND SOURCE OF TRUTH**, however
faithfully it is then checked. One review's family, and five of its six findings
are the same move: one authority, copied into a second form at the boundary,
and the copy is what runs. The published request contract, projected to two of
its keywords. The accepted byte commitment, recomputed at queue time from
caller input. The invitation record, re-declared as a function signature with a
different required set. `RdpId`, restated as a local pattern at three
boundaries. The required-property registry, overridden by two branches keyed on
its own output identifiers.

Every one of those **has** a check, and every check runs faithfully — against
the copy. So the question is not *is there a check* but **is the value carried
by reference from the one place that owns it, or reconstructed here?** A fix
that answers with a comparison has not closed it; a fix that answers with a
reference has. Where a parameter exists only to carry a value the server
already holds, **delete the parameter**: a request that cannot express a
different binding cannot install one, and there is then no second comparison to
keep in step with the first.

*Corollary.* **Write the inventory before the fix.** The identity
inventory found six restatements where the review named three, and its
acceptance-vector gate found three earlier criteria resting on source
inspection plus one of that review's own. Fixing the named instances first would
have left every one of those in place and looking closed — which is invariant 5
arriving through a different door.

*Corollary.* **A delegation is a claim about a run, so confirm it against the
run.** A row saying "another rule establishes this" replaced a hard-coded
`continue` that could not be wrong because it asserted nothing. Name the owner,
then check that the owner actually said something; where it did not, report the
gap. The same applies to a structural test standing in for a behavioural one:
it may stand only when it names the behavioural check that would fail on the
defect.

> *Sharpened later.* "The owner said something" was still too weak: the
> emitted-rule set is GLOBAL, so a row could delegate to a common rule and be
> established by an unrelated occurrence of it. A delegate must record WHICH
> property it established, keyed by that property's id. Coincidence can produce
> a rule identifier; it cannot produce a property-specific result.

**8. A VALUE THE PUBLIC CONTRACT REQUIRES MUST BE OBTAINABLE FROM THE PUBLIC
CONTRACT.** The next review's family, and the other side of invariant 7's coin. Seven
asks whether a value is carried by reference from the place that owns it; eight
asks one level out — **can a party holding only the published contract obtain
that value at all?**

A required request field produced by no published response. A state transition
that only a private helper performs. A credential binding enforced in the
reference and named by no published scheme. A successful response the
reference's own Schema rejects. Each was checked carefully, and none of them
could be reached by an implementer who had only the contract. If the only way
to obtain a value is to read the reference implementation, the contract is
incomplete however rigorously the reference validates it.

> *Sharpened later.* Obtainable **by the component the contract
> obliges to use it.** One remediation published `group_info_commitment` and assigned
> its check to the invited device, whose only input — the Welcome queue item —
> did not carry it; the contract's own description said the field "previously
> claimed a binding no component could check". The next review then found the DE
> issuer obliged to verify a receipt the Delivery Service returns only to the
> acknowledging device (open). A value can be published and still be
> out of reach of the one party that must use it: trace it to that party's
> inputs.

*Corollary.* **An inline schema is one nothing can reference, and therefore
nothing validates against.** Four of one review's response and request bodies were
inline; all four were wrong, and none of the wrongness was detectable until they
were named. Name what travels on the wire.

*Corollary.* **A gate that measures part of a surface reports on part of a
surface.** The contract fingerprint compared operations and security
alternatives and nothing else, so three breaking SCHEMA changes passed it in
silence and each version bump was manual. When a gate exists to stop a class of
drift, check what it does not look at.

*Corollary.* **An absence is tolerable only when it carries its reason.** A
published operation with no reference behind it, a property nobody can
establish, a residual — each may stand, and each must say why in a place a gate
reads. The gate then fails when the explanation is removed, which is what makes
it an explanation rather than an exemption.

*Corollary.* **The gates prove existence and shape, not sufficiency.**
Call-graph reachability shows a helper is called; a surface fingerprint shows
an operation exists. Neither shows that the caller supplied the evidence the
normative property needs. Where a property depends on retained material,
declare the material and iterate the declaration.

*Corollary.* **A gate that asserts *at least one* caller measures existence,
not coverage.** An early integration test did `assert hits` — some production
caller passes the act time. One correct call site satisfied it for ever, and
two incorrect ones sat behind it for a whole round, including the very call
site the finding had named. Assert over **every** site; name each exemption
individually, keyed by code rather than by line number.

*Corollary.* **A classification is a claim, and a stored claim goes stale.**
The first helper registry recorded each helper's integration status; two
entries still described the state on the day its review began, after that
review's own batches had changed it. Derive the classification — in both directions — and
keep in the file only what no analysis can infer: the obligation, the arguments
that do the work, and the exemptions a human signed for. Where a derivation
must approximate, choose the direction that **fails closed**.

*Corollary.* **A test that asserts a sentence exists is not a test of the
behaviour the sentence describes.** Where normative text requires a value to be
pinned, recorded or published, the test must find that value in the artefact.

*Corollary.* **Anything restated by hand drifts.** Version constants, field
lists, rule predicates, summary tables — each has been found stale at least
once. Derive from the single source; if you must restate, add a check that the
two agree.

**9. VERIFY WHERE THE VALUE ENTERS, AND MAKE THE UNVERIFIED FORM UNUSABLE.**
One review's family. None of its trust-boundary findings was a missing check. The
federation register's seal was verified — by a fixture helper; the loader every
consumer used checked shape only. The common seal check ran for every discovery
type except one. The expiry rules were implemented — two of them in linters
that run after the submission is sealed, the third nowhere. The RFC 3339 parser
was used — beside a string comparison deciding which instant it would parse.
Each check was correct, and each ran somewhere other than the boundary where
the value is consumed or the act takes place.

So the question is not *does a correct check exist* but **does every path by
which the value reaches a consumer pass through it first?** The robust answer
is structural: verify once, at ingress, and hand consumers a type only the
verifier can produce. `authenticate_register` returns an
`AuthenticatedRegister`, and `check_register_pin` refuses anything else, so the
step cannot be skipped by reaching past it.

*Corollary.* **A check that runs after the act it governs is a report, not a
gate.** Intake sealed all five expiry violations and moved three ledgers; the
linters then reported them, correctly. Where the specification says *refuse*,
the test asserts that nothing moved.

*Corollary.* **A closure criterion must drive the consumer, not the
instrument.** Batch A's criterion asked whether a wrongly sealed record fails
the fixture's verifier, and it did. The question was whether the verifier that
CONSUMES the register refuses it, and it did not. A second verifier that
passes is evidence about itself.

*Corollary.* **A fixture with one of everything cannot find a defect that
needs two.** Fan-out was tested with two devices of one member; a bilateral
group holds members of both entities, and the first two-member recipient lost
a message — which member, decided by the lexical order of their MIDs. Test the
topology the protocol defines, not the smallest one that runs.

**10. A SCOPED VALUE IS NEVER AN IDENTIFIER ON ITS OWN — CARRY THE SCOPE,
COMPARE THE WHOLE.** The next review's family. A MID is unique within its entity, a
device label within its member, a `message_id` within its originating provider,
a confirmation within one member's act, a cipher-suite code point within its
registry revision, a receipt's `server_time` within the grade whose event it
dates, a membership status within the question it answers. Each of those
values was used outside its scope: the Delivery Service compared bare labels,
and signed a receipt attributing a FR device's acknowledgement to a DE member;
confirmations were keyed on a bare message, so a second member's valid act
was a conflict; a retained group's code point was decoded through today's map;
every grade was dated by S2; a register answered "status at t" with a record
that contradicted its own assertion.

The question to ask of any key, comparison or lookup is not *is the value
right* but **within what is it unique, and is that part of the comparison?**
A label that is unique only within a scope is half of an identifier; the
other half is the scope, and it comes from the same authenticated context as
the label, never from a request field.

*Corollary.* **A fixture with globally distinct labels cannot find a defect
that needs two equal ones.** Every earlier fixture used unique MIDs and
device labels, one confirmation per message and one originating provider —
the one arrangement in which a missing scope is invisible. The previous
corollary said a fixture with one of everything cannot find a defect that
needs two; this is its other half. Test the collisions the scopes permit:
the same MID in two entities, the same label under two members, the same
`message_id` from two providers, two revisions of one registry.

*Corollary.* **A retained value is read with the dictionary it was written
in.** A code point, a policy version, a status — decoded later with today's
table, each can mean something it never meant, or nothing. Retain the
dictionary with the value, and when it was not retained, say so as
INCOMPLETE rather than guess.

*Corollary.* **An instant is a claim about an event; name the event.** The S2
receipt's time was correct and was copied into a field that, at two of three
grades, dates a different event.

**11. BUILD THE WORLD THE WAY A PARTICIPANT WOULD — A SHORTCUT IS WHERE THE
COMPOSITION'S DEFECT HIDES.** The most recent review's family. Every finding lived in a step
the previous closure fixture skipped on its way to the state it wanted. It
invited every device, the creator's included, so a creator whom MLS never
Welcomes was never missing from the routing. Each origin submitted
directly to one Delivery Service under its own identity, so the forwarding
through RDP(in) — where the origin's namespace was lost — never ran.
S3 objects were delivered without their content being challenged, so nothing
asked which message a validly signed confirmation was about. The
suite decision was verified against the members supplied that day.
The fixture reached the right end states, by paths no participant can take.

So ask of a composition test not *is the final state right* but **would a
participant holding only the published contract have reached it this way?**
Every input obtained through a published operation; no private ledger written;
no party acting under another's credential; no step — a Welcome, a relay hop, a
challenge — omitted because the state it produces could be set up directly.
The next fixture was built that way, and found one defect more on its first
run: a member who had refused a message could not reveal on it.

*Corollary.* **An identity that crosses a boundary crosses with its proof.**
RDP(in)'s credential proves RDP(in); the originating namespace needs the
originator's own sealed statement. Neither the hop's credential nor an
unchecked field stands in for the party whose namespace it is.

*Corollary.* **Accept an act for what it is about, not only for who made it.**
Authenticating a confirmation's signer says nothing about which message it
confirms. Bind the act to its subject by the rule the retained verifier will
apply, before it is stored or counted — invariant 9, applied to content.

*Corollary.* **A historical decision is recomputed from all of its own
inputs, or not at all.** One remediation retained the registry revision and read the
capabilities live; one input retained and one read today is a decision taken
today. Bind the inputs in the decision, and when they were not retained, say
INCOMPLETE.

## Provenance (DCO — required)

Every commit **MUST** carry a `Signed-off-by` line (`git commit -s`) asserting the Developer Certificate of Origin (<https://developercertificate.org>) — a lightweight statement that you wrote, or have the right to submit, the contribution. CI enforces this: the **`dco`** job fails a pull request whose commits are not all signed off.

## Questions

See **Feedback** in the [`README`](README.md#feedback): technical feedback by issue, using the *Technical feedback* template; the maintainer is named there. For patent disclosures or clarification on the RAND-Z scope, see [`IPR.md`](IPR.md) — that route is separate from ordinary feedback.
