<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Secure Business Messaging — a design study

**Secure Business Messaging is a design exercise.** It starts from an explicit
set of requirements — a message between two organisations that carries the legal
effect of registered delivery, across borders and across providers, while its
content stays end-to-end encrypted — and works out what a system satisfying them
would have to look like. What is in this repository is the result of taking that
seriously: a specification set, a reference implementation, and the machinery
that checks the two against each other.

The purpose is to bring the architectural and technical problems into focus,
including the ones that turn out to have no settled answer. Where a question is
open, this repository names it rather than choosing quietly, and the choices it
does make are written down with what they cost.

> **⚠️ Exploratory design study — not an official proposal.** An independent
> technical exploration of how existing EU building blocks — Regulation (EU) No
> 910/2014 as amended by Regulation (EU) 2024/1183, qualified electronic
> registered delivery, IETF MLS and the EUDI Wallet — *could* be composed into a
> secure business-messaging profile. It is **not** an official proposal,
> deliverable, or position of the European Commission, any Member State, or any
> standards body, and it confers no status; it is shared to invite technical
> discussion.

> **Status:** draft, exploratory. Not a Commission position. Not a
> standards-track document. Interoperability between independent
> implementations, and qualification of any operating provider, are **not**
> demonstrated here — see [*What a green bar means*](#what-a-green-bar-means--and-what-it-does-not).

**Reading this for the first time?** The six sections below go from the problem
to the open questions, each one making the previous more precise. If you are
reviewing the specification rather than meeting it, the
[reviewer guide](docs/REVIEWER_GUIDE.md) is the shorter route: one short path
and a branch per specialism. If you want the idea in twenty minutes, the
[executive brief](brief/executive-brief.md) is written for policy readers, and
the [requirements list](brief/requirements.md) is the baseline the study
started from, each requirement with its source. What this design does **not**
prove on its own is collected in [`OPEN-ITEMS.md`](OPEN-ITEMS.md).

---

## 1. The problem, and what the exercise leaves out

Registered delivery is what makes a message opposable: a qualified provider
attests that it was sent, that it reached an identified recipient, and when.
Traditionally that attestation rests on a provider that handles the content,
which is why registered delivery and end-to-end encryption have been treated as
alternatives — you could have the evidence or the confidentiality, not both.

The load-bearing proposition of this exercise is that they are not alternatives.
**Evidence can rest on cryptographic digests of the content and of the group
state rather than on the content itself**, so a provider can attest what it
observed without ever being able to read what it carried. That proposition is
concrete, it is executable, and it is untested in law.

The second problem the exercise takes on is that an opposable message between
two organisations is not a message between two people. It has to reach an
*entity*, which has devices, roles and a records function; it has to be
addressed through a directory that survives a change of provider; and the
question of who acted — which device, under whose authority, at which instant —
has to be answerable years later from retained material alone.

What the exercise deliberately leaves out is as much a part of its shape as what
it takes on. It addresses **homogeneous federations**: every participant runs
this profile, and a gateway to a different registered-delivery system is not
designed here. It carries a message between **two entities**, not among many:
multiparty groups are excluded and recorded as future study. It does not mandate
a wallet implementation, a PKI hierarchy or a storage technology. And it
establishes neither the qualification of any operating provider nor the legal
effect of the evidence it defines; whether the statutory presumption attaches is
a legal question this repository states rather than answers.

This profile is the first phase of a phased idea — registered entity messaging
first, then registered attestation exchange, then a registered presentation
profile, then governed agentic interactions — each reusing the same identity
model, channel and evidence layer
([vision and context](docs/vision-and-context.md)). The later phases are not
designed here, and their absence is deliberate rather than an omission; what is
specified today of the agent phase is its first subset, the optional agent
profile's mandates and evidence, while the cross-deployment agent interface is
open (A7).

## 2. What it takes as given

The requirements are the ones formalised in the specification's own scope
([umbrella §0](Secure-Business-Messaging-Profile.md#0-scope)); this section
summarises them and introduces none.

**What the specification is required to define.** A unique identifier scheme for
economic operators and public-sector bodies, assignable only by EU-listed
qualified trust service providers (QEAA) and public-sector attestation
providers (PubEAA). A directory and resolution model with its governance
framework and its linkage to the existing company registers. A messaging profile
binding IETF MLS to the business-wallet context, with registered delivery
providers operating under a defined trust framework and a standardised evidence
model. The integration points with the EUDI Wallet architecture, the identifier
carried as an attestation and the evidence storable in the wallet. And the
validation rules, conformance requirements and interoperability guidance that
make all of it checkable.

**What it assumes.** That registered delivery providers are admitted, qualified
and supervised rather than joining freely, because the evidence layer's legal
weight depends on who operates it — and that a messaging service provider,
which need not be qualified, is admitted to the federation all the same. That the recipient's organisation can publish signed statements
about itself — its providers, its policy, its devices — and that a counterparty
can read them before sending. That a qualified timestamp is available from
outside the protocol. And that a wallet can hold a key the entity is willing to
be bound by.

**What it does not set out to do.** It mandates no particular wallet
implementation, PKI hierarchy or storage technology. It does not define a
transport-security underlay: MLS is used as the end-to-end layer, not beneath
one. It does not attempt to make every deployment identical — the deployment
profiles in the umbrella's Annex P range from a single co-located provider with
a static directory to a full four-corner federation — and it does not require
the optional capabilities, so a deployment that adopts neither confidentiality
scopes nor the agent profile is a complete one.

## 3. The standards, and what they ask of the service

Three layers of external material constrain the design, and the exercise treats
them as constraints to satisfy rather than as references to cite.

**The registered-delivery service itself.** Regulation (EU) No 910/2014 as
amended, Article 44(1), sets the requirements a qualified electronic registered
delivery service must meet, and Article 43(2) attaches the presumption to data
sent and received through one; Commission Implementing Regulation (EU) 2025/1944
sets the technical specifications. The ETSI **EN 319 522** series is where those
requirements become an architecture: part 1 for the framework and definitions,
part 2 for the semantic contents — the event and evidence model this profile
maps onto — part 3 for formats, and part 4-1 for the message-delivery binding
to AS4, which this study's MLS binding sits beside rather than inside.
**EN 319 521** states the policy and security requirements on the provider,
**EN 319 401** the general ones for any trust service, and **TS 119 312** the
cryptographic suites. The TS-shaped document in this repository is where the
mapping is made clause by clause, with an implementation conformance statement.

**The protocol layer.** MLS (**RFC 9420**) is the end-to-end layer, profiled
here rather than reinvented. The evidence objects are deterministic CBOR (**RFC
8949 §4.2**) sealed with COSE (**RFC 9052**); the qualified timestamp is an RFC
**3161** token over the seal. MLS architecture considerations are **RFC 9750**.

**Three things that are easy to run together, and are not the same.** *Design
alignment* means the specification is written against the standards named above
and says where it maps onto them. *Verified conformance* means a gate in this
repository executes a check and it passes — that is what `make conformance`
establishes, and it establishes it about the artefacts here and nothing else.
*Qualification* is a status an operating provider holds, granted by a
supervisory body against a conformity assessment, and nothing in a repository
can confer it. The claim matrix in
[*What a green bar means*](#what-a-green-bar-means--and-what-it-does-not) keeps
the five distinct claims apart, and says which two are established.

One mapping is worth flagging rather than asserting: the relay-stage mapping
onto EN 319 522 is **this study's own reading** and has not been confirmed by
the standards owner. It is open question A8 on the
[review agenda](docs/REVIEW_AGENDA.md).

## 4. The architecture that answers them

Four parties and one instrument each. The **wallet** holds the entity's keys and
produces the acts the entity is bound by. The **messaging service provider**
is each side's local delivery service, carrying ciphertext it cannot read. The
**registered delivery provider** is the qualified party that seals evidence;
between two organisations there are two of them, and the relay between them runs
provider to provider. The **directory** resolves an identifier to the provider,
the policy and the devices that serve it at a given moment.

Underneath, the separation that makes the whole thing work is between *what was
said* and *what can be attested*. The content travels in an MLS group — one
group per entity pair, every device a leaf, so a message is addressed to an
organisation and delivered to its devices. The evidence travels beside it as
sealed objects that carry digests, identifiers and instants, never content: a
submission, a delivery, a non-delivery or a refusal, and an evidence package
that binds a whole exchange. What a provider attests is what it observed; what
the recipient's wallet confirms is what the recipient did. The two are separate
acts by separate parties, and the architecture's job is to keep them separable
years later.

Two diagrams carry this: the
[four-corner architecture](docs/diagrams/four-corner-architecture-technology-neutral.svg)
for who talks to whom, and the
[identity and proof map](docs/diagrams/identity-proof-map.svg) for which record
authorises which key. The authoritative statement is
[umbrella §7.1](Secure-Business-Messaging-Profile.md#71-technical-architecture-authoritative);
the compact cross-actor model, including who sees what, is
[`docs/architecture-identity-trust.md`](docs/architecture-identity-trust.md).

## 5. The choices that shape it, and what they cost

Thirteen architectural choices determine more of this design than all the rest
together. Each is an **architecture decision record** under
[`docs/adr/`](docs/adr/): the context, the requirement it answers, the decision,
the alternatives actually considered and why they were rejected, the trade-off,
the consequences, the status of the decision kept apart from the status of its
implementation, and the normative document that owns it. The
[decisions index](docs/decisions-index.md) is generated from those records and
is the one table to read first: the choice, the alternative, the benefit, the
cost and who pays it, and — separately — whether the choice stands and how far
it is implemented. The umbrella's own one-page version is
[§0.1](Secure-Business-Messaging-Profile.md#01-design-trade-offs-informative).

Three records are worth opening before anything else, because they are where a
first reader most often misreads the design:
[SBM-ADR-0007](docs/adr/SBM-ADR-0007.md), why delivery is a wallet confirmation
by default and availability only a declared grade;
[SBM-ADR-0004](docs/adr/SBM-ADR-0004.md), why the messaging service provider is
separated from the registered delivery provider and what that separation does
and does not protect against; and
[SBM-ADR-0011](docs/adr/SBM-ADR-0011.md), why every verdict is read from
retained history rather than live state, and what a retained history cannot
prove.

## 6. Going deeper, and the questions still open

**The questions this design does not answer** are collected in one place, each
with the assumption it currently rests on, the claim that depends on it and the
expertise that would settle it: the
[review agenda](docs/REVIEW_AGENDA.md). They are not a backlog of defects. They
are the points at which an architectural choice has not been made, and the
material around them is written to let a reader disagree with the alternatives
rather than to hide that a choice is pending. What the design does not prove
on its own, as opposed to what it has not decided, is in
[`OPEN-ITEMS.md`](OPEN-ITEMS.md); the two documents name each other's entries
rather than restating them.

**The specification is three documents**, and every normative prose requirement
lives in exactly one of them. The CDDL, the JSON Schemas, the OpenAPI contracts,
the registries and the lint catalogue are normative too, each for what it
describes; the umbrella's *Document map* says which governs what, and what
happens when two disagree.

| Document | Normative for |
|----------|---------------|
| [`Secure-Business-Messaging-Profile.md`](Secure-Business-Messaging-Profile.md) | **Umbrella** — identifiers, directory (EDD), roles, the authoritative technical architecture (§7.1), MED/ORG/MEMBER, EUDI Wallet integration, governance, and the Document map. Informative annexes: communication scenarios (L), organisational administration (O), deployment profiles and EDD staging (P). |
| [`ietf/draft-sbm-mls-erd-00.md`](ietf/draft-sbm-mls-erd-00.md) | **Internet-Draft** — the wire protocol: SM-MLS binding, application envelope, the deterministic-CBOR encoding (RFC 8949 §4.2, per `cddl/sm-mls-erd.cddl`), message flows and delivery states, evidence objects and COSE packaging, Security and IANA Considerations. |
| [`etsi/TS-SBM-QERDS-Binding-v0.1.md`](etsi/TS-SBM-QERDS-Binding-v0.1.md) | **TS-shaped profile** — the QERDS conformance layer, the ETSI EN 319 522 mapping, the Article 44 and CIR compliance argument, and the ICS pro forma. |

**The explanatory companions**, in the order a reader usually needs them:

| Document | What it gives you |
|----------|---------|
| [`docs/REVIEWER_GUIDE.md`](docs/REVIEWER_GUIDE.md) | The short path: what exists today, what is planned, what is open, and a branch per specialism. |
| [`docs/vision-and-context.md`](docs/vision-and-context.md) | Why the problem is worth solving: the framing, the design principles, the managed-network model, and where this sits in the EU framework. |
| [`docs/architecture-identity-trust.md`](docs/architecture-identity-trust.md) | Who does what and who talks to whom; which record authorises which key; the five questions a verifier keeps apart; who sees what. |
| [`docs/message-lifecycle.md`](docs/message-lifecycle.md) | How the published operations compose: a minimal trace, the four state machines and their owners, three different acknowledgements, five clocks, six worked cases, and where a trace stops at an open question. |
| [`docs/evidence-layer-explainer.md`](docs/evidence-layer-explainer.md) | The evidence layer — in brief first, then the objects, the seal and timestamp, the digests, the grade commitment and the ETSI event model. |
| [`docs/federated-flow-explainer.md`](docs/federated-flow-explainer.md) | One message between two providers, phase by phase through the published operations, with the open boundaries where they sit. |
| [`docs/decisions-index.md`](docs/decisions-index.md) | Today's choices — generated from the decision records: the alternative weighed, the benefit, the cost and who pays, the status of the decision and of its implementation. |
| [`docs/REVIEW_AGENDA.md`](docs/REVIEW_AGENDA.md) | The open questions, each with its assumption, the claim that depends on it and the expertise that would settle it. |
| [`docs/lifecycle-and-custody.md`](docs/lifecycle-and-custody.md) | What changes at enrolment, device replacement, role change, compromise, policy rotation and provider exit; who keeps plaintext, evidence and verification material — and what is not decided. |
| [`docs/production-verifier-architecture.md`](docs/production-verifier-architecture.md) | What a verifier must hold besides the package, input by input, with the verdict when one is missing — and what a production verifier must check beyond this repository's linters. |
| [`docs/scope-resolution-examples.md`](docs/scope-resolution-examples.md) | Seven worked cases of resolving a message to a group and reading the result. |
| [`docs/agent-profile-explainer.md`](docs/agent-profile-explainer.md) | The optional agent profile (Annex R): purpose, design, use cases and a worked example. |
| [`docs/wallet-agent-interface.md`](docs/wallet-agent-interface.md) | Outline of the wallet–agent companion contract for the agent deployment profile. |
| [`docs/wallet-assurance-profile.md`](docs/wallet-assurance-profile.md) | The minimum wallet assurance baseline: key protection, device binding, confirmation-key lifecycle, compromise latency, attestation. |
| [`docs/OCTET_AUTHORITATIVE_DESIGN.md`](docs/OCTET_AUTHORITATIVE_DESIGN.md) | Why the sealed bytes are authoritative and the JSON a projection, with the options that were rejected. |
| [`CHANGELOG.md`](CHANGELOG.md) | The history of the artefacts: versions, and what changed on the wire. |

**The conceptual minimum**, if you would rather read the specification directly:
the architecture and the delivery-semantics choice at
[umbrella §7.1](Secure-Business-Messaging-Profile.md#71-technical-architecture-authoritative);
the four delivery states at
[I-D, *Delivery State Model*](ietf/draft-sbm-mls-erd-00.md#delivery-state-model);
one evidence round trip at
[I-D, *Evidence Objects and COSE Packaging*](ietf/draft-sbm-mls-erd-00.md#evidence-objects-and-cose-packaging)
with [`samples/sample-SE.json`](samples/sample-SE.json),
[`samples/sample-DE.json`](samples/sample-DE.json) and
[`samples/sample-EP.json`](samples/sample-EP.json); and scenario 1 of
[umbrella Annex L](Secure-Business-Messaging-Profile.md#annex-l--communication-scenarios-informative).
Confidentiality scopes
([umbrella §8.3a](Secure-Business-Messaging-Profile.md#83a-confidentiality-scope-descriptor-normative-where-present))
are an advanced capability — skip them on first read.

**To run a pilot**, the minimum is deployment profile 1 of
[umbrella Annex P](Secure-Business-Messaging-Profile.md#annex-p--deployment-profiles-and-edd-staging-informative):
a static signed directory, one co-located provider, two wallets, the default
scope only, and pilot rather than qualified evidence. The reference mock is
[`scripts/mock_rdp.py`](scripts/mock_rdp.py); validate everything with
`make conformance`, below. Piloting on localhost? Sealed documents keep their
canonical `https` URLs — map endpoints wallet-side (Annex P.3).

**Generated, not hand-kept:** [`docs/lint-catalogue.md`](docs/lint-catalogue.md)
from the rule definitions, [`docs/rule-ownership.md`](docs/rule-ownership.md)
from the ownership inventory, [`docs/decisions-index.md`](docs/decisions-index.md)
from the decision records, and [`docs/project-counts.json`](docs/project-counts.json)
from the tree. Each is checked by a gate that fails when the copy drifts from
its source.

---

**The rest of this file is operational**: what is current, how to run the bar,
what a green bar does and does not mean, and how to send feedback.

## Current versions

| Artefact | Version |
|---|---|
| Umbrella profile | 2.1 (edition 2026-09-18) |
| Evidence objects (SE/DE/NDE/RE/CE/EP) | **2.8** (octet-authoritative) |
| Application envelope | 1.2 |
| BW-MED / BW-ORG / BW-MEMBER | 2.1 / 2.6 / 2.2 |
| EDD resolver contract (OpenAPI) | 1.12.0 |
| Federation register contract (OpenAPI) | 3.0.0 |
| Profile-2 companion contracts (wallet-RDP / DS / relay) | 9.0.0 |
| TS (QERDS binding) | v0.35 |

This table is generated-and-checked from [`versions.json`](versions.json), the
single source of truth: `make versions` (and `tests/test_version_matrix.py`)
fail if any schema `const`, schema title, CDDL body, sample or table cell drifts
from it. The discovery documents and the EDD contract version
**independently** of the evidence family (umbrella §9.3). The **agent profile**
(Annex R, deployment profile 5) is OPTIONAL: a network **MAY** run the current
evidence version without adopting it.

## Running the conformance bar

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r scripts/requirements.txt        # the canonical test/conformance environment
make dev-tools                                 # REUSE and pip-licenses, for the reuse gate
cargo install cddl --version 0.9.5 --locked    # the CDDL gate is fail-closed without it
make conformance                               # the bar; read the exit codes below before you run it
```

`make conformance` runs twelve gates over the specification: the version
manifest, the generated lint catalogue, the rule-ownership inventory, the
decision records and their index, the dependency preflight and the test suite,
JSON Schema validation of every sealed sample, the semantic linters with and
without demo-key seal verification, the CDDL non-divergence gate, independent
OpenAPI validation of the five contracts, the documentation guard, and REUSE
compliance. The rules the linters enforce are published as a catalogue,
[`docs/lint-catalogue.md`](docs/lint-catalogue.md), with each rule's input,
precondition, exact predicate and error, so an assessor can reproduce every
verdict without reading the reference code.

### The three verdicts, and the two invocations

The bundle verifier returns **three** results, not two:

| Verdict | Exit | Meaning |
|---|---|---|
| `[OK]` | 0 | Every required property was established from the retained material |
| `INCOMPLETE` (`[GAP]`) | **3** | No violation was found, **and** a required property could not be established — an *incomplete* verification, not a pass |
| `[FAIL]` | 1 | A violation was found |

**The bundles shipped in this repository report INCOMPLETE, and that is by
design.** Run the verifier the way the bar runs it — **anchored**, with the
demonstration trust store:

```sh
python3 scripts/bundle_lint.py --trust-store samples/trust-store.demo.json samples/bundle.default.manifest.json
# → INCOMPLETE: 0 violation(s), 2 unproven required property/properties · exit 3
```

Two unproven required properties remain, and both are the same one, reported
once for the submission's pinned policy and once for the delivery's: the
retained policy chain proves which version was in force at the act and that the
chain is unbroken back to a first publication, but it cannot prove that no
*later* version existed, because a retained prefix cannot exclude a successor
nobody supplied (`LINT-BND-I3`). That is precisely the property this study
declares it does not prove — item 3 of [`OPEN-ITEMS.md`](OPEN-ITEMS.md), question
A3 on the [review agenda](docs/REVIEW_AGENDA.md) — and the verifier says so
rather than passing.

Now run it **unanchored**, with no trust store configured:

```sh
python3 scripts/bundle_lint.py samples/bundle.default.manifest.json
# → INCOMPLETE: 0 violation(s), 3 unproven required property/properties · exit 3
```

The third unproven property is federation admission (`LINT-BND-I6`): the bundle
carries a membership register, but with no federation authority anchor
configured the register's authenticity cannot be established, so it is not
consulted and no provider's admission is resolved. In the reader's terms, this
is a verifier that has no anchor for the *admission* authority — a different
authority, and a different check, from the Trusted List that would vouch for a
provider's *qualification*. It is a **configuration state, not a limit of the
design**: give the verifier the authority's anchor and admission resolves. The
demonstration store is one file that holds demonstration keys for both roles,
the qualification-side signers and the federation authority; it proves nothing
about production, where the two kinds of trust material come from different
places.

For contrast, `samples/bundle.negative.manifest.json` exits **1** with six
violations. The full input-by-input account of what a verifier must hold, and
which missing input leaves which property unproven, is
[`docs/production-verifier-architecture.md`](docs/production-verifier-architecture.md).

`make lint` passes `--allow-incomplete` deliberately, so that a known, stated gap
does not fail the bar; the flag changes the exit code for declared gaps and
**never** forgives a violation. If you treat any non-zero exit as "violations
found", you will misread this repository.

## Conformance

> **Conformance definition.** An SM-MLS-1.0 evidence or discovery artefact is **conformant** only if it is all of: **(1) schema-valid** — validates against its JSON Schema; **(2) lint-clean** — no `evidence_lint` / `discovery_lint` violations, in the full `cbor2` mode; **(3) sealed over the authoritative payload** — the COSE_Sign1 is the authoritative artefact; its payload equals the deterministic-CBOR (RFC 8949 §4.2) body defined in the CDDL (`cddl/sm-mls-erd.cddl`), of which the JSON is a non-authoritative projection; **(4) for an evidence artefact only**, timestamped over the seal by a qualified timestamp — a discovery document is a bare COSE_Sign1 whose validity window is declared in its body and carries no timestamp; and **(5) verifiable against the declared trust material**. This is a summary of the normative definition in umbrella §9.4, which governs where the two differ; the reference tooling checks (1) to (3) and the demo slices of (4) and (5).

### What a green bar means — and what it does not

Five different claims are easy to run together. They are not the same claim, and
this repository establishes only the first two in full:

| # | Claim | What establishes it | Needs | In this repository |
|---|---|---|---|---|
| 1 | **The repository agrees with itself** — reference tooling, samples, schemas, contracts, catalogue, records and versions are mutually consistent | `make conformance` | nothing external | **Established** — the bar is green |
| 2 | **An artefact is valid** — one sealed object is schema-valid, lint-clean, and its seal verifies | `evidence_lint` / `discovery_lint`, with `--verify-demo` or `--trust-store` | the object, and trust material | **Established for the shipped samples**, against DEMO keys |
| 3 | **A retained bundle verifies completely** — every property a complete verification requires is established from retained material | `bundle_lint` | the retained material, an authenticated federation register, trust anchors | **Not established.** The shipped bundles are INCOMPLETE by design — see above |
| 4 | **Independent implementations interoperate** | two implementations exchanging messages and evidence | a second, independent implementation | **Not demonstrated.** The contracts are published; nobody else has exercised them |
| 5 | **Production qualification and legal effect** | QSealC chains to EU Trusted Lists, qualified timestamps, conformity assessment, admission by an operated federation register | external authorities | **Not established by anything here** |

**What the response gate is.** `scripts/response_conformance.py` drives the
**Delivery Service's published success responses** — 14 operations, with 1 declared residual — and
validates each against its contract. Error responses,
retries, multi-principal cases and the other four contracts are covered by their
own tests, not by this gate; it is a sweep of one contract's success paths, not
of the protocol.

**Lint modes**: the default `make lint` checks the **structural** conditions
against the reference samples and does **not** verify signatures against trust
material. `make lint-demo` (`--verify-demo`) additionally **cryptographically
verifies every seal** against the **published demo keys**. `--trust-store
<path>` runs the **minimal demo slice** of a production verifier: every seal's
`kid` must resolve to the store and verify against its key, the entry's role and
identities must match the document, and every declared instant must lie in the
entry's window — fail-closed. Full RFC 3161 / ETSI EN 319 422 timestamp
validation and EU-Trusted-List verification are **production-verifier**
obligations against a real trust store, and `evidence_lint --profile production`
is a structural precheck, **not** legal qualification validation.

### What the demo trust store pins

Passing `--trust-store samples/trust-store.demo.json` is a **fail-closed gate
against demo constants**, not just a signature check. The demo store pins:

- **Signer identities.** Evidence must carry an `rdp_id` in `{urn:sbm:rdp:mockeu-001, urn:sbm:rdp:mockeu-002}` — the canonical provider identifier (`RdpId`); discovery documents must carry a `uid` among the demo entities (`EU-DE-EOID-7K3D9W0Q2M5FW0`, `EU-FR-PSBID-ZYWVTSRQPNM8M4`). A pilot minting its own `rdp_id` or entity UID **fails `LINT-TRUST-02` by design** — the gate is doing its job.
- **A validity window.** Every declared instant must lie within `[2026-01-01, 2027-06-30]` — **all demo output stops passing the trust gate after 2027-06-30** (`LINT-TRUST-03`).
- **One key per role.** A single `rdp` evidence key, a single `entity-admin` discovery key shared by every demo entity, a `design-authority` key sealing the Stage-1 demo registry (Annex P.1.1), a **separate** `federation-authority` key sealing the membership register — umbrella §13.1 keeps the admission signer distinct from the protocol's maintainer — and a provider-descriptor key for `urn:sbm:rdp:mockeu-001`.

To run your own pilot against the gate: copy the store, replace the keys,
identities and window with your pilot's values, and pass your copy. The checks
are deterministic against the store you provide — no wall clock is consulted.

**The sample key material is demonstration-grade.** The samples are
cryptographically real — the signatures verify, the digests recompute — but the
keys, the entity identifiers, the registers and the trust store are for
demonstration. They exist so that "conformant" is machine-checkable, not to
represent a deployment.

## Quickstart

### Requirements

- Python 3.11+
- **Required for the canonical test/conformance environment** (= `scripts/requirements.txt`, enforced by the `make test` preflight): `jsonschema`, `pytest`, `cbor2`, `flask`, `pyyaml`, `pynacl`, `openapi-spec-validator` (meta-validates the published contracts) and `cryptography` (the reference verifier dispatches EdDSA, ES256 and ES384 confirmation keys).
- **Optional / demo-only**: `requests` (the HTTP-client demos).
- The `cddl` tool (`cargo install cddl --version 0.9.5 --locked`) for the CDDL gate; `make dev-tools` for the REUSE gate.

`make test` runs `scripts/check_env.py` first and **fails** (rather than silently skipping) if any of `jsonschema`, `cbor2`, `flask`, `pyyaml`, `pynacl`, `openapi-spec-validator` or `cryptography` is missing. A bare `python3 -m pytest -q` still works for ad-hoc runs, but only the preflighted `make test` is the canonical run.

### Generate and validate a UID

```sh
python3 scripts/eu_entity_uid_toolkit.py gen --country DE --scheme EOID
python3 scripts/eu_entity_uid_toolkit.py check EU-DE-EOID-7K3D9W0Q2M5FW0
```

### Produce a starter discovery document

**Quick start for a publisher.** `scripts/eu_entity_uid_toolkit.py` generates a
starter discovery document. Its `med-stub` output is a **sealed M4 artefact** —
the authoritative COSE bytes with the JSON projection beside them — signed with
an **ephemeral key, not a QSealC**: structurally valid for experimentation,
never publishable. *Removed: dns-zone* — an earlier revision offered DNS-based
alias discovery; alias layers cannot authorise a provider, key or endpoint, so
the mechanism was withdrawn rather than left as a parallel trust path.

### Run the gates one at a time

```sh
make test            # dependency preflight, then the full pytest suite
make schema-smoke    # every sample against its JSON Schema
make lint            # the semantic linters and the bundle verifier, structural mode
make lint-demo       # the same, verifying every seal against the demo keys
make versions        # every artefact's version against versions.json
make doc-lint        # the documentation guard: links, figures, stale mechanisms
```

### Run the mock RDP

```sh
python3 scripts/mock_rdp.py
# server listens on http://localhost:8000
```

## Feedback

This is a **review snapshot** of a design study, exported for an expert group
and published to be challenged. Start with
[`docs/REVIEW_AGENDA.md`](docs/REVIEW_AGENDA.md): it lists, in one place, the
questions this specification does **not** yet answer — protocol, production
trust and legal — with the assumption each one currently rests on. It also
names what is **not yet written**: the implementer guide — the exact pre-join
proof, one complete trace through the public operations, provider migration and
exit, and who sees what — deferred by decision, carried on the agenda as G1 to
G4, and not claimed as delivered.

- **Edition.** This snapshot is the review edition `design-study-2026-09-20-r4`,
  the git tag of that name; earlier tags of this snapshot stay where they are
  and each names the edition it was cut from. Cite the tag, or the commit you
  hold, so an answer can be matched to the text it answers. The reviewer
  guide's "tag named in the README" is this one.
- **Technical feedback** — an ambiguity, a contradiction, a rule an
  implementer cannot follow, a claim you think is wrong: a finding that names
  the document and section, and ideally the artefact or command that shows it,
  can be reproduced; that is what makes it actionable. The most useful
  contributions, in order: run the conformance bar against a **second
  implementation** — the confirmation-signature vectors have only ever been
  verified by one COSE implementation; attack the evidence model — the samples
  are real, and a construction that accepts something it should not is the
  finding worth having; challenge the legal argument — the claim that
  registered-delivery evidence can rest on digests rather than content is
  carefully built and untested.
- **Security issues:** do not describe them in public. Ask for a private
  channel first.
- **Patent disclosures** are not technical feedback and have their own route:
  [`IPR.md`](IPR.md) and [`IPR-DISCLOSURES.md`](IPR-DISCLOSURES.md). A comment
  is not a Contribution and carries no patent obligation
  ([`CONTRIBUTING.md`](CONTRIBUTING.md)).
- **Maintainer:** [@paolo-de-rosa](https://github.com/paolo-de-rosa) on GitHub.

## Licence

Dual-licensed and [REUSE](https://reuse.software)-compliant: the **specification
text and documentation** are under **CC BY 4.0**
([`LICENSES/CC-BY-4.0.txt`](LICENSES/CC-BY-4.0.txt)) with a royalty-free
(RAND-Z) patent commitment ([`IPR.md`](IPR.md)); the **reference code and
machine-readable artefacts** (`scripts/`, `tests/`, `schemas/`, `samples/`,
`registries/`, the OpenAPI contracts) are under the **MIT License**
([`LICENSES/MIT.txt`](LICENSES/MIT.txt)). Every file carries an
`SPDX-License-Identifier` or is covered by path in
[`REUSE.toml`](REUSE.toml).

© 2025–2026 Paolo De Rosa and contributors. This repository is an independent
technical exploration (see the exploratory banner above); the copyright holder
acts in a personal capacity and no institution is represented.
