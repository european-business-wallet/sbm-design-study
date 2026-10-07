<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Secure Business Messaging — a design study

**Secure Business Messaging is a design exercise.** It starts from an explicit
set of requirements — a message between two organisations that carries the legal
effect of registered delivery, across borders and across providers, while its
content stays end-to-end encrypted — and works out what a system satisfying them
would have to look like: a specification set, a reference implementation, and
the machinery that checks the two against each other. Where a question is open,
this repository names it rather than choosing quietly, and the choices it does
make are written down with what they cost.

> **Exploratory design study — not an official proposal.** An independent
> technical exploration of how existing EU building blocks — Regulation (EU) No
> 910/2014 as amended by Regulation (EU) 2024/1183, qualified electronic
> registered delivery, IETF MLS and the EUDI Wallet — *could* be composed into a
> secure business-messaging profile. It is not an official proposal, deliverable
> or position of the European Commission, any Member State or any standards
> body, and it confers no status; it is a draft, shared to invite technical
> discussion. Interoperability between independent implementations, and the
> qualification of any operating provider, are **not** demonstrated here — see
> [*What a green bar means*](#what-a-green-bar-means--and-what-it-does-not).

**Where to start.** The six sections below go from the problem to the open
questions. Reviewing the specification rather than meeting it? The
[reviewer guide](docs/REVIEWER_GUIDE.md) is the shorter route, one short path
and a branch per specialism. The [executive brief](brief/executive-brief.md)
gives the idea in about ten minutes for policy readers; the
[requirements list](brief/requirements.md) is the baseline the study started
from, each requirement with its source; what the design does **not** prove on
its own is collected in [`OPEN-ITEMS.md`](OPEN-ITEMS.md).

---

## 1. The problem, and what the exercise leaves out

Registered delivery is what makes a message opposable: a qualified provider
attests that it was sent, that it reached an identified recipient, and when.
Traditionally that attestation rests on a provider that handles the content,
which is why registered delivery and end-to-end encryption have been treated as
alternatives. The load-bearing proposition of this exercise is that they are
not: **evidence can rest on cryptographic digests of the content and of the
group state rather than on the content itself**, so a provider can attest what
it observed without ever being able to read what it carried. That proposition
is concrete, it is executable, and it is untested in law.

The second problem is that an opposable message between two organisations is
not a message between two people. It has to reach an *entity*, with devices,
roles and a records function; it has to be addressed through a directory that
survives a change of provider; and who acted — which device, under whose
authority, at which instant — has to be answerable years later from retained
material alone.

What the exercise leaves out is part of its shape. It addresses **homogeneous
federations** — every participant runs this profile, and a gateway to another
registered-delivery system is not designed. It carries a message between **two
entities**; multiparty groups are future study. It mandates no wallet
implementation, PKI hierarchy or storage technology. And it establishes neither
the qualification of any provider nor the legal effect of the evidence it
defines: whether the statutory presumption attaches is a legal question this
repository states rather than answers. The profile is the first phase of a
phased idea — entity messaging, then attestation exchange, a registered
presentation profile and governed agentic interactions (the
[executive brief](brief/executive-brief.md) §5); the later phases are not
designed here, and the cross-deployment agent interface is open (A7).

## 2. What it takes as given

The requirements are those formalised in the specification's own scope
([umbrella §0](Secure-Business-Messaging-Profile.md#0-scope)); this section
summarises them and introduces none.

**Required to define.** A unique identifier scheme for economic operators and
public-sector bodies, assignable only by EU-listed qualified trust service
providers and public-sector attestation providers; a directory and resolution
model, its governance, and its linkage to the existing company registers; a
messaging profile binding IETF MLS to the business-wallet context, with
registered delivery providers under a defined trust framework and a
standardised evidence model; the integration points with the EUDI Wallet; and
the validation rules, conformance requirements and interoperability guidance
that make all of it checkable.

**Assumed.** That registered delivery providers are admitted, qualified and
supervised rather than joining freely, and that the same provider operates the
delivery service its entities' wallets talk to. That
an organisation can publish signed statements about its providers, its policy
and its devices, which a counterparty reads before sending. That a qualified
timestamp is available from outside the protocol, and that a wallet can hold a
key the entity is willing to be bound by.

**Not attempted.** No new transport-security protocol: the contracts run over
ordinary HTTPS with TLS 1.3, and MLS sits **above** it as the end-to-end layer,
so the confidentiality and the legal claims rest on MLS and not on the
hop-by-hop underlay. No single deployment shape: the profiles in the umbrella's
Annex P range from one co-located provider with a static directory to a full
four-corner federation, and a deployment that adopts neither confidentiality
scopes nor the agent profile is a complete one.

## 3. The standards, and what they ask of the service

**The registered-delivery service.** Regulation (EU) No 910/2014 as amended,
Article 44(1), sets the requirements a qualified electronic registered delivery
service must meet, and Article 43(2) attaches the presumption to data sent and
received through one; Commission Implementing Regulation (EU) 2025/1944 sets
the technical specifications. The ETSI **EN 319 522** series is where those
requirements become an architecture — part 2 carries the event and evidence
model this profile maps onto, part 4-1 the AS4 binding this study's MLS binding
sits beside rather than inside — with **EN 319 521**, **EN 319 401** and **TS
119 312** for the provider, trust-service and cryptographic requirements. The
TS-shaped document in this repository makes the mapping clause by clause, with
an implementation conformance statement.

**The protocol layer.** MLS (**RFC 9420**) is the end-to-end layer, profiled
rather than reinvented. The evidence objects are deterministic CBOR (**RFC 8949
§4.2**) sealed with COSE (**RFC 9052**); the qualified timestamp is an RFC
**3161** token over the seal.

**Three things that are not the same.** *Design alignment*: the specification
is written against the standards above and says where it maps onto them.
*Verified conformance*: a gate in this repository executes a check and it
passes — what `make conformance` establishes, about the artefacts here and
nothing else. *Qualification*: a status an operating provider holds, granted
by a supervisory body, which nothing in a repository can confer. The claim
matrix under [*What a green bar means*](#what-a-green-bar-means--and-what-it-does-not)
keeps the five claims apart. One mapping is flagged rather than asserted: the
relay-stage mapping onto EN 319 522 is this study's own reading, not confirmed
by the standards owner — question A8 on the
[review agenda](docs/REVIEW_AGENDA.md).

## 4. The architecture that answers them

Three parties and one instrument each. The **wallet** holds the entity's keys and
produces the acts the entity is bound by. The **registered delivery provider** is
the qualified party that carries the ciphertext it cannot read and seals the
evidence over it; the delivery service each side's wallets talk to is that
provider's own function, not a party of its own. Between two organisations there
are two providers, and the relay runs provider to provider. The **directory** resolves an identifier to the provider, the policy
and the devices that serve it at a given moment.

Underneath, the separation that makes it work is between *what was said* and
*what can be attested*. The content travels in an MLS group — one group per
entity pair, every device a leaf. The evidence travels beside it as sealed
objects that carry digests, identifiers and instants, never content: a
submission, a delivery, a non-delivery or a refusal, and a package that binds a
whole exchange. What a provider attests is what it observed; what the
recipient's wallet confirms is what the recipient did; and the architecture's
job is to keep the two separable years later. Two diagrams carry this — the
[four-corner architecture](docs/diagrams/four-corner-architecture-technology-neutral.svg)
for who talks to whom, the
[identity and proof map](docs/diagrams/identity-proof-map.svg) for which record
authorises which key. The authoritative statement is
[umbrella §7.1](Secure-Business-Messaging-Profile.md#71-technical-architecture-authoritative);
the compact cross-actor model, including who sees what, is
[`docs/architecture-identity-trust.md`](docs/architecture-identity-trust.md).

## 5. The choices that shape it, and what they cost

A handful of architectural choices determine more of this design than all the
rest together. Each is an **architecture decision record** under
[`docs/adr/`](docs/adr/) — the requirement it answers, the alternatives
actually considered, the trade-off, and the status of the decision kept apart
from the status of its implementation — and the
[decisions index](docs/decisions-index.md) generated from them is the one table
to read first; the umbrella's one-page version is
[§0.1](Secure-Business-Messaging-Profile.md#01-design-trade-offs-informative).
Three records are where a first reader most often misreads the design:
[SBM-ADR-0007](docs/adr/SBM-ADR-0007.md), why delivery is a wallet confirmation
by default and availability only a declared grade;
[SBM-ADR-0004](docs/adr/SBM-ADR-0004.md), why delivery and evidence were once
separated into two providers and what that separation did and did not protect
against — superseded by [SBM-ADR-0015](docs/adr/SBM-ADR-0015.md), which folds
them into one; and [SBM-ADR-0011](docs/adr/SBM-ADR-0011.md), why
every verdict is read from retained history rather than live state, and what a
retained history cannot prove.

## 6. Going deeper, and the questions still open

**The questions this design does not answer** are in one place, each with the
assumption it currently rests on, the claim that depends on it and the
expertise that would settle it: the [review agenda](docs/REVIEW_AGENDA.md).
They are the points at which an architectural choice has not been made, not a
backlog of defects. What the design does not *prove*, as opposed to what it has
not decided, is in [`OPEN-ITEMS.md`](OPEN-ITEMS.md); the two documents name
each other's entries rather than restating them.

**The specification is three documents**, and every normative prose requirement
lives in exactly one of them; the CDDL, the JSON Schemas, the OpenAPI
contracts, the registries and the lint catalogue are normative too, each for
what it describes, and the umbrella's *Document map* says which governs what.

| Document | Normative for |
|----------|---------------|
| [`Secure-Business-Messaging-Profile.md`](Secure-Business-Messaging-Profile.md) | **Umbrella** — identifiers, directory (EDD), roles, the authoritative technical architecture (§7.1), MED/ORG/MEMBER, EUDI Wallet integration, governance, and the Document map. Informative annexes: communication scenarios (L), organisational administration (O), deployment profiles and EDD staging (P). |
| [`ietf/draft-sbm-mls-erd-00.md`](ietf/draft-sbm-mls-erd-00.md) | **Internet-Draft** — the wire protocol: SM-MLS binding, application envelope, the deterministic-CBOR encoding (RFC 8949 §4.2, per `cddl/sm-mls-erd.cddl`), message flows and delivery states, evidence objects and COSE packaging, Security and IANA Considerations. |
| [`etsi/TS-SBM-QERDS-Binding-v0.1.md`](etsi/TS-SBM-QERDS-Binding-v0.1.md) | **TS-shaped profile** — the QERDS conformance layer, the ETSI EN 319 522 mapping, the Article 44 and CIR compliance argument, and the ICS pro forma. |

**The explanatory companions**, in the order a reader usually needs them:

| Document | What it gives you |
|----------|---------|
| [`docs/REVIEWER_GUIDE.md`](docs/REVIEWER_GUIDE.md) | The short path: what exists today, what is planned, what is open, and a branch per specialism. |
| [`docs/architecture-identity-trust.md`](docs/architecture-identity-trust.md) | Who does what and who talks to whom; which record authorises which key; the five questions a verifier keeps apart; who sees what. |
| [`docs/message-lifecycle.md`](docs/message-lifecycle.md) | How the published operations compose: a minimal trace, the four state machines and their owners, three different acknowledgements, five clocks, six worked cases, and where a trace stops at an open question. |
| [`docs/evidence-layer-explainer.md`](docs/evidence-layer-explainer.md) | The evidence layer — in brief first, then the objects, the seal and timestamp, the digests, the grade commitment and the ETSI event model. |
| [`docs/federated-flow-explainer.md`](docs/federated-flow-explainer.md) | One message between two providers, phase by phase through the published operations, with the open boundaries where they sit. |
| [`docs/decisions-index.md`](docs/decisions-index.md) | Today's choices — generated from the decision records: each with its principal trade-off and its two statuses; the alternative weighed and the full cost are in the record it links to. |
| [`docs/REVIEW_AGENDA.md`](docs/REVIEW_AGENDA.md) | The open questions, each with its assumption, the claim that depends on it and the expertise that would settle it. |
| [`docs/lifecycle-and-custody.md`](docs/lifecycle-and-custody.md) | What changes at enrolment, device replacement, role change, compromise, policy rotation and provider exit; who keeps plaintext, evidence and verification material — and what is not decided. |
| [`docs/implementer-trace.md`](docs/implementer-trace.md) | One run through the published operations in order — formation, sending, delivery, confirmation, the multipart outcomes — with the negative and retry branches and what each call returned. Generated by driving the reference; it is not an interoperability result. |
| [`docs/retrievability.md`](docs/retrievability.md) | What must stay retrievable for a verdict to stay reachable: per verification input, which published read supplies it, who serves it, what its absence does to the verdict, and which inputs a provider exit leaves with no named server. Generated, and gated against the verifier's own arguments. |
| [`docs/production-verifier-architecture.md`](docs/production-verifier-architecture.md) | What a verifier must hold besides the package, input by input, with the verdict when one is missing — and what a production verifier must check beyond this repository's linters. |
| [`docs/scope-resolution-examples.md`](docs/scope-resolution-examples.md) | Seven worked cases of resolving a message to a group and reading the result. |
| [`docs/agent-profile-explainer.md`](docs/agent-profile-explainer.md) | The optional agent profile (Annex R): purpose, design, use cases and a worked example. |
| [`docs/wallet-agent-interface.md`](docs/wallet-agent-interface.md) | Outline of the wallet–agent companion contract for the agent deployment profile. |
| [`docs/wallet-assurance-profile.md`](docs/wallet-assurance-profile.md) | The minimum wallet assurance baseline: key protection, device binding, confirmation-key lifecycle, compromise latency, attestation. |
| [`CHANGELOG.md`](CHANGELOG.md) | The history of the artefacts: versions, and what changed on the wire. |

Six documents are generated rather than hand-kept, each checked by a gate that
fails when the copy drifts from its source:
[`docs/lint-catalogue.md`](docs/lint-catalogue.md),
[`docs/rule-ownership.md`](docs/rule-ownership.md),
[`docs/decisions-index.md`](docs/decisions-index.md),
[`docs/project-counts.json`](docs/project-counts.json),
[`docs/implementer-trace.md`](docs/implementer-trace.md) — produced by driving
the reference through the published operations — and
[`docs/retrievability.md`](docs/retrievability.md).

---

**The rest of this file is operational**: what is current, how to run the bar,
what a green bar does and does not mean, and how to send feedback.

## Current versions

| Artefact | Version |
|---|---|
| Umbrella profile | 2.1 (edition 2026-10-07) |
| Evidence objects (SE/DE/NDE/RE/CE/EP) | **2.12** (octet-authoritative) |
| Application envelope | 1.4 |
| BW-MED / BW-ORG / BW-MEMBER | 2.3 / 2.7 / 2.2 |
| EDD resolver contract (OpenAPI) | 2.1.0 |
| Federation register contract (OpenAPI) | 3.0.0 |
| Profile-2 companion contracts (wallet-RDP / DS / relay) | 16.0.0 |
| TS (QERDS binding) | v0.37 |

Generated-and-checked from [`versions.json`](versions.json), the single source
of truth: `make versions` fails if any schema `const`, schema title, CDDL body,
sample or table cell drifts from it. The discovery documents and the EDD
contract version independently of the evidence family (umbrella §9.3); the
**agent profile** (Annex R, deployment profile 5) is OPTIONAL.

## Running the conformance bar

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r scripts/requirements.txt        # the canonical test/conformance environment
make dev-tools                                 # REUSE and pip-licenses, for the reuse gate
cargo install cddl --version 0.9.5 --locked    # the CDDL gate is fail-closed without it
make conformance                               # the bar; read the exit codes below before you run it
```

`make conformance` runs fourteen gates: the version manifest, the generated lint
catalogue, the rule-ownership inventory, the decision records and their index,
the dependency preflight and the test suite, JSON Schema validation of every
sealed sample, the semantic linters with and without demo-key seal
verification, the CDDL non-divergence gate, OpenAPI validation of the five
contracts, the documentation guard, and REUSE compliance. The gates one at a
time are listed in [`CONTRIBUTING.md`](CONTRIBUTING.md). The rules the linters
enforce are published in [`docs/lint-catalogue.md`](docs/lint-catalogue.md)
with each rule's input, predicate and error, so an assessor can reproduce every
verdict without reading the reference code.

### The three verdicts, and the two invocations

The bundle verifier returns **three** results, not two:

| Verdict | Exit | Meaning |
|---|---|---|
| `[OK]` | 0 | Every required property was established from the retained material |
| `INCOMPLETE` (`[GAP]`) | **3** | No violation was found, **and** a required property could not be established — an *incomplete* verification, not a pass |
| `[FAIL]` | 1 | A violation was found |

**The bundles shipped here report INCOMPLETE, and that is by design.** Anchored
— with the demonstration trust store, the way the bar runs it — the default
bundle exits 3 with two unproven properties, both the same one: the retained
policy chain proves which version was in force at the act and that the chain
is unbroken, but cannot prove that no *later* version existed (`LINT-BND-I3`).
That is precisely the property this study declares it does not prove — item 3
of [`OPEN-ITEMS.md`](OPEN-ITEMS.md), question A3 on the agenda — and the
verifier says so rather than passing. Unanchored, with no trust store
configured, a third joins them: federation admission (`LINT-BND-I6`), because
without an anchor for the federation authority the membership register's
authenticity cannot be established. That is a configuration state, not a limit
of the design.

```sh
python3 scripts/bundle_lint.py --trust-store samples/trust-store.demo.json samples/bundle.default.manifest.json
# → INCOMPLETE: 0 violation(s), 2 unproven required property/properties · exit 3
python3 scripts/bundle_lint.py samples/bundle.default.manifest.json
# → INCOMPLETE: 0 violation(s), 3 unproven required property/properties · exit 3
```

For contrast, `samples/bundle.negative.manifest.json` exits **1** with six
violations. Which missing input leaves which property unproven is set out in
[`docs/production-verifier-architecture.md`](docs/production-verifier-architecture.md).
`make lint` passes `--allow-incomplete` so that a declared gap does not fail
the bar; the flag **never** forgives a violation. If you treat any non-zero
exit as "violations found", you will misread this repository.

## Conformance

> **Conformance definition.** An SM-MLS-1.0 evidence or discovery artefact is **conformant** only if it is all of: **(1) schema-valid** — validates against its JSON Schema; **(2) lint-clean** — no `evidence_lint` / `discovery_lint` violations, in the full `cbor2` mode; **(3) sealed over the authoritative payload** — the COSE_Sign1 is the authoritative artefact; its payload equals the deterministic-CBOR (RFC 8949 §4.2) body defined in the CDDL (`cddl/sm-mls-erd.cddl`), of which the JSON is a non-authoritative projection; **(4) for an evidence artefact only**, timestamped over the seal by a qualified timestamp — a discovery document is a bare COSE_Sign1 whose validity window is declared in its body and carries no timestamp; and **(5) verifiable against the declared trust material**. This is a summary of the normative definition in umbrella §9.4, which governs where the two differ; the reference tooling checks (1) to (3) and the demo slices of (4) and (5).

### What a green bar means — and what it does not

Five different claims are easy to run together. They are not the same claim, and
this repository establishes only the first two in full:

| # | Claim | What establishes it | Needs | In this repository |
|---|---|---|---|---|
| 1 | **The repository agrees with itself, as far as its gates can see** — reference tooling, samples, schemas, contracts, catalogue, records and versions are mutually consistent *in every respect a gate checks*. It is not a claim that no semantic inconsistency remains: external reviews have found real ones with the bar green, and each time the answer was a new gate | `make conformance` | nothing external | **Established for what the gates check** — the bar is green |
| 2 | **An artefact is valid** — one sealed object is schema-valid, lint-clean, and its seal verifies | `evidence_lint` / `discovery_lint`, with `--verify-demo` or `--trust-store` | the object, and trust material | **Established for the shipped samples**, against DEMO keys |
| 3 | **A retained bundle verifies completely** — every property a complete verification requires is established from retained material | `bundle_lint` | the retained material, an authenticated federation register, trust anchors | **Not established.** The shipped bundles are INCOMPLETE by design — see above |
| 4 | **Independent implementations interoperate** | two implementations exchanging messages and evidence | a second, independent implementation | **Not demonstrated.** The contracts are published; nobody else has exercised them |
| 5 | **Production qualification and legal effect** | QSealC chains to EU Trusted Lists, qualified timestamps, conformity assessment, admission by an operated federation register | external authorities | **Not established by anything here** |

**What the response gate is.** `scripts/response_conformance.py` drives the
**Delivery Service's published success responses** — 14 operations, with 1 declared residual — and
validates each against its contract; it is a sweep of one contract's success
paths, not of the protocol.

**Lint modes and trust material.** `make lint` checks the structural
conditions against the reference samples without verifying signatures; `make
lint-demo` (`--verify-demo`) additionally verifies every seal against the
published demo keys; `--trust-store <path>` runs the minimal demo slice of a
production verifier, fail-closed — every seal's `kid` must resolve to the
store, roles and identities must match the document, every declared instant
must lie in the entry's window. The demonstration store,
[`samples/trust-store.demo.json`](samples/trust-store.demo.json), pins the
demo provider and entity identifiers, one key per role — the federation
authority kept distinct from the design authority, as umbrella §13.1 requires
— and a validity window ending on **2027-06-30**, after which demo output stops
passing the trust gate (`LINT-TRUST-03`). A pilot minting its own identifiers
fails `LINT-TRUST-02` by design: copy the store, replace keys, identities and
window, and pass your copy. Full RFC 3161 / ETSI EN 319 422 timestamp
validation and EU-Trusted-List verification are production-verifier
obligations, and `evidence_lint --profile production` is a structural precheck,
not legal qualification validation. The samples are cryptographically real —
signatures verify, digests recompute — but keys, identifiers, registers and
trust store are demonstration-grade.

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

`scripts/eu_entity_uid_toolkit.py` generates a starter discovery document. Its
`med-stub` output is a **sealed artefact**, `{sm_artifact_b64, projection}` —
the authoritative COSE bytes with the JSON projection beside them — signed with
an **ephemeral key, not a QSealC**: structurally valid for experimentation,
never publishable. *Removed:
dns-zone* — an earlier revision offered DNS-based alias discovery; alias layers
cannot authorise a provider, key or endpoint, so the mechanism was withdrawn.

### Run the mock RDP, or a pilot

```sh
python3 scripts/mock_rdp.py
# server listens on http://localhost:8000
```

Send a submission:

```bash
curl -X POST http://localhost:8000/send \
    -H 'Content-Type: application/json' \
    -d '{
        "from_uid":"EU-DE-EOID-7K3D9W0Q2M5FW0",
        "to_uid":"EU-FR-PSBID-ZYWVTSRQPNM8M4",
        "payload_hash":{
            "alg":"SHA-256",
            "hex":"d8bae9a71f8d30c5cf47817ac8299037541d1a46aa1ee2edd476e3b1119ec77e",
            "hash_mode":"raw-sha256"
        },
        "mls_epoch": 3,
        "auth_method": "mls-x509"
    }'
```

The response contains `evidence_url` and `evidence_cbor_url`. Fetch the
evidence:

```bash
curl http://localhost:8000/evidence/<message_id>
```

This sequence is executed by a test that derives the body from this README, so
the document and the endpoint cannot drift apart.

The minimum pilot is deployment profile 1 of
[umbrella Annex P](Secure-Business-Messaging-Profile.md#annex-p--deployment-profiles-and-edd-staging-informative):
a static signed directory, one co-located provider, two wallets, the default
scope only, and pilot rather than qualified evidence. Sealed documents keep
their canonical `https` URLs on localhost — map endpoints wallet-side (Annex
P.3).

## Feedback

This is a **review snapshot** of a design study, exported for an expert group
and published to be challenged. Start with
[`docs/REVIEW_AGENDA.md`](docs/REVIEW_AGENDA.md): the questions this
specification does **not** yet answer — protocol, production trust and legal —
with the assumption each one rests on, and what is not yet written, the
implementer guide, carried as G1 to G4.

- **Edition.** This snapshot is the review edition `design-study-2026-09-20-r38`,
  the git tag of that name; earlier tags of this snapshot stay where they are
  and each names the edition it was cut from. Cite the tag, or the commit you
  hold, so an answer can be matched to the text it answers. The reviewer
  guide's "tag named in the README" is this one.
- **Technical feedback** — an ambiguity, a contradiction, a rule an implementer
  cannot follow, a claim you think is wrong: name the document and section, and
  ideally the artefact or command that shows it. The most useful contributions,
  in order: run the bar against a **second implementation** — the
  confirmation-signature vectors have only ever been verified by one COSE
  implementation; attack the evidence model — a construction that accepts
  something it should not is the finding worth having; challenge the legal
  argument that registered-delivery evidence can rest on digests rather than
  content.
- **Security issues:** do not describe them in public. Ask for a private
  channel first.
- **Patent disclosures** have their own route, [`IPR.md`](IPR.md) and
  [`IPR-DISCLOSURES.md`](IPR-DISCLOSURES.md); a comment is not a Contribution
  and carries no patent obligation ([`CONTRIBUTING.md`](CONTRIBUTING.md)).
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
technical exploration (see the notice above); the copyright holder acts in a
personal capacity and no institution is represented.
