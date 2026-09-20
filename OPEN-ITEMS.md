<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Open items — what this design does not prove on its own

Every item below is **deliberately open**. Each is marked in the normative text
where it applies, and several are enforced as *gaps* by the conformance tooling
rather than quietly assumed. This document exists so that a reader can tell the
difference between a property this specification establishes and one it merely
describes.

The pattern is consistent: where a property needs infrastructure, a legal
determination or an independent party that does not yet exist, the
specification says so and narrows its claim, rather than specifying a mechanism
nobody can operate.

**How this document relates to the review agenda.** This document says what the
study does *not prove*. The [review agenda](docs/REVIEW_AGENDA.md) says, for
each open question, what the specification currently assumes in the meantime,
which claim depends on it and whose expertise would settle it. Where the two
meet, this document states the unproven claim and names the agenda entry; it
does not repeat the assumption in its own words.

---

## 1. Production PKI and the trust path

**What works.** A member's confirmation key can be published with an X.509
chain; the reference verifier parses the chain, checks that the leaf
certificate actually carries the published key, and evaluates the certificate's
own validity window **at the instant of the act being verified** rather than at
verification time — so evidence does not expire with the key that signed it.

**What is not established.** Path validation to a trust anchor, qualification
of the certificate as a QSealC, its presence on an EU Trusted List, revocation
evidence, and the secure-device policy behind the key. These require a
production trust framework; the reference tooling uses a demonstration trust
store and says so. What a production verifier must hold and check beyond these
linters is set out, input by input, in
[`docs/production-verifier-architecture.md`](docs/production-verifier-architecture.md);
the production trust question is P1 on the agenda.

**Consequence for a reader.** Certificate *binding* is checked. Certificate
*trust* is not. The distinction is written into the rule descriptions where an
assessor reads them.

## 2. The federation register

**What works.** The membership register is specified as an instrument of its
own, distinct from the directory: its own contract
([`federation-register-openapi.yaml`](federation-register-openapi.yaml)), its
own signer — a **federation authority**, kept apart from the design authority
that seals the demonstration directory — and a record per participant that
pins the seal key of the participant's own signed descriptor. A Stage-1
demonstration register is shipped, sealed by that separate authority
([`samples/federation.stage1.demo.json`](samples/federation.stage1.demo.json)),
with a variant in which a participant is suspended
([`samples/federation.suspended.demo.json`](samples/federation.suspended.demo.json)),
and a bundle that names no register at all
([`samples/bundle.no-register.manifest.json`](samples/bundle.no-register.manifest.json)).
Admission is evaluated **at the instant of each act**, over the participant's
recorded history, never at verification time. Two rules fail closed: a register
is authenticated at ingress, against an anchor that is configuration and never
part of the input, before any status or key in it is read (`LINT-TRUST-08`);
and a provider's descriptor is accepted only if its seal key is the one the
register pins to that participant (`LINT-TRUST-07`). A provider the register
does not admit at the instant of its act is a violation (`LINT-TRUST-06`); a
register that is missing, or supplied with no anchor configured, leaves
admission **unestablished** rather than refuted, and the verification is
INCOMPLETE (`LINT-BND-I6`).

**What is not established.** The operation of a production register; the
admission of any real participant to anything; and the standing of the
demonstration trust store, one file of demonstration keys for both the
qualification-side signers and the federation authority, which proves nothing
about either kind of production trust material. A demonstration register admits
nobody: it shows the mechanism. The
maximum age a live admission decision should accept is agenda question A2. The
messaging service provider's own admission — its identifier on the wire, and
the binding of delivery evidence to what it observed — is decided and **not
implemented**: agenda question A6.

## 3. Completeness of the policy history (transparency)

**What works.** An organisation's acceptance policy is immutable once
published; each version links backwards to its predecessor by content digest;
the verifier recomputes which version was in force at the moment of the act
and rejects evidence pinned to a version that was not.

**What is not established.** That the retained chain is the *complete* one.
From inside a bundle, a complete chain and a chain with a hidden successor are
byte-identical — there is no local evidence that distinguishes them. Proving
completeness needs an authenticated log head, which needs a log, which is the
same missing primitive as key transparency. Agenda question A3.

**This is the property the shipped bundles report as a gap.** With the
demonstration trust store configured they exit 3 with two unproven properties,
both this one; the verifier states that maximality is not proven instead of
passing, which is why INCOMPLETE exists as a verdict at all. The README's
[*three verdicts*](README.md#the-three-verdicts-and-the-two-invocations) section
shows both invocations.

## 4. Key transparency

Related to the above and unresolved for the same reason. A published
cipher-suite floor makes a downgrade *decision* verifiable, but it does not
make provider **withholding** detectable: a provider that quietly declines to
serve the stronger key material is indistinguishable from a counterparty that
does not support it. Detecting equivocation or withholding requires a
transparency mechanism with an independent observer. The post-quantum hybrid
suite, pinned to a draft under a private-use code point, has no
cross-implementation test vector: agenda question A4.

## 5. Authenticity of retained group material

Verification of the cipher-suite decision uses the counterparty roster, the
per-device key-package availability and the suite registry **as they stood at
group formation**, from inputs whose digest the group committed. That material
is retained, bound to the evidence and checked — but its authenticity rests on
the bundle carrying it, not on a signature over it, and who publishes and
updates a group's retained state is declared as a residual: agenda question A5.

## 6. Interoperability: a second implementation

The confirmation-signature vectors — covering all three permitted algorithms —
have been verified by one COSE implementation; a **second COSE
implementation** has never run them. Cross-implementation agreement is
asserted by nobody. This is the single most useful thing an external reader
can contribute, and it is the reason the specification does not claim
demonstrated interoperability for that surface.

More broadly, the profile-2 contracts are published precisely so that two
independent implementations can exchange messages without private agreements.
That exercise has not been run. The study's most recent review was conducted
as an independent-implementation review, and its own judgment was that the
specification is not yet a frozen baseline for independent implementations;
the title of that review does not close this item.

## 7. Delivery evidence across two providers

**Carried open on purpose.** When sender and recipient use different providers,
the evidence that a message was delivered rests on a receipt the recipient's
delivery service signs when a device acknowledges the handover. The published
contracts say that whichever provider issues the delivery evidence must verify
that receipt; they do not publish how that provider obtains it, and they name
different providers as the issuer. Having the recipient's wallet forward the
receipt is not safe, because a recipient could suppress delivery evidence by
never forwarding it. The maintainer recorded this open rather than closing it,
and the two subsequent reviews restated that it is. It is agenda question A1,
and the observer question beneath it — who observes the handover, and what a
messaging service provider acting alone could make a registered delivery
provider attest — is A9, with three models analysed and **none chosen**.
Nothing in the specification claims resistance to a malicious messaging
service provider.

## 8. Legal effect

Marked `TODO(legal)` in the normative text wherever it applies. These are
questions for counsel, not for engineering, and no legal wording has been
drafted for any of them; they are L1 to L8 on the agenda, each with the
assumption the specification currently rests on:

- whether a mandatory sender signature over the submission tuple is compatible
  with — and preferably strengthens — the provider-attestation model of
  Article 44(1)(b);
- whether an availability-grade delivery that is final at authenticated
  availability but rebuttable by a proven content-class mismatch is acceptable
  under Article 43(2);
- the legal adoption of the authentication assurance floors, which are
  currently pilot-provisional;
- the legal and governance treatment of the qualified attestation that carries
  the entity identifier;
- the legal weight of each combination of authentication method and assurance
  level behind a wallet-signed act.

The broader legal argument — that registered-delivery evidence can rest on
content digests rather than on content — is carefully constructed and
**untested**; whether the statutory presumptions attach over end-to-end
encrypted traffic is exactly the question it leaves to counsel. The first
conformity assessment of any such binding will set precedent.

## 9. Standards-owner review

The mapping of a relay-stage rejection onto the ETSI EN 319 522 event model is
the study's own reading and is pending review by the standards owner.
Interoperability with heterogeneous registered-delivery systems is
**explicitly not claimed**: the specification publishes a claim matrix stating
that homogeneous federations are addressed and cross-system interoperability
awaits a mapping annex and a conformity assessment body's confirmation. Agenda
question A8.

---

## How these are kept honest

- `TODO(legal)` markers sit in the normative text, not in a side document, and
  a documentation gate prevents removed claims from returning.
- The bundle verifier distinguishes *incomplete* from *passing*: a required
  property that cannot be established yields INCOMPLETE and exit 3, and the
  shipped bundles do.
- The set of properties a complete verification must establish is a
  **declared list** the verifier iterates, so adding a property fails the build
  until it is wired in.
- Rule descriptions carry their own scope limits, where an assessor reads them
  rather than in a footnote.
- Every open question has one home, the review agenda; the decision records
  name the agenda entry a choice rests on and stop there.
