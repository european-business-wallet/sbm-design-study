<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Open items — what this design does not prove on its own

Every item below is **deliberately open**: marked in the normative text where
it applies, and, where the conformance tooling can see it, enforced as a *gap*
rather than quietly assumed. This document exists so that a reader can tell a
property this specification establishes from one it merely describes. Where a
property needs infrastructure, a legal determination or an independent party
that does not yet exist, the specification says so and narrows its claim
rather than specifying a mechanism nobody can operate.

**How this document relates to the review agenda.** This document says what
the study does *not prove*. The [review agenda](docs/REVIEW_AGENDA.md) says,
for each open *question*, what the specification currently assumes, which
claim depends on it and whose expertise would settle it. Where the two meet,
this document states the unproven claim and names the agenda entry; it does
not repeat the assumption.

---

## 1. Production PKI and the trust path

A member's confirmation key can be published with an X.509 chain, and the
reference verifier checks that the leaf certificate carries the published key
and that the certificate was valid **at the instant of the act**, so evidence
does not expire with the key that signed it. Certificate *binding* is checked;
certificate *trust* is not: path validation to a trust anchor, qualification
as a QSealC, presence on an EU Trusted List, revocation evidence and the
secure-device policy behind the key all need a production trust framework. The
reference tooling uses a demonstration trust store and says so; what a
production verifier must hold and check beyond these linters is set out, input
by input, in
[`docs/production-verifier-architecture.md`](docs/production-verifier-architecture.md).
Agenda: P1.

## 2. The federation register

The membership register is specified as an instrument of its own, with its own
contract ([`federation-register-openapi.yaml`](federation-register-openapi.yaml))
and its own signer, a **federation authority** kept apart from the design
authority that seals the demonstration directory. Admission is evaluated at the
instant of each act over the participant's recorded history; the register is
authenticated at ingress against an anchor that is configuration, never input
(`LINT-TRUST-08`); a descriptor is accepted only under the seal key the
register pins (`LINT-TRUST-07`); a provider not admitted at its act is a
violation (`LINT-TRUST-06`); and a register that is missing, or supplied with
no anchor configured, leaves admission **unestablished** and the verification
INCOMPLETE (`LINT-BND-I6`). The shipped fixtures show the mechanism — a Stage-1
register, a variant with a suspended participant, a bundle that names no
register — and admit nobody. Not established: the operation of a production
register, the admission of any real participant, and the standing of the
demonstration store, one file of demonstration keys for both the
qualification-side signers and the federation authority. Agenda: A2 (the
maximum age of a live admission decision) and A6 (the messaging service
provider's own admission, decided and not implemented).

## 3. Completeness of the policy history (transparency)

An organisation's acceptance policy is immutable once published, each version
links back to its predecessor by content digest, and the verifier recomputes
which version was in force at the act. What is not established is that the
retained chain is the *complete* one: from inside a bundle, a complete chain
and a chain with a hidden successor are byte-identical. Proving completeness
needs an authenticated log head, which needs a log — the same missing primitive
as key transparency. **This is the property the shipped bundles report as a
gap**: with the demonstration trust store they exit 3 with two unproven
properties, both this one, which is why INCOMPLETE exists as a verdict at all;
the README's [*three verdicts*](README.md#the-three-verdicts-and-the-two-invocations)
section shows both invocations. Agenda: A3.

## 4. Key transparency

Unresolved for the same reason. A published cipher-suite floor makes a
downgrade *decision* verifiable, but it does not make provider **withholding**
detectable: a provider that quietly declines to serve the stronger key
material is indistinguishable from a counterparty that does not support it.
Detecting equivocation or withholding requires a transparency mechanism with
an independent observer. Separately, the post-quantum hybrid suite, pinned to a
draft under a private-use code point, has no cross-implementation test vector.
Agenda: A4.

## 5. What a content digest conceals

**Established.** Evidence carries no content. It carries a digest of it, and
the profile salts its commitments: the grade commitment and the mandate
commitment each take sixteen fresh bytes carried in the encrypted envelope, and
a dispute object carries its salt.

**Not established.** That evidence discloses nothing about content where the
content has little entropy. `payload_hash` and the envelope `content_digest`
are **bare** digests over the plaintext, as are the per-part digests of a
multipart manifest, so a party that holds the evidence can test a guess against
them — and business correspondence on a known template, with an amount in a
narrow range, is guessable.

**Who is exposed bears stating**, because the exposure is narrower than a plain
reading suggests and not narrow enough to dismiss: it is whoever holds an
evidence object or an Evidence Package — both providers, the parties, an
archive, a verifier, a court — and it is **not** an observer of the network,
which sees no digest at all.

Raised by an external review on 25 September 2026. `SBM-ADR-0014` sets out a
construction that would answer it — a per-message salt carried in the encrypted
envelope and revealed with the content — and that record is a **proposal**
which decides nothing: it stays `proposed` and `not-implemented`, and nothing on
the wire, in a schema or in a sample changes until the question is settled.
Agenda: A12.

## 6. Authenticity of retained group material

The cipher-suite decision is verified against the roster, the key-package
availability and the suite registry **as they stood at group formation**, from
inputs whose digest the group committed. That material is retained, bound to
the evidence and checked — but its authenticity rests on the bundle carrying
it, not on a signature over it, and who publishes and updates a group's
retained state is declared as a residual. Agenda: A5.

## 7. Interoperability: a second implementation

The confirmation-signature vectors — covering all three permitted algorithms —
have been verified by one COSE implementation; a **second COSE implementation**
has never run them, so cross-implementation agreement is asserted by nobody.
More broadly, the profile-2 contracts are published so that two independent
implementations can exchange messages without private agreements, and that
exercise has not been run: the two proof-of-concept codebases are by the
specification's author, pinned to earlier editions. The study's most recent
review judged the specification not yet a frozen baseline for independent
implementations. This has no agenda entry because it is not a design question;
it is the single most useful thing an external reader can contribute.

## 8. Delivery evidence across two providers

**Carried open on purpose.** When sender and recipient use different
providers, the evidence that a message was delivered rests on a receipt the
recipient's delivery service signs when a device acknowledges the handover.
The published contracts say that whichever provider issues the delivery
evidence must verify that receipt; they do not publish how that provider
obtains it, and they name different providers as the issuer. Having the
recipient's wallet forward the receipt is not safe, because a recipient could
suppress delivery evidence by never forwarding it. Nothing in the
specification claims resistance to a malicious messaging service provider.
Agenda: A1, and beneath it A9 — who observes the handover, and what a
messaging service provider acting alone could make a registered delivery
provider attest — with three models analysed and **none chosen**.

## 9. Legal effect

Marked `TODO(legal)` in the normative text wherever it applies; questions for
counsel, not for engineering, and no legal wording has been drafted for any of
them: whether a mandatory sender signature over the submission tuple is
compatible with the provider-attestation model of Article 44(1)(b); whether an
availability-grade delivery that is final at authenticated availability but
rebuttable by a proven content-class mismatch is acceptable under Article
43(2); the legal adoption of the authentication assurance floors, currently
pilot-provisional; the legal and governance treatment of the qualified
attestation that carries the entity identifier; and the legal weight of each
combination of authentication method and assurance level behind a
wallet-signed act; and whether removing a standard from the exclusion list of the patent commitment in `IPR.md` §3 — RFC 8785, which the specification no longer references — would narrow a commitment already published, which is flagged on the agenda rather than in that document, because a patent commitment is not annotated by a maintenance pass. Above all of them, the argument that registered-delivery
evidence can rest on content digests rather than on content is carefully
constructed and **untested**; whether the statutory presumptions attach over
end-to-end encrypted traffic is exactly the question it leaves to counsel.
Agenda: L1 to L9.

## 10. Standards-owner review

The mapping of a relay-stage rejection onto the ETSI EN 319 522 event model is
the study's own reading and is pending review by the standards owner.
Interoperability with heterogeneous registered-delivery systems is
**explicitly not claimed**: homogeneous federations are addressed, and
cross-system interoperability awaits a mapping annex and a conformity
assessment body's confirmation. Agenda: A8.

---

## How these are kept honest

`TODO(legal)` markers sit in the normative text, and a documentation gate
prevents removed claims from returning. The bundle verifier distinguishes
*incomplete* from *passing*: a required property that cannot be established
yields INCOMPLETE and exit 3, the shipped bundles do, and the set of required
properties is a **declared list** the verifier iterates, so adding one fails
the build until it is wired in. Rule descriptions carry their own scope limits
where an assessor reads them. Every open question has one home, the review
agenda; the decision records name the agenda entry a choice rests on and stop
there.
