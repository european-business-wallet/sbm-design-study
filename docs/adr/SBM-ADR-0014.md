---
id: SBM-ADR-0014
title: "The content digest as a salted commitment"
label: "Salted content digest"
decision_status: proposed
implementation_status: [not-implemented]
implementation: >-
  not implemented; proposed on 26 September 2026, pending [A12](../REVIEW_AGENDA.md) — nothing on the wire, in a schema or in a sample changes until the question is decided
choice: >-
  `payload_hash` and the envelope `content_digest` become a salted commitment — a per-message salt carried only in the encrypted
  envelope, revealed with the content — in modes named for the content; `doc_digest` stays a bare digest of a published document ·
  no owner yet; the I-D, *Canonicalisation and Payload Hashing* and *Application Envelope*, would own it
alternative: >-
  leave the digest unsalted and state the assumption it rests on; derive the salt from the MLS exporter secret; reuse the grade
  commitment's salt — the first two weighed below, the third rejected
benefit: >-
  a guess about the content cannot be confirmed from the evidence alone: the salt, not the content's entropy, stands between
  the digest and a dictionary
cost: >-
  both wallets retain the salt with the content, or a package can no longer be tied to a document; an evidence bump with every
  sample re-sealed — the parties, the implementers, and whoever holds a package without the parties
open_questions: [A12]
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0014 — The content digest as a salted commitment

**Proposed, not accepted.** This record extends [SBM-ADR-0009](SBM-ADR-0009.md),
*Commitments before reveals*, to the one binding that record leaves bare: the
content digest. It sets out the construction that would answer
[A12](../REVIEW_AGENDA.md) so that the question can be put to the reviewers
it is assigned to with a concrete proposal in hand. It decides nothing: the
profile's `payload_hash` is unsalted until A12 is closed, and no document,
schema, sample or test changes on the strength of this record.

## Context

Evidence carries `payload_hash`, a digest of the plaintext declared by the
sender and echoed by the registered delivery provider into every evidence
object and, transitively, every Evidence Package; the application envelope
carries the same value as `content_digest`, and the recipient wallet
recomputes it before acknowledging. The digest is unsalted. The profile's
other bindings to things it must not disclose — the availability grade's
content class and an agent act's mandate — are salted commitments, with
sixteen bytes of fresh salt per message that travel only in the encrypted
envelope, precisely so that an observer cannot dictionary-test them.

The same observer can dictionary-test the content digest: anyone holding an
evidence object or a package — both providers, the parties, an archive, a
court — can confirm a guess about the content by recomputing. For
high-entropy content that is idle; for guessable content — an invoice on a
known template, an order confirmation whose only variable is an amount in a
narrow range, a standard notice — the digest is an oracle. The traffic this
profile is written for is largely of the second kind. Under Mode C the
disclosure is wider still: the multipart manifest travels in the sealed SE
with each part's unsalted digest, length, media type and, optionally, file
name.

The documents say the evidence carries digests and never content, which is
true, and do not say which kind of content the bare digest is safe for. The
question was raised by the publication review of 25 September 2026 and
recorded as A12; a test forbids any document from asserting an answer.

## Requirement and constraint

Evidence must bind to the content without carrying it — the load-bearing
claim of the study — for the content the profile is actually used to carry,
not only for content with enough entropy to defend itself. The binding must
stay checkable by anyone who holds the content: the recipient before
acknowledging, a party in a dispute, an assessor. It must not depend on
material only the providers hold, and it must not reuse a secret whose
reveal is already part of another dispute path.

## Decision

Proposed, pending A12:

- **Construction.** For a Mode A payload,
  `payload_hash.hex = hex(SHA-256(dCBOR([ "sm-mls:content-digest:v1", salt, octets ])))`
  — the typed, domain-separated array form every other commitment in the
  profile uses since the octet-authoritative inversion, with `salt` a
  sixteen-byte string and `octets` the transmitted payload octets as a byte
  string; SHA-512 likewise. The envelope `content_digest` is the same value,
  and the equality rule between the two is unchanged.
- **Salt.** A new envelope field, `content_digest_salt`, sixteen bytes of
  cryptographically random, fresh per-message salt, lowercase hex, under the
  same rule as the two existing salts: it never leaves the encrypted
  envelope except by deliberate reveal. It is a salt of its own, not the
  grade commitment's, because a grade dispute reveals that salt and must not
  hand back the content oracle with it.
- **Mode C.** Each part digest is the same construction with the part's
  identity in the domain — `[ "sm-mls:content-part-digest:v1", salt,
  part_id, part_octets ]` — so equal parts in different positions differ and
  a guessed part cannot be confirmed across messages; the manifest digest
  needs no salt of its own once its inputs are salted, and it stays
  recomputable by anyone holding the artefact, which is what `LINT-MAN-04`
  checks. **There is no chunk layer to decide about.** An earlier draft of
  this record asked the group whether a chunked part's Merkle root should be
  salted with the chunk index in the domain; that construction was withdrawn
  on 27 September 2026 and none is profiled ([A13](../REVIEW_AGENDA.md)). A
  part's octets are reassembled before hashing whatever framing carried them,
  so its digest is the construction above like any other. **A13 closed on
  27 September 2026** on the ground that the profile has no chunked part: the
  framing operation it defines acts on the envelope, and nothing splits a
  manifest part. If a later revision ever introduces one, whether its chunks are
  salted is decided **there**, after the descriptor and the evidence that would
  make a chunk an object at all — not carried here as a question about something
  the profile does not have.
- **One salt per message means one opening per message.** Every part commitment
  takes the message's `content_digest_salt`, so a reveal that proves one
  attachment hands over the value that lets its holder test candidates against
  **every other part digest in that message**. Domain separation by `part_id`
  does not prevent it: it stops a guessed part being confirmed across messages
  and in other positions, which is what it is for, and it cannot help once the
  salt itself is known. A dispute about one invoice therefore opens the
  multipart message it travelled in. This record does not promise selective
  opening, so this is a trade-off to decide with A12 and not a defect in the
  construction: **whole-message opening**, which is what is proposed and is
  simpler to implement and to reason about, or **an opening secret per part** —
  sixteen bytes each, carried in the envelope beside the manifest, at the cost of
  a larger envelope and a reveal procedure that has to say which parts it opens.
- **The manifest's cleartext** — attachment names, sizes and types in the
  sealed SE — is decided with A12 and not after it: either it stays and the
  metadata threat model says the providers see it, or the manifest moves
  into the envelope and the SE keeps only the manifest digest and the part
  count, at the price of the provider-side structural checks on it. **Those
  checks are three named rules, not a hypothetical**: `LINT-MAN-01` (part-id
  uniqueness), `LINT-MAN-02` (canonical byte-wise ascending order) and
  `LINT-MAN-04` (`payload_hash` is the digest of the manifest the artefact
  carries). Moving the manifest into the envelope puts all three out of reach
  of anyone but the two wallets, including the retained-bundle verifier, and
  `LINT-MAN-04` is the one that caught a hand-typed digest shipping through
  the Schema, the CDDL and the seal. The group should price that, not a
  general notion of structural checking.
- **The mode set — and what the digest domains already settled.** This
  bullet was written before the per-field domains existed, and half of what
  it proposed is now done. Since 27 September 2026 each digest field has a
  named type: the content fields take `ContentHash`, a part's digest
  `RawHash`, and `doc_digest` and `submission_hash` `RawSha256Hash`. So
  **keeping `doc_digest` bare needs no global retirement of a mode**: its
  domain already admits nothing else, and no rename is required to stop a
  content mode reaching it.

  **What remains is NOT confined to `ContentHash`, and an earlier draft of this
  bullet said it was.** That draft named `RawHash` as a part's type in one
  sentence and proposed adding the salted modes to `ContentHash` alone in the
  next. The two cannot both hold: the Mode C bullet above salts **each part's
  digest**, `Manifest.items.digest` references `RawHash` directly, and `RawHash`
  admits `raw-sha256` and `raw-sha512` over the part's bare octets and nothing
  else. An implementer following the earlier text would have left the per-part
  digests bare — preserving exactly the oracle this record exists to close, one
  level down, for the payloads whose metadata is most exposed — or put a salted
  construction under a `raw-*` label and changed what that label means. **Two
  domains move, not one**: the content fields, and the part digest, each with
  modes of its own; `doc_digest` and `submission_hash` stay bare for the reasons
  set out below. Naming the content modes for the content (`content-sha256`,
  `content-sha512`, `content-manifest-sha256`, `content-manifest-sha512`)
  remains the proposal, because a mode's name is what an artefact carries and
  a reader should not have to know the field's type to know whether a salt is
  in the construction; **retiring `raw-*` and `manifest-*` "for content by
  name", as `jcs-*` was, is not the mechanism any more** — narrowing
  `ContentHash`'s enum is, and the resolved-shapes gate will name every
  version dimension that narrowing reaches. Either way the set is closed
  again at the bump and every member is mandatory to implement, which is the
  condition on which A11 was closed.

  **What a migration touches**, so that acceptance is priced against the whole
  of it and not against one type:

  | Domain | Field(s) | Today | Under this proposal |
  |---|---|---|---|
  | Content | `payload_hash`, envelope `content_digest` | `ContentHash` | salted modes added; whether the bare ones leave is the decision |
  | Observed octets | `Manifest.items.digest` | `RawHash` | **a part commitment type of its own**, with a part-salted mode; `RawHash` keeps its meaning |
  | SHA-256 pinned | `doc_digest`, `submission_hash` | `RawSha256Hash` | **unchanged, deliberately** — a published document and pre-parse octets |
  | Transmitted octets | `envelope_hash`, `mls_state`, the seal imprint | fixed types, no selector | **unchanged** — recomputed by parties without the plaintext |

  and, beyond the types: the `Manifest` definition and the CDDL beside it, the
  recipient's Mode C re-verification, the sample generator, the published
  vectors, and every version dimension the resolved-shapes gate names for the
  two types that move.
- **What stays bare, by construction and not by oversight.** Four other
  digests are outside this proposal for a reason that is not a preference.
  `envelope_hash`, `mls_state` and the seal's own imprint are commitments
  over **transmitted octets that a party without the plaintext must be able
  to recompute independently** — the sending RDP at acceptance, every
  relaying RDP, the receiving RDP, and a verifier reading a retained
  package. A salt confined to the encrypted envelope would put each of those
  recomputations out of reach and would remove the only integrity check the
  relay path has.

  **`submission_hash` is the fourth, and its case is the sharpest.** The
  Internet-Draft requires SHA-256 over the **exact submitted octets as
  received at the intake boundary, before any parsing or decoding** — for a
  request the provider may never have parsed and certainly never decrypted.
  A salt that lives inside an encrypted envelope is unreachable there by
  definition, so a salted construction would leave an intake rejection unable
  to carry a digest at all. An earlier draft of this record omitted it, which
  is how a boundary drawn from memory rather than from the field list fails.

  `doc_digest` is bare for the different reason already given: the document
  it commits to is published. A reader who takes this record as the pattern
  for salting digests should take these five as the boundary of it — and
  should notice that the boundary is drawn **per semantic field**, not by
  retiring a mode globally. That was the same inventory the generic `Hash`
  type needed, and the two were done together: the domains were separated on
  27 September 2026, so this list is no longer a list this record has to
  keep — each field's type states its domain, and this boundary is readable
  from the schemas rather than from a paragraph.
- **Re-verification.** Unchanged in shape *where a salt is present*: the
  recipient recomputes with the salt it decrypted, the `mismatch`
  confirmation carries that recomputation, the sender declares and the
  provider echoes, as today.
- **A missing salt is not a mismatch, and this record must not say it is.**
  An earlier draft said a missing or malformed salt was "a mismatch by
  construction". It cannot be. The construction above needs a sixteen-byte
  salt; without one the recipient computes nothing, and a `mismatch`
  confirmation asserts a comparison that **was made** — the Internet-Draft
  says so in terms, and adds that the profile defines no reason for one that
  was not. A wallet asked to report a mismatch it could not perform would
  have to invent a digest or default a salt, and either is a false statement
  under the recipient's own key.

  **This is the defect A11 was closed to remove.** A11 closed because no
  receiver can meet a mode it has not implemented: the set is closed and
  every member is mandatory. Salting the content digest opens a *new* way for
  a receiver to be unable to compute — a salt absent, of the wrong type or of
  the wrong length, in an envelope it decrypted successfully — and calling
  that a mismatch reintroduces the false speech A11 forbade, one field along.

  So before this is accepted, four cases must be deterministic and
  **distinguishable**: salt absent; salt present but not a sixteen-byte
  value; salt well-formed and the digest different; and the ordinary match.
  The first two are post-decryption failures of the envelope's own contents,
  attributable to the recipient, and the profile has no outcome for them
  today. **`malformed-envelope` must not be reused**: the registry binds it
  to `A.2-SubmissionRejection` and `B.3-RelayFailure` — an intake stage and a
  relay stage, where nothing has been decrypted and no recipient has spoken.
  What the outcome is — which reason code, which event, which object carries
  the recipient's proof — is part of what the group decides with A12, and is
  not decided here.
- **Reveal.** No new evidence object. A dispute about content is settled as
  now, by producing the content — and its salt. The retained-bundle
  verifier gains an optional content-reveal input beside the grade and
  mandate reveals, checked against the package's `payload_hash`; without
  it a package verifies exactly as it does today.

## Alternatives considered

- **Leave the digest unsalted and state the assumption.** **This alternative
  has been executed**, which changes what A12 now asks. The Internet-Draft
  carries the paragraph since 27 September 2026 — *Guessable content behind an
  unsalted digest*: who can test a guess (the parties, both providers, an
  archive, a verifier, a court — whoever holds an evidence object or a
  package), who cannot (an observer of the network, which sees no digest), and
  what an implementation handling low-entropy content should do about it. The
  umbrella's consolidated threat model, which that paragraph defers to for the
  residual risks, omitted it and now carries it. No wire change, nothing
  re-sealed.

  So the question is no longer "document it or change it" but **"is the
  documented assumption enough?"** Answering no to A12 leaves the study's
  central claim standing with a qualification on exactly the traffic that
  motivates it, stated in both documents and on the agenda, and costs nothing
  further. Answering yes buys evidence from which a guess cannot be confirmed
  without the parties, at the price set out above. That is the choice, and it
  is a narrower one than this record was first written for.
- **Derive the salt from the MLS exporter secret.** No envelope field and
  no new retention duty, since any group member can re-derive it. Weighed,
  not rejected: it ties the content binding to retained MLS key material,
  which is the territory of [A5](../REVIEW_AGENDA.md) and of the custody
  note's hardest cases, and a third party given content and salt cannot
  check the derivation.
- **Reuse the grade commitment's salt.** Rejected: the grade's dispute path
  reveals that salt to the dispute's parties, who would then hold the
  content oracle for that message.
- **A keyed construction (HMAC over the octets with the salt as key)**
  instead of the dCBOR array. Not rejected: equivalent in effect, different
  in shape from the profile's other commitments; a question of form for the
  cryptographers the agenda names.

## Trade-off

Evidence from which a guess about the content cannot be confirmed without
the parties' cooperation, at the price of a package whose reach without that
cooperation shrinks: a holder of the document proves the binding only with the salt,
which lives only in the two wallets. And the price of the change itself — an
evidence bump, the envelope and the companion contracts with it, every sample
carrying a `payload_hash` re-sealed, and a sample generator that must compute
digests from fixture content rather than carry them as constants.

## Consequences and residual limit

Both wallets would retain `content_digest_salt` with the message for as long
as they retain the content: a retention duty to be written into the
Internet-Draft, the TS's retention clause and the custody note. A lost salt
leaves a package that still proves who sent which commitment to whom and
when, and no longer lets its holder tie it to a document. What the documents
may say moves one notch, from "carries a digest of the content" to "carries a
salted commitment to the content, which discloses nothing about it without
the salt", and the test that forbids the over-claim today would be inverted
to require the precise one. Whether a salted digest still reads, for a
conformity assessor, as the integrity binding that EN 319 522's M02 and
Article 44(1)(d) expect is a question for counsel and stays flagged; it is
not answered here. The two proof-of-concept codebases are pinned to earlier
editions and do not break; their re-pin grows by this.

**No reinterpretation of already-issued evidence.** If this is accepted, an
artefact sealed under an earlier edition keeps the meaning it had when it was
sealed:
its `payload_hash` is a bare digest, it is verified by the rules of the
edition it was sealed under, and
acceptance neither invalidates it nor makes it verifiable under the new
construction. A later edition does not reach backwards. Nothing is re-sealed
except this repository's own samples, which are illustrations and not
evidence anyone holds. This is the rule the umbrella §13.4 already writes for
registry actions — they *"MUST NOT change the meaning of already-issued
evidence or already-sealed discovery documents"*, and what would is a
versioned change instead — applied to the versioned change itself: the route
§13.4 points at is prospective, or the distinction it draws would be empty.
A record that proposes changing what a digest *is* is where that has to be
said.

## Status

- **Decision:** proposed — pending [A12](../REVIEW_AGENDA.md), assigned to
  applied cryptography and to QERDS operators. Accepting it is the
  maintainer's act after the group's answer; nothing in this record is in
  force.
- **Implementation:** not implemented. If accepted, the cost is **one evidence
  minor, one application-envelope minor and one companion-contracts major**,
  from whatever editions are in force on the day it is accepted — with every
  sample carrying a `payload_hash` re-sealed and the TS revised, in one change.
  Stated as a relation and not as four numbers: this paragraph named the
  editions of the day it was written and went stale three times in two days, on
  every pass that moved one of them. `versions.json` is where the editions in
  force are read.

## Supersedes

Nothing. Extends SBM-ADR-0009, whose decision that evidence binds the
content digest stands; this record changes what the digest is, not that it
is bound.

## Normative owner

None yet. If accepted: the Internet-Draft, *Canonicalisation and Payload
Hashing* and *Application Envelope*; the CDDL under `cddl/`; the TS for the
retention clause and the ICS rows.

## Open questions

- [A12](../REVIEW_AGENDA.md): whether the content digest should be salted at
  all — this record is the proposal, not the answer — and, within it, the
  manifest's cleartext, the form of the construction, the outcome for a salt that
  cannot be used, and whether opening is per message or per part. The chunk layer was a fourth item here until
  [A13](../REVIEW_AGENDA.md) closed on 27 September 2026; there is no chunked
  part, so there is nothing of it to salt.
