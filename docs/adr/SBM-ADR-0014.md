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

Evidence must bind to the content without disclosing it — the load-bearing
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
  needs no salt of its own once its inputs are salted. Whether the Merkle
  chunk layer is salted likewise, with the chunk index in the domain, or
  left bare and said so, is a choice for the group (A12).
- **The manifest's cleartext** — attachment names, sizes and types in the
  sealed SE — is decided with A12 and not after it: either it stays and the
  metadata threat model says the providers see it, or the manifest moves
  into the envelope and the SE keeps only the manifest digest and the part
  count, at the price of the provider-side structural checks on it.
- **The mode set.** `doc_digest`, the acceptance-policy reference, is a bare
  digest of a *published* document and stays so. The content gets modes of
  its own, salted by definition and named for it — `content-sha256`,
  `content-sha512`, `content-manifest-sha256`, `content-manifest-sha512` —
  and `raw-*` / `manifest-*` are retired for content by name, as `jcs-*`
  was, with `raw-sha256` surviving for `doc_digest` alone. The set is closed
  again at the bump and every member is mandatory to implement, which is
  the condition on which A11 was closed.
- **Re-verification and mismatch.** Unchanged in shape: the recipient
  recomputes with the salt it decrypted; a missing or malformed salt is a
  mismatch by construction; the `mismatch` confirmation carries the
  recipient's recomputation. The sender declares, the provider echoes, as
  today.
- **Reveal.** No new evidence object. A dispute about content is settled as
  now, by producing the content — and its salt. The retained-bundle
  verifier gains an optional content-reveal input beside the grade and
  mandate reveals, checked against the package's `payload_hash`; without
  it a package verifies exactly as it does today.

## Alternatives considered

- **Leave the digest unsalted and state the assumption.** One paragraph in
  the Internet-Draft's security considerations and one line in the
  umbrella's metadata threat model: a bare digest is an oracle for guessable
  content, and a sender of such content should know it. No wire change,
  nothing re-sealed. Weighed, not rejected: it is the honest minimum if the
  group answers no, and it leaves the study's central claim with a
  qualification on exactly the traffic that motivates it.
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

## Status

- **Decision:** proposed — pending [A12](../REVIEW_AGENDA.md), assigned to
  applied cryptography and to QERDS operators. Accepting it is the
  maintainer's act after the group's answer; nothing in this record is in
  force.
- **Implementation:** not implemented. If accepted: evidence 2.9 → 2.10,
  application envelope 1.2 → 1.3, companion contracts 9.0.0 → 10.0.0, every
  sample carrying a `payload_hash` re-sealed, the TS revised, in one change.

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
  chunk layer, the manifest's cleartext, and the form of the construction.
