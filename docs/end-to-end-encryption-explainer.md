<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# What "end-to-end encrypted" means in this profile

## A detailed explanation

**Status:** informative companion, draft for discussion · **Applies to:** Secure Business Messaging Profile (SBM) spec set, at the versions in the README's version table (not restated here, so they cannot drift) · **Audience:** technical, legal and privacy readers

> **Exploratory design study — not an official proposal.** This note explains; it specifies nothing. Where it and a normative document differ, the normative document governs, and §9 says which one owns each claim.

---

"End-to-end encrypted" is a phrase that has been used for enough different
arrangements that it no longer tells a reader what they get. This note says what
it buys **here**: which parties can read what, which properties the construction
supplies, which it does not, and the two places where the design deliberately
lets something be learnable.

## In brief — the properties, and the four that surprise people

*The short version. Everything after it is the detail, for a second reading.*

| Property | What supplies it | What it does **not** give |
|---|---|---|
| Only group members read content | MLS (RFC 9420): the provider routes ciphertext and holds no content key | protection from a member, or from a compromised member device |
| The sender of a message is authenticated | the sender's MLS leaf signature | that the human the device belongs to intended it ([L4](REVIEW_AGENDA.md)) |
| Membership is authenticated, and inspectable | MLS credentials, and the roster the counterparty enumerates before sending | that the roster you read is the roster at the instant of the act, unless you retained it |
| Forward secrecy and post-compromise security, **per epoch** | MLS epochs | anything about a message already queued when the epoch changed (§7) |
| The content class is hidden until a reveal | a salted commitment carried only in the encrypted envelope | hiding it from the parties to a dispute, who see the reveal |
| The content *digest* is bound to the evidence | `payload_hash` over the transmitted plaintext octets | **secrecy of guessable content: the digest is unsalted and confirms a guess** (§4) |

The four that surprise people, stated once:

1. **The ends are devices, not entities.** Every device of both entities is a
   leaf of the group, so "encrypted to the recipient" means encrypted to all of
   them (§1).
2. **The address is not the encryption boundary.** A message addressed to one
   member is readable by the whole group it was sent into — a records or archival
   function among them, visibly (§6).
3. **The digest is an oracle for guessable content.** Not a defect of the
   encryption: a consequence of binding evidence to content nobody may read
   (§4).
4. **The provider learns more on the four-corner path than on the single-provider
   one** — not plaintext, but the origin's sealed evidence (§2).

## 1. The ends are devices, not entities

The group is per pair of entities, per confidentiality scope, and **every device
of both entities is a leaf** ([SBM-ADR-0003](adr/SBM-ADR-0003.md)). There is no
entity-level key that a device borrows: the leaves are the ends.

Three consequences a reader should hold on to:

- Enrolling a device widens the set that can read **future** messages. A device
  added by an Add and a Commit receives the group's secrets from the epoch it
  joined, not from earlier ones, so it cannot decrypt traffic that preceded it.
  Read the Internet-Draft's *sender multi-device continuity* with that in mind:
  thread history is available on the member's devices **that were in the group
  when the traffic flowed**, and a replacement device joining later is not among
  them. Recovering content for a replaced device is a wallet-side retention
  question, not something the encryption provides.
- Removing a device — a departure, a retirement, a compromise — narrows the set
  for everything after. A member binding that is suspended or retired fails the
  member closed at the directory and triggers removal from the group
  ([SBM-ADR-0006](adr/SBM-ADR-0006.md)).
- A message is addressed to a **member**, and the addressing is a matter for the
  evidence and the acceptance policy. It is not what decides who can decrypt.
  That is §6, and it is the point most often read the other way round.

## 2. What the provider can and cannot see

The provider operates the Delivery Service as part of its qualified service
([SBM-ADR-0015](adr/SBM-ADR-0015.md)), and it routes ciphertext. It holds no
content key — the property the whole legal argument rests on, which is why a
server-side group was rejected rather than merely not chosen
([SBM-ADR-0003](adr/SBM-ADR-0003.md), *Alternatives considered*).

What it does see, on the ordinary path: entity identifiers, group identifiers,
message sizes and times. Not the plaintext, and **not the `content_class`**,
which travels only inside the encrypted envelope. MLS group identifiers are
opaque and carry no entity identity of their own.

What it sees in addition on the **four-corner** path, where the two
correspondents are customers of different providers: the recipient-side provider
is handed a submission stating the origin **and that provider's sealed Sending
Evidence**, which it decodes and verifies in order to prove the origin namespace
and refuse a spoofed one. With one provider role that is a provider reading
evidence fields it already holds; what remains is what the recipient-side
provider learns about the originating one. No collusion is assumed, and this is
the price of refusing a forged origin rather than an oversight.

Two other parties see something: the directory sees resolution queries, and the
timestamping authority sees timing only, over seal hashes. A verifier of an
Evidence Package sees everything the package carries — which is why the
package's fields are the ones minimised, not the message's.

## 3. Two layers, and what each one protects

The encryption is one layer; the thing it carries is another, and the evidence
binds to both.

- **The MLS application message** is the ciphertext. The evidence commits to a
  digest of the **transmitted octets** of that ciphertext (`envelope_hash`), and
  to the group state at the act (`mls_state`, `mls_epoch`). Any party on the
  path can recompute those without holding a content key — which is exactly why
  they are not salted (§4).
- **The application envelope** is inside the ciphertext. It carries the content
  digest and the salt of any commitment, and it is the reason the content class
  is invisible on the wire.

So there are two digests with two different jobs. One identifies *the bytes that
travelled*, and every relaying party must be able to check it. The other
identifies *the content*, and only a party holding the content can check it.
Confusing them is how a reader concludes either that the provider could read the
message or that the evidence proves more than it does.

## 4. The content digest, and why it is unsalted

Evidence must bind to content that nobody on the path may read. It does that
with `payload_hash`, a digest over the plaintext's transmitted octets, which the
recipient's wallet recomputes after decryption and confirms.

A digest is not a cipher. **Anyone holding an evidence object or a package can
take a guess at the content, hash it, and see whether it matches**: both
providers, either party, an archive, an assessor, a court. For content with real
entropy that is useless. For content drawn from a small set — an invoice on a
known template whose only variable is an amount in a narrow range, a standard
notice — it **confirms** the guess.

This is not a flaw in the encryption. The encryption did its job: no observer of
the network sees a digest at all. It is the cost of the binding, and it falls on
whoever holds the evidence.

**Why it is not salted today, and what is proposed.** The profile's other
bindings to things it must not disclose *are* salted commitments: the
availability grade's content class, and an agent act's mandate. Those are opened
by an explicit reveal, in a dispute, to the parties to it
([SBM-ADR-0009](adr/SBM-ADR-0009.md)). The content digest is not one of them.
[A12](REVIEW_AGENDA.md) is the open question of whether it should be, and
[SBM-ADR-0014](adr/SBM-ADR-0014.md) sets out a construction that would answer it
— a per-message salt carried only in the encrypted envelope and disclosed with
the content.

That record is **proposed and not implemented.** Today `payload_hash` is a bare
digest, and no document, schema or sample behaves otherwise. The reason the
question is not simply closed by salting everything is in that record's own cost:
both wallets would have to retain the salt alongside the content, or a package
could no longer be tied to the document it is about — and a salt that lives
inside an encrypted envelope is unreachable to a party that never decrypted,
which is every relaying provider. Three other digests stay bare for that reason,
by construction: the transmitted-octet commitments each relaying party must
recompute independently.

Under the multipart mode the exposure is wider and worth naming separately: the
manifest travels in the sealed Sending Evidence with each part's own digest,
length, media type and, optionally, its file name.

What is written down rather than left to be noticed: the Internet-Draft carries
*Guessable content behind an unsalted digest* — who can test a guess, who cannot,
and what an implementation handling low-entropy content should do about it.

## 5. The commitments that *are* hidden

Where the design needs to bind to something it must not disclose, it uses a
salted commitment rather than a digest
([SBM-ADR-0009](adr/SBM-ADR-0009.md)):

- the **grade commitment**, which binds the content class an availability-grade
  delivery was declared for;
- the **mandate commitment**, which binds the mandate an agent acted under.

Each carries fresh salt per message, inside the encrypted envelope, and is opened
only by an explicit reveal. A matching reveal shows the commitment opens to that
class. A failing reveal **proves nothing on its own** — it starts a dispute, and
neither outcome changes the delivery. And a reveal discloses the class to the
parties to that dispute: the commitment buys secrecy until then, not secrecy
afterwards.

One subtlety, because it limits the first bullet: a cleartext scope reference,
resolved against a published scope map, can narrow the class before any reveal —
and a scope covering a single class gives it away. The commitment hides which
class **within what the scope already admits**.

## 6. The address is not the encryption boundary

A message is addressed to a member. It is encrypted to a **group**. Those are
different sets, and the second is the one that can read it.

Where an organisation gives a records or archival function access, that function
is a **visible leaf of the roster**, not a silent capability
([SBM-ADR-0010](adr/SBM-ADR-0010.md)): the counterparty resolves the member set
through the enumeration surface before sending, so the audience is knowable in
advance rather than discovered afterwards. That is the deliberate trade — a
larger visible audience than strict confidentiality would allow, in exchange for
no undisclosed decryption capability anywhere.

Confidentiality scopes narrow the set where a deployment adopts them, and they
are optional, so the minimum deployment has one group per entity pair. Cross-
entity scope agreement follows the recipient's scope descriptor.

The practical reading for a sender: **check who is in the group, not who is in
the `To` field.**

## 7. Epochs: what changes when membership does

MLS forward secrecy and post-compromise security hold **per epoch**. An epoch
changes when membership does, and two consequences matter to this profile:

- A message already **queued** is not re-encrypted by an epoch change. It
  remains what it was when it was submitted.
- A resubmission after an epoch change is a **new submission**, with a new
  evidence chain. It is not a retry of the old one.

So "the device was removed" and "the message the device could read is gone" are
different statements, and only the first is true. The window is the
compromise-latency question the wallet assurance profile bounds
([`docs/wallet-assurance-profile.md`](wallet-assurance-profile.md)), not
something the encryption closes by itself.

## 8. What end-to-end encryption does not give

Stated plainly, because each of these has been read as following from it:

- **It does not make delivery evidential.** The delivery states, the
  confirmations and the evidence objects are this profile's, not MLS's
  ([`docs/evidence-layer-explainer.md`](evidence-layer-explainer.md)).
- **It does not hide metadata.** Identifiers, sizes and times are observable to
  the provider by construction (§2).
- **It does not protect against the endpoint.** A signature attributes a
  statement to a device; it does not show the device behaved honestly. That
  assumption lives in the wallet assurance profile
  ([SBM-ADR-0006](adr/SBM-ADR-0006.md)).
- **It does not stop a recipient disclosing** what they lawfully received.
- **It does not make the provider's observations resistant to the provider.**
  The availability grade rests on the Delivery Service's own signed receipt, and
  the Delivery Service is the qualified provider's own — settled, not removed
  ([A9](REVIEW_AGENDA.md), resolved by
  [SBM-ADR-0015](adr/SBM-ADR-0015.md)).
- **It does not keep guessable content secret from a holder of the evidence**
  (§4).

## 9. Where each claim is written down

This note owns nothing. Each row names the document that does.

| Claim | Owner |
|---|---|
| Confidentiality, integrity, authentication; forward secrecy and post-compromise security per epoch; opaque group identifiers | the Internet-Draft, *Security Considerations* |
| The provider routes ciphertext and holds no content key | the umbrella's object model and Delivery-Service mapping, and the Internet-Draft's DS mapping |
| What each party observes, per path | umbrella, the privacy section |
| Group topology: one group per entity pair and scope, every device a leaf | the Internet-Draft, *Group Topology*; [SBM-ADR-0003](adr/SBM-ADR-0003.md) |
| Canonicalisation, the digest and its modes | the Internet-Draft, *Canonicalisation and Payload Hashing* |
| The salted commitments and their reveals | the Internet-Draft, *Grade Commitment* and *Mandate Commitment*; [SBM-ADR-0009](adr/SBM-ADR-0009.md) |
| Confidentiality scopes and the visible records leaf | umbrella §8.3a; [SBM-ADR-0010](adr/SBM-ADR-0010.md) |
| The wallet assurance baseline and compromise latency | [`docs/wallet-assurance-profile.md`](wallet-assurance-profile.md) |
| Whether the content digest should be salted | **open**: [A12](REVIEW_AGENDA.md); proposed construction in [SBM-ADR-0014](adr/SBM-ADR-0014.md), not implemented |
