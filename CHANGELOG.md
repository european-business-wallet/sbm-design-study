<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Changelog

The history of the **artefacts** — what changed on the wire, in the schemas and
in the contracts. This is history, not a second status page: what the current
artefacts establish is said where it is checked — the README's
[*What a green bar means*](README.md#what-a-green-bar-means--and-what-it-does-not),
[`OPEN-ITEMS.md`](OPEN-ITEMS.md) for what is not proven, and the
[decision records](docs/adr/) for why the design is the way it is. The
current version of every artefact is held in [`versions.json`](versions.json),
enforced by `make versions`, and never restated by hand; the tables below are
the versions each dated edition was cut with.

This snapshot was exported for review; the design study's internal development
record is not reproduced here.

---

## Current — 2026-09-27, edition r24

**Wire-breaking.** An external review of the previous edition found seven points;
all seven are addressed here, and two of them changed the protocol.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.11** | 2.10 |
| Application envelope | **1.4** | 1.3 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **11.0.0** | 10.0.0 |

**A recipient can now report a multipart failure it detects.** The previous
edition required a recipient to check each received part before the manifest
digest, and then directed every failure into the ordinary digest-mismatch
outcome — which requires the recipient's recomputed value to differ from the
sender's. For a multipart message it cannot differ: the payload digest is the
digest of the **manifest**, so a recipient whose received parts are wrong
recomputes the same value the sender declared, and a payload that is not the
specified layout yields no parts to describe at all. A recipient could therefore
**detect the failure and have no way to report it** — it would have had to invent
a digest, assert a comparison it never performed, or stay silent and let the
message expire.

There is now a distinct outcome for it: an attributable assertion by the
recipient, bound to the message, to the octets it decrypted and to the commitment
it was checking, carrying a typed cause — a part's digest, its length, a part
absent, a part the manifest does not describe, a duplicate identifier, or a
payload that is not the layout — and the per-part detail where parts exist. It
carries **no recomputed payload digest**, because there is none, and an observed
digest appears only for the one cause where a comparison was actually made. The
intake-stage refusal code is **not** reused for it: that code belongs where
nothing has been decrypted and no recipient has spoken. Single-part messages are
unaffected, and their digest-mismatch outcome is unchanged.

**And two provider transformations are withdrawn from use.** A
Change-Indication Evidence may record that a provider re-packaged the transmitted
envelope or split it into several, committing to the input and to each output.
Neither operation is defined. The output commitment is typed as a hash of a
**complete** wire message, which a fragment is not; re-packaging an unchanged
message in an outer wrapper leaves the inner bytes untouched, so the output
commitment equals the input; and no published contract defines a fragment
descriptor, a chunk order, a reassembly operation or the boundary at which the
original message is reconstructed. Two providers given the same message could not
perform the same transformation, and no verifier could reproduce either.

So a provider **must not** issue either transformation until this is defined, and
a verifier that meets one **must** treat the transformation as unproven rather
than as an attested re-framing: the seal still establishes who attested what, and
the relation of the outputs to the input is what nothing establishes. The
retained-bundle verifier reports it as an unproven property, alongside the
policy-history completeness it already reports, and the open question records what
a definition would have to pin.

**The previous edition's closure of the chunked-part question stands, on
corrected ground.** Nothing in this profile splits a content part — that is true
whatever happens to envelope framing — and citing the envelope transformations as
a defined operation in its support was wrong.

**Three introductory corrections, where a reader meets them first.** The executive
brief said nobody learns from the evidence what kind of content was exchanged; the
commitment discloses nothing, and the routing scope reference resolved against the
recipient's published map gives the set of classes that scope covers — a scope
covering one class gives that class. The first architecture figure placed protocol
change control inside the federation authority's box, merging two authorities the
profile keeps apart; it now draws both. And the README said there was no
transport-security underlay, where the profile specifies ordinary HTTPS beneath
MLS and says only that the security claims do not rest on it.

**A compatibility boundary that the previous edition did not name.** Defining the
multipart layout added no field and re-sealed nothing, so it was reported as
moving no version — but a layout previously unconstrained became the only
conformant one, and an implementer had no number to name in order to say which it
implements. The application-envelope version covers the layout of the application
data as well as the headers, and it moves with this change.

## Edition r23 — 2026-09-27

**No artefact version moves and nothing changes on the wire.** Two open
questions close and one defect in a recipient obligation is corrected — the
last of which an implementer reading the previous edition would have got wrong.

**How a multipart payload is laid out is now specified.** The manifest described
the parts of a multipart message and bound them, and no document said how a
recipient finds a given part's octets: no delimiter, no length-prefix framing, no
reference to an existing multipart format. Two independent implementations could
satisfy every rule in the profile and fail to exchange one multipart message. The
payload is now the deterministic-CBOR encoding of an array of
`{part_id, octets}` records, in the manifest's own canonical order, carrying
exactly the parts the manifest describes. Keyed by part identifier rather than by
position, because a fixed-position encoding is one silent reordering away from
attributing one part's octets to another part's descriptor. The payload is
therefore self-describing: a recipient that has decrypted the envelope splits it
without holding any evidence. Single-part messages are unaffected.

**And a recipient obligation that could be satisfied without reading the
content.** For a multipart message the payload digest is the digest of the
*manifest*, not of the plaintext — while the re-verification rule said only that
the recipient recomputes the payload digest over the decrypted plaintext. A
recipient could therefore hash the manifest it already held, compare it with
itself, and **confirm a match for a message whose every part had been replaced**.
The rule now states two recomputations in order: each part's digest from the
octets received, compared with the manifest including its declared length, and
only then the manifest's digest against the declared payload digest. A failure is
reported exactly as any digest mismatch is, through the recipient's mismatch
confirmation; no new outcome is introduced.

**The published multipart example now proves the framing.** Its manifest is
reproduced from the two part files this snapshot carries, through the specified
layout, so an implementer who builds a payload as specified arrives at the digests
published here.

**A chunked part's digest: the question does not arise.** Whether such a digest
should ever be a Merkle root was open. This profile has no chunked part: the
framing operation it defines acts on the **envelope** — a provider may re-package
it or split it into several output envelopes, recording the operation in
change-indication evidence that commits to the input and to each output — and the
TS confines permitted transformations to the envelope and its metadata, because
content cannot be transformed under end-to-end encryption. A sentence permitting a
"very large part" to be chunked in transport named no descriptor, no evidence of a
split and no size at which a part becomes large; it is withdrawn, and the
invariant it existed to state is kept: **a part's digest is over that part's
octets whatever framing carried them**, so one envelope or several produce the
same manifest and the same payload digest. If a later revision wants part-level
chunking, the mechanism comes first and the construction after; the record says so
in that order.

**The manifest's own rules, made to agree.** Nesting was described three ways —
the specification permitted one level, both machine-readable definitions made it
inexpressible, and a conformance rule guarded a depth nothing could produce. A
manifest is flat, and a part that is itself a container is one part committed by
the digest of its own octets. The rule is retired and recorded with the reason,
because an identifier is assigned once and never reused. A content encoding was
permitted with no field in which to declare one, so a recipient could not have
known whether to decode and a verifier could not have known what the digest
covered; there is no encoding layer inside the encrypted envelope, compression is
content, and the term the rules use is now defined once.

**Two quoted definitions did not match the normative one.** The specification
embeds CDDL so a reader meets the wire format where the rule is explained. One
block named a type the previous edition removed and described a reduced form its
own prose forbids two lines above; another rule was embedded twice with two
different bodies, one naming a type the normative file does not define. A new
check holds every embedded block to the file, and a deliberately illustrative
block has to say so and give its reason — and is still held to the
domain-separation tags it carries.

## Edition r22 — 2026-09-27

**No artefact version moves and nothing changes on the wire.** This edition
makes one open question decidable: **A12**, whether the content digest should
become a salted commitment, which stays open and is now put to the reviewers the
agenda assigns it to — applied cryptography, and registered-delivery operators —
with a record they can act on.

**A residual risk was missing from the document that is meant to hold all of
them.** The specification's security considerations describe what a bare digest
over the plaintext exposes: a party holding an evidence object or a package can
**confirm a candidate document** against the digest, which is a practical
disclosure wherever the content has little entropy — correspondence on a known
template, an amount within a narrow range, a form with few filled fields. That
paragraph defers to the umbrella profile for the consolidated metadata threat
model, and the umbrella's list of what the metadata can reveal did not include
it. A reader following the pointer found five entries and not this one. It is
there now, informatively and with no new obligation: who can confirm a guess
(the parties, both providers, an archive, a verifier, a court — whoever holds the
evidence), who cannot (an observer of the network, which sees no digest), that a
multipart message widens it through the manifest's per-part digests, and that the
question is open with nothing decided.

**The decision record was corrected against the two editions published since it
was written.** It asked the reviewers about salting a chunk construction the
previous edition withdrew; it proposed retiring hash modes by name for content,
which the per-field digest domains of the previous edition made unnecessary; it
priced moving the multipart manifest into the encrypted envelope against
"provider-side structural checks" that are three named conformance rules, one of
them added in that same edition; and it named a superseded artefact version where
the rule is about the version an artefact was sealed under.

**And the agenda row itself said the profile was silent about the assumption.**
It was, when the row was written. It is not now, and a reviewer reads the agenda
before the specification — that is what the agenda is for. The row says what is
actually open, which is no longer whether to state the exposure but **whether
stating it is enough**.

Nothing here accepts the proposal. It remains proposed and not implemented, the
question remains open, and the digest is unsalted.

## Edition r21 — 2026-09-27

**Wire-breaking. A hash mode is now admissible only in the domain of the field
that carries it**, and five artefact versions move with the restriction.

| Artefact | This edition | Previous |
|---|---|---|
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.10** | 2.9 |
| Application envelope | **1.3** | 1.2 |
| BW-ORG discovery document | **2.7** | 2.6 |
| EDD resolver contract (OpenAPI) | **1.13.0** | 1.12.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **10.0.0** | 9.0.0 |

One shared hash type was referenced by fourteen sites, so **every digest field
accepted every mode the profile defines** while the normative text gave each
field a narrower one. The effects were not theoretical: an acceptance-policy
reference could declare a manifest mode — a digest of a structure — where a
verifier recomputes SHA-256 over a published document's signed payload, so the
issuer accepted an artefact its own bundle verifier refused; an intake-stage
rejection's submission digest could declare SHA-512 or a manifest mode where the
Internet-Draft requires SHA-256 over the exact submitted octets, for a request
that may never have been parsed; and a multipart part's digest could declare a
manifest mode where the value is over that part's decoded octets.

There are now three named types, and the Internet-Draft states the three domains
before the schemas enforce them:

- **content** — the payload digest and the envelope's content digest: either the
  transmitted octets or the deterministic-CBOR manifest of a multipart payload.
  The only domain in which a manifest mode means anything;
- **observed octets** — a multipart part's digest: SHA-256 or SHA-512 over that
  part's decoded octets;
- **SHA-256 over octets, pinned to one algorithm** — the rejected-submission
  digest and a referenced document's digest, which a verifier recomputes from
  bytes it holds, so another algorithm makes the value unrecomputable.

**An artefact that declares a mode outside its field's domain is refused**,
whatever else validates. The published wallet-provider contract inherited the
restriction through its own reference to the shared type, so a submission with a
manifest-mode policy digest is now refused by the contract, naming the field and
the value the domain admits, **before the delivery service is contacted** — no
transport acceptance and no evidence are produced.

Two generic envelope-digest fields that appeared in one schema and the CBOR
definitions, and in no normative text, are removed; the defined envelope
commitments are unaffected.

**What this costs an implementer.** An implementation that put a manifest mode
on a policy reference, or SHA-512 on a rejected-submission digest, no longer
interoperates — it was producing artefacts the profile's own verifier refused.
Nothing that followed the normative text has to change.

*The edition note above is written for this edition. Editions r18, r19 and r20
carried this section forward from r9 unchanged, so it described a record added
three editions earlier and said "the artefact versions are unchanged" while two
of those editions changed normative text; the dated headline is written by the
rebuild and was correct, the body under it was not. What each of those editions
did is in this repository's commit for it.*

## Edition r8 — 2026-09-26

The artefact versions are those of the previous snapshot, unchanged; nothing
moves on the wire. That edition carried four source-side corrections:

- **The patent commitment's exclusion list** in `IPR.md` §3 no longer names
  the JSON Canonicalization Scheme, which the Specification stopped
  referencing at the previous edition. The exclusion is defined by reference
  and its list is illustrative, so the perimeter is unchanged; the review
  agenda's L9 row records the call.
- **Two links into the study's historical trust analysis**, in the
  architecture note and the reviewer guide, are plain text: the analysis is
  not part of this snapshot and was never a selected design.
- **Five identifier tokens** left in reader-facing prose by the earlier
  cleanup are gone from the umbrella, the TS, the Internet-Draft, the agenda
  and the agent explainer.
- **Three tests travel again** — the licence-list, repository-prose and
  historical-record tests read what they check from the tree they run in, so
  this snapshot runs them as the source does.

---

## Previous snapshot — 2026-09-25

| Artefact | Version |
|---|---|
| Umbrella profile | 2.1, edition 2026-09-18 |
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.9** |
| Application envelope | 1.2 |
| BW-MED / BW-ORG / BW-MEMBER discovery documents | 2.1 / 2.6 / 2.2 |
| BW-PROVIDER participant descriptor | 1.0 |
| Status assertion · roster snapshot | 1.0 · 1.0 |
| EDD resolver contract (OpenAPI) | 1.12.0 |
| Federation register contract (OpenAPI) | 3.0.0 |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | 9.0.0 |
| TS — QERDS binding | v0.35 |

### What changed on the wire since the previous snapshot (2026-09-20)

- **Wire-breaking: evidence objects 2.8 → 2.9**, every sample re-sealed. The
  `jcs-sha256` and `jcs-sha512` values of `payload_hash.hash_mode` are removed from the profile.
  An artefact that declares either is **refused by name** (`LINT-HASH-01`), not
  ignored, and there is **no replacement mode**: deterministic CBOR is the
  profile's only canonicalisation. An implementation that emitted those modes
  no longer interoperates, and a sender whose original octets are gone cannot
  produce a conformant `payload_hash` for that payload — the profile's answer
  is to retain the bytes.
- **Every defined hash mode is mandatory to implement**: `raw-sha256`,
  `raw-sha512`, `manifest-sha256`, `manifest-sha512`. The set is closed; the
  Internet-Draft owns the rule, the TS ICS carries a row for it, and a gate
  fails if the Internet-Draft stops stating it. Adding a mode reopens the
  question of advertisement (agenda A11).
- **A privacy statement corrected.** The umbrella no longer offers a neutral
  scope name as a mitigation: `scope_ref` travels in clear and the recipient's
  published scope map resolves it, so the name hides nothing; a coarser scope
  map does. Whether the content digest should be salted is opened as agenda
  question A12 and left unanswered.
- **The reference mock's `POST /send`** returned 500 on the body the README
  documents. Fixed; the quickstart is now executed by a test that derives the
  body from the README.
- **Licence overview 1.5** for this snapshot: it names the repository it is
  published from and lists only files this snapshot contains.
- **Documentation.** The drafting ordinals and migration-step codes are out of
  the reader-facing text; the vision note and the octet migration record left
  the snapshot; the executive brief, README, CONTRIBUTING, OPEN-ITEMS and this
  file were shortened to one home per topic.
- Unchanged: the discovery documents, the envelope, the three contracts and the
  TS revision. The catalogue holds 158 rules.

### Verification

The shipped bundles verify INCOMPLETE at this edition, by design; the README's
[*three verdicts*](README.md#the-three-verdicts-and-the-two-invocations)
section shows both invocations and what each leaves unproven.

---

## Previous snapshot — 2026-09-20

| Artefact | Version |
|---|---|
| Umbrella profile | 2.1, edition 2026-09-18 |
| Evidence objects (SE / DE / NDE / RE / CE / EP / Relay / GCM) | **2.8** |
| Application envelope | 1.2 |
| BW-MED / BW-ORG / BW-MEMBER discovery documents | 2.1 / 2.6 / 2.2 |
| BW-PROVIDER participant descriptor | **1.0** (new) |
| Status assertion · roster snapshot | 1.0 · 1.0 |
| EDD resolver contract (OpenAPI) | 1.12.0 |
| Federation register contract (OpenAPI) | **3.0.0** (new since the previous snapshot) |
| Profile-2 companion contracts (wallet–RDP, delivery service, relay) | **9.0.0** |
| TS — QERDS binding | **v0.35** |

### What changed on the wire since the previous snapshot (2026-08-01)

- **Companion contracts 4.0.0 → 9.0.0** (breaking, in five steps). Delivery
  items are fanned out per device, each bound to its own member, and a
  collection token records the transfer. Group-establishment refusals are
  collected by the creator from a delivery-service queue; refusal dequeues an
  invitation, expiry is read from the reservation, and an obsolete refusal
  cannot remove a newer invitation's routing. Member and device principals are
  bound whole, `(uid, mid)` and `(uid, mid, device_id)`, in the contract and
  not only in the reference. Confirmations are per-member acts with per-act
  idempotency; a wallet can deliver a digest-mismatch proof. A forwarded
  submission carries the originating provider's sealed SE as proof of its
  namespace, and the creating device registers itself as a group's founding
  member through a device-authenticated operation. Committed single-use
  packages and creator-scoped invitation handles close the deposit-identity
  gaps.
- **Federation register contract, new: 1.0.0 → 3.0.0.** The membership
  register as an instrument of its own, sealed record by record by a federation
  authority; the register is authenticated at ingress — seal, timestamp,
  Schema, history, all or nothing — before anything in it is read; `as_of`
  evaluates a complete record rather than truncating it; status histories are
  read chronologically. Two new dimensions in `versions.json`: the register
  contract and the `BW-PROVIDER` descriptor a participant seals for itself.
- **Evidence objects stay 2.8**; the EDD resolver contract stays 1.12.0; the
  discovery documents stay 2.1 / 2.6 / 2.2. No downstream re-pin.
- **TS v0.32 → v0.35.** Federation admission at act time in clause 6; the
  issuing identity derived from the authenticated principal, with the
  forwarded-origin exception; the clock for each grade; the companion-contract
  rows of the ICS pro forma at 9.0.0. The TS's version-by-version change
  history is kept with the source repository and is not reproduced here.
- **MLS profile.** The post-quantum hybrid suite is pinned to
  draft-ietf-mls-pq-ciphersuites-06 under the private-use code point `0xF5C1`;
  wire maps are per registry revision and a group decodes under the revision it
  pinned. `sbm_group_params` version 2 names whole device principals and
  commits the formation instant and a digest of the exact inputs the suite
  decision was taken on.
- **Verifier.** New rules for federation admission at the act
  (`LINT-TRUST-06`), a descriptor's seal key pinned by the register
  (`LINT-TRUST-07`), the register authenticated at ingress (`LINT-TRUST-08`),
  and a missing register or anchor as a third-verdict gap (`LINT-BND-I6`); the
  suite decision is recomputed from committed formation inputs and reported
  INCOMPLETE without them (`LINT-BND-I5`); expiry is validated at the live
  intake boundary as well as at verification. The catalogue now holds 157
  rules, published with their inputs, predicates and errors in
  [`docs/lint-catalogue.md`](docs/lint-catalogue.md).
- **Documentation.** A reviewer guide, an architecture and trust note, a
  message-lifecycle primer, a lifecycle-and-custody note, an extended
  production-verifier note with an annotated shipped bundle, a redrawn figure
  set with a freshness gate, thirteen architecture decision records with the
  decisions index generated from them, and a review agenda that names every
  open question with the expertise that would settle it.

---

## Previous snapshot — 2026-08-01

| Artefact | Version |
|---|---|
| Umbrella profile | 2.1 |
| Evidence objects | 2.8 |
| Application envelope | 1.2 |
| BW-MED / BW-ORG / BW-MEMBER | 2.1 / 2.6 / 2.2 |
| Status assertion · roster snapshot | 1.0 · 1.0 |
| EDD resolver contract (OpenAPI) | 1.12.0 |
| Profile-2 companion contracts | 4.0.0 |
| TS — QERDS binding | v0.32 |

Breaking changes recorded at that snapshot: provider-to-provider submission
became mutual-TLS only under a canonical `urn:sbm:rdp:<uid>` identity, the
entity-level fallback removed because it collapsed several providers of one
entity into a shared idempotency namespace; the receipt acknowledgement moved
to a provider-namespaced path with the issuing provider identity signed into
the receipt; group-establishment refusals stopped travelling as group messages;
a published organisation policy stopped storing its own end instant.

## Earlier revisions

The evidence family, the discovery documents and the companion contracts were
developed iteratively, each version accompanied by regenerated sealed samples
and by the conformance rules that enforce it. Version numbers are sequential
within each stream and independent across streams — the discovery documents and
the contracts version independently of the evidence family. The milestones that
shaped the current wire format:

- **Octet-authoritative inversion.** The COSE_Sign1 became the authoritative
  artefact, its payload deterministic CBOR defined in CDDL, JSON a
  non-authoritative projection; canonicalised-JSON signing was removed.
- **Transmitted-octet and group-state commitments** (evidence 2.1 → 2.2):
  `envelope_hash` and `mls_state` as byte-exact dedicated types, extended to
  every transport boundary and every grade.
- **Sender, recipient and refusal proof** (evidence 2.2 → 2.3): the
  wallet-signed sender confirmation, portable quorum and session proofs, and a
  refusal bound like a confirmation.
- **Organisation policy** (evidence 2.3 → 2.4, BW-ORG 2.3 → 2.4): a
  self-contained policy document, deterministic selection, the selected key
  named in the evidence.
- **MLS profile and establishment** (evidence 2.4 → 2.5): change evidence
  restricted to observable bytes; the scope and group-parameter extensions.
- **Remaining wire semantics** (evidence 2.5 → 2.6): two hash domains, one S2
  event, the attribution model.
- **Fixtures and directory format**: one confirmation key per device, one
  mandatory directory-record signature format, the atomic roster snapshot.
- **The dispute model** (evidence 2.6 → 2.7): a grade-mismatch dispute carries
  an attributable recipient assertion; commitment inequality alone rebuts
  nothing.
- **Historical resolution** (evidence 2.7 → 2.8): member versions and device
  keys resolved as they stood at the act; the policy window derived from the
  signed successor and never stored.
