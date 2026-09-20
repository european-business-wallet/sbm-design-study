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

## Current — 2026-09-20

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

### Verification

The shipped bundles verify INCOMPLETE at this edition, by design; the README's
[*three verdicts*](README.md#the-three-verdicts-and-the-two-invocations)
section shows both invocations and what each leaves unproven.

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
