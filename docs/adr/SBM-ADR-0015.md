---
id: SBM-ADR-0015
title: "One provider: the Delivery Service inside the Registered Delivery Provider"
label: "One provider role, not two"
decision_status: proposed
implementation_status: [specified, in-reference]
implementation: >-
  Specified, and in the reference. No evidence object, companion contract or schema rule carries a second provider's identity, and the membership register admits only the one provider role. But two DISCOVERY documents did change shape and version for this decision — the Messaging Entity Descriptor at 2.2 dropped `msp` and `ds_receipt_keys`, and the provider descriptor at 1.1 publishes them — and the reference resolves the receipt key accordingly. 'Nothing changes on the wire' was true of the evidence family and not of discovery
choice: >-
  The Registered Delivery Provider operates the Delivery Service itself, as part of the qualified service it is already supervised for. There is one provider role. The Messaging Service Provider ceases to exist as a participant, as a role and as a name on the wire · §7.2, [§13.1](../../Secure-Business-Messaging-Profile.md#131-institutional-roles)
alternative: >-
  Two. The Messaging Service Provider as a federation participant with an identity, an admission and an `observed_by` binding of its own — that was SBM-ADR-0004, planned and never implemented, and this record supersedes it. And a relay running between two Messaging Service Providers — still rejected
benefit: >-
  One qualified party observes the handover, carries the message and attests to both, so it is accountable for all three. Two questions that had been open disappear rather than being answered ([A9](../REVIEW_AGENDA.md), [L1](../REVIEW_AGENDA.md)). One fewer identity, contract, descriptor and interface to specify and keep. And it is the model the consultation asked for
cost: >-
  Transport and evidence can no longer be bought from different suppliers. The provider sits in the data path of every delivery. The privacy argument for keeping the two apart is given up. And a decision accepted on 17 September 2026 is superseded three weeks later
open_questions: [A10]
author_questions: []
supersedes: [SBM-ADR-0004]
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0015 — One provider: the Delivery Service inside the Registered Delivery Provider

## Context

Two terms, since this record is about the relationship between them. A
**Registered Delivery Provider** (RDP) is the qualified provider that issues a
message's evidence and is supervised for doing so. The **Messaging Service
Provider** (MSP) was to be the party that actually moved messages — queueing
them, handing them over, collecting the acknowledgement — as a separate
company, with a separate identity.

SBM-ADR-0004 decided that the Messaging Service Provider would be a federation
participant in its own right: identified by a value space of its own, admitted
by the membership register, and named in the evidence that rests on what it
observed. The relay between the two sides would stay provider-to-provider.

Only part of that was ever built. The register shipped (Batch A, PR #49) with its
`role` list closed to the single value `rdp`. The second batch — the one that
would have given the Messaging Service Provider its own identity, put an `msp_id`
on the Delivery Service's artefacts and an `observed_by` on the Delivery Evidence
— was never started. As of `d94097f`, no schema, no contract and no wire-format
rule carries a Messaging Service Provider identity at all. **On the wire the two
roles have never been apart.**

What exists of the separation is text, and only text:

- the Messaging Service Provider as a named role in the umbrella profile, in the
  Internet-Draft and in the technical specification;
- a row of its own, with its own supervisory authority, in the institutional-roles
  table at §13.1;
- a deployment ladder whose first rung reads *"one co-located MSP/RDP"*;
- a figure;
- an agenda item (A6) describing the participation as planned;
- and a legal question (L1): whether the act of observation that Article
  44(1)(b) and (c) of Regulation (EU) No 910/2014 require may be performed by a
  participant that is admitted to the federation but is not itself qualified.

The consultation returned comments that point the other way: the two-role
model is read as complexity without a corresponding guarantee, and the
reviewers asked for the model to be simplified.

> **Consultation reference: placeholder.** The comments this record relies on
> are not public at the time of writing. The maintainer will add the
> reference — source, date and comment identifiers — when it can be cited.
> Until then this record states what the comments asked for and does not
> quote them; it is `proposed` and should not leave that status without the
> reference in place. The reference, when added, is not part of the exported
> design study unless the maintainer decides otherwise.

## Requirement and constraint

The profile's load-bearing claim has two parts: that registered-delivery
evidence can rest on digests rather than on the content itself, and that the
party sealing that evidence has actually observed the events it attests.

SBM-ADR-0004 analysed three models for who observes the acknowledged handover,
and selected none of them. Its third model — *the handover inside the
Registered Delivery Provider's own trust boundary* — is the one in which the
verifier has to trust only the testimony the design already depends on: the
provider's.

That record also warned what the third model is **not**. In its own words, *"a
co-located or renamed delivery service is not this option"*. Control has to be
effective, and the handover point and the authenticated principal have to be
defined.

The constraint on this record is therefore that it must not be a rename. The
Delivery Service's observations — device-authenticated session, collection
token, acknowledgement over the digest (R8-X1, R9-01) — are already specified;
what this record changes is **who is accountable for them**, and it must say so
in a way that cannot quietly become a subcontractor with no name.

## Decision

1. **There is one provider role.** The Registered Delivery Provider operates
   the Delivery Service as part of the qualified service it is supervised for.
   The Delivery Service remains the MLS architectural component of RFC 9750,
   mapped to a function of the RDP rather than to a provider.
2. **The MSP ceases to be a role.** It leaves the §13.1 roles table, the
   deployment ladder, the figures and the normative prose as a named party.
   Where the text needs to name the function, it says *the RDP's Delivery
   Service*.
3. **Operating the Delivery Service is the provider's own responsibility, and
   is not delegable on the wire.** The provider MAY use a subcontractor to run
   it, as a trust service provider may for any component — under that provider's
   supervision and liability, and invisible to the protocol. No identifier, no
   admission record and no evidence field names such a party. <!-- TODO(legal): whether a
   subcontracted Delivery Service falls within the qualified provider's own
   conformity assessment, and under which policy requirements for
   subcontracting; cite the EN 319 401 clause once verified. -->
4. **The observation is the provider's own.** The delivery receipt — what the
   Delivery Service signs when the recipient collects a message — is now a
   statement by the same provider that seals the Delivery Evidence. So the
   Delivery Evidence needs no `observed_by` field: the observer is whoever
   `rdp_id` names. `receipt_digest`, binding the DE to the receipt it rests on,
   is retained as a **separate question** and is not decided here. <!-- The
   receipt binding was motivated by delegation; without delegation it is an
   integrity question about the RDP's own records, and belongs to a record of
   its own if wanted. -->
5. **The receipt key is the provider's key.** `ds_receipt_keys` moves out of
   the customer's own discovery document (`BW-MED`, the Messaging Entity
   Descriptor) and into the provider's (`BW-PROVIDER`), where a provider's key
   belongs — pinned to that provider by its membership record, as every other
   key in that document is. This moves a discovery document's version; it moves
   no evidence version.
6. **The relay stays RDP-to-RDP** (ADR-0004's FED-X4 survives unchanged).
7. **The register, `BW-PROVIDER`, admission at the instant of the act and
   `LINT-TRUST-06/07` stand as built.** The `role` enumeration stays `[rdp]`,
   now by decision rather than as a stage. The provider-composition deployment
   axis is withdrawn.

## Alternatives considered

- **Keep SBM-ADR-0004 and build the second batch.** Not chosen. It would add an
  identity, a contract, a descriptor role, an evidence binding and an admission
  category — all of that to carry an observer whose honesty the design would
  still have to assume. SBM-ADR-0004's own words about that model: *"attributable,
  no longer anonymous, but possible"*. And it leaves L1 open. The consultation
  read this as cost without a corresponding guarantee.
- **ADR-0004's model 2, an independent endpoint proof.** Not chosen here and
  not foreclosed: it is the model to take *if* resistance to a malicious
  transport operator is ever to be claimed. With one provider that claim is
  not needed for the observer question, and the model's own costs — a wallet
  outbox with persistent retries, an RDP-side event clock that changes what
  "timely" means — are not paid for a property nobody claims.
- **Rename without control: the MSP as a silent subcontractor.** Rejected, as
  ADR-0004 rejected it; decision 3 exists so that this record cannot be read
  as that.
- **An MSP-to-MSP relay with RDPs as observers.** Remains rejected for the
  reasons ADR-0004 gives.

## Trade-off

What is given up is the thesis that transport and evidence are separable
markets, which is why ADR-0004 was taken; and the §11.1 observation that
separating the roles across two accountable parties turns an internal join of
views into a collusion the register could address. What is gained is one accountable party for observing, transferring and
attesting. That is the ordinary shape of a qualified electronic registered
delivery service, in which the qualified provider attests to what it did itself.
And with it goes the removal of one identity, one contract surface, one
descriptor role, one evidence field and two open questions.

The RDP is now in the data path of every delivery, with the capacity,
backpressure and availability consequences ADR-0004's model 3 lists. That
cost is real and is the price of the simplification.

## Consequences and residual limit

- **Three agenda questions change state.** A6 closes as *withdrawn*, not
  answered — there is no longer a participant for it to be about. A9 is
  *resolved*: the observer is the provider itself, so what remains is the trust
  the design already placed in a qualified provider, and no claim of resistance
  to a dishonest provider is made or needed. L1 closes as *moot*. A10 remains
  open but simpler: the Delivery Service that routes a group is the provider's
  own, and who routes a group after it is formed is still the question.
- **Text and figures.** The MSP leaves the umbrella (31 occurrences at
  `d94097f`), the Internet-Draft (19), the technical specification (7), the §13.1 table, Annex P's
  ladder, §11.1, the architecture figure corrected by the onboarding Pass 1,
  and the six onboarding notes that teach MSP participation as planned. The
  figure and version-claim gates added in September catch what the sweep
  misses.
- **Decisions.** FED-X1, FED-X3 and FED-X5 are superseded by this record;
  FED-X2 (the register) and FED-X4 (the relay) stand. `decisions-index.md` is
  regenerated.
- **Discovery.** `BW-MED.msp` is withdrawn or folded into `BW-MED.rdp`;
  `ds_receipt_keys` moves to `BW-PROVIDER`. Both are discovery bumps.
- **Claim register.** `positions.md` and `OPEN-ITEMS.md`: the register entry
  loses its "MSP admission planned" clause; the privacy entry loses the
  separation argument; nothing becomes *established* that was not.
- **Residual limit.** For S2 — the delivery state that records the handover to
  the recipient — the verifier trusts the provider's testimony, as it did before
  SBM-ADR-0004 and as that record's third model says. This decision does not make
  a false S2 impossible. It makes the only party that could produce one the
  qualified, supervised, liable one.

## Status

- **Decision:** proposed, for the maintainer.
- **Implementation:** specified and in the reference. The evidence family, the
  CDDL and the register's enumeration are untouched, and no object names a second
  provider — but this decision moved a published key between two discovery
  documents, so **BW-MED 2.2** and **BW-PROVIDER 1.1** are wire changes and the
  reference implements the new resolution. The first form of this bullet said
  *nothing changes on the wire* and then *plus two discovery-document bumps* in
  the same sentence; the first half was a claim about evidence objects stated as
  though it covered everything. [SBM-ADR-0016](SBM-ADR-0016.md) carries the field
  the move needed and did not have.

## Supersedes

[SBM-ADR-0004](SBM-ADR-0004.md), whose decision status becomes `superseded`
with a forward marker to this record; its *Alternatives considered* stays as
the analysis this record relies on.

## Normative owner

The umbrella, §7.2 and [§13.1](../../Secure-Business-Messaging-Profile.md#131-institutional-roles);
the Delivery Service contract, `delivery-service-openapi.yaml`, for the
receipt; `schemas/bw-provider.schema.json` for the receipt key.

## Open questions

- [A10](../REVIEW_AGENDA.md): which Delivery Service routes a group and who
  owns its membership after formation — unchanged, now about the RDP's own
  Delivery Service.
