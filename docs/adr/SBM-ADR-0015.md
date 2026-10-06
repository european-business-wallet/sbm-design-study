---
id: SBM-ADR-0015
title: "One provider: the Delivery Service inside the Registered Delivery Provider"
label: "MSP folded into the RDP"
decision_status: proposed
implementation_status: [not-implemented]
implementation: >-
  nothing on the wire changes: no Schema, contract or CDDL carries an MSP identity, and the register admits only `rdp`; the change is to the roles, the text, the figures and the agenda
choice: >-
  the Registered Delivery Provider operates the Delivery Service as part of its qualified service; there is one provider role, and the MSP ceases to be a participant, a role or a name on the wire · §7.2, [§13.1](../../Secure-Business-Messaging-Profile.md#131-institutional-roles)
alternative: >-
  the MSP as a federation participant with its own identity, admission and `observed_by` binding (SBM-ADR-0004, planned, never implemented) — superseded; an MSP-to-MSP relay — remains rejected
benefit: >-
  one accountable, qualified party observes, transfers and attests; A9 and L1 dissolve by construction; one fewer identity, contract, descriptor and interface; the model the consultation asked for
cost: >-
  transport and evidence are no longer separable markets; the RDP sits in the data path of every delivery; the privacy argument for separation is given up; a decision accepted on 17 September 2026 is superseded three weeks later
open_questions: [A10]
author_questions: []
supersedes: [SBM-ADR-0004]
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0015 — One provider: the Delivery Service inside the Registered Delivery Provider

## Context

SBM-ADR-0004 decided that the Messaging Service Provider would be a federation
participant in its own right — identified by a value space of its own, admitted
by the membership register, named in the evidence that rests on what it
observed — and that the relay would stay RDP-to-RDP. The register was built
(Batch A, PR #49) with its `role` enumeration closed to `rdp`, and the
second batch that would have given the MSP its identity, `msp_id` on the
Delivery Service artefacts and `observed_by` on the DE was never started. At
`d94097f` no Schema, contract or CDDL carries an MSP identity. On the wire the
two roles have never been apart.

What exists of the separation is text: the MSP as a named role in the
umbrella, the Internet-Draft and the TS; a row in the §13.1 roles table with
its own authority column; a deployment ladder whose first rung reads *"one
co-located MSP/RDP"*; a figure; an agenda item (A6) describing the
participation as planned; and a legal question (L1) asking whether the act of
observation that Article 44(1)(b) and (c) of Regulation (EU) No 910/2014
require may be performed by a participant that is admitted but not itself
qualified.

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

The profile's load-bearing claim is that registered-delivery evidence can rest
on digests rather than content, and that the party sealing the evidence has
observed the events it attests. ADR-0004's own *Alternatives considered*
analysed three models for who observes the acknowledged handover and chose
none. Its third model — *the handover inside the RDP's trust boundary* — is
the one in which the verifier trusts only the testimony the design already
assumes, the RDP's. ADR-0004 also warned what that model is **not**: *"a
co-located or renamed delivery service is not this option"*; control must be
effective, the handover point and the authenticated principal defined.

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
3. **Operating the Delivery Service is the RDP's responsibility and is not
   delegable on the wire.** The RDP MAY use a subcontractor to run it, as a
   trust service provider may for any component, under the RDP's supervision
   and liability and invisible to the protocol; no identifier, admission
   record or evidence field names such a party. <!-- TODO(legal): whether a
   subcontracted Delivery Service falls within the qualified provider's own
   conformity assessment, and under which policy requirements for
   subcontracting; cite the EN 319 401 clause once verified. -->
4. **The observation is the RDP's.** The DS receipt is a statement by the
   provider that seals the DE, so the DE needs no `observed_by`: the observer
   is `rdp_id`. `receipt_digest`, binding the DE to the receipt it rests on,
   is retained as a **separate question** and is not decided here. <!-- The
   receipt binding was motivated by delegation; without delegation it is an
   integrity question about the RDP's own records, and belongs to a record of
   its own if wanted. -->
5. **The receipt key is the RDP's key.** `ds_receipt_keys` moves from the
   entity's `BW-MED` to the RDP's `BW-PROVIDER`, where a provider's key
   belongs, pinned by the RDP's membership record as every other
   `BW-PROVIDER` key is. A discovery version bump; no evidence bump.
6. **The relay stays RDP-to-RDP** (ADR-0004's FED-X4 survives unchanged).
7. **The register, `BW-PROVIDER`, admission at the instant of the act and
   `LINT-TRUST-06/07` stand as built.** The `role` enumeration stays `[rdp]`,
   now by decision rather than as a stage. The provider-composition deployment
   axis is withdrawn.

## Alternatives considered

- **Keep ADR-0004 and implement Batch B.** Not chosen: it adds an identity,
  a contract, a descriptor role, a DE binding and an admission category to
  carry an observer whose honesty the design would still have to assume
  (ADR-0004, model 1: *"attributable, no longer anonymous, but possible"*),
  and it keeps L1 open. The consultation read that as cost without guarantee.
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
views into a collusion the register could address. What is gained is one
accountable party for observation, transfer and attestation — the ordinary
QERDS shape, in which the qualified provider attests what it did — and the
removal of one identity, one contract surface, one descriptor role, one
evidence field and two open questions.

The RDP is now in the data path of every delivery, with the capacity,
backpressure and availability consequences ADR-0004's model 3 lists. That
cost is real and is the price of the simplification.

## Consequences and residual limit

- **A6 closes as withdrawn**, not answered. **A9 is resolved by this
  decision**: the observer is the RDP; what remains is the trust the design
  already placed in the qualified provider, and no claim of resistance to a
  malicious provider is made or needed. **L1 closes as moot.** **A10
  remains**, simplified: the Delivery Service that routes a group is the
  RDP's, and post-formation membership routing is still the open question.
- **Text and figures.** The MSP leaves the umbrella (31 occurrences at
  `d94097f`), the Internet-Draft (19), the TS (7), the §13.1 table, Annex P's
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
- **Residual limit.** The verifier trusts the RDP's testimony for S2, as it
  did before ADR-0004 and as ADR-0004's model 3 states. This record does not
  make a false S2 impossible; it makes the only party that could produce one
  the qualified, supervised, liable one.

## Status

- **Decision:** proposed, for the maintainer.
- **Implementation:** not implemented. Nothing on the wire changes; the work
  is an editorial and governance cycle, plus two discovery-document bumps.

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
