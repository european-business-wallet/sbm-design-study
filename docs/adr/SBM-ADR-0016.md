---
id: SBM-ADR-0016
title: "The receipt names the provider that observed the handover"
label: "the observer is named on the receipt"
decision_status: proposed
implementation_status: [specified, in-reference]
implementation: >-
  specified and in the reference. `DeliveryReceipt.observed_by` is signed and REQUIRED; the receipt key resolves in that provider's BW-PROVIDER descriptor on both the live and the retained path; companion contracts 16.0.0
choice: >-
  a DS receipt names TWO providers — `issuing_rdp_id`, the message's origin proven by its SE, and `observed_by`, the provider whose Delivery Service collected the acknowledgement and signed. The key that verifies the receipt resolves in the descriptor of the SECOND · delivery-service-openapi.yaml `DeliveryReceipt`
alternative: >-
  resolve by `issuing_rdp_id` — what the reference did, correct only where origin and observer coincide; a retained association supplied by the bundle rather than signed by the observer — rejected because the claimant would be asserting what the signer should attest; try every supplied descriptor until one resolves the `kid` — rejected, that is "any descriptor carrying the key will do"
benefit: >-
  a receipt can be bound to the party that signed it, so its key is resolved in one descriptor and authenticated against that participant's admission; the legitimate recipient-side signer is no longer refused
cost: >-
  a wire change to a published contract, and a field SBM-ADR-0015 had withdrawn is restored for a different reason than the one it was withdrawn with
open_questions: []
author_questions: []
supersedes: []
analysed_not_decided: >-
  **How the receipt reaches the evidence issuer** ([A1](../REVIEW_AGENDA.md)) is untouched by this record. Naming the observer makes a retained receipt verifiable; it does not publish an operation that carries one.
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# SBM-ADR-0016 — The receipt names the provider that observed the handover

## Context

SBM-ADR-0015 folded the Delivery Service into the Registered Delivery Provider:
one provider role, and the Delivery Service is a function of it. The batch that
carried that decision into the discovery layer moved the DS receipt key off the
customer's BW-MED and into the provider's own BW-PROVIDER descriptor, because a
provider's key belongs in the provider's document.

That left a question the move did not ask: **whose** descriptor. The reference
answered `issuing_rdp_id`, the only provider identifier a `DeliveryReceipt`
carries. The Delivery-Service contract defines that field as the message's
**origin, proven by its SE** — it is the namespace the message belongs to, and
the contract carries a separate `forwarding_rdp_id` for the provider that
forwarded it.

The handover a receipt attests happens on the other side. The recipient's
Delivery Service issues the collection token, authenticates the device session
and records the acknowledgement; its provider signs. So in any exchange between
two entities on different providers, the receipt's key is published by a
participant the receipt does not name.

Two defects followed, in the same cycle. The live check demanded that the
descriptor's `participant_id` equal `issuing_rdp_id`, which refuses the
legitimate recipient-side signer. The retained path selected the descriptor by
the same field, so it resolved the key in the origin's document and reported
LINT-BND-38 against a receipt that verifies. Neither was visible, because the
sample built to exercise the path had been generated with the Delivery Evidence
issuer substituted for the origin: the receipt claimed origin `mockeu-002` for a
message whose SE says `mockeu-001`, so the two identifiers held one value and
nothing could disagree.

**One provider role does not mean one provider per message.** That is the
sentence this record exists to add.

## Requirement and constraint

A verifier holding a retained receipt, years later, must be able to say which
published document contains the key that signed it, and to authenticate that
document against the admission of the participant it belongs to. The answer must
come from the receipt, because the receipt is what is retained; and it must be
**signed**, because an unsigned association is the claimant's assertion about
whose observation this was.

The constraint is that `issuing_rdp_id` cannot be repurposed. It is the message
namespace, proven by the SE, and it appears in the request path
(`POST /messages/{issuing_rdp_id}/{message_id}/receipt-ack`). Changing its
meaning would silently re-label every receipt already issued.

## Decision

`DeliveryReceipt` carries **`observed_by`**: the `participant_id` of the provider
whose Delivery Service observed the handover and signed the receipt. It is
REQUIRED and inside the signed object.

The key that verifies a receipt resolves in the `ds_receipt_keys` of
`observed_by`'s BW-PROVIDER descriptor, whose seal the membership register pins
to that participant, with validity judged at the receipt's own `server_time`.
One implementation of that check serves the live path and the retained path, and
it refuses a document of any other kind, a document belonging to another
participant, and a receipt that names no observer.

The Delivery Service does not learn its own identity from a request:
`observed_by` is server-side, like `server_time` and `message_digest`, and is
recorded in the cross-representation gate's `NON_BODY` as such.

## Alternatives considered

**Resolve by `issuing_rdp_id`.** What the reference did. Correct exactly where
the origin and the observer are the same party — Annex P deployment profile 1,
one provider serving both entities — and wrong in the four-corner case the
profile exists for. It also cannot be made right by convention: the origin
genuinely does not hold the recipient's Delivery Service's key.

**A retained association supplied alongside.** The bundle manifest states which
descriptor signed which receipt. No wire change, and the descriptor is still
authenticated against the register. Rejected: the association is the claimant's,
and a claimant assembling a package has an interest in which provider's
observation the handover is attributed to. What the verifier needs is what the
signer said.

**Try every supplied descriptor.** Resolve the `kid` against each candidate
until one verifies. Rejected: it restores "any descriptor carrying the key will
do", which is the property this round was opened to remove, and it makes the
verdict depend on what the claimant chose to supply.

## Trade-off

A published contract changes, and the companion contracts move to 16.0.0. The
field is one SBM-ADR-0015 explicitly withdrew — it was ADR-0004's `observed_by`,
planned so that a false observation by a separate transport provider would be
**attributable**. It returns for a different reason: not to attribute a false
observation to a party outside the provider, but to say which of two qualified
providers observed, so that the right key can be found. The name is kept because
the question it answers is the same one, asked within one provider role instead
of across two.

## Consequences and residual limit

A receipt is now self-describing: origin, observer, act, instant, digest, and the
key identifier, with the observer's descriptor as the one place its key may be
published. A verifier that holds the receipt and the register can resolve and
authenticate without being told which document to look in.

**What this does not do.** It does not publish an operation that carries the
receipt from the Delivery Service to the party that issues the Delivery
Evidence; [A1](../REVIEW_AGENDA.md) stays open, and naming the observer neither
closes it nor makes it smaller. It claims no resistance to a malicious provider:
`observed_by` says which provider asserted the observation, and that provider is
the qualified, supervised, liable one whose word the grade already rests on. It
does not make a receipt discoverable — retention of the observer's descriptor as
it stood at the act is the same custody question `docs/retrievability.md` records
for every other input, and a provider exit takes that surface away.

## Status

- **Decision:** proposed, for the maintainer. It amends SBM-ADR-0015 rather than
  superseding it: one provider role stands, and this adds that one role is not
  one party per message.
- **Implementation:** specified and in the reference. The field is signed and
  required, both verification paths resolve by it, and
  `samples/receipt.availability.demo.json` is a four-corner receipt whose origin
  and observer differ.

## Supersedes

Nothing. SBM-ADR-0015 remains the record of the one-provider decision; this
record adds the identifier that decision's discovery move needed and did not
have.

## Normative owner

The Delivery-Service contract (`delivery-service-openapi.yaml`,
`DeliveryReceipt`) owns the field and its requiredness. The Internet-Draft owns
where the key is published and how validity is judged. The umbrella's §13.1
roles table is unaffected: `observed_by` names a provider in the one existing
role, not a second one.
