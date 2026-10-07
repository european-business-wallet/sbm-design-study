---
id: SBM-ADR-0005
title: "Composition across providers: the origin's sealed SE, the founder registration"
label: "Crossing from one provider to another"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference
choice: >-
  When a message crosses from one provider to another, the receiving provider proves where it came from by reading the origin's own sealed Sending Evidence, rather than taking the sender's word for it. And the device that creates an MLS group registers as that group's founder · the I-D, *Delivery Service* and *Group Establishment*; the delivery-service contract
alternative: >-
  Two. A forwarding token signed by the origin, instead of its Sending Evidence. Or a founder inferred from whoever deposited into the group first, instead of a registration
benefit: >-
  Two messages that happen to carry the same local identifier under two different origins stay two messages. And no device has to welcome itself into its own group
cost: >-
  The Delivery Service has to hold the origins' evidence-verification keys and a list of who may forward. Two things stay open: how a receipt reaches the party that issues the Delivery Evidence ([A1](../REVIEW_AGENDA.md)), and who routes a group after it has been formed ([A10](../REVIEW_AGENDA.md))
open_questions: [A1, A10]
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0005 — Composition across providers: the origin's sealed SE, the founder registration

## Context

Two terms. A **Registered Delivery Provider** (RDP) is the qualified provider
that issues a message's evidence. **Sending Evidence** (an SE) is the sealed
object the sender's provider issues when it accepts a message; it is what proves
which provider a message came from.

When sender and recipient use different providers, a message is submitted at
the origin's Registered Delivery Provider (RDP), relayed provider-to-provider,
and handed by the recipient-side provider to
its own delivery service. Message identifiers are unique only within the
issuing provider's namespace, and a group's creating device joins no group
through a Welcome, because MLS begins a group with its creator.

## Requirement and constraint

Two messages with equal local identifiers from two origins must stay two
messages at every delivery service that handles them, and the origin
namespace must be proven, not asserted. The creating device must be routed
like every other member without inventing a protocol step MLS does not have.

## Decision

A forwarding submission to a delivery service names the originating provider and
carries that provider's own sealed Sending Evidence. The receiving delivery
service then checks four things: that the seal verifies against the origin's
published evidence key; that the evidence names *this* provider, *this* message
identifier and the digest of *these* octets; and that whoever submitted it is a
forwarder it actually serves.

Acceptance, delivery items and receipts all carry the origin's namespace, with
the forwarder recorded beside it. An origin claim arriving without Sending
Evidence that verifies is refused.

Separately: the device that created a group registers itself as that group's
founding member, through a device-authenticated operation, once per group, bound
to the principal that deposits the group's invitations. The operation is
idempotent, and it routes exactly as a joined invitation does.

## Alternatives considered

- **An origin-signed forwarding token.** Rejected: the SE already binds
  exactly the triple that must travel, sealed by the party whose namespace it
  is; a token would restate it under a new signature.
- **An unchecked origin string.** Rejected: it would trade the collision for
  spoofing.
- **A founder implied by the first deposit, or named in a
  member-authenticated deposit.** Rejected: it would route to a device the
  delivery service never authenticated.
- **A self-Welcome for the creator.** Rejected: a protocol step MLS does not
  have.

## Trade-off

Proof reused from an artefact that already exists, at the price of the
delivery service holding the origins' evidence keys and a list of the
forwarders it serves.

## Consequences and residual limit

The delivery service keys idempotency on the origin namespace and holds
material to verify it. How the provider that issues the Delivery
Evidence obtains the delivery service's receipt, and which provider issues that
evidence in the four-corner case, is not published; later membership changes after formation have no decided
owner.

## Status

- **Decision:** accepted.
- **Implementation:** specified; in the reference.

## Supersedes

Nothing.

## Normative owner

The Internet-Draft, *Delivery Service* and *Group Establishment*; the
delivery-service contract, `delivery-service-openapi.yaml`; the technical specification, clause 6,
for the issuing identity.

## Open questions

- [A1](../REVIEW_AGENDA.md): the receipt's path to the DE issuer, and which RDP issues the
  DE across providers.
- [A10](../REVIEW_AGENDA.md): routing and membership ownership after formation.
