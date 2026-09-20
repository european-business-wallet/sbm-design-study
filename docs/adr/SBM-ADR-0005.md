<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
---
id: SBM-ADR-0005
title: "Composition across providers: the origin's sealed SE, the founder registration"
label: "Composition across providers"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference
choice: >-
  the origin's sealed SE proves its namespace through RDP(in); the creating device registers as the group's founder ·
  the I-D, *Delivery Service* and *Group Establishment*; the delivery-service contract
alternative: >-
  an origin-signed forwarding token; a founder implied by the first deposit
benefit: >-
  equal local ids from two origins stay two messages; no self-Welcome
cost: >-
  the DS holds the origins' evidence keys and a forwarder list; the receipt's path to the DE issuer ([A1](../REVIEW_AGENDA.md))
  and post-formation routing ([A10](../REVIEW_AGENDA.md)) are open
open_questions: [A1, A10]
author_questions: []
supersedes: []
---

# SBM-ADR-0005 — Composition across providers: the origin's sealed SE, the founder registration

## Context

When sender and recipient use different providers, a message is submitted at
the origin's RDP, relayed RDP-to-RDP, and handed by the recipient-side RDP to
its own delivery service. Message identifiers are unique only within the
issuing provider's namespace, and a group's creating device joins no group
through a Welcome, because MLS begins a group with its creator.

## Requirement and constraint

Two messages with equal local identifiers from two origins must stay two
messages at every delivery service that handles them, and the origin
namespace must be proven, not asserted. The creating device must be routed
like every other member without inventing a protocol step MLS does not have.

## Decision

A forwarding submission to a delivery service names the originating provider
and carries that provider's sealed SE; the delivery service verifies the seal
against the origin's published evidence key, checks that it names this
provider, this message identifier and the digest of these octets, and that
the submitter is a forwarder it serves. Acceptance, delivery items and
receipts carry the origin namespace, with the forwarder recorded beside it;
an origin claim without a verifying SE is refused. The device that created a
group registers itself as the group's founding member through a
device-authenticated operation, once per group, bound to the creator
principal that deposits the group's invitations; it is idempotent and routes
as a joined invitation does.

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
material to verify it. How the RDP that issues a DE obtains the delivery
service's receipt, and which RDP issues the DE in the four-corner case, is
not published; later membership changes after formation have no decided
owner.

## Status

- **Decision:** accepted.
- **Implementation:** specified; in the reference.

## Supersedes

Nothing.

## Normative owner

The Internet-Draft, *Delivery Service* and *Group Establishment*; the
delivery-service contract, `delivery-service-openapi.yaml`; the TS, clause 6,
for the issuing identity.

## Open questions

- [A1](../REVIEW_AGENDA.md): the receipt's path to the DE issuer, and which RDP issues the
  DE across providers.
- [A10](../REVIEW_AGENDA.md): routing and membership ownership after formation.
