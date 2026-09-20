---
id: SBM-ADR-0007
title: "Declared delivery grades and terminal outcomes"
label: "Declared grades, terminal outcomes"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference
choice: >-
  verification by default, acceptance under quorum or `all`, availability only where the recipient declared it per class;
  each grade dated by its own event; a verified mismatch or refusal ends the message ·
  [§8.3b](../../Secure-Business-Messaging-Profile.md#83b-delivery-grade-declaration-normative); the I-D, *Delivery State Model* and *Timing*; TS clause 6
alternative: >-
  an implicit handover grade for every message — excluded ([§7.1](../../Secure-Business-Messaging-Profile.md#71-technical-architecture-authoritative));
  a refusal that changes nothing — revised
benefit: >-
  the legally operative act is chosen and visible; mailbox deposit never counts
cost: >-
  recipient cooperation at the default grades; one member's refusal or mismatch ends the message;
  the availability grade rests on the DS's observation ([A9](../REVIEW_AGENDA.md))
open_questions: [A9]
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0007 — Declared delivery grades and terminal outcomes

## Context

Registered delivery systems disagree about what "delivered" means: deposit in
a mailbox, availability to an authenticated endpoint, verification by the
recipient, or acceptance. Some national systems require the availability
reading; the profile's own argument rests on an authenticated act by the
recipient.

## Requirement and constraint

The legally operative act must be chosen explicitly and be visible in the
evidence, never implied by a message reaching a queue. Each grade must be
dated by an event a verifier can check, on a clock a client cannot move, and
the outcome of a message must be terminal and consistent across the members
of the recipient entity.

## Decision

Three delivery grades: verification by default, acceptance under a quorum or
`all` policy, and availability only where the recipient declared it for that
content class. Each grade is dated by its own event: the availability grade
by the delivery service's server-observed receipt of the acknowledged
handover, the verification and acceptance grades by the instant the
recipient-side RDP received and verified the completing confirmation, on its
own clock, with every contributing act preceding it. A recipient confirmation
is one member's act; distinct eligible members contribute until the policy
is satisfied; a verified digest mismatch or a verified refusal by an eligible
member ends the message, and a reveal is dispute material that changes no
state.

## Alternatives considered

- **An implicit handover grade for every message.** Excluded: deposit in an
  unauthenticated mailbox never establishes delivery
  ([§7.1](../../Secure-Business-Messaging-Profile.md#71-technical-architecture-authoritative)).
- **Client-declared instants.** Rejected: a client clock must not decide
  timeliness, for S2 and equally one grade up.
- **Confirmations keyed on the message rather than the member.** Rejected:
  it made quorum and `all` unreachable through the published request.
- **A refusal that is recorded and changes nothing.** Revised: it left a DE
  issuable over an explicit, attributable refusal by a member of the entity
  the DE says accepted the message.

## Trade-off

A chosen, visible operative act, at the price of needing the recipient's
cooperation at the default grades and of letting one member's verified
refusal or mismatch end the message.

## Consequences and residual limit

A verified mismatch is terminal because the digest is message-wide: every
member decrypts the same ciphertext, so a DE asserting a verified digest
could not stand beside an attributable proof that it failed. The availability
grade rests on the delivery service's observation of the handover, which is
the observer question of the previous record.

## Status

- **Decision:** accepted.
- **Implementation:** specified; in the reference.

## Supersedes

Nothing.

## Normative owner

The umbrella [§8.3b](../../Secure-Business-Messaging-Profile.md#83b-delivery-grade-declaration-normative) for
the declaration; the Internet-Draft, *Delivery State Model* and *Timing*; the
TS, clause 6, for the operative act and its evidence.

## Open questions

- [A9](../REVIEW_AGENDA.md): who observes S2.
