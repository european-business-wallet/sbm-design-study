---
id: SBM-ADR-0007
title: "Declared delivery grades and terminal outcomes"
label: "Delivery grades are declared, not assumed"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference
choice: >-
  There is no single meaning of 'delivered'. Three grades are named, and which one applies is declared rather than assumed: verification by default; acceptance where a quorum or all members must accept; availability only for the content classes the recipient has declared it for. Each grade is dated by its own event. A verified digest mismatch, or a refusal, ends the message · [§8.3b](../../Secure-Business-Messaging-Profile.md#83b-delivery-grade-declaration-normative); the I-D, *Delivery State Model* and *Timing*; TS clause 6
alternative: >-
  Two. An implicit handover grade applied to every message — excluded ([§7.1](../../Secure-Business-Messaging-Profile.md#71-technical-architecture-authoritative)). And a refusal that changes nothing about the message's state — revised rather than kept
benefit: >-
  Which act carries legal effect is chosen deliberately and is visible in the evidence. Depositing a message in a mailbox never counts as delivery
cost: >-
  At the default grades the recipient has to cooperate for delivery to be evidenced at all. One member's refusal or digest mismatch ends the message for everyone. The availability grade rests on the Delivery Service's observation — which SBM-ADR-0015 makes the provider's own ([A9](../REVIEW_AGENDA.md), resolved)
open_questions: []
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

Three delivery grades: **verification** by default, **acceptance** under a
quorum or `all` policy, and **availability** only where the recipient has
declared it for that class of content.

Each grade is dated by its own event, and the events differ:

- the **availability** grade by the delivery service's own server-observed
  receipt of the acknowledged handover;
- the **verification** and **acceptance** grades by the instant the
  recipient-side Registered Delivery Provider (RDP) received and verified the
  confirmation that completes them, on that provider's own clock, with every
  contributing act preceding it.

A recipient confirmation is one member's act. Distinct eligible members
contribute until the policy is satisfied. A verified digest mismatch, or a
verified refusal by an eligible member, ends the message. A reveal is dispute
material and changes no state.

## Alternatives considered

- **An implicit handover grade for every message.** Excluded: deposit in an
  unauthenticated mailbox never establishes delivery
  ([§7.1](../../Secure-Business-Messaging-Profile.md#71-technical-architecture-authoritative)).
- **Client-declared instants.** Rejected: a client clock must not decide
  timeliness, for S2 and equally one grade up.
- **Confirmations keyed on the message rather than the member.** Rejected:
  it made quorum and `all` unreachable through the published request.
- **A refusal that is recorded and changes nothing.** Revised: it left
  Delivery Evidence (a DE) issuable over an explicit, attributable refusal by a
  member of the very entity that evidence says accepted the message.

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
technical specification, clause 6, for the operative act and its evidence.

## Open questions

- None. [A9](../REVIEW_AGENDA.md) — who observes S2 — was resolved on 6 October 2026
  by [SBM-ADR-0015](SBM-ADR-0015.md): the observer is the RDP, which operates the
  Delivery Service as part of its qualified service.
