---
id: SBM-ADR-0002
title: "A governed federation on four separate instruments"
label: "A governed federation, four instruments"
decision_status: accepted
implementation_status: [specified, in-reference, planned]
implementation: >-
  Specified, and the register is in the reference: it admits Registered Delivery Providers, and its `role` list is closed to that one role by decision rather than as a stage, since SBM-ADR-0015 withdrew the second kind of participant ([A6](../REVIEW_AGENDA.md), closed). What is still only planned is an OPERATED register. None exists; what ships is a file
choice: >-
  Providers are admitted and supervised, and four instruments answer four different questions, each kept separate from the others: Trusted Lists say who is qualified, the membership register says who is admitted to the federation, the European Directory of Entities says who an entity is, and a design authority controls changes to the specification · [§13.1](../../Secure-Business-Messaging-Profile.md#131-institutional-roles)
alternative: >-
  Two. An open federation that anyone may join, on the model of e-mail. Or admission folded into the directory resolver, so that one service answers both who an entity is and who may act for it
benefit: >-
  The weight evidence carries rests on operators who are known, and a verifier can check qualification and admission independently of each other
cost: >-
  There is a barrier to entry, there is central governance, and somebody must keep the admission data fresh — the Federation Authority and the providers. How old an admission record may be and still authorise a live exchange is not yet fixed ([A2](../REVIEW_AGENDA.md))
open_questions: [A2]
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0002 — A governed federation on four separate instruments

## Context

The evidence layer's legal weight depends on who operates it. A registered
delivery service is qualified by a supervisory body and listed on a Trusted
List; a messaging federation must also decide who may take part, who says so,
and how a verifier learns it after the fact
([§13.1](../../Secure-Business-Messaging-Profile.md#131-institutional-roles)).

## Requirement and constraint

Four questions must have four independently checkable answers: is this
provider qualified, is it admitted to the federation, is this the entity it
claims to be, and who changes the rules. Each answer must be verifiable at
the instant of a past act, not only today, and no single instrument may be
allowed to answer two of the questions for the convenience of having one
fewer contract.

## Decision

A governed federation of admitted, supervised providers, resting on four
instruments kept apart: the Trusted Lists for qualification, a membership
register for admission, the European Directory of Entities (EDD) for identity
and discovery, and the design
authority for change control. The membership register is a distinct
instrument with its own contract and its own signer, the Federation
Authority, which is not the design authority. Admission is resolved as of the
instant of the act, over half-open windows, the same validity-at-act-time
rule the profile applies to certificates and to delivery-service receipt
keys.

## Alternatives considered

- **An open, e-mail-style federation.** Rejected: it would surrender exactly
  the guarantees the profile exists to provide, because nothing would bind
  evidence weight to known operators.
- **Admission folded into the EDD resolver.** Rejected: it would merge two of
  the four instruments, and a verifier could no longer tell identity from
  admission.

## Trade-off

Independently checkable qualification and admission, at the price of
admission barriers, central governance and a freshness operation the
Federation Authority must run.

## Consequences and residual limit

Providers pay admission; the Federation Authority pays governance and
freshness. A record speaks only up to the instant it was asserted, so a
verifier needs a record asserted at or after the act; live use between
providers is a separate lease whose maximum age the Federation Authority
publishes, and that number is not yet set. An operated register is not
established: the reference ships a sealed stage-1 demonstration register
signed by a demonstration federation authority distinct from the design
authority, and it admits Registered Delivery Providers (RDPs) only.

## Status

- **Decision:** accepted.
- **Implementation:** specified; the register admits RDPs and is in the
  reference — its `role` enum is closed to `rdp`, and provider descriptors are
  sealed by the participant. [SBM-ADR-0015](SBM-ADR-0015.md) withdrew the second
  participant kind (6 October 2026), so the closed `role` enum is the decision and
  not a stage on the way to another one ([A6](../REVIEW_AGENDA.md), closed); an
  operated register is not established.

## Supersedes

Nothing.

## Normative owner

The umbrella [§13.1](../../Secure-Business-Messaging-Profile.md#131-institutional-roles) for the four instruments;
the register's own contract, `federation-register-openapi.yaml`; the technical specification,
clause 6, for admission at act time.

## Open questions

- [A2](../REVIEW_AGENDA.md): the maximum age a live decision should accept for a membership
  assertion.
