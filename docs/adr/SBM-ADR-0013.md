<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
---
id: SBM-ADR-0013
title: "Pilot evidence kept apart; the agent profile optional"
label: "Pilot evidence apart; agents optional"
decision_status: accepted
implementation_status: [specified, not-implemented]
implementation: >-
  specified; production qualification not established
choice: >-
  pilot evidence is structurally identical and makes no claim under the regulation; agents are the optional deployment profile 5 ·
  [§13.3](../../Secure-Business-Messaging-Profile.md#133-conformance-profiles-pilot-and-production); TS clause 9; Annex R
alternative: >-
  qualification as a property of the protocol; composition as a new rung of the deployment ladder — rejected
benefit: >-
  no claim beyond what is established
cost: >-
  qualification, conformity assessment and a cross-deployment agent contract lie outside the repository
  ([A7](../REVIEW_AGENDA.md), [P1](../REVIEW_AGENDA.md))
open_questions: [A7, P1]
author_questions: []
supersedes: []
---

# SBM-ADR-0013 — Pilot evidence kept apart; the agent profile optional

## Context

The study ships a reference implementation, demonstration keys and sample
bundles, and describes deployments from a single pilot to a qualified
federation. What a green bar means, and what a pilot's evidence is worth,
must be legible to a reader who has not seen the review history.

## Requirement and constraint

Nothing in the repository may claim more than it establishes; qualification
is a property of the operating providers, never of the protocol alone; and
optional capabilities must be separable from the core so that a deployment
without them is complete.

## Decision

A pilot produces evidence that is structurally identical to qualified
evidence and makes no claim under the regulation; the conformance profiles
keep pilot and production apart, and the TS's compliance clause states what
each establishes. Agents are the optional deployment profile 5: the agent's
evidence and mandate rules are specified, and the profile is complete without
them. The deployment ladder counts pairs of independent providers that have
proven interoperation, and provider composition is kept off it.

## Alternatives considered

- **Qualification as a property of the protocol.** Rejected: a green bar
  shows that the reference tooling and the shipped artefacts are consistent;
  qualification, conformity assessment and Trusted-List status are decided
  outside the repository by the bodies that decide them.
- **Composition as a new rung of the deployment ladder.** Rejected, as
  recorded for the MSP's separation: it would let a deployment climb by
  reorganising its contracts.

## Trade-off

No claim beyond what is established, at the price of leaving qualification,
conformity assessment and the cross-deployment agent contract outside the
repository.

## Consequences and residual limit

The demonstration trust store stands in for a Trusted List and for nothing
else; the production verifier's trust policy is stated and not implemented
here. The agent-wallet interface between deployments is informative only.

## Status

- **Decision:** accepted.
- **Implementation:** specified; production qualification not established.

## Supersedes

Nothing.

## Normative owner

The umbrella
[§13.3](../../Secure-Business-Messaging-Profile.md#133-conformance-profiles-pilot-and-production) and §9.3; the
TS, clause 9; the umbrella's Annex R for the agent profile.

## Open questions

- [A7](../REVIEW_AGENDA.md): a cross-deployment contract for the wallet-agent interface.
- [P1](../REVIEW_AGENDA.md): production trust.
