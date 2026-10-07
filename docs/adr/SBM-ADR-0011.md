---
id: SBM-ADR-0011
title: "Historical signed state governs; today's state never substitutes"
label: "Historical state governs, never today's"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  Specified, and in the reference. One part is still undecided: proving that the policy a message pinned was the LATEST one then in force, rather than merely one that was in force
choice: >-
  A verifier judges an act by the state that was signed and published at the time of the act, never by the state as it stands today. A published policy is never edited — its window ends where its signed successor begins. Admission is evaluated as of the act. A group is decoded under the registry revision it pinned. A cipher-suite decision is recomputed only from the inputs committed at formation · the umbrella §8.3; the I-D; TS clause 6
alternative: >-
  Three. A stored `valid_until` that can be edited, with the verdict depending on a live history service — superseded, though retrieving history as of an instant remains compatible with this record. And a single signed assertion of the current head of the chain — rejected
benefit: >-
  A verdict that was correct about the past stays correct, whatever changes afterwards
cost: >-
  The chains, registries, formation inputs and assertions all have to be retained, and where the material is missing the verification is reported INCOMPLETE rather than passed. One thing stays unproven: that no later policy version existed ([A3](../REVIEW_AGENDA.md))
open_questions: [A3, A5]
author_questions: []
supersedes:
  - the signed policy chain with a stored `valid_until` and an `as_of` retrieval endpoint, an earlier decision of this study
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0011 — Historical signed state governs; today's state never substitutes

## Context

Evidence is verified years after the act, against material that has since
changed: acceptance policies are superseded, providers are suspended,
cipher-suite registries evolve, devices are added and removed. A verdict that
depends on the state of any of these *today* is wrong for an act that
happened under yesterday's.

## Requirement and constraint

Three requirements:

- a verdict that was correct about the past must survive later change, and must
  be reachable from the retained material alone — without assuming any service
  is still online, or still honest;
- a published artefact that evidence has pinned by digest must never be
  modified, because modifying it breaks the pin;
- and what the retained material cannot establish must be *reported* as not
  established, rather than assumed.

## Decision

The state that governs a verdict is the signed state as it stood at the act,
retained or obtained as of that instant; today's state never substitutes for
it. A published
acceptance policy is never modified: its window ends where its signed
successor begins, derived from the digest-linked chain and never stored.
Admission is evaluated at the instant of the act over the full history of a
record asserted at or after it; live use between providers is a separate,
named lease. A group decodes its cipher-suite values under the registry
revision it pinned, and a revision that carries no wire map resolves only
IANA-allocated values. A suite decision recomputes only from the formation
inputs whose digest the group committed. Missing material yields
INCOMPLETE, a third verdict beside pass and fail; and a retained chain is
stated to prove linkage and in-force-at-the-act, not that no later version
existed.

## Alternatives considered

- **A stored `valid_until` with an `as_of` retrieval endpoint.** Superseded,
  for two reasons. Writing an end date into a published document changes the
  digest that evidence had already pinned, so for an ordinary publication the
  two rules could not both be satisfied. And a verdict that depends on an
  endpoint answering makes a verification performed in 2033, of an act from
  2026, depend on that service still being online and still honest.

  What is rejected is the mutable end date and the dependence — not as-of
  retrieval itself. Obtaining an authenticated historical object through a live
  service is compatible with this decision, and the umbrella requires the
  directory to serve as-of reads.
- **A separate signed history manifest.** Rejected: two artefacts that can
  disagree about the same truth.
- **A signed head assertion to make maximality locally checkable.**
  Rejected: it invents a new signed artefact and a publication duty with no
  register to support them, building the mechanism before the institution.
- **Truncating a record's history at `as_of`.** Rejected: a record asserted
  after a later suspension, truncated before it, ends in a status that was
  not its status at its own assertion instant.
- **Publishing today a wire value an earlier registry revision never
  specified.** Rejected: it would write down a history that was never
  specified.

## Trade-off

Verdicts that survive change, at the price of retaining chains, registries,
formation inputs and assertions, and of saying INCOMPLETE where the material
is missing.

## Consequences and residual limit

A complete chain and a successor-truncated chain are byte-identical from
inside a bundle, so that no later policy existed is never claimed: excluding
a hidden successor needs an authenticated log head, the same missing
primitive as key transparency. The shipped positive bundles therefore report
INCOMPLETE with that gap, by design. Who publishes and updates a group's
retained state is declared as a residual.

## Status

- **Decision:** accepted.
- **Implementation:** specified; in the reference; maximality undecided.

## Supersedes

The signed policy chain with a stored `valid_until` and an `as_of` retrieval
endpoint, an earlier decision of this study, superseded before any deployment
shipped it.

## Normative owner

The umbrella, §8.3 for the policy chain and §13.1 for admission at the act;
the Internet-Draft for the pinned registry revision and the committed
formation inputs; the technical specification (the TS), clause 6, for admission and for what a
verification establishes.

## Open questions

- [A3](../REVIEW_AGENDA.md): how a verifier can know a retained policy chain is complete.
- [A5](../REVIEW_AGENDA.md): who publishes and updates a group's retained state.
