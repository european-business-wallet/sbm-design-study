---
id: SBM-ADR-0009
title: "Commitments before reveals"
label: "Commitments before reveals"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference; the effect of a proven mismatch open ([L5](../REVIEW_AGENDA.md), [L7](../REVIEW_AGENDA.md))
choice: >-
  evidence binds the content digest, the ciphertext digest and the group state; availability and opposable agent acts carry
  salted commitments opened only by a reveal · the I-D, *Grade Commitment* and *Mandate Commitment*
alternative: >-
  a cryptographic ciphertext-to-reveal proof — future work; commitment inequality alone as a rebuttal — rejected
benefit: >-
  claims checkable without disclosing content or class before a dispute
cost: >-
  a reveal discloses the class to the dispute's parties; a failing reveal proves nothing alone
open_questions: [L5, L7, A12]
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0009 — Commitments before reveals

## Context

Evidence must let a third party check what was sent, to whom and under
which grade, without the providers seeing content and without disclosing the
content class or the agent's mandate before anyone disputes them.

## Requirement and constraint

Every claim in the evidence must be checkable against something committed at
the time of the act; a later dispute must be able to open a commitment
without the evidence having disclosed it; and a rebuttal must be an act a
party can be held to, not a value anyone can manufacture.

## Decision

Evidence binds the content digest, the digest of the transmitted ciphertext
and the group state at the act. The availability grade's content class and
an opposable agent act's mandate are carried as salted commitments, opened
only by a reveal. A grade-mismatch dispute carries a recipient-device wallet
signature over the reveal tuple, resolved against the historical device key,
and the specification says plainly that this proves an *attributable
recipient claim*, not objective extraction from the ciphertext.

## Alternatives considered

- **A cryptographic ciphertext-to-reveal proof.** Recorded as specified
  future work with its prerequisites named, not invented now.
- **Commitment inequality alone as a valid rebuttal.** Rejected: inequality
  is trivially manufacturable by inventing a salt, so any recipient provider
  could have rebutted any availability-grade DE.

## Trade-off

Claims checkable before disclosure, at the price of a reveal that discloses
the class to the dispute's parties and of a dispute model that proves
attribution rather than extraction.

## Consequences and residual limit

A failing reveal is an attributable assertion that starts a dispute; it
proves nothing alone. What legal effect a proven mismatch has, and the
rebuttable clause it bears on, are questions for counsel and stay flagged.
The one binding this record leaves bare is the content digest itself, which
is not salted; whether it should be is [A12](../REVIEW_AGENDA.md), and
[SBM-ADR-0014](SBM-ADR-0014.md) records the construction that would answer
it, as a proposal.

## Status

- **Decision:** accepted.
- **Implementation:** specified; in the reference.

## Supersedes

Nothing.

## Normative owner

The Internet-Draft, *Grade Commitment* and *Mandate Commitment*; the TS,
clause 6, for the dispute's evidence.

## Open questions

- [L5](../REVIEW_AGENDA.md), [L7](../REVIEW_AGENDA.md): the legal effect of a proven grade mismatch.
- [A12](../REVIEW_AGENDA.md): whether the content digest, the one unsalted binding here, should be a salted commitment — proposed in SBM-ADR-0014, not decided.
