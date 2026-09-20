<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
---
id: SBM-ADR-0012
title: "A mandatory suite floor and a committed formation"
label: "Suite floor, committed formation"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference
choice: >-
  a mandatory floor at the baseline, raisable per device; the decision pinned in the GroupContext with its inputs ·
  the I-D, *Cipher Suites* and the `sbm_group_params` extension
alternative: >-
  a floor per entity or per device alone; a higher mandatory floor (P-256); a separate signed artefact; committing the instant only
benefit: >-
  uniform enforcement, checkable by a third party
cost: >-
  device constraints narrow the selection; formation inputs must be retained; post-quantum interoperability untested ([A4](../REVIEW_AGENDA.md))
open_questions: [A4]
author_questions: []
supersedes: []
---

# SBM-ADR-0012 — A mandatory suite floor and a committed formation

## Context

Two creators must choose the same cipher suite from the same capability
sets, a deployment must not be able to downgrade a group below what the
profile promises, and a verifier must be able to check the decision later
from retained material rather than from today's registry and today's
published capabilities.

## Requirement and constraint

The security claim must be verifiable, not optional and local; a member that
publishes nothing must be protected as much as one that does; the baseline
suite must stay in every intersection so that a selection always exists; and
raising the floor later must be a governance action, not a redesign.

## Decision

A mandatory floor, `mls-suite-floor/v1`, set at the baseline suite as a
versioned constant of the profile, binding on every conforming deployment;
a group below it must not form and is refused with a typed reason. An
optional per-device declaration may only raise it. The selected vector, the
floor in force, the selection, the device raises that produced it, the
formation instant and a digest of the exact inputs the decision was taken on
are pinned in the `sbm_group_params` GroupContext extension, so that the
group state the evidence commits to carries the decision and a verifier
recomputes it only from retained inputs that match the digest.

## Alternatives considered

- **A floor declared per entity, then per device.** Rejected: a floor each
  participant declares protects only the participants who declare one, and a
  member that publishes nothing is exactly where a provider-induced downgrade
  lands.
- **A higher mandatory floor, the hardware-holdable P-256 suite.** Rejected:
  it would exclude software-only wallets and break the invariant that the
  baseline is always in the intersection. The floor at the baseline adds no
  cryptographic strength; it adds uniform enforcement.
- **A separate signed artefact for the decision.** Rejected: the group state
  is already a cryptographic commitment to the GroupContext, so a pin there
  is evidence-visible for free; a separate artefact would rebuild that by
  hand.
- **Committing the formation instant only.** Rejected: an instant resolves
  member documents approximately and cannot resolve package availability at
  all; a digest makes the retained inputs exact and a missing input visible.

## Trade-off

Uniform, third-party-checkable enforcement, at the price of narrowing the
selection to what the devices allow and of retaining the formation inputs.

## Consequences and residual limit

Raises, publications and availability are keyed by the device's whole
principal; without the retained formation the recomputation is INCOMPLETE,
not partially run. A floor does not make provider withholding or
equivocation detectable, which stays with key transparency. The post-quantum
hybrid suite is pinned to a draft under a private-use code point, and no
cross-implementation vector exists for it.

## Status

- **Decision:** accepted.
- **Implementation:** specified; in the reference.

## Supersedes

Nothing.

## Normative owner

The Internet-Draft, *Cipher Suites*, the preference vector and floor
registry, and the `sbm_group_params` extension.

## Open questions

- [A4](../REVIEW_AGENDA.md): how the post-quantum hybrid suite is tested across
  implementations.
