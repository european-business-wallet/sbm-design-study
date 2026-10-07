---
id: SBM-ADR-0012
title: "A mandatory suite floor and a committed formation"
label: "A mandatory cipher-suite minimum"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference
choice: >-
  There is a mandatory minimum cipher suite that every deployment must support, set at the baseline, and a device may insist on more than the minimum. Which suite a group settled on is pinned in the group's own context, together with the inputs the decision was made from · the I-D, *Cipher Suites* and the `sbm_group_params` extension
alternative: >-
  Four. A minimum set per entity, or per device, instead of one for the whole profile. A higher mandatory minimum (P-256). Recording the decision in a separate signed object. Or committing only to the instant the decision was taken, not to its inputs
benefit: >-
  The minimum is enforced uniformly, and a third party can check for itself that it was honoured
cost: >-
  What a device can support narrows what may be selected, the formation inputs have to be retained, and post-quantum interoperability is untested ([A4](../REVIEW_AGENDA.md))
open_questions: [A4]
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0012 — A mandatory suite floor and a committed formation

## Context

Two creators must choose the same cipher suite from the same capability
sets, a deployment must not be able to downgrade a group below what the
profile promises, and a verifier must be able to check the decision later
from retained material rather than from today's registry and today's
published capabilities.

## Requirement and constraint

Four requirements:

- the security claim must be verifiable by a third party, not merely a local
  option each deployment sets for itself;
- a member that publishes nothing must be protected as well as one that does;
- the baseline suite must remain in every intersection, so that a usable
  selection always exists;
- and raising the minimum later must be a governance action rather than a
  redesign.

## Decision

A mandatory floor, `mls-suite-floor/v1`, set at the baseline suite as a
versioned constant of the profile, binding on every conforming deployment;
a group below it must not form and is refused with a typed reason. An
optional per-device declaration may only raise it.

Six things are pinned in the `sbm_group_params` extension of the group's own
context: the selected vector, the minimum in force, the selection itself, the
device raises that produced it, the instant of formation, and a digest of the
exact inputs the decision was taken on. Two consequences follow. The group state
that the evidence commits to carries the decision with it. And a verifier can
recompute that decision only from retained inputs whose digest matches — not
from whatever inputs it happens to have.

## Alternatives considered

- **A floor declared per entity, then per device.** Rejected: a floor each
  participant declares protects only the participants who declare one, and a
  member that publishes nothing is exactly where a provider-induced downgrade
  lands.
- **A higher mandatory floor, the P-256 suite.** Rejected: it would exclude
  every implementation that supports only the mandatory baseline suite of RFC
  9420, and break the invariant that the baseline is always in the
  intersection. Hardware key protection is a separate property from suite
  support and is not what a floor decides. The floor at the baseline adds no
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
