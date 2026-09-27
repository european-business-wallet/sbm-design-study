---
id: SBM-ADR-0003
title: "MLS, bilateral, per device"
label: "MLS, bilateral, per device"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference
choice: >-
  one MLS group per entity pair (and scope); every device of both entities is a leaf · the I-D, *Group Topology*
alternative: >-
  multiparty groups — prohibited, recorded as future study
benefit: >-
  one sender, one addressee: the evidence and policy model stays singular
cost: >-
  per-device membership and group lifecycle; multiparty use excluded;
  who routes a group after formation is open ([A10](../REVIEW_AGENDA.md))
open_questions: [A10]
author_questions:
  - "Why MLS, against named alternatives? *Why this choice* states the requirements the choice was made from, what MLS supplies natively and what a pairwise composition would have to be given — as assurance and complexity, not impossibility. No specific competing protocol or product is assessed, and no such comparison is written down."
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0003 — MLS, bilateral, per device

## Context

The profile carries registered messages end-to-end encrypted between the
devices of two entities, over the Messaging Layer Security protocol, with the
provider as a delivery service that never holds content keys.

## Requirement and constraint

The evidence, addressing, policy and directory model of the profile is
singular: one sender, one addressee, one acceptance policy per message, one
directory record per side. The legal argument for the evidence likewise
identifies one sender and one addressee. Every device of each entity must be
able to receive, and the group must survive device changes without
re-keying the relationship.

## Decision

One MLS group per pair of entities (and per confidentiality scope where
scopes are used); every enrolled device of both entities is a leaf. Groups
are bilateral: a group containing the devices of three or more entities is
rejected at creation, at join and at verification. Multiparty use is
recorded as a possible future extension, not current scope.

## Why this choice

**Why MLS at all.** The record above profiles MLS; it did not say why the
profile rests on MLS
rather than on another end-to-end protocol, and a reviewer of the architecture
meets that question first. This section answers it at the level the choice was
actually made, from the requirements — it is a rationale, not a survey, and no
product or competing specification is assessed here.

**Four requirements drove it.** *Asynchrony*, because a registered message is
delivered to a party who may be offline for days and the evidence must still
attach to a defined act. *Many devices per party*, because an entity is not a
person with one handset: every enrolled device must be able to receive, and a
device added or retired must not re-key the relationship or invalidate earlier
evidence. *A group whose membership is itself the subject of proof*, because
the evidence says which devices of which entity could read a message, so
membership has to be a signed, inspectable state rather than a list held by a
provider. And *a provider that never holds content keys*, because the whole
legal argument rests on a provider attesting delivery of something it cannot
read.

**What MLS supplies natively, and what an alternative would have to be given.**
The argument is about what comes with the protocol, not about what other
protocols make impossible — an earlier revision of this section claimed the
latter and was wrong to.

A pairwise design meets asynchrony and multiple devices on its own: published
prekeys let a sender encrypt to a recipient who is offline (X3DH; HPKE's
single-shot encryption to a public key needs no live participation at all), and
multi-device session management is a solved problem in that family (Sesame).
What such a design does not carry is a **group object**: a membership that both
parties hold as cryptographic state, changes by a signed operation, and advances
a counter a third party can be shown. This profile's evidence names
`mls_group_id`, `mls_epoch` and `mls_state` because those are exactly that
state; on a pairwise base they would have to be **specified, implemented and
proven by this profile** — a signed roster with its own versioning and conflict
rules, a membership-change operation, an epoch equivalent, and a story for how a
verifier years later checks that the devices it names were the members then.

A server-side group gives the group object and breaks the requirement that the
provider never holds content keys, which is not a matter of composition: it is
the boundary the whole legal argument rests on.

So the choice is **assurance and complexity, not impossibility**. MLS brings
group membership, its epochs and its transcript as reviewed, implemented
machinery with its own security analysis; the alternative is a smaller base plus
a roster mechanism this study would own end to end. Nothing here assesses whether
a particular pairwise composition could satisfy the full requirement set — that
comparison is not written down, and the record says so under *Unanswered*.

**What it costs, stated where an architect will look for it.** Persistent group
state per relationship, which a provider must store and a wallet must not lose.
Roster synchronisation between two organisations that hire and dismiss
independently. Epoch handling, with the delivery and re-verification rules that
follow from it — a queued message is not re-encrypted by an epoch change, and a
resubmission after one is a new submission with a new evidence chain. Onboarding
cost: a device cannot join without a KeyPackage, so key material has to be
reserved, distributed and replenished, and the failure modes of that pool are
real enough to have their own reason codes. And coordination with a delivery
service that neither party controls, which is where the open questions about
routing and post-formation membership live ([A10](../REVIEW_AGENDA.md)).

**What MLS does not give the profile**, so that nothing is assumed to follow
from the choice: it does not make delivery evidential — the S1–S4 model, the
confirmations and the evidence objects are this profile's, not MLS's; it does
not identify a legal entity — that is the UID attestation and the discovery
documents; it does not order or timestamp anything a court would accept — the
qualified timestamps do; and it does not decide who may accept a message, which
is the acceptance policy. MLS supplies the confidential channel and the
inspectable group; everything the evidence asserts is built on top and is this
specification's own responsibility.

## Alternatives considered

- **Multiparty groups.** Rejected for this version: the whole evidence,
  addressing, policy and directory model is singular, no concrete multiparty
  use case was on the table, and prohibiting removed a large under-specified
  surface at no current cost. The prohibition is reversible: multiparty can
  be added later as a specified extension.

## Trade-off

A singular evidence and policy model that stays checkable, at the price of
per-device group membership and lifecycle work and of excluding multiparty
use.

## Consequences and residual limit

Each side's devices are group members and must be added, removed and rotated
through MLS; group establishment, refusal and the cipher-suite decision get
their own rules. Which delivery service routes a group after formation, and
who owns its membership then, is not decided.

## Status

- **Decision:** accepted.
- **Implementation:** specified; in the reference.

## Supersedes

Nothing.

## Normative owner

The Internet-Draft, *Group Topology* and *Group Establishment*.

## Open questions

- [A10](../REVIEW_AGENDA.md): which delivery service routes a group, and who owns its
  membership after formation.

## Unanswered

A comparison against named alternatives. *Why this choice* above states the
requirements the choice was made from, what MLS supplies natively and what a
pairwise composition would have to be given instead — a difference of assurance
and complexity. It is not an assessment of any specific competing protocol or
product: whether a particular composition could satisfy the full requirement set
is not established either way, and no such comparison is written down.
