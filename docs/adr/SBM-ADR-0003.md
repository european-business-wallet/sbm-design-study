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
  - "Why MLS? The record explains how MLS is profiled, not why it was chosen over other end-to-end protocols; no comparison is written down."
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

**What that excludes, in kind.** A pairwise protocol with per-device ratchets
meets asynchrony and multiple devices, and gives no group object: "the devices
of the recipient entity at this instant" becomes a provider's list, which is
precisely the thing the evidence must not depend on. A server-side group with
transport encryption gives the group object and breaks the last requirement.
A key-agreement-per-message design meets confidentiality and makes the
device set a matter of who was online. MLS is the one shape in which the group,
its membership and its epoch are cryptographic state that both parties hold and
a third party can be shown — which is what `mls_group_id`, `mls_epoch` and
`mls_state` in the evidence are.

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

A comparison against named alternatives. *Why MLS at all* above states the
requirements the choice was made from and the shapes they exclude, which is the
level the decision was actually taken at; it is not an assessment of specific
competing protocols or products, and none is written down.
