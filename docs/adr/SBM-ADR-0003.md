<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
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

Why MLS: the record explains how MLS is profiled, not why it was chosen over
other end-to-end protocols; no comparison is written down.
