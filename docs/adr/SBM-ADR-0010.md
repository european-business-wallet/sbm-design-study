---
id: SBM-ADR-0010
title: "Optional confidentiality scopes and a visible records leaf"
label: "Optional scopes, a visible records leaf"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference
choice: >-
  scopes are optional; a records function is a visible roster member ·
  [§8.3a](../../Secure-Business-Messaging-Profile.md#83a-confidentiality-scope-descriptor-normative-where-present)
alternative: >-
  mandatory scoping; invisible archival access
benefit: >-
  a small minimum deployment; no silent decryption capability
cost: >-
  extra groups and administration where adopted; a larger visible audience than strict confidentiality;
  the address is not the encryption boundary
open_questions: []
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0010 — Optional confidentiality scopes and a visible records leaf

## Context

An organisation may need some messages readable only by a part of itself,
and may need a records function that can read what a departed member
received. Both are common in registered delivery and both are places where
an invisible decryption capability tends to appear.

## Requirement and constraint

The minimum viable deployment must stay small; a counterparty must be able
to see, before sending, every party that will be able to read; and no
capability to decrypt may exist that the roster does not show.

## Decision

Confidentiality scopes are optional: an entity may adopt them per use case,
and the profile is complete without them. Where an organisation extends a
scope's confidentiality to a records function, that function is a visible
MLS roster member the counterparty can verify before sending, declared on
the scope descriptor as the role whose active members are the records leaf,
distinct from the scope's acceptance roles.

## Alternatives considered

- **Mandatory scoping.** Rejected: it would enlarge the minimum deployment
  for every entity to serve a capability only some need.
- **Invisible archival access.** Rejected: a silent decryption capability is
  exactly what the roster-transparency rule exists to forbid.

## Trade-off

A small minimum and no hidden reader, at the price of extra groups and
administration where scopes are adopted and of a visible audience larger than
strict confidentiality would allow.

## Consequences and residual limit

The address is not the encryption boundary: a scoped message is encrypted to
the scope's members, records leaf included, and the counterparty resolves
that set through the member-enumeration surface before sending. Cross-entity
scope agreement follows the recipient's scope descriptor.

## Status

- **Decision:** accepted.
- **Implementation:** specified; in the reference.

## Supersedes

Nothing.

## Normative owner

The umbrella
[§8.3a](../../Secure-Business-Messaging-Profile.md#83a-confidentiality-scope-descriptor-normative-where-present);
the Internet-Draft's roster-transparency rule and scope lifecycle.
