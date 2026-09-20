<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
---
id: SBM-ADR-0001
title: "A new entity identifier, issued as an attestation and resolved through the EDD"
label: "A new identifier"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; a stage-1 demonstration registry in the reference; an operated EDD not established
choice: >-
  UID issued as a qualified attestation, resolved through the EDD, *linked* to EUID and LEI ·
  [§3.7](../../Secure-Business-Messaging-Profile.md#37-why-a-new-identifier-informative), §5.2, §6
alternative: >-
  reusing EUID, LEI, VAT or national numbers — none is universal, entity-faithful and cross-border resolvable
benefit: >-
  one routing and trust anchor, stable across provider changes
cost: >-
  issuance, governance and resolution infrastructure, and a duty to keep the linkage current — issuers, the EDD operator
open_questions: []
author_questions:
  - "What does a UID cost an entity? The record names who operates the infrastructure; who pays for issuance, and on what terms, is not recorded."
supersedes: []
---

# SBM-ADR-0001 — A new entity identifier, issued as an attestation and resolved through the EDD

## Context

Registered delivery between entities needs one name per entity that every
participant can route to, resolve and trust. Europe already has entity
identifiers: the EUID of the business-register interconnection, the LEI, VAT
identifiers and national registration numbers. The study asked whether any of
them could serve as the wallet ecosystem's routing and trust anchor before
minting a new one ([§3.7](../../Secure-Business-Messaging-Profile.md#37-why-a-new-identifier-informative)).

## Requirement and constraint

The identifier must be universal across the entities that send and receive
registered communications, entity-faithful (one identifier, one legal entity),
resolvable across borders at runtime, bindable to the entity's trust material,
and stable when the entity changes provider. It must not become a second
register of facts about the entity: authoritative facts stay in the source
registers.

## Decision

A new identifier, the UID: uniform, checksummed, issued as a qualified
attestation, bound to the entity's trust material and resolvable through the
entity discovery directory (EDD). The directory record *links* the UID to the
EUID and the LEI rather than replacing them, so the source registers remain
authoritative and a future register integration is absorbed by the linkage
without re-addressing the network.

## Alternatives considered

- **Reuse the EUID.** Rejected: it is scoped to the business-register
  interconnection, so public-sector bodies, associations, foundations and many
  other entities have none, and its register-oriented format was never meant
  for runtime routing or key discovery.
- **Reuse the LEI.** Rejected: coverage tracks financial-market participation,
  elsewhere it is voluntary and fee-based, and it was designed for regulatory
  reporting, not as an address or a trust anchor.
- **Reuse VAT identifiers.** Rejected: not every relevant entity is
  VAT-registered, and VAT groups, branches and fiscal representatives break
  the one-identifier-one-entity assumption.
- **Reuse national registration numbers.** Rejected: format, semantics,
  uniqueness guarantees and register access differ per Member State, so they
  cannot anchor a cross-border protocol.

## Trade-off

One anchor for routing, discovery and evidence, at the price of building and
governing an issuance and resolution infrastructure that did not exist. The
study judged the anchor worth the infrastructure because no existing
identifier gave all three properties at once, and because the linkage keeps
the new identifier from competing with the registers it points at.

## Consequences and residual limit

Issuers and the EDD operator carry issuance, governance and resolution, and a
duty to keep the linkage current. The UID's binding to the entity's seal key
is pinned by the discovery record itself; how the qualified attestation's
lifecycle and revocation bind to the UID lifecycle is an external-counsel
item and stays flagged in the umbrella. An operated EDD is not established:
the reference ships a stage-1 demonstration registry.

## Status

- **Decision:** accepted.
- **Implementation:** specified; a stage-1 demonstration registry in the
  reference; an operated EDD not established.

## Supersedes

Nothing.

## Normative owner

The umbrella: [§3.7](../../Secure-Business-Messaging-Profile.md#37-why-a-new-identifier-informative) for the
rationale, §4.1 and §10.1 for the attestation, §5.2 and §6 for the directory
record and its linkage.

## Unanswered

What a UID costs an entity: the record names who operates the infrastructure;
who pays for issuance, and on what terms, is not recorded.
