---
id: SBM-ADR-0001
title: "A new entity identifier, issued as an attestation and resolved through the EDD"
label: "A new identifier"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  Specified. The reference ships a stage-1 demonstration registry — a signed file, not a service. No operated European Directory of Entities exists, so that part is not established
choice: >-
  Every entity gets a new identifier of its own, a UID. It is issued to the entity as a qualified attestation, resolved through the European Directory of Entities, and *linked* to the identifiers that already exist — the Business Registers Interconnection System identifier (EUID) and the Legal Entity Identifier (LEI) — rather than derived from either · [§3.7](../../Secure-Business-Messaging-Profile.md#37-why-a-new-identifier-informative), §5.2, §6
alternative: >-
  Two. Reuse a number that already exists — EUID, LEI, a VAT number, a national register number — rejected, because no single one of them is at once universal, faithful to the entity itself, and resolvable across borders. Or derive the new identifier's content from the EUID — rejected: the link between the two stays an explicit, sealed attribute rather than something a reader is expected to compute
benefit: >-
  One anchor serves both routing and trust, and it does not change when the entity changes provider
cost: >-
  Somebody must issue these identifiers, govern them, operate the service that resolves them, and keep the link to the existing registers current. That falls on the issuers and the directory's operator
open_questions: []
author_questions:
  - "What does a UID cost an entity? The record names who operates the infrastructure; who pays for issuance, and on what terms, is not recorded."
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
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

A new identifier of the entity's own, the UID: uniform, checksummed, issued as
a qualified attestation, bound to the entity's trust material and resolvable
through the **European Directory of Entities** (EDD). The directory record
*links* the UID to the EUID and the LEI rather than replacing them, so the
source registers remain authoritative, and a future register integration is
absorbed by the linkage without re-addressing the network.

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
- **Derive the UID's payload from the EUID**, by encoding or hashing it, so
  that the link to the business register is intrinsic to the identifier
  rather than an attribute beside it. Considered on 20 September 2026 and
  rejected; the umbrella's §6.3 forbids it in production and points here.
  Coverage: the EUID exists only for companies and branches in the registers
  connected through BRIS, so public-sector bodies, associations, foundations
  and non-EU entities — the cases §3.7 names — would need a second minting
  rule, and the UID would stop being uniform. Stability: the EUID can change
  with the competent register, a conversion or a cross-border merger, while
  the UID must survive everything anchored to it; a derived UID either
  changes with it, losing the property it exists for, or stays, leaving the
  "intrinsic" link stale and the explicit attribute needed anyway. Trust: a
  derived value proves that the minter chose that EUID, not that the entity
  holds it; the issuing QTSP's due diligence and its sealed `EUID-LINK`
  attribute (§6.1) are the guarantee either way, and derivation adds nothing
  to them. Enumerability: register numbers are public and sequential, so a
  derived payload lets anyone compute every company's UID offline and probe
  the directory as an existence oracle, where today discovery goes through
  the reverse link the register controls (§6.2). Semantics: the payload is
  semantics-free by design, and a derived one would carry another scheme's
  lifecycle into the anchor. Where a stronger link is wanted, it belongs to
  the attribute — a register countersignature, or a salted commitment to the
  EUID in the record — not to the payload.

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
