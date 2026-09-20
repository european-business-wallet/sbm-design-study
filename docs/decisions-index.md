<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- GENERATED from docs/adr/SBM-ADR-*.md by scripts/adr_index.py --render. Do not edit: edit the record. -->

# Decisions index — today's choices, what they cost, what is undecided

**Status:** informative companion, generated from the [architecture decision records](adr/) · **Applies to:** the specification set at the versions in the README's version table (not restated here, so they cannot drift) · **Audience:** reviewers who want the design's reasons before its rules

> **Exploratory design study — not an official proposal.** This index points at the decisions; it restates no rule. In any conflict, the normative documents prevail, and each record names the one that governs.

---

## How to read this

One row per architecture decision record, one record per choice that shapes the design. A record's identifier is assigned once and never renumbered, so a decision can be cited durably. Each row gives the **choice** and the document that makes it normative, the **alternative that was actually considered** — the record says why it was rejected — the **benefit**, the **cost and who pays it**, and two statuses kept apart:

- **Decision:** *proposed*, *accepted* or *superseded* — whether the choice stands;
- **Implementation:** *specified* (the normative text says it), *in the reference* (the reference implementation and its gates execute it), *planned* (decided, not implemented), *not established* (outside what the repository can show).

The **open** column names the review-agenda question a choice rests on; the record names it and stops. Where a reason was never written down, the record says so as an **unanswered** question rather than supplying one. The umbrella's six trade-offs ([§0.1](../Secure-Business-Messaging-Profile.md#01-design-trade-offs-informative)) are the short version of several rows below. The byte-level and group-design reasons are records 3, 8, 9 and 12.

## The choices

| ADR | Choice | Current choice · normative owner | Alternative considered | Benefit | Cost — who pays | Decision | Implementation | Open |
|---|---|---|---|---|---|---|---|---|
| [SBM-ADR-0001](adr/SBM-ADR-0001.md) | **A new identifier** | UID issued as a qualified attestation, resolved through the EDD, *linked* to EUID and LEI · [§3.7](../Secure-Business-Messaging-Profile.md#37-why-a-new-identifier-informative), §5.2, §6 | reusing EUID, LEI, VAT or national numbers — none is universal, entity-faithful and cross-border resolvable | one routing and trust anchor, stable across provider changes | issuance, governance and resolution infrastructure, and a duty to keep the linkage current — issuers, the EDD operator | accepted | specified; a stage-1 demonstration registry in the reference; an operated EDD not established | — |
| [SBM-ADR-0002](adr/SBM-ADR-0002.md) | **A governed federation, four instruments** | admitted, supervised providers; Trusted Lists (qualification), membership register (admission), EDD (identity), design authority (change control) kept apart · [§13.1](../Secure-Business-Messaging-Profile.md#131-institutional-roles) | an open, e-mail-style federation; or admission folded into the EDD resolver | evidence weight rests on known operators; qualification and admission independently checkable | admission barriers, central governance, freshness operations — the Federation Authority, providers; the live lease's maximum age is still to be set ([A2](REVIEW_AGENDA.md)) | accepted | specified; register for RDPs in the reference (Batch A); MSP admission planned (Batch B); an operated register not established | [A2](REVIEW_AGENDA.md) |
| [SBM-ADR-0003](adr/SBM-ADR-0003.md) | **MLS, bilateral, per device** | one MLS group per entity pair (and scope); every device of both entities is a leaf · the I-D, *Group Topology* | multiparty groups — prohibited, recorded as future study | one sender, one addressee: the evidence and policy model stays singular | per-device membership and group lifecycle; multiparty use excluded; who routes a group after formation is open ([A10](REVIEW_AGENDA.md)) | accepted | specified; in the reference | [A10](REVIEW_AGENDA.md) |
| [SBM-ADR-0004](adr/SBM-ADR-0004.md) | **MSP and RDP separated** | the MSP is each side's local delivery service and a participant in its own right; the relay stays RDP-to-RDP; a DE should bind the observation it rests on; provider composition is a deployment axis, not a rung · §7.2, [§13.1](../Secure-Business-Messaging-Profile.md#131-institutional-roles) | a relay between the two MSPs with RDPs as observers — rejected; the MSP as the RDP's subcontractor — rejected | evidence authorship stays with qualified parties; transport and evidence become separable markets | one more interface, and a trusted observer: separation makes a false S2 *attributable*, not impossible ([A9](REVIEW_AGENDA.md)) | accepted | relay: in force. MSP identity, `observed_by`, `receipt_digest`, composition axis: planned (Batch B), not implemented | [A6](REVIEW_AGENDA.md), [A9](REVIEW_AGENDA.md) |
| [SBM-ADR-0005](adr/SBM-ADR-0005.md) | **Composition across providers** | the origin's sealed SE proves its namespace through RDP(in); the creating device registers as the group's founder · the I-D, *Delivery Service* and *Group Establishment*; the delivery-service contract | an origin-signed forwarding token; a founder implied by the first deposit | equal local ids from two origins stay two messages; no self-Welcome | the DS holds the origins' evidence keys and a forwarder list; the receipt's path to the DE issuer ([A1](REVIEW_AGENDA.md)) and post-formation routing ([A10](REVIEW_AGENDA.md)) are open | accepted | specified; in the reference | [A1](REVIEW_AGENDA.md), [A10](REVIEW_AGENDA.md) |
| [SBM-ADR-0006](adr/SBM-ADR-0006.md) | **The wallet as evidence participant** | the recipient confirms, wallet-signed or session-bound; the sender signs its submission by default · TS clause 6; [§7.5](../Secure-Business-Messaging-Profile.md#75-the-wallet-as-evidence-participant-informative) | provider-attested acts only — kept as an explicitly narrowed fallback | both sides' acts attributable to a device key, independently of the providers, in the wallet-signed modes | key custody, an assurance floor and compromise handling join the evidence story — wallet providers, entities ([MWAP](wallet-assurance-profile.md)) | accepted | specified; in the reference; the legal weight of each combination open ([L4](REVIEW_AGENDA.md)) | [L4](REVIEW_AGENDA.md) |
| [SBM-ADR-0007](adr/SBM-ADR-0007.md) | **Declared grades, terminal outcomes** | verification by default, acceptance under quorum or `all`, availability only where the recipient declared it per class; each grade dated by its own event; a verified mismatch or refusal ends the message · [§8.3b](../Secure-Business-Messaging-Profile.md#83b-delivery-grade-declaration-normative); the I-D, *Delivery State Model* and *Timing*; TS clause 6 | an implicit handover grade for every message — excluded ([§7.1](../Secure-Business-Messaging-Profile.md#71-technical-architecture-authoritative)); a refusal that changes nothing — revised | the legally operative act is chosen and visible; mailbox deposit never counts | recipient cooperation at the default grades; one member's refusal or mismatch ends the message; the availability grade rests on the DS's observation ([A9](REVIEW_AGENDA.md)) | accepted | specified; in the reference | [A9](REVIEW_AGENDA.md) |
| [SBM-ADR-0008](adr/SBM-ADR-0008.md) | **Octet-authoritative encoding** | the deterministic-CBOR payload is what is signed; JSON is a projection; the qualified timestamp attests the seal from outside · the I-D; [the design record](OCTET_AUTHORITATIVE_DESIGN.md) | signing JSON canonicalised with the JSON Canonicalization Scheme — the model the profile left — and the other options [that record rejects](OCTET_AUTHORITATIVE_DESIGN.md#5-options-considered-and-rejected) | the same bytes verify everywhere; nothing is re-canonicalised at verification | byte retention, binary tooling, debugging through projections — implementers, archivists | accepted | specified; in the reference | — |
| [SBM-ADR-0009](adr/SBM-ADR-0009.md) | **Commitments before reveals** | evidence binds the content digest, the ciphertext digest and the group state; availability and opposable agent acts carry salted commitments opened only by a reveal · the I-D, *Grade Commitment* and *Mandate Commitment* | a cryptographic ciphertext-to-reveal proof — future work; commitment inequality alone as a rebuttal — rejected | claims checkable without disclosing content or class before a dispute | a reveal discloses the class to the dispute's parties; a failing reveal proves nothing alone | accepted | specified; in the reference; the effect of a proven mismatch open ([L5](REVIEW_AGENDA.md), [L7](REVIEW_AGENDA.md)) | [L5](REVIEW_AGENDA.md), [L7](REVIEW_AGENDA.md) |
| [SBM-ADR-0010](adr/SBM-ADR-0010.md) | **Optional scopes, a visible records leaf** | scopes are optional; a records function is a visible roster member · [§8.3a](../Secure-Business-Messaging-Profile.md#83a-confidentiality-scope-descriptor-normative-where-present) | mandatory scoping; invisible archival access | a small minimum deployment; no silent decryption capability | extra groups and administration where adopted; a larger visible audience than strict confidentiality; the address is not the encryption boundary | accepted | specified; in the reference | — |
| [SBM-ADR-0011](adr/SBM-ADR-0011.md) | **Historical state governs, never today's** | a published policy is never modified — its window ends at its signed successor; admission is evaluated as of the act; a group decodes under its pinned registry revision; a suite decision recomputes only from its committed inputs · the umbrella §8.3; the I-D; TS clause 6 | a stored `valid_until` and an `as_of` endpoint — superseded; a signed head assertion — rejected | a correct historical verdict survives later change | retention of chains, registries, formation inputs and assertions; missing material is INCOMPLETE; that no later policy existed stays unproven ([A3](REVIEW_AGENDA.md)) | accepted | specified; in the reference; maximality undecided | [A3](REVIEW_AGENDA.md), [A5](REVIEW_AGENDA.md) |
| [SBM-ADR-0012](adr/SBM-ADR-0012.md) | **Suite floor, committed formation** | a mandatory floor at the baseline, raisable per device; the decision pinned in the GroupContext with its inputs · the I-D, *Cipher Suites* and the `sbm_group_params` extension | a floor per entity or per device alone; a higher mandatory floor (P-256); a separate signed artefact; committing the instant only | uniform enforcement, checkable by a third party | device constraints narrow the selection; formation inputs must be retained; post-quantum interoperability untested ([A4](REVIEW_AGENDA.md)) | accepted | specified; in the reference | [A4](REVIEW_AGENDA.md) |
| [SBM-ADR-0013](adr/SBM-ADR-0013.md) | **Pilot evidence apart; agents optional** | pilot evidence is structurally identical and makes no claim under the regulation; agents are the optional deployment profile 5 · [§13.3](../Secure-Business-Messaging-Profile.md#133-conformance-profiles-pilot-and-production); TS clause 9; Annex R | qualification as a property of the protocol — rejected | no claim beyond what is established | qualification, conformity assessment and a cross-deployment agent contract lie outside the repository ([A7](REVIEW_AGENDA.md), [P1](REVIEW_AGENDA.md)) | accepted | specified; production qualification not established | [A7](REVIEW_AGENDA.md), [P1](REVIEW_AGENDA.md) |

## Decided is not implemented

A decision stands from the day it is recorded, whether or not code has shipped it. The records whose implementation is **planned**:

- [SBM-ADR-0002](adr/SBM-ADR-0002.md) **A governed federation, four instruments** — specified; register for RDPs in the reference (Batch A); MSP admission planned (Batch B); an operated register not established.
- [SBM-ADR-0004](adr/SBM-ADR-0004.md) **MSP and RDP separated** — relay: in force. MSP identity, `observed_by`, `receipt_digest`, composition axis: planned (Batch B), not implemented.

## Analysed is not decided

**Who observes S2** ([A9](REVIEW_AGENDA.md)). Three models are analysed in the study's historical RDP/MSP trust analysis (`docs/rdp-msp-trust-analysis/`, not a selected design): an accountable MSP observer, a handover proof authenticated independently of the MSP, and the handover inside the RDP's boundary. The analysis recommends the second *if* resistance to an MSP acting alone is to be claimed. **No model is selected**, and nothing in the specification claims that resistance. ([SBM-ADR-0004](adr/SBM-ADR-0004.md))

## Open

The review-agenda questions a record rests on, and the records that name them:

- [A1](REVIEW_AGENDA.md) — [SBM-ADR-0005](adr/SBM-ADR-0005.md)
- [A2](REVIEW_AGENDA.md) — [SBM-ADR-0002](adr/SBM-ADR-0002.md)
- [A3](REVIEW_AGENDA.md) — [SBM-ADR-0011](adr/SBM-ADR-0011.md)
- [A4](REVIEW_AGENDA.md) — [SBM-ADR-0012](adr/SBM-ADR-0012.md)
- [A5](REVIEW_AGENDA.md) — [SBM-ADR-0011](adr/SBM-ADR-0011.md)
- [A6](REVIEW_AGENDA.md) — [SBM-ADR-0004](adr/SBM-ADR-0004.md)
- [A7](REVIEW_AGENDA.md) — [SBM-ADR-0013](adr/SBM-ADR-0013.md)
- [A9](REVIEW_AGENDA.md) — [SBM-ADR-0004](adr/SBM-ADR-0004.md), [SBM-ADR-0007](adr/SBM-ADR-0007.md)
- [A10](REVIEW_AGENDA.md) — [SBM-ADR-0003](adr/SBM-ADR-0003.md), [SBM-ADR-0005](adr/SBM-ADR-0005.md)
- [L4](REVIEW_AGENDA.md) — [SBM-ADR-0006](adr/SBM-ADR-0006.md)
- [L5](REVIEW_AGENDA.md) — [SBM-ADR-0009](adr/SBM-ADR-0009.md)
- [L7](REVIEW_AGENDA.md) — [SBM-ADR-0009](adr/SBM-ADR-0009.md)
- [P1](REVIEW_AGENDA.md) — [SBM-ADR-0013](adr/SBM-ADR-0013.md)

Every other open question — the implementer guide (G1–G4), the legal questions (L1–L8) and the agenda entries no record names — is on the [review agenda](REVIEW_AGENDA.md), each with the assumption it rests on and whose expertise would settle it.

## Author questions

- **What does a UID cost an entity?** The record names who operates the infrastructure; who pays for issuance, and on what terms, is not recorded. ([SBM-ADR-0001](adr/SBM-ADR-0001.md))
- **Why MLS?** The record explains how MLS is profiled, not why it was chosen over other end-to-end protocols; no comparison is written down. ([SBM-ADR-0003](adr/SBM-ADR-0003.md))
