<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- GENERATED from docs/adr/SBM-ADR-*.md by scripts/adr_index.py --render. Do not edit: edit the record. -->

# Decisions index — today's choices, what they cost, what is undecided

**Status:** informative companion, generated from the [architecture decision records](adr/) · **Applies to:** the specification set at the versions in the README's version table (not restated here, so they cannot drift) · **Audience:** reviewers who want the design's reasons before its rules

> **Exploratory design study — not an official proposal.** This index points at the decisions; it restates no rule. In any conflict, the normative documents prevail, and each record names the one that governs.

---

## How to read this

One row per architecture decision record, one record per choice that shapes the design. A record's identifier is assigned once and never renumbered, so a decision can be cited durably. Each row gives the **choice**, its **status**, and the **principal trade-off** — what the choice buys and who pays for it. The alternative that was actually considered, why it was rejected, the normative owner and the full cost are in the record itself, one click away: nine columns of them in a table made the index a document to study rather than a map to choose from, which is the opposite of what an index is for.

Two statuses are kept apart:

- **Decision:** *proposed*, *accepted* or *superseded* — whether the choice stands;
- **Implementation:** *specified* (the normative text says it), *in the reference* (the reference implementation and its gates execute it), *planned* (decided, not implemented), *not established* (outside what the repository can show).

The **open** column names the review-agenda question a choice rests on; the record names it and stops. Where a reason was never written down, the record says so as an **unanswered** question rather than supplying one. The umbrella's six trade-offs ([§0.1](../Secure-Business-Messaging-Profile.md#01-design-trade-offs-informative)) are the short version of several rows below. The byte-level and group-design reasons are records 3, 8, 9 and 12.

## The choices

| ADR | Choice | Principal trade-off | Decision | Implementation | Open |
|---|---|---|---|---|---|
| [SBM-ADR-0001](adr/SBM-ADR-0001.md) | **A new identifier** | one routing and trust anchor, stable across provider changes — at the cost of issuance, governance and resolution infrastructure, and a duty to keep the linkage current — issuers, the EDD operator | accepted | specified; a stage-1 demonstration registry in the reference; an operated EDD not established | — |
| [SBM-ADR-0002](adr/SBM-ADR-0002.md) | **A governed federation, four instruments** | evidence weight rests on known operators; qualification and admission independently checkable — at the cost of admission barriers, central governance, freshness operations — the Federation Authority, providers; the live lease's maximum age is still to be set ([A2](REVIEW_AGENDA.md)) | accepted | specified; the register admits RDPs and is in the reference; admission for messaging providers is planned, not implemented ([A6](REVIEW_AGENDA.md)); an operated register not established | [A2](REVIEW_AGENDA.md) |
| [SBM-ADR-0003](adr/SBM-ADR-0003.md) | **MLS, bilateral, per device** | one sender, one addressee: the evidence and policy model stays singular — at the cost of per-device membership and group lifecycle; multiparty use excluded; who routes a group after formation is open ([A10](REVIEW_AGENDA.md)) | accepted | specified; in the reference | [A10](REVIEW_AGENDA.md) |
| [SBM-ADR-0004](adr/SBM-ADR-0004.md) | **MSP and RDP separated** | evidence authorship stays with qualified parties; transport and evidence become separable markets — at the cost of one more interface, and a trusted observer: separation makes a false S2 *attributable*, not impossible ([A9](REVIEW_AGENDA.md)) | superseded | relay: in force. MSP identity, `observed_by`, `receipt_digest`, composition axis: planned, not implemented ([A6](REVIEW_AGENDA.md)) | [A6](REVIEW_AGENDA.md), [A9](REVIEW_AGENDA.md) |
| [SBM-ADR-0005](adr/SBM-ADR-0005.md) | **Composition across providers** | equal local ids from two origins stay two messages; no self-Welcome — at the cost of the DS holds the origins' evidence keys and a forwarder list; the receipt's path to the DE issuer ([A1](REVIEW_AGENDA.md)) and post-formation routing ([A10](REVIEW_AGENDA.md)) are open | accepted | specified; in the reference | [A1](REVIEW_AGENDA.md), [A10](REVIEW_AGENDA.md) |
| [SBM-ADR-0006](adr/SBM-ADR-0006.md) | **The wallet as evidence participant** | both sides' acts attributable to a device key, independently of the providers, in the wallet-signed modes — at the cost of key custody, an assurance floor and compromise handling join the evidence story — wallet providers, entities ([MWAP](wallet-assurance-profile.md)) | accepted | specified; in the reference; the legal weight of each combination open ([L4](REVIEW_AGENDA.md)) | [L4](REVIEW_AGENDA.md) |
| [SBM-ADR-0007](adr/SBM-ADR-0007.md) | **Declared grades, terminal outcomes** | the legally operative act is chosen and visible; mailbox deposit never counts — at the cost of recipient cooperation at the default grades; one member's refusal or mismatch ends the message; the availability grade rests on the DS's observation ([A9](REVIEW_AGENDA.md)) | accepted | specified; in the reference | [A9](REVIEW_AGENDA.md) |
| [SBM-ADR-0008](adr/SBM-ADR-0008.md) | **Octet-authoritative encoding** | the same bytes verify everywhere; nothing is re-canonicalised at verification — at the cost of byte retention, binary tooling, debugging through projections — implementers, archivists | accepted | specified; in the reference | — |
| [SBM-ADR-0009](adr/SBM-ADR-0009.md) | **Commitments before reveals** | claims checkable without the commitment disclosing content or class before a dispute — the echoed scope reference still narrows the class to its scope's set — at the cost of a reveal discloses the class to the dispute's parties; a failing reveal proves nothing alone | accepted | specified; in the reference; the effect of a proven mismatch open ([L5](REVIEW_AGENDA.md), [L7](REVIEW_AGENDA.md)) | [L5](REVIEW_AGENDA.md), [L7](REVIEW_AGENDA.md), [A12](REVIEW_AGENDA.md) |
| [SBM-ADR-0010](adr/SBM-ADR-0010.md) | **Optional scopes, a visible records leaf** | a small minimum deployment; no silent decryption capability — at the cost of extra groups and administration where adopted; a larger visible audience than strict confidentiality; the address is not the encryption boundary | accepted | specified; in the reference | — |
| [SBM-ADR-0011](adr/SBM-ADR-0011.md) | **Historical state governs, never today's** | a correct historical verdict survives later change — at the cost of retention of chains, registries, formation inputs and assertions; missing material is INCOMPLETE; that no later policy existed stays unproven ([A3](REVIEW_AGENDA.md)) | accepted | specified; in the reference; maximality undecided | [A3](REVIEW_AGENDA.md), [A5](REVIEW_AGENDA.md) |
| [SBM-ADR-0012](adr/SBM-ADR-0012.md) | **Suite floor, committed formation** | uniform enforcement, checkable by a third party — at the cost of device constraints narrow the selection; formation inputs must be retained; post-quantum interoperability untested ([A4](REVIEW_AGENDA.md)) | accepted | specified; in the reference | [A4](REVIEW_AGENDA.md) |
| [SBM-ADR-0013](adr/SBM-ADR-0013.md) | **Pilot evidence apart; agents optional** | no claim beyond what is established — at the cost of qualification, conformity assessment and a cross-deployment agent contract lie outside the repository ([A7](REVIEW_AGENDA.md), [P1](REVIEW_AGENDA.md)) | accepted | specified; production qualification not established | [A7](REVIEW_AGENDA.md), [P1](REVIEW_AGENDA.md) |
| [SBM-ADR-0014](adr/SBM-ADR-0014.md) | **Salted content digest** | a guess about the content cannot be confirmed from the evidence alone: the salt, not the content's entropy, stands between the digest and a dictionary — at the cost of both wallets retain the salt with the content, or a package can no longer be tied to a document; an evidence bump with every sample re-sealed — the parties, the implementers, and whoever holds a package without the parties | proposed | not implemented; proposed on 26 September 2026, pending [A12](REVIEW_AGENDA.md) — nothing on the wire, in a schema or in a sample changes until the question is decided | [A12](REVIEW_AGENDA.md) |
| [SBM-ADR-0015](adr/SBM-ADR-0015.md) | **MSP folded into the RDP** | one accountable, qualified party observes, transfers and attests; A9 and L1 dissolve by construction; one fewer identity, contract, descriptor and interface; the model the consultation asked for — at the cost of transport and evidence are no longer separable markets; the RDP sits in the data path of every delivery; the privacy argument for separation is given up; a decision accepted on 17 September 2026 is superseded three weeks later | proposed | nothing on the wire changes: no Schema, contract or CDDL carries an MSP identity, and the register admits only `rdp`; the change is to the roles, the text, the figures and the agenda | [A10](REVIEW_AGENDA.md) |

## Decided is not implemented

A decision stands from the day it is recorded, whether or not code has shipped it. The records whose implementation is **planned**:

- [SBM-ADR-0002](adr/SBM-ADR-0002.md) **A governed federation, four instruments** — specified; the register admits RDPs and is in the reference; admission for messaging providers is planned, not implemented ([A6](REVIEW_AGENDA.md)); an operated register not established.
- [SBM-ADR-0004](adr/SBM-ADR-0004.md) **MSP and RDP separated** — relay: in force. MSP identity, `observed_by`, `receipt_digest`, composition axis: planned, not implemented ([A6](REVIEW_AGENDA.md)).

## Analysed is not decided

**Who observes S2** ([A9](REVIEW_AGENDA.md)). Three models are analysed in this record's own *Alternatives considered*: an accountable MSP observer, a handover proof authenticated independently of the MSP, and the handover inside the RDP's boundary. The second is the one to take *if* resistance to an MSP acting alone is to be claimed. **No model is selected**, and nothing in the specification claims that resistance. ([SBM-ADR-0004](adr/SBM-ADR-0004.md))

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
- [A10](REVIEW_AGENDA.md) — [SBM-ADR-0003](adr/SBM-ADR-0003.md), [SBM-ADR-0005](adr/SBM-ADR-0005.md), [SBM-ADR-0015](adr/SBM-ADR-0015.md)
- [A12](REVIEW_AGENDA.md) — [SBM-ADR-0009](adr/SBM-ADR-0009.md), [SBM-ADR-0014](adr/SBM-ADR-0014.md)
- [L4](REVIEW_AGENDA.md) — [SBM-ADR-0006](adr/SBM-ADR-0006.md)
- [L5](REVIEW_AGENDA.md) — [SBM-ADR-0009](adr/SBM-ADR-0009.md)
- [L7](REVIEW_AGENDA.md) — [SBM-ADR-0009](adr/SBM-ADR-0009.md)
- [P1](REVIEW_AGENDA.md) — [SBM-ADR-0013](adr/SBM-ADR-0013.md)

Every other open question — the implementer guide (G1–G4), the legal questions (L1–L8) and the agenda entries no record names — is on the [review agenda](REVIEW_AGENDA.md), each with the assumption it rests on and whose expertise would settle it.

## Author questions

- **What does a UID cost an entity?** The record names who operates the infrastructure; who pays for issuance, and on what terms, is not recorded. ([SBM-ADR-0001](adr/SBM-ADR-0001.md))
- **Why MLS, against named alternatives?** *Why this choice* states the requirements the choice was made from, what MLS supplies natively and what a pairwise composition would have to be given — as assurance and complexity, not impossibility. No specific competing protocol or product is assessed, and no such comparison is written down. ([SBM-ADR-0003](adr/SBM-ADR-0003.md))
