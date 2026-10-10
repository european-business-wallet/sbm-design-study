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
| [SBM-ADR-0001](adr/SBM-ADR-0001.md) | **A new identifier** | **Buys:** One anchor serves both routing and trust, and it does not change when the entity changes provider **Costs:** Somebody must issue these identifiers, govern them, operate the service that resolves them, and keep the link to the existing registers current. That falls on the issuers and the directory's operator | accepted | Specified. The reference ships a stage-1 demonstration registry — a signed file, not a service. No operated European Directory of Entities exists, so that part is not established | — |
| [SBM-ADR-0002](adr/SBM-ADR-0002.md) | **A governed federation, four instruments** | **Buys:** The weight evidence carries rests on operators who are known, and a verifier can check qualification and admission independently of each other **Costs:** A barrier to entry, central governance, and admission data somebody must keep fresh — the Federation Authority and the providers | accepted | Specified, and the register is in the reference: it admits the one provider role by decision rather than as a stage ([A6](REVIEW_AGENDA.md), closed). An OPERATED register is only planned — what ships is a file | [A2](REVIEW_AGENDA.md) |
| [SBM-ADR-0003](adr/SBM-ADR-0003.md) | **MLS, one pair of entities, device-level membership** | **Buys:** One sender and one addressee, so the evidence and the policy model each describe a single relationship instead of a set of them **Costs:** Membership is per device, and the group has a lifecycle to manage. Multiparty use is excluded. Who routes a group once it has been formed is still open ([A10](REVIEW_AGENDA.md)) | accepted | specified; in the reference | [A10](REVIEW_AGENDA.md) |
| [SBM-ADR-0004](adr/SBM-ADR-0004.md) | **The messaging provider as a separate participant** | **Buys:** Evidence is authored only by qualified parties, and transport and evidence can be bought from different suppliers **Costs:** One more interface to specify, and a trusted observer to rely on. Separating the two roles makes a false delivery claim *attributable* to whoever made it — not impossible ([A9](REVIEW_AGENDA.md)) | superseded | The relay is in force and is the only part of this record that was ever built. SBM-ADR-0015 withdrew the rest rather than leave it to be built later | — |
| [SBM-ADR-0005](adr/SBM-ADR-0005.md) | **Crossing from one provider to another** | **Buys:** Two messages that happen to carry the same local identifier under two different origins stay two messages. And no device has to welcome itself into its own group **Costs:** The Delivery Service has to hold the origins' evidence-verification keys and a list of who may forward | accepted | specified; in the reference | [A1](REVIEW_AGENDA.md), [A10](REVIEW_AGENDA.md) |
| [SBM-ADR-0006](adr/SBM-ADR-0006.md) | **The wallet as evidence participant** | **Buys:** In the wallet-signed modes, each side's act is attributable to a key held on that side's device, so it does not rest on the providers' word **Costs:** Key custody, a minimum assurance level and a story for a compromised device all become part of the evidence model — for wallet providers and for entities | accepted | Specified, and in the reference. What legal weight each combination carries is open ([L4](REVIEW_AGENDA.md)) | [L4](REVIEW_AGENDA.md) |
| [SBM-ADR-0007](adr/SBM-ADR-0007.md) | **Delivery grades are declared, not assumed** | **Buys:** Which act carries legal effect is chosen deliberately and is visible in the evidence. Depositing a message in a mailbox never counts as delivery **Costs:** At the default grades the recipient has to cooperate for delivery to be evidenced at all, and one member's refusal or digest mismatch ends the message for everyone | accepted | specified; in the reference | — |
| [SBM-ADR-0008](adr/SBM-ADR-0008.md) | **The signed bytes are authoritative; JSON is a view** | **Buys:** The same bytes verify the same way everywhere, and nothing has to be re-canonicalised at verification time — which is where canonicalisation schemes go wrong **Costs:** The bytes themselves must be retained, tooling has to handle binary, and debugging happens through a projection rather than the real object — for implementers and archivists | accepted | specified; in the reference | — |
| [SBM-ADR-0009](adr/SBM-ADR-0009.md) | **Commitments before reveals** | **Buys:** A claim can be checked without the evidence having disclosed the content, or even the class of content, before a dispute arises **Costs:** Performing a reveal discloses the content class to the parties to the dispute. And a reveal that fails proves nothing by itself | accepted | Specified, and in the reference. What a proven mismatch should legally imply is open ([L5](REVIEW_AGENDA.md), [L7](REVIEW_AGENDA.md)) | [L5](REVIEW_AGENDA.md), [L7](REVIEW_AGENDA.md), [A12](REVIEW_AGENDA.md) |
| [SBM-ADR-0010](adr/SBM-ADR-0010.md) | **Scopes optional; archival access visible** | **Buys:** The minimum viable deployment stays small, and nothing holds a decryption capability that the other side cannot see **Costs:** Where scopes are adopted there are more groups to run and administer, and the audience that can read a message is visibly larger than strict confidentiality would allow | accepted | specified; in the reference | — |
| [SBM-ADR-0011](adr/SBM-ADR-0011.md) | **Historical state governs, never today's** | **Buys:** A verdict that was correct about the past stays correct, whatever changes afterwards **Costs:** The chains, registries, formation inputs and assertions all have to be retained, and where the material is missing the verification is reported INCOMPLETE rather than passed | accepted | Specified, and in the reference. One part is still undecided: proving that the policy a message pinned was the LATEST one then in force, rather than merely one that was in force | [A3](REVIEW_AGENDA.md), [A5](REVIEW_AGENDA.md) |
| [SBM-ADR-0012](adr/SBM-ADR-0012.md) | **A mandatory cipher-suite minimum** | **Buys:** The minimum is enforced uniformly, and a third party can check for itself that it was honoured **Costs:** What a device can support narrows what may be selected, the formation inputs have to be retained, and post-quantum interoperability is untested ([A4](REVIEW_AGENDA.md)) | accepted | specified; in the reference | [A4](REVIEW_AGENDA.md) |
| [SBM-ADR-0013](adr/SBM-ADR-0013.md) | **Pilot evidence apart; agents optional** | **Buys:** Nothing claims more than has actually been established **Costs:** Qualification, conformity assessment and an agent contract that works across deployments all lie outside this repository ([A7](REVIEW_AGENDA.md), [P1](REVIEW_AGENDA.md)) | accepted | Specified. Qualification for production use is not established, and nothing in this repository can establish it | [A7](REVIEW_AGENDA.md), [P1](REVIEW_AGENDA.md) |
| [SBM-ADR-0014](adr/SBM-ADR-0014.md) | **The content digest becomes a salted commitment** | **Buys:** A guess at the content cannot be confirmed from the evidence alone **Costs:** Both wallets must keep the salt alongside the content, or an evidence package can no longer be tied to the document it is about | proposed | Not implemented. Proposed on 26 September 2026 and pending [A12](REVIEW_AGENDA.md); nothing on the wire, in a schema or in a sample changes until that question is decided | [A12](REVIEW_AGENDA.md) |
| [SBM-ADR-0015](adr/SBM-ADR-0015.md) | **One provider role, not two** | **Buys:** One qualified party observes the handover, carries the message and attests to both, so it is accountable for all three **Costs:** Transport and evidence can no longer be bought from different suppliers. The provider sits in the data path of every delivery. The privacy argument for keeping the two apart is given up | proposed | Specified, and in the reference. No evidence object, companion contract or schema rule carries a second provider's identity — but two DISCOVERY documents did change shape and version for it | [A10](REVIEW_AGENDA.md) |
| [SBM-ADR-0016](adr/SBM-ADR-0016.md) | **The observer is named on the receipt** | **Buys:** A receipt can be tied to the party that signed it, so a verifier knows which single published document should hold the verifying key **Costs:** A published contract changes shape, and a field SBM-ADR-0015 had just withdrawn comes back, for a different reason than the one it was withdrawn with | proposed | Specified, and in the reference: the delivery receipt carries a required `observed_by`, inside the part the signature covers, and one piece of code resolves the key from it | — |

## Decided is not implemented

A decision stands from the day it is recorded, whether or not code has shipped it. The records whose implementation is **planned**:

- [SBM-ADR-0002](adr/SBM-ADR-0002.md) **A governed federation, four instruments** — Specified, and the register is in the reference: it admits the one provider role by decision rather than as a stage ([A6](REVIEW_AGENDA.md), closed). An OPERATED register is only planned — what ships is a file.

## Analysed is not decided

**Who observes S2** ([A9](REVIEW_AGENDA.md)). Three models are analysed in this record's own *Alternatives considered*: an accountable MSP observer, a handover proof authenticated independently of the MSP, and the handover inside the RDP's boundary. The second is the one to take *if* resistance to an MSP acting alone is to be claimed. **No model is selected**, and nothing in the specification claims that resistance. — **from a superseded record**, kept as the analysis a later decision rests on, not as an open choice ([SBM-ADR-0004](adr/SBM-ADR-0004.md))

**How a receipt reaches the party that issues the Delivery Evidence** ([A1](REVIEW_AGENDA.md)) is untouched by this record. Naming the observer makes a retained receipt verifiable; it does not add an operation that carries one from the provider that holds it to the party that needs it. ([SBM-ADR-0016](adr/SBM-ADR-0016.md))

## Open

The review-agenda questions a record rests on, and the records that name them:

- [A1](REVIEW_AGENDA.md) — [SBM-ADR-0005](adr/SBM-ADR-0005.md)
- [A2](REVIEW_AGENDA.md) — [SBM-ADR-0002](adr/SBM-ADR-0002.md)
- [A3](REVIEW_AGENDA.md) — [SBM-ADR-0011](adr/SBM-ADR-0011.md)
- [A4](REVIEW_AGENDA.md) — [SBM-ADR-0012](adr/SBM-ADR-0012.md)
- [A5](REVIEW_AGENDA.md) — [SBM-ADR-0011](adr/SBM-ADR-0011.md)
- [A7](REVIEW_AGENDA.md) — [SBM-ADR-0013](adr/SBM-ADR-0013.md)
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
