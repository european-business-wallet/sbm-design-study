<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Architecture, identity and trust

**Status:** informative companion · **Applies to:** the specification set at the versions in the README's version table (not restated here, so they cannot drift) · **Audience:** reviewers who need the model before the rules

> **Exploratory design study — not an official proposal.** This note assembles what the normative documents already say; it adds no rule. In any conflict they prevail: the umbrella §7 (architecture and roles), §5 and §8 (directory and discovery), §13 (governance); the TS clause 6 (evidence duties); the companion contracts.

The question this note answers: **who does what, who talks to whom, and why is any returned key or claim trusted?** It keeps apart five things a verifier asks separately, because the design depends on none of them standing in for another.

---

## 1. Who does what

![Four-corner federated architecture — who carries what](diagrams/architecture-four-corner.svg)

Each entity runs **wallet devices**, the only place plaintext exists. Its **Delivery Service** (the MSP) holds its KeyPackages and queues and observes the handover of bytes to a device. Its **Registered Delivery Provider** (the RDP, a qualified trust service provider) seals the evidence. A message goes from the sender's wallet to its RDP, which gets its own Delivery Service to accept the exact octets before it seals the Sending Evidence, then relays the ciphertext **with that SE** to the recipient's RDP. That RDP hands it to its Delivery Service with the origin proven, and the recipient's devices collect it there. The recipient's confirmations reach its RDP, the **sole** evaluator of the acceptance policy (TS clause 6). An MSP may carry them, verbatim; it decides nothing. The two MSPs never relay to each other.

In the minimal deployment (Annex P profile 1) one operator runs both RDPs, and no relay occurs. Group formation is the exception to "each side talks to its own providers": the creating wallet reserves KeyPackages, deposits Welcomes, registers as the group's founder and collects replies at the **counterparty's** Delivery Service. Which Delivery Service routes a group whose devices span two, after formation, is open ([A10](REVIEW_AGENDA.md)). The phase-by-phase version is [`federated-flow-explainer.md`](federated-flow-explainer.md).

## 2. Two chains of trust

![Identity and proof provenance](diagrams/identity-proof-map.svg)

**An entity** is trusted through its identifier. A qualified issuer issues the UID. The EDD core registry's **directory record**, sealed by the registry operator, says where to resolve the entity and **pins the keys that may seal its documents** (umbrella §5.2). A document sealed by any other key — even a qualified certificate issued to another entity — is not the entity's (`LINT-TRUST-05`). The pinned key seals BW-MED, BW-ORG and BW-MEMBER, and BW-MEMBER publishes each device's confirmation key and MLS leaf.

**A provider** is trusted through its admission. The Federation Authority's key is an anchor the verifier is **configured** with; the membership register's record, which that key seals, gives the provider's admission history and pins the key that seals its descriptor, `BW-PROVIDER` (`LINT-TRUST-07`). An RDP's evidence counts only if the RDP was admitted at the instant of **each** act. The register answers two different questions, and one never stands in for the other. *Was it admitted when it acted?* is answered later, by a record asserted after the act, which speaks for the history up to its own `asserted_at`. *May it exchange now?* is a live **lease**, decided once at the start of an exchange against a fresh record; it authorises that exchange and is not evidence of admission at any act in it.

The **EU Trusted Lists** sit beneath both, and establish only qualification. "Everything chains to the Trusted Lists" is not a trust model: a qualified certificate does not speak for an entity unless the directory pins it, and a qualified provider is not thereby admitted (umbrella §13.1).

## 3. Five questions a verifier keeps apart

| Question | What answers it | What it cannot answer |
|---|---|---|
| **Authenticity** — did this key sign these bytes? | the signature | whether the key was entitled to sign |
| **Authorisation** — does this key speak for this entity or provider? | the directory pin; the register's pin | whether the provider may operate |
| **Admission** — was the provider allowed to act *then*? | the register's status history, at the act's instant | whether it is qualified |
| **Qualification** — is the provider or certificate qualified? | the Trusted Lists | whether it is admitted, or authorised for an entity |
| **Observation** — who witnessed the event, and is their report true? | the party that observed it, identified in the evidence | the truth of an observation the sealer did not make |

The last row is where a seal stops. An RDP's seal proves the RDP made a statement; at the availability grade that statement rests on the Delivery Service's signed receipt of the handover, which the RDP does not re-witness. The event is **attributed** to the MSP, not independently established. Who observes S2, and what an MSP alone could make an RDP attest, is undecided ([A9](REVIEW_AGENDA.md)); separating MSP and RDP makes a false observation attributable — once the planned `observed_by` binds the observer ([A6](REVIEW_AGENDA.md)) — not impossible.

## 4. Which key does what

| Act | Key | Authorised by | Checked by |
|---|---|---|---|
| Authenticate inside the MLS group | the device's MLS credential | the Trusted Lists, and the device's leaf in BW-MEMBER | the other devices, inside MLS |
| Authenticate an API session (HTTPS) | the scheme the contract names — a device or member credential, mutual TLS between providers | the contract | the server of the operation; distinct from the MLS credential |
| Sign the sender's submission | the sending device's confirmation key | BW-MEMBER, sealed by the pinned entity key | RDP(out) at submission, before it issues the SE; any verifier later |
| Sign a recipient's message act — an `s3` confirmation, a mismatch proof, a message refusal, a reveal | the device's confirmation key | BW-MEMBER, sealed by the pinned entity key | RDP(in) at intake (INTF-1a); any verifier later |
| Refuse a Welcome before joining | the private key of the KeyPackage the invitation consumed | the device's own KeyPackage | the Delivery Service, against the package it issued; the exact proof bytes are open ([G1](REVIEW_AGENDA.md)) |
| Seal evidence | the RDP's seal (QSealC), plus a qualified timestamp | the Trusted Lists (qualification) and the register (admission at the act) | any verifier |
| Sign the S2 receipt | the Delivery Service's receipt key, valid at the receipt's `server_time` | today BW-MED, sealed by the entity key; planned: the MSP's own descriptor ([A6](REVIEW_AGENDA.md)) | the DE issuer — through no published path yet ([A1](REVIEW_AGENDA.md)) — and the retained verifier (`LINT-BND-38`) |
| Seal an entity's documents | the entity's seal key | the directory record | any resolver |
| Seal a provider's descriptor | the participant's descriptor key | the register | any verifier |
| Assert admission | the Federation Authority's key | configuration — a trust anchor | any verifier holding that anchor |

## 5. Claims, observers and limits

| Claim | Observed by | Attested by | Independently checkable | Whose honesty still matters |
|---|---|---|---|---|
| The sender submitted these octets | RDP(out), in an authenticated session | the SE, and by default the sender's own signature | seal, timestamp, and the signature against the device's published key | RDP(out) for `sent_at`; the signature shows the device's act, not the entity's intent ([L4](REVIEW_AGENDA.md)) |
| The octets reached the recipient's RDP unchanged | RDP(in) recomputes the digest against the SE | the hop evidence (B.1) | the digest relation, by anyone holding the octets; the hop evidence's seal and timestamp | RDP(in)'s — that it received these octets at the hop's instant is its own report, like every observation in this table |
| A device collected and acknowledged them (S2) | the Delivery Service | its signed receipt | the signature and the key's validity at `server_time` | the Delivery Service's — the event is its own observation ([A9](REVIEW_AGENDA.md)) |
| A member decrypted and the digest matched (S3) | the recipient's device | its confirmation, wallet-signed or session-bound | wallet-signed: the signature against the device's published key; session-bound: only through RDP(in)'s record | the device's, in both modes — a signature attributes the statement to the device, it does not show that an honest implementation decrypted and checked (the wallet assurance profile is where that assumption lives); and RDP(in)'s, for a session-bound confirmation |
| The acceptance policy was satisfied (S4) | RDP(in), on receiving the completing act | the DE | re-evaluation over the retained policy and confirmations | that no later policy existed is unproven ([A3](REVIEW_AGENDA.md)) |
| The provider was admitted at the act | the Federation Authority | its record | yes, with the configured anchor | the Authority's — two contradictory histories stay an open transparency gap |
| The provider is qualified | the supervisory body | the Trusted List | by a production verifier | not established in this repository ([P1](REVIEW_AGENDA.md)) |

## 6. Who sees what

The umbrella's metadata-privacy inventory (§11.1) is the authority; this is its shape by actor.

| Actor | Plaintext | Ciphertext | Identity and routing metadata | A dispute reveal |
|---|---|---|---|---|
| Wallet devices of the two entities | yes — their own | yes | yes | disclose it, or receive it |
| Delivery Service (MSP) | never | yes | UIDs, group ids, device principals, sizes, times | no |
| RDPs | never | yes — they relay it and hash it | the evidence fields they seal, including `scope_ref` | when presented in a dispute |
| EDD | never | no | resolution queries | no |
| Time-stamping service | never | no | timing, over seal hashes | no |
| A later verifier of an Evidence Package | only if it holds it | no | everything the package carries | if presented |

The content class never appears in evidence; a reveal discloses one message's class to the parties of that dispute. Who retains what, and for how long, is set for evidence by the TS; for the other actors it is part of the deferred implementer guide ([G4](REVIEW_AGENDA.md)).

## 7. What is planned, and what is undecided

- **Planned ([A6](REVIEW_AGENDA.md)):** the MSP's own identity on the wire, its admission, and the DE's binding to the observation it rests on. Decided, not implemented.
- **Undecided ([A9](REVIEW_AGENDA.md)):** the S2 observer model. Three models are analysed in the study's historical RDP/MSP trust analysis (`docs/rdp-msp-trust-analysis/`, not a selected design); none is selected, and nothing here claims resistance to a malicious MSP.
- **Open ([A1](REVIEW_AGENDA.md), [A10](REVIEW_AGENDA.md)):** how the DE issuer obtains the S2 receipt; which Delivery Service routes a group after formation.
