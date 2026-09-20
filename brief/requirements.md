# The requirements this study started from

**What this is.** The list of requirements and properties the design study set
out to satisfy, with the source each one comes from. It is a baseline for
discussion, not a scorecard: it does not assess this design or any other
against the list, and it does not claim that the list is complete or that every
reading of a source is the only one. Where a requirement is an external
obligation, the source is the law, the implementing regulation, the ETSI
standard or the Business Wallet proposal that states it; where it is the
study's own reading of what a robust solution needs, the last column says so,
so that the two are not mistaken for each other.

**How to challenge it.** If a requirement is missing, mis-scoped or over-read,
that correction is worth more to the study than anything else in this
package. The specification's own compliance mapping, clause by clause with an
implementation conformance statement, is in the TS-shaped document
([`etsi/TS-SBM-QERDS-Binding-v0.1.md`](../etsi/TS-SBM-QERDS-Binding-v0.1.md)); this list is the starting point, the TS
is where the mapping is made and can be checked.

**Sources.** [Regulation (EU) No 910/2014 as amended](https://eur-lex.europa.eu/eli/reg/2014/910/2024-10-18/eng), consolidated text of 18 October 2024, Articles 3(36), 43 and 44 · [Commission Implementing Regulation (EU) 2025/1944](https://eur-lex.europa.eu/eli/reg_impl/2025/1944/oj/eng), Annex I (ETSI EN 319 521 adapted, `REQ-*` identifiers, quoted in this list by their clause) and Annex II (the EN 319 522 series) · ETSI [EN 319 521](https://www.etsi.org/deliver/etsi_en/319500_319599/319521/) and [EN 319 522 parts 1 to 4](https://www.etsi.org/deliver/etsi_en/319500_319599/) · the European Business Wallet proposal, [COM(2025) 838](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52025PC0838) of 19 November 2025, Annex points 11 and 12 · [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) (MLS) and the the [Agreed Cryptographic Mechanisms](https://certification.enisa.europa.eu/publications/eucc-guidelines-cryptography_en) of the European Cybersecurity Certification Group's sub-group on cryptography, published by ENISA — the reference the CIR's Annex I cites; [version 2 of 6 May 2025](https://certification.enisa.europa.eu/document/download/a845662b-aee0-484e-9191-890c4cfa7aaa_en?filename=ECCG%20Agreed%20Cryptographic%20Mechanisms%20version%202.pdf) is the applicable edition, version 3 is a draft for public review (June 2026) and not yet applicable — for the security properties. Where a row abbreviates a provision, the provision governs; the rows for the CIR quote the options the provision lists.

## A — Regulation (EU) No 910/2014: the qualified registered delivery service

| ID | Source | Category | Requirement | Kind |
|---|---|---|---|---|
| R1 | Art. 3(36) | Legal | Transmit data between third parties with evidence of handling: proof of sending and receiving | external |
| R2 | Art. 3(36) | Legal | Protect transmitted data against loss, theft, damage and unauthorised alteration | external |
| R3 | Art. 44(1)(a) | Legal | The service is provided by one or more qualified trust service providers | external |
| R4 | Art. 44(1)(b) | Identity | Identification of the sender with a high level of confidence | external |
| R5 | Art. 44(1)(c) | Identity | Identification of the addressee before the delivery of the data | external |
| R6 | Art. 44(1)(d) | Evidence | Sending and receiving secured by an advanced electronic signature or seal of the qualified provider, precluding undetectable change | external |
| R7 | Art. 44(1)(e) | Evidence | Any change of the data needed for sending or receiving is clearly indicated to sender and addressee | external |
| R8 | Art. 44(1)(f) | Evidence | The date and time of sending, receiving and any change are indicated by a qualified electronic timestamp | external |
| R9 | Art. 43(2) | Legal | The statutory presumption of integrity, sender, addressee and time, for data sent and received through a qualified service | external |
| R10 | Art. 44(2a), (2b) | Interoperability | Interoperability between qualified providers, confirmed by a conformity assessment body | external |

## B — CIR (EU) 2025/1944 and ETSI EN 319 521 / 522: presumption of compliance

| ID | Source | Category | Requirement | Kind |
|---|---|---|---|---|
| C1 | REQ-ERDS-5.1.1-01 | Security | Availability, integrity and confidentiality of user content while handled by the service, with ACM-approved cryptography | external |
| C2 | [REQ-QERDS-5.2.1.1-01](https://eur-lex.europa.eu/eli/reg_impl/2025/1944/oj/eng) | Identity | **Recipient identity proofing** at a very high level of confidence, directly or through a third party, by one or a combination of: (a) physical presence of the natural person or of the legal person's authorised representative; (b) remotely, a notified eID at assurance level *high*, or the European Digital Identity Wallet; (c) a certificate of a qualified electronic signature or seal; (d) other methods giving a very high level of confidence, **the assurance of which a conformity assessment body confirms** | external |
| C3 | [REQ-QERDS-5.2.1.1-01A](https://eur-lex.europa.eu/eli/reg_impl/2025/1944/oj/eng) | Identity | **Sender identity proofing**, directly or through a third party, by one or a combination of: (a) physical presence of the natural person or of the legal person's authorised representative; (b) remotely, the Wallet, or a notified eID at assurance level *substantial* issued on prior physical presence; (c) a certificate of an advanced electronic signature or seal issued to the natural person or to the legal person's authorised representative under a Normalised Certificate Policy (ETSI EN 319 411-1); (d) other methods giving a very high level of confidence — for which the provision requires a conformity assessment body to confirm that the identification is performed with a *high* level of confidence | external |
| C4a | [REQ-QERDS-5.2.2-03](https://eur-lex.europa.eu/eli/reg_impl/2025/1944/oj/eng) | Identity | **Sender authentication**, bound to the identity proofed under C3, by one of: (a) two-factor authentication; (b) the Wallet, or a notified eID at *high* or *substantial*; (c) mutual TLS with a certificate issued to the sender under NCP; (d) a digital signature supported by an NCP certificate; (e) other means ensuring the identified sender's authentication, **the conformity of the binding confirmed by a conformity assessment body** — the provision's example is registering a TLS client certificate or a seal certificate through one of the means above | external |
| C4b | [REQ-QERDS-5.2.2-03A](https://eur-lex.europa.eu/eli/reg_impl/2025/1944/oj/eng) | Identity | **Recipient authentication**, bound to the identity proofed under C2, by one of, provided the means give a very high level of confidence: (a) multi-factor authentication; (b) the Wallet, or a notified eID at *high* or *substantial*; (c) a certificate of a qualified electronic signature or seal; (d) other means ensuring the identified recipient's authentication, **the conformity of the binding confirmed by a conformity assessment body** | external |
| C5 | REQ-ERDS-5.4.1-06 | Evidence | Evidence generated for the registered-delivery events of EN 319 522-1 clause 6: submission, relay, consignment, handover and the rest | external |
| C6 | REQ-ERDS-5.4.1-08 | Evidence | Evidence complying with the semantics of EN 319 522-2 clause 8: event codes, evidence identifiers, policy identifiers | external |
| C7 | REQ-ERDS-5.4.1-07 | Evidence | Archival of issued evidence, or of evidence digests | external |
| C8 | REQ-ERDS-7.5-01A | Cryptography | All cryptographic techniques taken from the Agreed Cryptographic Mechanisms of the ECCG, published by ENISA (version 2 applicable; version 3 in draft) | external |
| C9 | REQ-ERDSP-7.5-03 | Cryptography | The evidence-seal key held in a certified secure cryptographic device | external |
| C10 | REQ-ERDSP-7.8-04 | Cryptography | State-of-the-art transport-layer encryption per the ACM | external |
| C11 | EN 319 522-2 clause 9 | Interoperability | A common service interface across providers: routing, trust establishment, capability management | external |
| C12 | EN 319 522-4 | Interoperability | A standardised binding of the registered-delivery semantics to a transport | external |
| C13 | EN 319 522-1 clause 6; SBM TS clause 4.1 | Evidence | Per-hop evidence in a multi-provider transfer: each provider seals its own act for its own hop, with a qualified timestamp at that hop, bound into the evidence package | external requirement; the per-hop reading is the study's |

## C — The European Business Wallet proposal, COM(2025) 838, Annex points 11 and 12

| ID | Source | Category | Requirement | Kind |
|---|---|---|---|---|
| B1 | Annex 11(1) | Wallet | Business Wallets integrate and support a qualified registered delivery service as the secure legal communication channel | external |
| B2 | Annex 11(2)(b) | Legal | Alignment with the reference standards, specifications and procedures of Articles 43 and 44 | external |
| B3 | Annex 11(2)(c) | Interoperability | Based on open, publicly available, royalty-free standards; no vendor lock-in | external |
| B4 | Annex 11(2)(d) | Security | The qualified service provides end-to-end encryption to guarantee confidentiality | external |
| B5 | Annex 11(2)(e) | Operations | Continuous availability, redundancy and fallback procedures | external |
| B6 | Annex 11(3) | Wallet | Mandatory interoperability between Business Wallets and the designated qualified service | external |
| B7 | Annex 12 | Wallet | Access control based on electronic attestations of the acting subject | external |

## D — What end-to-end encryption must mean to be robust

The study's reading of what "end-to-end encryption" in B4 must provide to be
worth the name, drawn from the properties of MLS-class protocols; the rows
whose source is the study itself are its own requirements, not an external
obligation.

| ID | Source | Category | Requirement | Kind |
|---|---|---|---|---|
| E1 | RFC 9420 | E2EE | Structural content confidentiality against the providers: no escrow, no interception capability | external property, the study's requirement |
| E2 | RFC 9420 | E2EE | Forward secrecy: a compromise today does not expose past messages | external property, the study's requirement |
| E3 | RFC 9420 | E2EE | Post-compromise security: healing after a key compromise | external property, the study's requirement |
| E4 | the study | E2EE | Authenticated key discovery with resistance to substitution: transparency of published keys | the study's own; open (key transparency is a residual) |
| E5 | RFC 9420 | E2EE | Native multi-device membership per member: each device a cryptographic leaf | external property, the study's requirement |
| E6 | the study | E2EE | Role-scoped confidentiality: the cryptographic boundary can coincide with an organisational role | the study's own |
| E7 | the study | E2EE | A verified audience: the sender can verify who can decrypt before sending | the study's own |
| E7b | the study | E2EE | A declared records leaf: records access to role-scoped content exists only if the organisation declares it, and the sender can resolve exactly who it is before sending | the study's own |
| E8 | RFC 9420; AS4 | Security | Replay protection at the messaging layer | external property, the study's requirement |
| E9 | the study | Function | Asynchronous store-and-forward: the parties need not be online at the same time | the study's own |
| E10 | ACM; IETF | Cryptography | Cryptographic agility with a credible post-quantum path for content encryption | external property, the study's requirement |
| E11 | the study | Privacy | Metadata minimisation towards the providers | the study's own |
| E12 | the study | Evidence | Evidence without content access: the provider certifies digests of content it cannot read | the study's own — its central claim |
| E13 | the study | Evidence | Defined evidence-validity semantics on endpoint credential compromise: validity at the act, disputed windows reviewable | the study's own |

## E — Functional and ecosystem requirements

| ID | Source | Category | Requirement | Kind |
|---|---|---|---|---|
| F1 | the Business Wallet proposal; the study | Identity | Canonical legal-entity addressing linked to the business registers, EU-wide | the proposal implies it; the identifier is the study's |
| F2 | the study | Governance | Organisational acceptance policies: role- and quorum-based legal acceptance | the study's own |
| F2b | the study | Legal | A configurable legal delivery grade per content class — availability, verification, acceptance — with the availability grade externally verifiable through a privacy-preserving commitment | the study's own |
| F3 | CIR 5.2.2-04; the study | Agents | Machine and automated senders with an accountable identity: the mutual-TLS path for a non-natural person, and agent mandates | external in part; the mandate model is the study's |
| F3a | the study | Agents | An automated act is bound to the scoped mandate it acted under, so that it is attributable to the entity and acting outside the mandate is attributable | the study's own |
| F3b | the study | Governance | A policy can require a human to perform the legally operative acceptance: an agent may verify but not accept | the study's own |
| F4 | the study | Function | Large payloads and attachments | the study's own |
| F5 | the study | Evidence | Evidence storable and independently verifiable by the parties, as a wallet artefact | the study's own |
| F6 | the study | Operations | Cross-border production adoption | the study's own; not established by anything in this package |
| F7 | the study | Conformance | An executable, machine-checkable conformance bar that any implementer can run | the study's own |
| F8 | the study | Adoption | A staged deployment path: a pilot without the full institutional stack | the study's own |

**What is not here.** A comparison of this design with other candidate
solutions was part of an earlier edition of this package as a workbook. It
was withdrawn on 20 September 2026 because its judgments rested on an older
edition of the specification, on private reference folders, and on a scoring
that added a specified property to a deployed one; it is kept in the study's
archive and is not part of this snapshot. Any comparison of candidates is for
the expert group to make on terms it sets.
