# Secure Business Messaging for Europe
## Vision and Context

**Status:** draft for discussion · **Audience:** policy, product and engineering stakeholders

> **⚠️ Exploratory design study — not an official proposal.** An independent technical exploration of how existing EU building blocks (the EUDI Regulation, QERDS, IETF MLS, the EUDI Wallet) *could* be composed into a secure business-messaging profile. It is **not** an official proposal, deliverable, or position of the European Commission, any Member State, or any standards body, and it confers no status; it is shared to invite technical discussion.

*This document consolidates and supersedes the earlier high-level overview and the ERDN concept note. It carries the general and vision-level aspects of the initiative; everything technical and normative lives in the specification set (see §4). It is exploratory: not a Commission position, not a standards-track document.*

---

## 1. The problem

European businesses still have no common way to exchange messages that are at once **legally effective**, **confidential** and **cross-border**. What exists forces a choice between two halves of the problem.

National registered e-delivery systems (PEC in Italy, De-Mail in Germany, and their counterparts elsewhere) provide legal evidence of sending and receipt, but they are domestic silos built on e-mail: they do not interoperate across borders, they identify mailboxes rather than legal entities, and the service provider can read every message. Modern messengers provide the opposite: strong end-to-end encryption and a good multi-device experience, but none of the guarantees a qualified registered-delivery service confers: no verified legal-entity identity behind an account, no qualified evidence of sending and receipt, and no statutory presumption of integrity, sender, addressee and time. A messenger's records may still be admissible and weighed in proceedings — what they lack is the qualified service's presumption, not evidential existence. Meanwhile the volume of legally significant machine-to-machine exchange between businesses — orders, invoices, mandates, regulatory submissions — keeps growing, with no channel designed for it.

## 2. The opportunity and the bet

The EUDI Regulation (Regulation (EU) No 910/2014, as amended) has put every missing building block on the table: qualified electronic registered delivery services (QERDS, Article 44) with a statutory presumption of integrity, sender, addressee and time (Article 43(2)); qualified attestations of attributes for identity; the European Digital Identity Wallet and the emerging Business Wallet; and the EU Trusted Lists as a common trust root. What this study sets out to do is **compose these blocks into a single messaging system in which the legal evidence layer and end-to-end encryption coexist**; it has not found a published system that does, and it does not claim to have surveyed them all.

That is the central bet of this initiative, and it is deliberately contrarian: registered delivery and end-to-end confidentiality are usually presented as a trade-off. They are not. Evidence can be built on **cryptographic fingerprints of the content rather than on the content itself**: providers certify events, identities, times and digests — never what a message says, because they never see it. Legal certainty and confidentiality stop competing.

## 3. Design principles

**Entities, not mailboxes.** Addressing is based on the legal entity — identified by a canonical UID issued only by qualified providers and linked to the official business registers — with members, roles and systems within the entity addressable underneath it.

**End-to-end encryption by construction.** Content is encrypted between the parties' wallet devices using IETF Messaging Layer Security (RFC 9420). There is no provider escrow and no lawful-intercept backdoor: confidentiality is a structural property, not a policy promise. The confidentiality boundary can optionally coincide with a **role** — via confidentiality scopes (one MLS group per entity-pair-and-scope) — so only members holding a role can decrypt content designated for it; the communication scenarios are tabulated in the umbrella's Annex L.

**Evidence without content.** Qualified providers issue sealed, time-stamped evidence of submission, delivery, non-delivery and refusal, bound to content digests that both endpoints can verify.

**A governed federation.** Multiple competing providers, no single EU operator — but membership is gated by qualification and admission, and the protocol evolves under a central design authority. Decentralised operations, centralised rules.

**Standards all the way down.** MLS, COSE, CBOR (RFC 8949 deterministic encoding), HTTPS, JSON, the ETSI EN 319 522 series and the EUDI Wallet stack. The initiative adds profiles and bindings, not new cryptography.

## 4. Architecture at a glance

Four layers — addressing and discovery (UID + the European Directory of Entities), end-to-end secure messaging (the SM-MLS profile of MLS), the application envelope with content digests, and registered delivery evidence — over an ordinary HTTPS underlay, in a four-corner federation of Messaging Service Providers and QERDS-qualified Registered Delivery Providers. Delivery is legally distinct from technical availability: by default, Delivery Evidence is issued only when an authenticated recipient has decrypted the message, re-verified its digest, and satisfied the organisation's published acceptance policy — and, only for content classes the recipient has expressly declared availability-grade, upon availability to an authenticated endpoint of the identified entity. This profile is not encrypted certified e-mail: it is wallet-based registered delivery, where the legally operative act is — by default — authenticated verification and acceptance by an authorised endpoint; availability-grade delivery exists only where the recipient has expressly declared it for a content class, and then only to an authenticated endpoint.

The authoritative description lives in the specification set, organised in three documents: the **umbrella profile** `Secure-Business-Messaging-Profile.md` (identifiers, directory, the authoritative architecture clause, governance), the **IETF Internet-Draft** `ietf/draft-sbm-mls-erd-00.md` for the wire protocol (the SM-MLS binding, evidence packaging, IANA registrations), and the **TS-shaped QERDS binding** `etsi/TS-SBM-QERDS-Binding-v0.1.md`, drafted following ETSI drafting rules for prospective submission to ETSI TC ESI (conformance requirements, the ETSI EN 319 522 mapping, the implementing-act compliance matrix, and an ICS pro forma backed by machine-checkable conformance tooling).

## 5. A managed network, not an open one

The comparison with e-mail invites a misunderstanding worth correcting explicitly. E-mail is an open federation: anyone can stand up a server. This network is deliberately not that — it is a **European Registered Delivery Network**: closed at the membership level, centrally governed at the protocol level, decentralised at the operational level.

Admission is a two-gate process: qualification under Regulation (EU) No 910/2014 first (conformity assessment, national supervisory body, Trusted List inscription), then admission to the federation under the Commission's governance framework (participation agreement, interoperability testing, membership registry). Neither gate implies the other. Membership is verifiable and revocable, and the registry is the enforcement point: an excluded provider stops resolving and being resolved. The protocol itself — profiles, evidence semantics, cryptographic policy, registries, conformance suite — is owned and versioned by a **design authority**; providers compete on service, capacity and price, never on the rules.

Four instruments, four functions, none implying another: the Trusted Lists say who is a qualified trust service provider; the federation membership registry says who is admitted to this network; the EDD says which legal entities exist and how to reach them; the design authority says what protocol everyone runs.

## 6. Placement in the EU framework

The registered-delivery layer is designed against Article 44 of Regulation (EU) No 910/2014 and CIR (EU) 2025/1944, which references the ETSI EN 319 522 series; the identity layer against the European Digital Identity framework (qualified attestations, the ARF, the Business Wallet initiative); the encryption layer against IETF standards, with the IANA registrations the profile needs (an MLS credential type, well-known URIs) pursued through an Internet-Draft. The profile can support the Article 43(2) presumption **only when operated by qualified providers within their qualified service scope and after conformity assessment** — the protocol alone does not confer qualified status. The intended trajectory is a pilot under a transitional regime, with evidence marked non-qualified, followed by conformity assessment of the profile.

## 7. Vision horizon — a registered interaction layer, phased

The project is best read as a **registered interaction layer** for the EU wallet ecosystem, delivered in phases. Each phase builds on the previous one without re-architecture — the identity model, the channel and the evidence layer stay the same; what grows is the class of *interactions* they make legally reliable. This is a modular roadmap, not scope creep: everything below rests on the same insight — the channel's evidence layer can make interactions legally reliable, not just documents.

- **Phase 1 — secure registered entity messaging**: this profile (the specification set in this repository).
- **Phase 2 — registered attestation exchange** (§7.1).
- **Phase 3 — registered presentation profile** (§7.2).
- **Phase 4 — governed agentic interactions** (§7.3).

### 7.1 Phase 2 — registered attestation exchange

An electronic attestation of attributes is just a payload, so the network already carries EAAs and verifiable credentials end-to-end encrypted, with qualified evidence of who delivered which attestation to whom and when — which the wallet protocols this study builds on do not themselves provide: they carry attestations, not registered-delivery evidence of their delivery. Mandates, powers of representation, compliance attestations and regulatory submissions become deliveries with legal receipts.

### 7.2 Phase 3 — registered presentation profile

The next step is a **registered presentation profile**: binding a wallet presentation (nonce, holder-binding proof) to the channel's session and message identifiers, so that the QERDS evidence proves *that a verifiable presentation took place* between two identified parties. Qualified evidence of a presentation is a primitive the EUDI ecosystem does not yet have; this network is naturally positioned to provide it. Person-to-business flows remain on the ARF presentation rails (OpenID4VP), which the channel can transport and evidence rather than replace.

### 7.3 Phase 4 — governed agentic interactions

> **Where this stands today.** Part of this phase is no longer horizon: the agent's *evidence and mandate rules* are specified now, as the OPTIONAL deployment profile 5 (umbrella Annex R) — a system member acting under a scoped mandate, recorded in the evidence. What remains ahead is the *cross-deployment* wallet-agent interface, which is informative, not an interoperability contract. The text below describes the direction; the umbrella's Annex R is what is defined.

AI agents are beginning to act for businesses — negotiating, ordering, filing, responding, reconciling. This is no longer speculative: procurement, customer operations and back-office workflows are being delegated to software that initiates and answers communications on the organisation's behalf. The question, therefore, is not *whether* agents will transact between businesses; it is **what infrastructure those transactions will run on**.

**Why this capability is necessary.** Four converging pressures make an accountable agent channel a necessity rather than a feature.

*The accountability gap.* The agent-to-agent rails this study looked at in 2026 — bespoke APIs, platform accounts and the emerging agent protocols — share the same structural weaknesses: no verified legal-entity identity behind the agent, no machine-verifiable scope of authority, and no opposable evidence of what was exchanged. When an agent over-orders, agrees to the wrong terms or files the wrong declaration, there is no evidence chain establishing what happened, who authorised it, and within which mandate. Disputes fall back on platform logs that one party controls and the other cannot verify.

*Machine speed changes the safety model.* Human-paced business tolerates weak channels because people review what they send and receive. Agents transact at machine speed and volume — and so does fraud: impersonated suppliers, fabricated invoices and manipulated instructions no longer arrive one at a time. When no human reads each message, guarantees cannot live in vigilance or policy; they must be structural. Verified entity identity, end-to-end encryption and automatic qualified evidence are precisely the guarantees that survive the removal of the human from the loop.

*Trust is the adoption bottleneck.* Organisations will not delegate legally significant acts to agents without accountability infrastructure — and where they do so anyway, they accumulate silent risk. Legal certainty is not a brake on agentic automation; it is its enabler. A channel on which an agent's transaction carries statutory presumptions — identified parties, verified content, certain time — turns delegation from a leap of faith into a governed decision. The same logic aligns with the European approach to AI governance, with its emphasis on human oversight and traceability for consequential automated behaviour: acceptance policies operationalise the oversight, qualified evidence operationalises the traceability.

*The alternative is platform lock-in.* If no open, governed infrastructure exists, agent-to-agent commerce will consolidate on proprietary platforms, with the platform operator as identity provider, arbiter and sole record-keeper. Europe holds building blocks no other region has — legal-entity identity, attestations that can express mandates, registered delivery with statutory effect — and this network composes them into the open alternative: a governed federation in which the evidence belongs to the parties, not to a platform.

**The vision.** An agent is an addressable, accountable actor within an entity — a system member with its own delegated credential and a **scoped mandate issued as an attestation**, verifiable by counterparties before treating the agent's messages as binding. Its transactions inherit the channel's guarantees: identified parties, verified content, certain time, qualified evidence. "My agent agreed X with your agent" becomes verifiable evidence of who acted, under which mandate — the precondition for an agreement and the law to attach effect, which the protocol does not decide (Annex R.5) — and the network needs no redesign to host it: the identity model already distinguishes the legal entity, the person *or system* acting for it, and the device, and the implementing act already provides a machine-to-machine authentication path for automated senders.

**The guardrails are already in the architecture.** Organisations publish **acceptance policies** that keep humans in the loop where it matters: an agent may receive and verify, but legal acceptance of designated content classes can require a human role or a quorum. Agents never hold the channel's encryption keys — they instruct the wallet through a controlled interface. Message content from an identified counterparty is still untrusted input for the agent that reads it, and implementations must treat it as such. And non-repudiation is layered: the protocol provides verifiable evidence that an agent acted under a valid mandate, the participation agreement establishes whether that evidence is opposable to the entity, and the applicable framework governs the final qualification — exactly the discipline that makes organisations deliberate about what they delegate. The agent profile — system members, mandate attestations, policy classes — is specified as the OPTIONAL deployment profile 5 (umbrella Annexes O and R); what remains open is a cross-deployment contract for the wallet-agent interface, which is informative today (review agenda A7).

## 8. What this is not

Not another messenger: a profile any provider or wallet vendor can implement — though operating it in the federation requires qualification and admission. Not a replacement for the EUDI Wallet: an application of it. Not an open network in the e-mail sense: operations are federated, membership is gated, rules are central. Not novel cryptography: every primitive is a published open standard; the contribution is the composition, its governance and its legal binding.

## 9. Status and next steps

The specification set is restructured into its three documents (the umbrella, the Internet-Draft `draft-sbm-mls-erd-00` and the TS-shaped QERDS binding — current revisions in `versions.json`, not restated here so that they cannot drift), with a hardened conformance layer: JSON Schemas plus semantic linters, cryptographically bound samples, and CI — the conformance bar is schema-valid *and* lint-clean, with an ICS pro forma mapping every requirement to its verification method. The happy path already has a reference implementation (`scripts/mock_rdp.py`) and an independent proof of concept (profile 1); what the review edition does not claim is two independent implementations interoperating over the published contracts. Next steps: take the Internet-Draft to the IETF and the binding towards ETSI TC ESI, close the open questions on the review agenda, and prepare the pilot. The later phases of §7 follow.

---

*Repository: the specification set and conformance tooling live in this repository; see the README for the document map and quickstart.*
