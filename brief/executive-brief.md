# A Secure Communication Channel for the European Business Wallet
## Executive Brief

**Date:** August 2026 · **Audience:** executive and policy readers · **Full brief:** ~20 minutes · **Core argument (§§1–3):** ~5 minutes

> **Disclaimer — exploratory exercise.** This document, and the design study it summarises, is an **independent exploratory exercise**. It is not an official proposal, deliverable or position of the European Commission, of any Member State, or of any standards body, and it confers no status. Its purpose is to provide a **clear, concrete input to the newly established expert group** tasked with evaluating and selecting candidate solutions for the **secure communication channel of the European Business Wallet**: a worked example of what a solution can look like, a requirements baseline extracted from the applicable law and standards, and executable artefacts against which any candidate — including this one — can be tested.

---

## 1. What this is, in one paragraph

A design study for a business-to-business messaging system in which **qualified registered delivery and end-to-end encryption coexist**. Businesses are addressed as verified legal entities, not mailboxes; message content is encrypted between the parties' wallet devices so that no intermediary — including the service providers — can ever read it; and qualified providers issue sealed, time-stamped evidence of sending and receipt, designed clause-by-clause against the requirements Regulation (EU) No 910/2014 sets for qualified electronic registered delivery (Articles 43 and 44). The two properties are usually presented as a trade-off. The study's central claim is that they are not: evidence can be built on **cryptographic fingerprints of the content rather than the content itself**.

## 2. The system in action — a worked example

*Rossi Meccanica S.r.l.*, a Milanese manufacturer, must terminate a supply contract with *Bergmann Stahl GmbH* of Dortmund — a notice with deadlines attached, where proof of delivery matters as much as the content is commercially sensitive.

**Finding the counterparty.** Rossi's Business Wallet looks up Bergmann in the European Directory of Entities by its entity identifier — not an e-mail address someone typed years ago, but a canonical identifier issued by a qualified provider and linked to the German business register. The directory returns Bergmann's published profile: its providers, its encryption key material, and its declared communication policy — which says, among other things, that contractual notices are received by the *legal-affairs role* and accepted only by that role.

**Sending.** Rossi's wallet establishes an encrypted channel whose members are, verifiably, the enrolled devices of the two companies' relevant roles — the wallet *checks the roster before sending*, so the audience is verified, not assumed. It computes a digital fingerprint of the notice, encrypts everything end-to-end, and hands the ciphertext to Rossi's messaging provider. Rossi's registered-delivery provider — a qualified trust service provider — verifies the authenticated submission and issues **Sending Evidence**: who sent, to whom, when (qualified timestamp), and the fingerprint. It never sees the notice.

**Receiving.** The message is relayed provider-to-provider and reaches the devices of Bergmann's legal-affairs team. For a contractual notice — a content class this recipient has declared at *verification* grade — queueing and even retrieval are not yet delivery. A member of the legal-affairs role authenticates at the required assurance level, her wallet decrypts the notice, recomputes the fingerprint and confirms it matches; Bergmann's published acceptance policy for this content class is satisfied. Only then does Bergmann's registered-delivery provider issue **Delivery Evidence** — this content class is set to *verification* grade (the grades are explained in §4). Both parties receive a sealed, timestamped **Evidence Package**, stored in their wallets.

**Eighteen months later**, the termination date is disputed. Rossi produces the Evidence Package: sealed, qualified-timestamped evidence of the integrity of the data, of the identity of sender and addressee, and of the time of sending and receipt — the elements Regulation (EU) No 910/2014 addresses for registered delivery — and the fingerprint in the evidence matches the notice Rossi holds. Throughout the entire exchange, no provider, directory or intermediary ever saw a single word of the notice. Meanwhile, the two companies' procurement systems exchange routine order confirmations over the same channel through software agents operating under scoped, verifiable mandates — same identities, same encryption, same evidence, no human in the loop where none is needed.

## 3. Why this is needed

**The gap.** European businesses have no common channel that is at once legally effective, confidential and cross-border. National registered e-delivery systems (PEC, De-Mail and their counterparts) provide legal evidence but are domestic silos, identify mailboxes rather than legal entities, and let the provider read every message. Modern messengers offer strong encryption but no legal effect, no verified entity identity, and no evidence usable in proceedings.

**The timing.** The EUDI Regulation has put every missing building block on the table — qualified electronic registered delivery (QERDS) with statutory presumptions, qualified attestations for identity, the Digital Identity and Business Wallets, the EU Trusted Lists as a common trust root — and its implementing act for QERDS (CIR (EU) 2025/1944) is in force. What is missing is the composition of these blocks into one system.

**The horizon.** Legally significant machine-to-machine exchange is growing — orders, invoices, mandates, regulatory submissions — and AI agents are beginning to transact on businesses' behalf. Every current agent-to-agent rail lacks verified legal-entity identity and opposable evidence. Whoever provides the accountable channel for that traffic will define the terms of European agentic commerce; if no open, governed infrastructure exists, it will consolidate on proprietary platforms.

## 4. The shape of the solution

**Policy framing: a managed network.** Not an open federation like e-mail, and not a single EU platform. A **European Registered Delivery Network**: operations decentralised across competing providers; membership gated by two independent doors (qualification under the Regulation, then admission to the federation under the Commission's governance framework); the protocol owned and versioned by a central **design authority**. Providers compete on service and price, never on the rules. Four instruments with four distinct functions: the Trusted Lists (who is qualified), the federation membership registry (who is admitted), the directory of entities (who exists and how to reach them), the design authority (what protocol everyone runs).

**Architecture.** A four-corner model, familiar from registered e-mail: each business talks to its own Messaging Service Provider; providers relay ciphertext to their counterparts; QERDS-qualified Registered Delivery Providers on each side issue the evidence.

![Four-corner federated architecture](assets/architecture-four-corner.svg)

The stack has four layers over ordinary HTTPS: addressing and discovery (a canonical entity identifier linked to business registers — deliberately new, because the existing identifiers are register- or sector-scoped: EUID lives inside BRIS, LEI inside finance, VAT numbers are neither universal nor entity-faithful; the new identifier is the *routing and trust anchor* that links to all of them, not a substitute register — resolved through an EU-governed core registry with federated discovery); end-to-end secure messaging (a profile of IETF Messaging Layer Security, RFC 9420 — the open standard for group encryption); an application envelope carrying content digests; and the registered-delivery evidence layer (sealed, time-stamped evidence objects aggregated into a wallet-storable Evidence Package).

![Protocol stack](assets/protocol-stack.svg)

### The key design moves

**Delivery is distinct from technical availability.** A deliberate choice, not an accident: this is *not* certified e-mail re-platformed. By default, the act that delivery evidence attests is authenticated verification and acceptance by an authorised endpoint — evidence is issued only once an *authenticated* recipient has decrypted the message, re-verified its digest, and satisfied the organisation's published acceptance policy (a role, or a quorum; human-in-the-loop is native).

**The required grade is declared per content class**, along a three-rung ladder of ascending recipient involvement: **availability**, **verification** (the default), **acceptance**. *Availability* issues delivery evidence the moment sealed content reaches an authenticated, credential-bound device of the addressee, with no obligation to open it — the contexts mailbox-based registered systems are built for, such as formal notices and regulatory filings, where a recipient who never opens must not be able to defeat delivery. It is **never a default**: it applies only where the recipient has expressly declared it for a content class, so the addressee is always identified and authenticated before delivery — the identification-before-delivery requirement of Article 44(1)(c) — even at the lightest grade.

**The declared grade is externally verifiable.** A privacy-preserving cryptographic commitment binds each availability-grade delivery to the recipient's published declaration, so a third party can check that the grade applied was the one declared, without learning what kind of content was exchanged.

**Confidentiality boundaries can coincide with organisational roles**, so only the designated function within a company can read designated content classes — with the audience *cryptographically verified* before sending, and every device that can decrypt visible to both parties.

**The identity model distinguishes three things**: the legal entity, the person or system acting for it, and the device. That is precisely the structure needed to host software agents under scoped, verifiable mandates.

**An agent's act is bound to the mandate it acted under**, by the same commitment technique — so the act is verifiably *attributable* to the entity, and an agent acting outside its mandate can be **proven** to have overreached, without the mandate or the content class ever leaving the encrypted channel. Where the law or the organisation wants a human in the loop, the policy says so: an agent may then verify a message but cannot perform the acceptance itself.

### What exists today, at a glance

Terms used throughout this document, so that "specified" is never mistaken for "running in production":

| State | Means |
|---|---|
| **Specified** | Defined normatively, with machine-readable schemas and conformance rules that a third party can run |
| **Exercised** | A reference implementation performs it end to end and passes the specification's own conformance gates, unmodified |
| **Pinned to an earlier edition** | The reference implementations currently target a previous evidence edition; re-alignment to the current one is the next implementation step, tracked in the repository |
| **Optional profile** | Cumulative and opt-in — a deployment that does not enable it is unaffected (the agent profile is the only one) |
| **Future study** | Named, scoped, and deliberately not designed yet |
| **External residual** | Requires a decision or an artefact this study cannot produce: legal counsel, production PKI, a federation register, an ETSI review, or key transparency. Listed in `OPEN-ITEMS.md` |

**Nothing here is qualified, and nothing is in production.** The evidence in the reference artefacts is cryptographically real but marked non-qualified, and its key material is demonstration-grade.

## 5. Supported communication scenarios

The design covers a spectrum of communication patterns, each with an explicitly declared confidentiality boundary (who can decrypt) and evidence semantics. Two invariants hold in every row: **providers never decrypt anything**, and **every device that can decrypt is visible to the parties** — no invisible access.

| Scenario | Who can read | Status |
|---|---|---|
| **Business ↔ business** (baseline) | The enrolled devices of both entities in the channel | Specified |
| **Role ↔ role** (e.g. legal affairs to legal affairs) | Only devices of members holding the designated roles. A compliance-records function may be included, but only if the organisation *names that role* in its published policy — so the sender can resolve who it is before sending, and the records function recovers content without being an acceptance party. | Specified · exercised |
| **Employee ↔ employee, different companies** | The role or scope group their organisations configured. A two-person boundary is a configuration choice, not a default; members act *for* their organisation. | Specified |
| **Employee ↔ employee, same company** | Internal to the organisation, which administers all credentials | Explicitly out of scope — personal confidentiality belongs to the personal EUDI Wallet domain |
| **Software agent ↔ business/role** | As per the scope it operates in; scopes can exclude agents from sensitive content classes; the agent acts under a scoped, verifiable mandate, each act bound to that mandate; a policy can require a human to perform the acceptance (an agent may verify, but not accept) | Specified · optional profile |
| **Natural person ↔ business** | Person's wallet devices ↔ the business's scope | Future study (the person as a party in their own right) |

Beyond plain messaging, the same channel and evidence machinery define a **modular roadmap — a registered interaction layer, delivered in phases**: Phase 1, secure registered entity messaging (this profile); Phase 2, registered attestation exchange — delivering electronic attestations (mandates, powers of representation, compliance attestations) with a legal receipt; Phase 3, a registered presentation profile — qualified evidence that a verifiable credential was presented between two identified parties, a primitive the EUDI ecosystem does not yet have; Phase 4, governed agentic interactions. Each phase reuses the previous one's identity, encryption and evidence machinery; none is required to adopt Phase 1.

## 6. Strengths

| Strength | What it rests on |
|---|---|
| **Registered-delivery evidence without content access** | The study's central claim, and the property no system the authors are aware of currently offers: qualified registered-delivery evidence over end-to-end encrypted traffic — the combination the Business Wallet proposal requires (Annex point 11). Providers certify events, identities, times and digests — never content. |
| **Standards all the way down** | MLS, COSE, deterministic CBOR, HTTPS, the ETSI EN 319 522 series, the EUDI Wallet stack. No new cryptography — the contribution is composition and profiling against the regulatory requirements. |
| **Regulatory anchoring by design** | Built clause-by-clause against the requirements of Article 44 and CIR (EU) 2025/1944, with a compliance matrix and a conformance-statement pro forma prepared for assessment bodies — which retain the assessment itself. |
| **Executable, not rhetorical** | The specification set ships with JSON Schemas, CDDL, a published catalogue of 150 semantic conformance rules (including a cross-document validator), companion API contracts, cryptographically real sample evidence and CI: "conformant" is machine-checkable today, and any competing candidate can be measured against the same artefacts. |
| **Governed openness** | The federation model avoids both e-mail's ungoverned sprawl and platform lock-in; evidence belongs to the parties, not to an operator. |
| **Extensible where the market is going** | Role-scoped confidentiality and the **agent profile** (mandates as attestations, acceptance policies as oversight, agent acts bound to their mandate and therefore attributable) are not sketches: both are specified against the same primitives and exercised by the reference implementation. Attestation exchange with registered-delivery receipts is the next phase of the same machinery. |

## 7. Weaknesses and open risks

| Risk | Why it is real |
|---|---|
| **Ecosystem prerequisites** | The directory of entities, the federation authority, the design authority and entity-identifier issuance do not exist yet; the Business Wallet itself is still maturing. The protocol is ready before its institutions. |
| **Uncharted conformity path** | The messaging binding is new to the ETSI registered-delivery framework; the first conformity assessment will set precedent, and the legal argument that the presumption holds over ciphertext-plus-digest, while carefully constructed, is untested. |
| **Operational maturity of MLS at B2B scale** | MLS is standardised and has solid implementations, but large-scale operation of the delivery service and of key-transparency infrastructure in a business federation has little production precedent. |
| **Incumbency and adoption** | National registered-mail systems have entrenched user bases and simpler (weaker) models; a network needs a critical mass of providers and at least one committed Member State or sector to start. |
| **Governance is the hard part** | Standing up gated admission, a membership registry and central change control requires institutional will; the technology does not substitute for it. |

## 8. Feasibility and indicative timeline

**The technical primitives all exist; the institutions do not.** That is the asymmetry to hold on to — §4 named a directory, a federation register and a design authority that have yet to be built, while every *technical* component is already available: MLS has mature open-source implementations (OpenMLS, AWS mls-rs, Cisco mlspp); COSE signing, qualified timestamps (RFC 3161) and certified cryptographic hardware are routine for qualified trust service providers; transport is ordinary HTTPS; identity reuses the wallet ecosystem's attestations. The contribution is composition and profiling, not new cryptography — which is why the remaining work is institutional rather than research.

**The specification set.** Edition 2026-09-18: an umbrella specification, an IETF Internet-Draft and an ETSI-style conformance profile with a conformance-statement pro forma, plus four published API contracts — wallet-to-provider, delivery service, provider-to-provider relay, and the federation membership register — so the federated profile is implementable without private agreements. Role-scoped confidentiality, the agent profile and the four-corner relay are each specified *and* exercised in the reference artefacts.

**The conformance bar is executable.** More than two thousand automated checks across twelve gates: schema validation, structural CDDL validation, semantic linters whose 157 rules are published as a generated machine-readable catalogue, a cross-document bundle validator, a version manifest that fails the build when any artefact drifts, and cryptographically real signed samples — all in CI, under a REUSE-compliant licensing and IPR framework.

**What is left open, and said so.** The external residuals — legal counsel, production PKI, ETSI review, IANA and key transparency — are marked as such in the normative text, and the properties the reference verifier cannot establish from retained material are reported as unproven rather than passed, pinned by tests so that neither can lapse quietly. The claim being made is about the artefacts and their checks, not about completeness.

**Adoption is staged, not all-or-nothing.** The profile defines deployment profiles so nobody has to build the full institutional picture on day one: a *minimal pilot* (a static signed registry, one co-located provider pair, default scope, evidence marked non-qualified); a *federated pilot* (multiple providers, a resolver, one role-scoped use case); a *production baseline* (qualified providers, Trusted List validation, default scope); *production advanced* (confidentiality scopes, records recoverability, registered presentations); and — cumulative and **optional** on top of any of them — the *agent profile*, for organisations that want software agents to act under scoped, verifiable mandates. A network that enrols no agent is entirely unaffected by it. The directory itself stages the same way — from a minimum viable federation registry towards an EU-governed core registry, and only later full business-register integration. Each profile is framed as a level of *institutional risk proven* — the round trip and evidence model, then provider interoperability, then legal effect and qualification, then full organisational capability — and each declares, just as explicitly, what it does **not** prove.

Indicative phasing, assuming a small, focused team and no institutional blockers:

- **Reference implementation: built, and past the part usually assumed hardest.** An open-source proof of concept (*sbm-poc*: a Rust wallet on a real MLS implementation, Python provider services, a signed directory) implements the minimal pilot end-to-end — first contact, delivery through all four states, evidence issuance, failure paths — and also the **federated pilot: a genuine four-corner exchange between two independent providers**, each sealing its own evidence for its own hop, aggregated into a single two-hop Evidence Package. Role-scoped confidentiality and the agent profile run too. A second codebase (*sbm-services*: a deployable, database-backed provider and directory) runs the same two profiles on real containers. **Both pass the specification's conformance gates unmodified** — they consume the spec's linters as-is rather than adapting them, which is what makes the claim mean anything. (Both are currently pinned to an earlier evidence edition; their re-architecture to the current one, driven by the completed design-review backlog, is the next implementation step and is tracked explicitly.) That the four-corner case *runs* matters: provider-to-provider relay with per-hop evidence is the part most often assumed to be the hard one, and it is no longer hypothetical.
- **The feedback loop is the method, and it keeps paying.** Every implementation pass is treated as an experiment against the specification, and each has surfaced real under-specification — first thirteen ambiguities in the initial pass, then, as the harder profiles landed, subtler ones: a digest whose *input* was never stated (two conformant implementations would have produced mutually unverifiable evidence), and an identity check that silently skipped the one object it most needed to bind. Each was resolved in the specification, with a machine check and a byte-exact sample added so it cannot recur. This is what a design study is *for*: the errors are found by building, before anyone has to live with them.
- **Multi-provider pilot** under the transitional regime foreseen by the design (evidence explicitly marked non-qualified; 2–3 providers; interoperability, key management and evidence verification exercised end-to-end): roughly **6–12 months**, overlapping the above.
- **Standards and qualification track**, in parallel: Internet-Draft to the IETF, the conformance profile towards ETSI TC ESI, and conformity assessment of the profile with a pilot assessment body: realistically **12–24 months**, driven by institutional calendars more than by engineering.

The long pole is not code; it is governance and conformity assessment. That is an argument for starting those tracks early — and it is exactly the kind of question an expert group is positioned to weigh.

## 9. What the expert group can take from this study

Four things, usable regardless of which solution is ultimately selected.

1. **A requirements baseline** distilled from Regulation (EU) No 910/2014, CIR (EU) 2025/1944 and the ETSI EN 319 522 series, separating legal obligations from technical requirements and from provider operational duties.
2. **A worked candidate architecture** arguing that the E2EE-versus-evidence trade-off is false, with the difficult questions — delivery semantics, identity binding, key discovery, digest verification, failure evidence — answered concretely rather than waved at.
3. **A comparison lens** for the other candidates (Matrix, Signal-based designs, eDelivery/AS4): each will have to answer the same questions this study answers, and the requirements grid puts them side by side.
4. **Executable artefacts** — schemas, conformance linters, signed samples and a test suite — that turn evaluation claims into checkable facts.

### Three questions we would put to the group

- **Is the baseline right?** The requirements grid is our reading of the law and the standards. If a requirement is missing, mis-scoped, or over-read, that correction is worth more to the group than anything else in this document.
- **Is the evidence argument sound?** Registered-delivery evidence resting on content digests rather than on content is the load-bearing claim, and it is untested. Where would it fail — legally, or in a conformity assessment?
- **What would make a comparison fair?** The artefacts here are executable so that candidates can be measured rather than described. What else would the group need in order to compare options on the same terms?

The study is offered in that spirit: not as the answer, but as a concrete, falsifiable input that raises the floor of the discussion. The complete specification set and conformance tooling are in the accompanying repository — documents under CC BY 4.0, code and machine-readable artefacts under MIT.
