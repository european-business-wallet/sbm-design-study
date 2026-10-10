# The Agent Profile
## Purpose, design and use cases

**Status:** informative companion, draft for discussion · **Applies to:** Secure Business Messaging Profile (SBM) spec set, umbrella **Annex R**, at the versions in the README's version table (not restated here, so they cannot drift) · **Audience:** technical, legal and standards readers

> **Exploratory design study — not an official proposal.** This document explains an independent technical exploration; it is not a position of the European Commission, any Member State, or any standards body, and confers no status. In any conflict, the normative documents prevail — here, umbrella **Annex R** (agent profile), §8.3/§8.3a/§8.4/§11.2, the TS clause 6, and the I-D *Deployment-Defined Interfaces*.

---

## 1. Why an agent profile

AI agents are beginning to act for businesses — negotiating, ordering, filing, responding, reconciling. The question is not *whether* agents will transact between businesses, but *what infrastructure those transactions run on*. The rails such transactions run on today — bespoke APIs, platform accounts, the emerging agent protocols — were not built to carry the three properties this study is about, and a deployment that needs them has to supply them some other way:

- **No verified legal-entity identity** behind the agent.
- **No machine-verifiable scope of authority** — nothing a counterparty can check to know the agent was allowed to do what it did.
- **No opposable evidence** of what was exchanged. When an agent over-orders, agrees to the wrong terms, or files the wrong declaration, disputes fall back on platform logs one party controls and the other cannot verify.

Two shifts make this urgent. **Machine speed changes the safety model:** human-paced business tolerates weak channels because people review what they send and receive; agents transact at machine speed and volume, and so does fraud — impersonated suppliers, fabricated invoices and manipulated instructions no longer arrive one at a time. When no human reads each message, guarantees cannot live in vigilance; they must be structural. And **trust is the adoption bottleneck:** organisations will not delegate legally significant acts to agents without accountability infrastructure — and where they do anyway, they accumulate silent risk. Legal certainty is not a brake on agentic automation; it is its enabler.

The agent profile turns "my agent agreed X with your agent" into verifiable evidence — identified parties, verified content, certain time, qualified evidence — the precondition, not a guarantee, for an agreement and the law to attach effect (Annex R.5), *and it needs no redesign of the network to host it.* The identity model already distinguishes the legal entity, the person **or system** acting for it, and the device; acceptance policies already express human-in-the-loop gates; the wallet↔RDP and Delivery-Service interfaces already use the deployment-defined-interface pattern; and the implementing act already provides a machine-to-machine authentication path for automated senders. The agent profile is the composition of these building blocks, not a new stack.

## 2. What the profile is, in one paragraph

An **agent** is an addressable, accountable **system member** within an entity — software that acts for the organisation, holding its own delegated credential and a **scoped mandate issued as an attestation** that counterparties verify before treating its messages as binding. Its transactions inherit the channel's guarantees. Agents **never hold the channel's encryption keys**: they instruct the wallet through a controlled interface, and the wallet acts. Organisations keep humans in the loop where it matters — an agent may receive and verify, but **legal acceptance of designated content classes can require a human** role or quorum. And **non-repudiation is layered**: the protocol provides verifiable evidence that an agent acted under a valid mandate, the participation agreement establishes whether that evidence is opposable to the entity, and the applicable legal framework governs the final qualification — the discipline that makes organisations deliberate about what they delegate.

The profile is the OPTIONAL, cumulative **deployment profile 5** (Annex P): layered on the production profiles, it changes nothing for a deployment that never enrols a system member.

## 3. The six pieces (and how each is implemented)

The profile decomposes into six pieces, **R.1 to R.6** of [Annex R](../Secure-Business-Messaging-Profile.md#annex-r--agent-profile-normative-where-a-deployment-adopts-it). The annex also labels them A1 to A6; this document uses the section numbers, because `A1` to `A16` are the review agenda's and a reader meeting both should not have to guess which register a bare `A3` belongs to. Each reuses existing machinery; each machine-checkable rule has a conformance linter.

### 3.1 System members (Annex R.1) — *who is acting*

A member binding (`BW-MEMBER`) now declares **`member_type`** ∈ {`person`, `system`} (default `person`, so existing bindings are unchanged). A `system` member is an agent. When an agent is the acting identity, the evidence records it: **`auth_context.identity` = `system`**, together with the acting **`auth_context.mid`** — the pseudonymous member id of the agent that acted. Recording *that an agent, not a person, acted* is the accountability anchor; the MID resolves (off-wire, under controlled conditions) to the organisation's authorisation event (§8.4).

*Implemented as:* `bw-member.schema.json` `member_type`; `evidence-common` `AuthContext.identity` gains `system` and an `mid` that is schema-required when `identity=system`. Cross-document check: `bundle_lint` **LINT-BND-14** — a system acting identity that names a MID of the acting entity must resolve to an *active* `member_type=system` member. This change moved the evidence family to **v1.12**.

### 3.2 Mandate attestations (Annex R.2) — *by what authority*

An agent's authority is a **scoped mandate** — an electronic attestation of attributes (EAA) or verifiable credential. The mandate credential itself travels **end-to-end encrypted** like any payload; only its **reference** is bound where a counterparty can check it:

- **Standing authority** — the system member's `BW-MEMBER.mandate_ref`: `{issuer, id, scope, valid_from, valid_until}`, where `scope` enumerates the content classes the agent may act on. Published in the signed member binding, so a counterparty checks the agent's standing authority before treating its messages as binding.
- **Acted-under** — the `SE.mandate_ref` on an agent-sent Sending Evidence: `{issuer, id}` linking to the standing mandate, recording *which* mandate was invoked for *this* message.
- **Verifiable scope — required for an opposable act** — an `SE.mandate_ref.mandate_commitment`: a salted digest over (mandate id, content class, the referenced **BW-ORG** — the entity's signed organisation document, carrying its roles and acceptance policy) whose salt travels only in the encrypted envelope, so a verifier can later confirm the acted-under scope covered the content class. An agent SE is **opposable by default** (an absent `opposable` field means opposable), and an opposable SE **must** carry the commitment; `opposable: false` marks an informative act, for which the commitment is **forbidden** and scope conformance can be established only by internal audit, payload reveal or the dispute path (Annex R.2; `evidence_lint` LINT-DE-15). **What the commitment hides, and what it does not.** The commitment itself discloses neither the mandate nor the class: a reader cannot test a guess against it. The bundle as a whole is a different question. The standing `mandate_ref` — including its `scope`, the classes the agent may act on — is published in the signed member binding, and the cleartext `scope_ref` resolved against the recipient's published scope map gives the set of classes the message could have belonged to; a scope covering one class gives that class. The mandate **credential** is never disclosed, and a reveal of `(salt, content_class)` discloses the committed class to the parties of that dispute. **What a valid opening proves** is what the sender *committed to* — that the class it declared falls inside the mandate's scope — not that the declared class describes the encrypted document. A sender could commit to a permitted class and encrypt something else; the commitment binds the declaration, and no cryptography here inspects the plaintext. The same limit is stated for the grade commitment, and for the same reason. The reveal procedure mirrors the availability-grade grade commitment (TS clause 6).

*Implemented as:* `evidence-common` `Mandate`/`MandateRef` definitions; `discovery_lint` **LINT-DISC-20** (a `system` member must publish a `mandate_ref`); `evidence_lint` **LINT-DE-14** (an agent-sent SE must carry a `mandate_ref`; a non-agent SE must not) and **LINT-DE-15** (an opposable agent SE must carry the commitment); `bundle_lint` **LINT-BND-15** (the SE mandate matches the member's standing mandate by issuer+id and is in validity at `sent_at`; the scope-covers-class check is verifier-side, or via the commitment reveal).

### 3.3 Human-in-the-loop policy classes (Annex R.3) — *where a human must decide*

The guardrail against fully-autonomous acceptance is the acceptance-policy machinery you already have. A confidentiality-scope descriptor may declare **`human_acceptance: true`** (§8.3a); system members are then **excluded from that scope's acceptance eligible set** (§8.3). An agent can still receive and verify a message in that scope, but its acknowledgement does **not** satisfy a human-gated content class — acceptance requires a human role or quorum. A misconfiguration where a human-gated scope could only ever be satisfied by agents is caught and rejected.

*Implemented as:* `bw-org.schema.json` scope-descriptor `human_acceptance` (BW-ORG → v1.5); the §8.3 eligible-set definition excludes `member_type=system` for such scopes; `bundle_lint` **LINT-BND-16** rejects a `human_acceptance` scope whose entire eligible set is system members (unsatisfiable by agents alone).

### 3.4 Wallet-agent interface (Annex R.4) — *how an agent acts without holding keys*

Agents never hold the channel's MLS or seal private keys. They **instruct the wallet** through a controlled, **deployment-defined** interface — the same pattern the profile already uses for wallet↔RDP and the Delivery-Service. Its normative REQUIRED properties:

1. the agent is **authenticated to its wallet** in a session bound to the system member;
2. **key isolation** — the agent cannot extract MLS or seal private keys (it instructs, the wallet acts), so compromise of the agent process cannot forge channel authentication or evidence;
3. **attributability** — every agent instruction is attributable to the system member (feeding the `identity=system` acting-identity record);
4. **mandate-scope enforcement** — the wallet refuses an instruction outside the agent's mandate scope.

*Implemented as:* a fourth surface in the I-D *Deployment-Defined Interfaces*, enumerated in the TS clause 4.1 companion-contract list. Its OpenAPI contract is a profile-5 companion deliverable (as the wallet↔RDP contract was a profile-2 prerequisite) — declared now, contracted later.

### 3.5 Accountability and non-repudiation (Annex R.5) — *layered*

The evidence chain records **who acted** (the acting MID, resolvable to the `accountability` event, §8.4) and **within which mandate** (the `mandate_ref`). Non-repudiation is **layered**, deliberately: **(1)** the protocol provides **verifiable evidence** that an agent MID acted under a mandate valid at act time; **(2)** whether that evidence is **opposable to the entity** is established by the federation / participation agreement, not by the protocol; **(3)** the **final legal qualification** depends on the applicable legal framework. The protocol makes the act *verifiable* — the precondition for the agreement and the law to attach effect — not automatically binding. A mandate that was revoked or expired at `sent_at` does not support acceptance.

*Implemented as:* TS clause 6 (identity proofing / accountability), reusing the A1/A2 fields; no new field.

### 3.6 Security posture (Annex R.6) — *the machine-speed threat*

Three properties are load-bearing and stated as a normative NOTE (§11.2):

- **Counterparty content is untrusted input.** Message content from an identified counterparty is still adversary-influenced input to the agent that reads it — the machine-speed analogue of a manipulated instruction. Implementations MUST treat received content as untrusted, and content received over the channel MUST NOT escalate the agent's authority or push it outside its mandate scope. Identified-sender + qualified evidence establish *who* sent *what*, not that the content is *safe to act on*.
- **Key isolation** (Annex R.4): the agent holds no keys, so agent-process compromise cannot forge channel authentication or evidence **by itself**. What a compromised agent can still do is **instruct the wallet within its mandate** — which is why the mandate's scope and `human_acceptance` are the bound that matters, and why key isolation alone is not a containment argument.
- **Mandate revocation propagates:** a revoked or expired mandate MUST NOT yield acceptance (validity is checked at `sent_at`, LINT-BND-15; the wallet-agent interface stops honouring instructions once the mandate lapses).

This maps onto the European approach to governing consequential automated behaviour — **human oversight** operationalised by acceptance policies (§8.3/A3), **traceability** operationalised by qualified evidence (the acting identity and mandate on the evidence chain, A5) — without asserting conformance to any specific instrument.

## 4. Use cases

- **Procurement agent that files orders.** A `system` member of the **buyer**, which is the *sender* here, holds a mandate scoped to the order class it may send. It resolves the counterparty, builds and submits the message; the SE records `identity=system`, the acting MID, and the acted-under mandate. The **seller**, the *recipient*, verifies the agent's standing mandate before treating the order as binding — and where the seller has declared that class `human_acceptance`, the seller's own human role or quorum must accept, because the gate governs the **recipient's** act and sits in the recipient's published posture. An approval the buyer requires before its own agent may send is an internal workflow control outside this profile: `human_acceptance` does not reach it. Automation with a human gate exactly where the money is accepted.
- **Invoice reconciliation / dispatch.** Verification-grade traffic (receipt + integrity) is a natural agent task: the agent receives, re-verifies the digest, and issues acknowledgements at machine speed, while the evidence chain stays opposable. No human gate needed where the act is receipt, not commitment.
- **Regulatory filing bots.** An agent files on deadline; where the authority has declared the availability grade for that class (§8.3b), the DE is dated at the acknowledged handover to its authenticated endpoint, and the mandate reference, with its commitment, shows the bot was authorised to file that class. What that evidence is worth if the filing is contested is Annex R.5's layered question, not the protocol's.
- **Cross-agent negotiation.** "My agent agreed X with your agent" becomes provable: each side's SE/DE carries the acting agent identity and its mandate, so the agreement is attributable to authorised agents of identified entities, not to platform logs.
- **Mixed human/agent desks.** An entity runs agents for high-volume verification and humans for acceptance of sensitive classes, declared once in its published posture (`human_acceptance` scopes) so counterparties can read the split before sending.

## 5. A worked example (procurement order, agent-sent)

1. **Enrolment.** The buyer entity — the **sender** in this example — publishes a `system` BW-MEMBER for its procurement agent — `member_type: system`, roles it may act in, and a standing `mandate_ref` scoped to `x-payment-order`, the class of the act in this example, valid for the year. `discovery_lint` checks the mandate is present (LINT-DISC-20).
2. **Instruction.** The agent decides to place an order and **instructs its wallet** over the wallet-agent interface; the wallet authenticates the agent to the system member, checks the instruction is within the mandate scope, and — the agent never touching a key — builds and encrypts the message.
3. **Submission.** The sender-side RDP issues **SE** recording `auth_context.identity = system`, the acting `mid`, and the `mandate_ref` for the mandate acted under. `evidence_lint` confirms the agent SE carries a mandate (LINT-DE-14); a verifier with the buyer's discovery documents confirms the SE mandate matches the standing mandate and was in validity (LINT-BND-15).
4. **Acceptance.** On the seller side — the **recipient** — if the order's class is human-gated (`human_acceptance`), the seller's **human** role/quorum must accept — the seller's own agents cannot satisfy it (LINT-BND-16). Otherwise the normal grade applies.
5. **Dispute, later.** Either side produces the Evidence Package. It shows *who* acted (an authorised agent of an identified entity), *within which mandate*, over verified content at a certain time — and, if the acted-under scope is contested, the mandate commitment (present because the order is opposable, the default) can be revealed: it discloses the content class to the parties of the dispute, not the mandate credential, and confirms the class was in scope. That is the first of Annex R.5's three layers — **protocol evidence** that an authorised agent acted under a mandate valid at the time. Whether the act is opposable to the buyer is for the **participation agreement**, and its final **legal qualification** for the applicable law; the protocol makes the act verifiable, not automatically binding (Annex R.5).

## 6. What the profile deliberately does *not* do

- **It does not make agents autonomous over acceptance.** Where an organisation wants a human in the loop, `human_acceptance` keeps them there; the profile provides the gate, not a policy that the gate be absent.
- **It does not give agents keys.** Key isolation is a REQUIRED property of the wallet-agent interface, not an implementation preference.
- **It does not vouch for content safety.** Qualified evidence establishes identified-sender and verified-content; it does not certify that acting on the content is safe — counterparty content remains untrusted input (§11.2).
- **It does not change the base profiles.** It is OPTIONAL and cumulative (deployment profile 5); a deployment that enrols no system member operates profiles 1–4 unchanged.
- **It does not ship a wallet-agent HTTP contract yet.** The interface's required properties are normative now; its OpenAPI is a profile-5 companion deliverable (as the wallet↔RDP contract was for profile 2).

## 7. Where it lives (normative anchors)

| Piece | Normative home | Conformance |
|---|---|---|
| System members (Annex R.1) | §8.4 (`member_type`); `auth_context.identity=system`+`mid` | LINT-BND-14; ICS AGENT-1 |
| Mandate attestations (Annex R.2) | `BW-MEMBER.mandate_ref`, `SE.mandate_ref` | LINT-DISC-20, LINT-DE-14, LINT-BND-15; ICS AGENT-2 |
| Human-in-the-loop (Annex R.3) | §8.3/§8.3a (`human_acceptance`) | LINT-BND-16; ICS AGENT-3 |
| Wallet-agent interface (Annex R.4) | I-D *Deployment-Defined Interfaces*; TS clause 4.1 | verifier-side; ICS AGENT-4 |
| Accountability (Annex R.5) | TS clause 6 | verifier-side; ICS AGENT-5 |
| Security posture (Annex R.6) | §11.2 | analysis |

## Corrections, for readers of earlier editions

Earlier editions of this document carried claims that were wrong in a way a reader could have acted on. They are kept in [`corrections-to-earlier-editions.md`](corrections-to-earlier-editions.md) — out of the explanation, and still there for someone working from an earlier reading.

---

*Normative sources: the SBM specification set — umbrella `Secure-Business-Messaging-Profile` (Annex R; §8.3/§8.3a/§8.4/§11.2), the Internet-Draft `draft-sbm-mls-erd` (*Deployment-Defined Interfaces*), the TS-shaped `TS-SBM-QERDS-Binding` (clauses 4.1, 6) — with the JSON Schemas and conformance tooling in the specification repository. This document is informative; in any conflict, the normative documents prevail.*
