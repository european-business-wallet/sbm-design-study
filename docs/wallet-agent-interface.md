# The Wallet-Agent Interface
## Companion-contract outline (agent profile, deployment profile 5)

**Status:** informative outline of a normative companion deliverable, draft for discussion · **Applies to:** Secure Business Messaging Profile (SBM), umbrella **Annex R** (agent profile) · **Audience:** implementers and standards readers

> **Exploratory design study — not an official proposal.** This is an *outline* of a companion contract, not the contract itself. It states the interface's required properties and shape; the full OpenAPI definition is the deliverable that makes profile-5 cross-deployment interoperability claimable. In any conflict, the normative documents prevail — umbrella Annex R.4, the I-D *Deployment-Defined Interfaces*, and the TS clause 4.1 companion-contract enumeration.

---

## 1. Why this interface exists

An **agent** (a system member, Annex R) acts for the entity but **never holds the channel's MLS or seal private keys**. It reaches the channel only by *instructing its wallet* through a controlled local interface; the wallet performs every cryptographic act. This interface is therefore the boundary where an agent's authority is authenticated, attributed, and confined to its mandate scope — the point at which "the agent decided" becomes "the wallet acted, attributably, within scope."

Like the wallet↔RDP and Delivery-Service surfaces, the wallet-agent interface is **deployment-defined**: an implementation MUST satisfy the required properties below, but the HTTP/IPC shape is not standardised by the base profile. **Profile-5 cross-deployment interoperability REQUIRES this contract to be normatively defined** — exactly as profile-2 interoperability requires the wallet↔RDP contract. Until it is, a deployment MAY operate the interface internally, but MUST NOT claim profile-5 interoperability on the basis of the base documents alone.

## 2. Required properties (normative, from Annex R.4 / TS clause 4.1)

1. **Agent-wallet authentication.** The agent is authenticated to its wallet in a session **bound to the system member** (the acting MID). An unauthenticated or wrongly-bound caller MUST be refused.
2. **Key isolation.** The agent **cannot extract** MLS or seal private keys, nor obtain a signing oracle beyond issuing scoped instructions. Compromise of the agent process MUST NOT allow forging channel authentication or evidence.
3. **Attributability.** Every agent instruction is attributable to the system member, feeding the `auth_context.identity=system` / `auth_context.mid` acting-identity record on the resulting evidence.
4. **Mandate-scope enforcement.** The wallet **refuses** an instruction outside the agent's mandate scope (the standing `mandate_ref.scope` in the agent's **BW-MEMBER**, the entity's signed roster of members and their devices); an opposable act additionally causes the wallet to compute the `mandate_commitment` (Annex R.1). A revoked or expired mandate MUST stop honouring instructions (act-time validity, A2).

## 3. Interface shape (outline — not the contract)

The contract, when written, is expected to cover at least these operations (names indicative):

| Operation | Purpose | Enforces |
|---|---|---|
| `authenticate` | Establish an agent↔wallet session bound to the system member | Property 1 |
| `submit` | Instruct the wallet to send a message on a (pair, scope) group | Properties 3, 4 |
| `confirm` | Instruct the wallet to produce a recipient confirmation (S3) | Properties 3, 4; never S4 for a `human_acceptance` class (A8) |
| `status` | Query mandate validity / scope for a prospective act | Property 4 (fail-closed on revoked/expired) |

What the interface **does not** expose: raw key material, an unscoped signing oracle, or any path that bypasses mandate-scope enforcement or the acting-identity record.

## 4. Relationship to the rest of the profile

- **Evidence:** the acting identity (`auth_context.identity=system`, `mid`) and the acted-under mandate (`SE.mandate_ref`, `mandate_commitment`) originate from instructions crossing this interface (A1/A2/A5).
- **Acceptance:** the interface never lets an agent perform an act reserved to humans — S4 acceptance of a `human_acceptance` class is out of an agent's reach (A8).
- **Security posture:** counterparty content an agent reads is untrusted input and MUST NOT escalate authority across this interface or push an instruction outside mandate scope (§11.2).

---

*Normative sources: umbrella **Annex R** (R.4), the Internet-Draft `draft-sbm-mls-erd` (*Deployment-Defined Interfaces*), the TS-shaped `TS-SBM-QERDS-Binding` (clause 4.1 companion contracts). This document is an informative outline; the full contract is a profile-5 companion deliverable.*
