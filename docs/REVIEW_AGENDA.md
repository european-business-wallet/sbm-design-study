<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Review agenda — the open questions, stated so they can be answered

This is the list a reviewer should read before the specification, because it
says where the specification does **not** yet have an answer. Each entry names
the question, what the specification currently assumes, which claim depends on
the answer, and whose expertise would settle it. Nothing here is hidden
elsewhere: every legal question below is also marked, visibly, where it applies
in the normative text as `TODO(legal)`.

A question being on this list is not a defect in the review edition. A question
being open and **not** on this list would be.

## Protocol and architecture

| # | Question | Current assumption | Claim that depends on it | Expertise |
|---|---|---|---|---|
| A1 | **How does the RDP that issues a DE obtain the Delivery Service's receipt — and which RDP issues the DE when sender and recipient use different providers?** | None published. The DS contract says the issuer MUST verify the receipt; the only way the receipt leaves the DS is back to the acknowledging device. The contract names RDP(out) as issuer; TS clause 4.1 names the recipient-side RDP. Having the wallet forward the receipt is **not** safe: a recipient could suppress delivery evidence by never forwarding it, which defeats the availability grade. | Availability-grade DE; every DE in the four-corner deployment | Protocol and security design; QERDS operators |
| A2 | **What maximum age should a live decision accept for a membership assertion?** | The MODEL is settled: live use is a lease, decided once at the start of the exchange on the deciding provider's clock, against a record that states `admitted`, was not asserted after that instant and is no older than the maximum the Federation Authority publishes. Only the number is open. Historical verification needs no such bound — an assertion speaks up to its own `asserted_at`, and `as_of` evaluates a complete record rather than truncating one. | Live admission checks between providers | Federation governance; operations |
| A3 | **How can a verifier know a retained acceptance-policy chain is complete** — that no later version existed? | It cannot, from inside a bundle: every shipped bundle reports this as INCOMPLETE. Closing it needs an authenticated log head — the same missing primitive as key transparency. | "The governing policy was the latest in force"; detection of provider withholding | Transparency systems; applied cryptography |
| A4 | **How should the post-quantum hybrid suite be tested across implementations?** | Pinned to draft-ietf-mls-pq-ciphersuites-06 under a private-use code point (0xF5C1). The draft publishes no test vectors and this repository implements no ML-KEM, so no cross-implementation KEM vector exists. | Post-quantum confidentiality of any group that selects the suite | MLS and post-quantum implementers |
| A5 | **Who publishes and updates a group's retained state?** | `GET /groups/{group_id}/context` is published and nothing publishes the bytes it serves; declared as a residual. | Retained verification of the cipher-suite decision and `mls_state` | MLS Delivery Service implementers |
| A6 | **The MSP as a federation participant** — its identifier, its contract, and the binding of a DE to the MSP's observation. | Decided; Batch B is **planned, not implemented**: the register admits only `rdp`, and no Schema carries `MspId` or `observed_by`. | Separated MSP/RDP deployments | Implementers; operators |
| A7 | **A cross-deployment contract for the wallet-agent interface.** | The agent's evidence and mandate rules are specified (profile 5, Annex R); the interface between deployments is informative only. | Profile-5 interoperability | Wallet and agent implementers |
| A8 | **Mapping to heterogeneous registered-delivery systems.** | Homogeneous federations only; the relay-stage mapping onto ETSI EN 319 522 is the study's own reading. | Any gateway to another QERDS | ETSI ESI; QERDS providers |
| A9 | **Who observes S2, and what can an MSP acting alone make an RDP attest?** | S2 is the Delivery Service's signed receipt over a device acknowledgement made in a device-authenticated session with a collection token the DS issued — not wallet-signed. So the MSP is a **trusted observer** of the handover: a malicious MSP could fabricate one, and Batch B's `observed_by` would make that attributable, not impossible. Three models are analysed, none chosen (`docs/rdp-msp-trust-analysis/`): an accountable MSP observer, a handover proof authenticated independently of the MSP, and the handover inside the RDP's boundary. **Nothing claims resistance to a malicious MSP** until one is chosen. | The availability grade in a separated deployment; any claim about MSP compromise | Security design; QERDS operators |
| A10 | **Which Delivery Service routes a group, and who owns its membership after formation?** | A DS routes the devices it observed joining: the founder registered with it and the devices invited through it. In the four-corner flow the creator deposits every invitation at the counterparty's DS, which therefore routes the whole group, the creator included; the creator's own DS routes only devices invited through it, so the acceptance the SE rests on may create no items there. Whether each entity's devices should be served by its own DS is not decided. After formation, an Add arrives as a new invitation and is routed like any other; a Remove — or a member leaving — changes no DS's delivery set, because nothing publishes it to the DS, so a removed device keeps receiving ciphertext it can no longer decrypt. | Device-scoped delivery after formation; separated DS stores | MLS Delivery Service implementers; protocol design |
| A11 | **How does a receiver say “I cannot compute this” — and where is a hash mode advertised?** | **Decided, 25 September 2026: every defined mode is mandatory to implement** — `raw-sha256`, `raw-sha512`, `manifest-sha256`, `manifest-sha512`. The Internet-Draft (*Canonicalisation and Payload Hashing*) states it, the TS carries ICS row 192, and `LINT-HASH-01` refuses a mode outside the profile. Before the decision: nothing published. The canonicalisation modes were removed on 25 September 2026 because a receiver that met one without an implementation could only assert a `payload-hash-mismatch` that had not occurred, or fall silent into NDE `expired`; removing them did not close the class, because `manifest-*` needs a construction `raw-*` does not and reproduced the same dead end. The decision removes the receiver that cannot comply rather than giving it a way to say so, which holds **only while no mode is added**: adding one reopens this entry, and the honest alternatives are then to advertise supported modes in BW-MED / BW-ORG and add an NDE reason for a mode that cannot be computed | Every multipart message; any future mode or extension a peer may meet — which is what would reopen this | Protocol design; registry governance |
| A12 | **Should the content digest be salted** — the salt carried in the encrypted envelope and revealed only with the content, as the grade commitment already is? | That a digest over plaintext discloses nothing useful. That holds where the plaintext has entropy and fails where it is guessable — an invoice on a known template, an amount in a narrow range — and the profile does not say which it assumes. It salts commitments (`grade_commitment_salt`, `mandate_commitment_salt`, the dispute `salt`, sixteen bytes each, fresh per message) and does not salt `payload_hash` or the envelope `content_digest`. | Every statement that evidence carries no content: it carries a digest of it, which is a test oracle for a guess — and under Mode C each part digest likewise. A change would reach the envelope schema, the evidence schemas, the recipient's re-verification rule, the multipart manifest and its per-part digests, and the reveal path at dispute. | Applied cryptography; QERDS operators, because a salted digest changes what a retained bundle proves without the salt |

## Deferred deliverable — the implementer guide

Not a question, and not delivered. The maintainer deferred implementer-grade
flows to the architecture documentation that follows this review; until that
exists, an implementer has the contracts and the reference, and these four
things in neither of them:

| # | Missing | Where it will be answered |
|---|---|---|
| G1 | **The pre-join proof, exactly**: which KeyPackage key signs a Welcome refusal, the exact signed request bytes, the transport, and freshness and replay protection (the DS contract states that the proof exists; it does not specify it). | Implementer guide; then the DS contract |
| G2 | **One complete trace through the public operations**, negative and retry branches included — reservation to evidence retrieval, both entities, several members. | Implementer guide |
| G3 | **Bootstrap and change**: key-role transitions, and a provider's migration or exit — draining queues, and who holds the retained evidence afterwards. | Implementer guide; custody duties in the umbrella |
| G4 | **Who sees what**: metadata, privacy and retention visibility per actor (wallet, MSP, RDP, Federation Authority, directory). | Implementer guide |

Status: **deferred, not closed**. The maintainer owns it; the
deliverable is a public implementer guide in this repository. Parts of it
overlap A5 and A7 above. Two of the four are partly addressed by the reviewer
notes, and neither is closed: G2 by [`message-lifecycle.md`](message-lifecycle.md)
— a minimal trace and six retry and failure cases, not yet a complete
two-entity, several-member trace; G4 by
[`architecture-identity-trust.md`](architecture-identity-trust.md) §6 and
[`lifecycle-and-custody.md`](lifecycle-and-custody.md) §3 — who sees what, and
who holds what, without setting a retention period. G3 likewise: that note
inventories the migration and exit steps that have no published operation,
which is not the same as specifying them.

## Production trust

| # | Question | Current assumption | Claim that depends on it | Expertise |
|---|---|---|---|---|
| P1 | **The production certificate profiles** — QSealC chains to EU Trusted Lists, qualified timestamps, the certificate profile for delegated device credentials. | Production-verifier duties, not established by the reference tooling; the demo trust store holds demonstration keys in place of production trust material, for the qualification and the admission roles alike. | Every "qualified" claim | PKI; trust-service conformity assessment |

## Legal — the `TODO(legal)` questions

Each of these is marked where it applies. None is answered by this
specification, and none should be read as answered by its silence.

| # | Question | Where it is marked |
|---|---|---|
| L1 | May the act of observation that Article 44(1)(b) and (c) require be performed by a participant that is admitted but not itself qualified — and what must the qualified issuer then bind? | umbrella §7.2 |
| L2 | Does a qualified RDP excluded from the federation keep any Article 43(2) presumption for evidence issued while excluded; may admission be referred to in a conformity assessment at all? | umbrella §13.1 |
| L3 | How is liability allocated between an MSP and an RDP for a delivery failure that is a protocol artefact rather than a recipient's act? | umbrella §13.2 |
| L4 | The respective evidential weight of provider-attested and wallet-signed acts, of the refusal kinds, and of the admissible authentication combinations. | TS clause 6 |
| L5 | The consequences of a grade-commitment dispute: what a signed reveal establishes is stated; whether the delivery evidence may then be relied upon is not. | TS clause 6 |
| L6 | The qualification of a directory-pinned seal key; the coupling of a UID attestation's own status to the UID lifecycle. | umbrella §5.2, §10.1; the I-D, *Credential Mapping* |
| L7 | The effect of a PROVEN grade mismatch on the Article 43(2) presumption (final-but-rebuttable). | the I-D, *Object Definitions* |
| L8 | How a mandated transparency control — the answer to A3 — would interact with qualification. | TS clause 9 |
| L9 | **Closed as editorial, 26 September 2026.** `IPR.md` §3 named the JSON Canonicalization Scheme RFC 8785 among the external standards the patent commitment excludes, and the Specification stopped referencing it on 25 September. The name is removed from the list. The perimeter did not move: the exclusion is defined by reference — standards *referenced by the Specification* — and the list is illustrative ("including but not limited to"), so an example no longer referenced was stale, not operative. And the commitment is not in force: the document limits itself to the artefacts *as published in this repository*, and the repositories are private. No legal wording was drafted; the row stays as the record of the call, taken by the maintainer. | `IPR.md` §3; this row |

## Questions for the call for feedback

- Is the split between entity, member, device, MSP, RDP and Federation
  Authority understandable and operationally plausible?
- Are the delivery grades, and the scope of what each evidence object claims —
  including the narrowed provider-attested modes — clear?
- Can an implementer derive every required request field and verification
  input from the published contracts and retained artefacts? Where not, that
  is a finding: the reviews have already found several (two
  fixed; one still open).
- Does the admission model — an assertion speaks up to its own `asserted_at` —
  handle suspension, recovery, key rotation and later verification?
- Are reservation consumption, group membership and retry rules sufficient
  for two independent implementations to build the same state machines?
- What minimum production wallet and credential profile, and what migration
  and retention duties, are needed?
- Which qualification, event-mapping and legal-effect claims need correction
  or external confirmation?

## How to send an answer

See **Feedback** in the README: technical feedback by issue using the
technical-feedback template; patent disclosures through the separate IPR
route, which is not ordinary feedback.
