---
id: SBM-ADR-0004
title: "The MSP separated from the RDP, with the relay left RDP-to-RDP"
label: "MSP and RDP separated"
decision_status: accepted
implementation_status: [specified, in-reference, planned]
implementation: >-
  relay: in force. MSP identity, `observed_by`, `receipt_digest`, composition axis: planned, not implemented ([A6](../REVIEW_AGENDA.md))
choice: >-
  the MSP is each side's local delivery service and a participant in its own right; the relay stays RDP-to-RDP;
  a DE should bind the observation it rests on; provider composition is a deployment axis, not a rung · §7.2, [§13.1](../../Secure-Business-Messaging-Profile.md#131-institutional-roles)
alternative: >-
  a relay between the two MSPs with RDPs as observers — rejected; the MSP as the RDP's subcontractor — rejected
benefit: >-
  evidence authorship stays with qualified parties; transport and evidence become separable markets
cost: >-
  one more interface, and a trusted observer: separation makes a false S2 *attributable*, not impossible ([A9](../REVIEW_AGENDA.md))
open_questions: [A6, A9]
author_questions: []
supersedes: []
analysed_not_decided: >-
  **Who observes S2** ([A9](../REVIEW_AGENDA.md)). Three models are analysed in the study's historical RDP/MSP trust analysis
  (`docs/rdp-msp-trust-analysis/`, not a selected design): an accountable MSP observer, a handover proof
  authenticated independently of the MSP, and the handover inside the RDP's boundary. The analysis recommends
  the second *if* resistance to an MSP acting alone is to be claimed. **No model is selected**, and nothing in
  the specification claims that resistance.
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0004 — The MSP separated from the RDP, with the relay left RDP-to-RDP

## Context

Two providers serve each entity: a messaging service provider (MSP) that
operates MLS delivery, and a registered delivery provider (RDP) that issues
the evidence. The umbrella's §7.2 already permitted an entity to contract the
two to different operators, but the wire could not express it: the MSP had no
identity of its own, so it could not be admitted, pinned, or named in the
evidence that rests on what it observed.

## Requirement and constraint

Evidence must be authored by qualified parties, and the path evidence travels
between two qualified parties must not pass through an unqualified one
without an artefact that binds what it did. A qualified seal over a statement
the sealer did not witness, with no reference to what it did witness, would
launder a non-qualified statement into a qualified one.

## Decision

The MSP is each side's local delivery service and a federation participant in
its own right, with its own identifier, its own admission record and its own
signed descriptor; it is not a subcontractor of the RDP. The relay between
providers stays RDP-to-RDP. A DE issued on the strength of another
participant's observation carries `observed_by` and the digest of the
receipt it rests on, and the receipt is a retained artefact. Provider
composition (who operates transport, who operates evidence) is a deployment
axis orthogonal to the deployment ladder, not a new rung on it.

## Alternatives considered

- **A relay between the two MSPs, with the RDPs as observers.** Rejected: it
  would put a non-qualified participant on the evidence-bearing path between
  two qualified ones, with no artefact to bind what it did.
- **The MSP as the RDP's subcontractor, with no identity of its own.**
  Rejected: a participant with no identifier cannot be admitted, cannot be
  pinned and cannot be named in the evidence that rests on its observations.
- **Composition as a fifth rung of the deployment ladder.** Rejected: the
  ladder counts pairs of independent providers that have proven they
  interoperate; composition varies what a pair is made of, and a rung that
  measured both would let a deployment climb by reorganising its contracts
  rather than by proving anything new.

**The S2 observer — three models analysed, none selected ([A9](../REVIEW_AGENDA.md)).**
The separation leaves one question this record does not decide: who observes
the acknowledged handover, and what an MSP acting alone could make an RDP
attest. The study's historical trust analysis (not part of the public
snapshot) compares three models. They are alternatives, this record chooses
none, and the costs below are the analysis's qualitative expectations, not
measurements:

1. **The MSP as an accountable trusted observer.** The MSP stays the transport
   provider and the sole witness of the handover, but it is identified,
   admitted, named in the DE (`observed_by`) and subject to assurance and
   audit. What a malicious MSP could still cause: a fabricated or withheld
   handover — attributable, no longer anonymous, but possible. Event clock:
   the MSP's `server_time`. Cost: governance and audits, retention of the
   receipt and its history so a challenge works without the MSP online,
   retries and reconciliation. Remaining assumption: the MSP's honesty for
   the decisive fact; the gain is verifiable accountability, not new
   independent proof.
2. **An independent endpoint proof.** The MSP stays the transport provider;
   the recipient's wallet adds an application-level acknowledgement, signed
   with its own key over the bytes it received, the message and device
   identity, the RDP it is for and a freshness context, and sends it to the
   RDP over an end-to-end authenticated path — directly, not through the MSP.
   What a malicious MSP could still cause: withholding or delaying the bytes,
   but not inventing the decisive input. Event clock: the RDP's, which
   changes what "timely" means — an acknowledgement the RDP receives and
   verifies after the deadline counts as late even if the device received the
   bytes earlier, a semantic change to declare, not a detail; a different
   temporal-proof protocol would be a further project. Cost: a signature and
   its verification, a control channel and an outbox at the wallet with
   persistent retries, the RDP's deduplication index, an availability
   dependency on the RDP for the decisive fact, and a freshness challenge that
   survives lost responses and failover. Remaining assumption: an honest
   endpoint — the acknowledgement is a wallet statement, not proof of reading
   by a dishonest device.
3. **The handover inside the RDP's trust boundary.** The point that
   authenticates the recipient, transfers the ciphertext and observes the
   application-level acknowledgement comes under the RDP's control; the MSP
   **keeps storage and queues**, and the RDP verifies the digest before
   serving the bytes. Control must be effective — a co-located or renamed
   delivery service is not this option, and a completed TLS connection or a
   write is not the application-level confirmation; the handover point and
   the authenticated principal have to be defined. What a malicious MSP could
   still cause: nothing decisive for S2; the verifier now trusts the RDP's
   testimony, which the design assumes already. Event clock: the RDP's.
   Cost: on the data plane — RDP capacity, connections, backpressure,
   possible ciphertext copies, and the RDP in the path of every delivery so
   that its outage blocks them all; in return, reconciliation inside one
   operational boundary. Remaining assumption: the RDP's honesty; and the
   S3/S4 confirmations gain no independence if their channel stays delegated
   to the MSP.

The analysis recommends the second *if* resistance to an MSP acting alone is
to be claimed, and the third where the RDP already controls the data path and
an interoperable wallet proof is not practicable. Nothing in the specification
claims that resistance, and no model is selected.

## Trade-off

Separable transport and evidence markets, and evidence whose authorship stays
qualified, at the price of one more interface and of a trusted observer at
the handover.

## Consequences and residual limit

The MSP becomes a trusted observer of the acknowledged handover: separating
it from the RDP makes a false observation *attributable*, once the DE binds
the observer, but not impossible. Three observer models have been analysed
and none selected; nothing in the specification claims resistance to an MSP
acting alone. The MSP's identity on the wire, the DE's binding to the
observation, and the composition axis are decided and not implemented: no
schema carries an MSP identifier and the register admits RDPs only.

## Status

- **Decision:** accepted.
- **Implementation:** the RDP-to-RDP relay is in force; the MSP identity,
  `observed_by`, `receipt_digest` and the composition axis are planned and not
  implemented — no Schema carries `MspId` or `observed_by`, and the register
  admits only `rdp` ([A6](../REVIEW_AGENDA.md)); the S2 observer model is
  undecided.

## Supersedes

Nothing.

## Normative owner

The umbrella, §7.2 and [§13.1](../../Secure-Business-Messaging-Profile.md#131-institutional-roles); the relay
contract, `rdp-relay-openapi.yaml`; the TS, clause 4.1, for the four-corner
requirements.

## Open questions

- [A6](../REVIEW_AGENDA.md): the MSP as a federation participant on the wire.
- [A9](../REVIEW_AGENDA.md): who observes S2, and what an MSP acting alone can make an RDP
  attest.
