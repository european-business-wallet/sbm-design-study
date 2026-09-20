---
id: SBM-ADR-0004
title: "The MSP separated from the RDP, with the relay left RDP-to-RDP"
label: "MSP and RDP separated"
decision_status: accepted
implementation_status: [specified, in-reference, planned]
implementation: >-
  relay: in force. MSP identity, `observed_by`, `receipt_digest`, composition axis: planned (Batch B), not implemented
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
snapshot) compares three models. They are alternatives, and this record
chooses none:

1. **The MSP as an accountable trusted observer.** Trusted party: the MSP,
   admitted and named in the DE (`observed_by`). A malicious MSP could still
   fabricate or withhold a handover; the binding makes that attributable,
   not impossible. The event clock is the MSP's `server_time`. Cost: the
   lowest — one retained receipt. Remaining assumption: no collusion between
   the MSP and the party the fabrication favours, and no censorship the
   sender cannot detect.
2. **A handover proof authenticated independently of the MSP.** Trusted
   party: the recipient device, whose key signs the acknowledgement the DE
   rests on. A malicious MSP could still withhold or delay, but not
   fabricate. The event clock becomes contestable: the device's instant is
   client-declared, and the profile has rejected client clocks for S2 once
   already. Cost: availability and retry semantics at the device, and a
   second retained artefact. Remaining assumption: an honest device
   implementation, and a resolution for the offline recipient.
3. **The handover inside the RDP's trust boundary.** Trusted party: the
   qualified RDP, which then operates or co-locates the delivery service. A
   malicious MSP disappears from the evidence path, at the price of the
   separation this record introduces: transport and evidence stop being
   separable markets. The event clock is the RDP's. Cost: the highest, in
   deployment freedom. Remaining assumption: the RDP's honesty, which the
   design already assumes for the seal.

The analysis recommends the second *if* resistance to an MSP acting alone is
to be claimed. Nothing in the specification claims that resistance, and no
model is selected.

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
  `observed_by`, `receipt_digest` and the composition axis are planned
  (Batch B) and not implemented; the S2 observer model is undecided.

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
