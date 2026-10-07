---
id: SBM-ADR-0016
title: "The receipt names the provider that observed the handover"
label: "The observer is named on the receipt"
decision_status: proposed
implementation_status: [specified, in-reference]
implementation: >-
  Specified, and in the reference implementation. The delivery receipt carries `observed_by`; it is required, and it is inside the part of the receipt the signature covers. One piece of code resolves the verifying key from that field, and both paths use it — the live one that issues receipts and the retained one that verifies them years later. Companion contracts at 16.0.0
choice: >-
  A delivery receipt names TWO providers, because in general two are involved. `issuing_rdp_id` is where the message came FROM, proven by that message's Sending Evidence. `observed_by` is the provider whose Delivery Service actually took delivery of it, watched the recipient collect it, and signed the receipt. The key that verifies the receipt belongs to the SECOND of those · delivery-service-openapi.yaml, `DeliveryReceipt`
alternative: >-
  Three were considered, all rejected. (1) Go on resolving the key from `issuing_rdp_id` — what the reference did; correct only when the sender's provider and the recipient's provider are the same one. (2) Let the party assembling the evidence state the association in the bundle, with no change to the receipt — rejected, because then the claimant asserts whose observation this was, which is the signer's statement to make. (3) Try every descriptor supplied until one of them resolves the key — rejected, because that is "any document carrying the key will do", and it makes the verdict depend on what the claimant chose to hand over
benefit: >-
  A receipt can be tied to the party that signed it, so a verifier knows which single published document should hold the verifying key and can check that document against that provider's admission to the federation. The legitimate signer — the recipient's provider — is no longer refused
cost: >-
  A published contract changes shape, and a field SBM-ADR-0015 had just withdrawn comes back, for a different reason than the one it was withdrawn with
open_questions: []
author_questions: []
supersedes: []
analysed_not_decided: >-
  **How a receipt reaches the party that issues the Delivery Evidence** ([A1](../REVIEW_AGENDA.md)) is untouched by this record. Naming the observer makes a retained receipt verifiable; it does not add an operation that carries one from the provider that holds it to the party that needs it.
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# SBM-ADR-0016 — The receipt names the provider that observed the handover

## Context

A few words first, because this record turns on four of them.

A **Registered Delivery Provider** is the qualified provider that issues a
message's evidence. Its **Delivery Service** is the part of it that actually
moves messages: it queues them for the recipient's device, hands them over, and
collects the acknowledgement. **Sending Evidence** is the sealed object the
sender's provider issues when it accepts a message, and it is what proves which
provider a message came from. A **delivery receipt** is what the Delivery Service
signs when the handover happens: the signed record that this recipient, on this
device, in this session, collected these bytes at this instant.

SBM-ADR-0015 folded the Delivery Service into the Registered Delivery Provider:
one provider role, with the Delivery Service a function of it rather than a
separate participant. The batch of work that carried that decision into the
discovery layer moved the receipt's verifying key out of the *customer's*
discovery document and into the *provider's* own, on the straightforward ground
that a provider's key belongs in the provider's document.

That move left a question it had not asked: **whose** provider document.

The reference answered: the document of whoever `issuing_rdp_id` names. That was
the only provider identifier a receipt carried. But the Delivery-Service contract
defines that field as the message's **origin** — the provider the message came
from, proven by that message's Sending Evidence — and it is the namespace the
message's identifier lives in. The same contract carries a *separate*
`forwarding_rdp_id` for a provider that merely passed the message along.

The handover a receipt attests happens at the other end. It is the **recipient's**
Delivery Service that issues the collection token, authenticates the device
session, records the acknowledgement and signs. So whenever the two correspondents
are customers of different providers — the four-corner case the deployment
profiles exist for — the receipt's verifying key is published by a participant
the receipt never names.

Two defects followed, in the same cycle:

- The **live** check required the provider descriptor's `participant_id` to equal
  `issuing_rdp_id`, which refuses the recipient-side signer — the only party that
  could legitimately have signed.
- The **retained** check selected the descriptor by the same field, so it looked
  for the key in the origin's document, did not find it, and reported a violation
  against a receipt that verifies perfectly well.

Neither was visible, and the reason is worth recording. The sample built to
exercise that path had been generated with the *Delivery Evidence issuer*
substituted for the origin: the receipt claimed to come from `mockeu-002` for a
message whose Sending Evidence says `mockeu-001`. Both identifiers therefore
held the same value in the only fixture that tested them, and nothing could
disagree with anything.

**One provider role does not mean one provider per message.** That is the sentence
this record exists to add.

## Requirement and constraint

A verifier holding a retained receipt years after the fact must be able to answer
two questions: *which published document contains the key that signed this*, and
*was the participant that published it admitted to the federation when the
handover happened*.

The answer has to come **from the receipt**, because the receipt is what was
retained. And it has to be **signed**, because an unsigned association is the
claimant's assertion about whose observation this was — and the claimant is the
party with an interest in the answer.

The constraint is that `issuing_rdp_id` cannot be quietly repurposed to mean the
observer. It is the message's namespace, it is proven by the Sending Evidence,
and it appears in the request path itself
(`POST /messages/{issuing_rdp_id}/{message_id}/receipt-ack`). Changing what it
means would silently re-label every receipt already issued.

## Decision

A delivery receipt carries **`observed_by`**: the `participant_id` of the provider
whose Delivery Service observed the handover and signed. It is required, and it
sits inside the signed part of the object, not beside it.

The key that verifies a receipt is found in the `ds_receipt_keys` of that
provider's own published descriptor. Three things make that answer trustworthy
rather than merely stated:

- the membership register pins the descriptor's seal to that participant, so the
  document cannot be someone else's;
- the key's validity is judged at the receipt's **own** instant, not at
  verification time, so a receipt signed in 2026 still verifies in 2033 after the
  key has been rotated out;
- one implementation performs this check, and both the live path and the retained
  path call it — so the two cannot drift apart, which is how the pair of defects
  above came to disagree with each other in the first place.

That implementation refuses three things: a document of any other kind, a
document belonging to a different participant, and a receipt that names no
observer at all.

The Delivery Service does not learn its own identity from the request it is
answering. `observed_by` is filled in by the server, like the server's timestamp
and the digest of the delivered bytes, and the conformance gate that compares the
wire request with the signed object records it as such — so a client cannot
assert who observed its own handover.

## Alternatives considered

**Go on resolving the key from `issuing_rdp_id`.** What the reference did. It is
correct in exactly one case — where the origin and the observer are the same
party, which is deployment profile 1, one provider serving both correspondents —
and wrong in the four-corner case the profile exists for. It cannot be rescued by
convention either: the sending provider genuinely does not hold the recipient
provider's Delivery Service key, so there is nothing for a convention to point at.

**Let the bundle state the association.** The party assembling the evidence
declares which descriptor signed which receipt. No change to the wire, and the
descriptor is still authenticated against the register. Rejected: the association
would then be the claimant's, and a claimant assembling a package has an interest
in which provider's observation the handover is attributed to. What a verifier
needs is what the *signer* said.

**Try every descriptor supplied.** Resolve the key identifier against each
candidate until one verifies. Rejected on two counts: it restores "any document
carrying the key will do", which is the property this round of work was opened to
remove; and it makes the verdict depend on which documents the claimant chose to
include.

## Trade-off

A published contract changes, and the companion contracts move to 16.0.0.

The field is also one that SBM-ADR-0015 had explicitly withdrawn three weeks
earlier. It was SBM-ADR-0004's `observed_by`, planned so that a false observation
by a *separate transport provider* would be attributable to that provider. It
comes back for a different reason: not to attribute a false observation to a party
outside the qualified provider, but to say which of **two qualified providers**
observed, so that the right key can be found.

The name is kept deliberately. The question it answers is the same question —
*who observed this?* — now asked within one provider role instead of across two.

## Consequences and residual limit

A receipt is now self-describing. It states the origin, the observer, the act, the
instant, the digest of what was delivered and the identifier of the key that
signed, with the observer's own descriptor as the single place that key may be
published. A verifier holding the receipt and the membership register can resolve
and authenticate it without being told where to look.

**What this does not do**, stated plainly, because each of these has been mistaken
for a consequence of it:

- It does not add an operation that carries the receipt from the Delivery Service
  to the party that issues the Delivery Evidence. [A1](../REVIEW_AGENDA.md) stays
  open, and naming the observer neither closes it nor makes it smaller.
- It claims no resistance to a dishonest provider. `observed_by` says which
  provider asserted the observation; that provider is the qualified, supervised,
  liable one whose word the evidence grade already rests on.
- It does not make a receipt discoverable. Keeping the observer's descriptor as it
  stood at the moment of the act is the same custody question
  [`docs/retrievability.md`](../retrievability.md) records for every other
  verification input, and a provider leaving the market takes that surface away.

## Status

- **Decision:** proposed, for the maintainer. It **amends** SBM-ADR-0015 rather
  than superseding it: one provider role still stands, and this adds that one
  role is not one party per message.
- **Implementation:** specified and in the reference. The field is signed and
  required, both verification paths resolve by it, and
  `samples/receipt.availability.demo.json` is a four-corner receipt whose origin
  and observer genuinely differ — which is what the fixture that hid the original
  defect did not do.

## Supersedes

Nothing. SBM-ADR-0015 remains the record of the one-provider decision. This record
adds the identifier that decision's discovery move needed and did not have.

## Normative owner

The Delivery-Service contract (`delivery-service-openapi.yaml`,
`DeliveryReceipt`) owns the field and the fact that it is required. The
Internet-Draft owns where the key is published and how its validity is judged.
The umbrella's institutional-roles table is unaffected: `observed_by` names a
provider in the one existing role, not a second role.
