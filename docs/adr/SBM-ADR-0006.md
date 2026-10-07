---
id: SBM-ADR-0006
title: "The wallet as an evidence participant"
label: "The wallet as evidence participant"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  Specified, and in the reference. What legal weight each combination carries is open ([L4](../REVIEW_AGENDA.md))
choice: >-
  The recipient's own act is part of the evidence: a confirmation signed by the recipient's wallet, or bound to the authenticated session. By default the sender signs its submission too · TS clause 6; [§7.5](../../Secure-Business-Messaging-Profile.md#75-the-wallet-as-evidence-participant-informative)
alternative: >-
  Evidence attested only by the providers, with no act of the parties in it — kept, but as an explicitly narrowed fallback rather than the default
benefit: >-
  In the wallet-signed modes, each side's act is attributable to a key held on that side's device, so it does not rest on the providers' word
cost: >-
  Key custody, a minimum assurance level and a story for handling a compromised device all become part of the evidence model — for wallet providers and for entities ([MWAP](../wallet-assurance-profile.md))
open_questions: [L4]
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0006 — The wallet as an evidence participant

## Context

The recipient's confirmation that a message was verified or accepted is
produced by the wallet, in an authenticated session, and is what the Registered
Delivery Provider (RDP)
relies on to issue delivery evidence. The sender's act, by contrast, was
attested only by the sender's provider, so the recipient's act was
attributable to its device in the wallet-signed mode while the sender's was
attributable only through its provider, in a system whose legal argument
covers sending by the identified sender as much as delivery.

## Requirement and constraint

Both legally operative acts must be attributable to the party that made
them, independently of the providers that attest them, without removing the
provider attestation the regulation asks for. The wallet already holds a
signing key, so the addition must cost one object, not a new key ceremony.

## Decision

The wallet is a trust component of the registered-delivery process. The
recipient confirms by a wallet-signed confirmation or a member-bound
authenticated session, and evidence records which. The sender signs its
submission by default: a wallet-signed sender confirmation over the full
submission tuple, required for opposable acts, keyed and verified like the
recipient's. Provider-attested acts remain an explicitly narrowed fallback
for constrained senders, and where it is used the attribution claim is
narrowed accordingly. Two limits are part of the decision, and both are stated rather than left
implicit.

First, the weaker modes attribute an act only through a provider's own record: a
session-bound confirmation through the recipient-side provider's, and a
provider-attested submission through the sender-side provider's. The technical
specification narrows the claim accordingly for both.

Second, a signature in *any* mode attributes a statement to a device. It does
not show that the device behaved honestly. That assumption lives in the wallet
assurance profile, not in the signature.

## Alternatives considered

- **Provider-attested acts only, as the default.** Rejected as the default
  and kept as the narrowed fallback: it left an asymmetry between the two
  sides' acts, and the sender signature is additive, adding an independent
  second proof beside the provider attestation rather than replacing it.

## Trade-off

Both acts attributable to a device key in the wallet-signed modes, at the
price of key custody, an assurance floor and compromise handling becoming part
of the evidence story, and with the endpoint's honesty still assumed.

## Consequences and residual limit

Wallet providers and entities carry key custody, and the minimum assurance level
the wallet assurance profile sets.

Suspending or revoking a member binding fails that member closed at the
directory and triggers removal from the MLS group. A confirmation made *before*
a credential was suspended keeps its standing, under the credential-validity
baseline the technical specification sets, whenever the evidence was sealed.

Two questions are for counsel and stay flagged: what legal weight each
authentication combination carries, and whether a mandatory sender signature
sits well beside the provider-attestation model the regulation uses.

## Status

- **Decision:** accepted; the normative clause's legal standing awaits
  counsel, and the technical specification says so where it applies.
- **Implementation:** specified; in the reference.

## Supersedes

Nothing.

## Normative owner

The TS, clause 6; the umbrella
[§7.5](../../Secure-Business-Messaging-Profile.md#75-the-wallet-as-evidence-participant-informative) for what is
asked of the wallet; the Internet-Draft for the confirmation objects; the
[wallet assurance profile](../wallet-assurance-profile.md) for the floor.

## Open questions

- [L4](../REVIEW_AGENDA.md): the legal weight of each authentication combination.
