---
id: SBM-ADR-0006
title: "The wallet as an evidence participant"
label: "The wallet as evidence participant"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference; the legal weight of each combination open ([L4](../REVIEW_AGENDA.md))
choice: >-
  the recipient confirms, wallet-signed or session-bound; the sender signs its submission by default ·
  TS clause 6; [§7.5](../../Secure-Business-Messaging-Profile.md#75-the-wallet-as-evidence-participant-informative)
alternative: >-
  provider-attested acts only — kept as an explicitly narrowed fallback
benefit: >-
  both sides' acts attributable to a device key, independently of the providers, in the wallet-signed modes
cost: >-
  key custody, an assurance floor and compromise handling join the evidence story — wallet providers, entities
  ([MWAP](../wallet-assurance-profile.md))
open_questions: [L4]
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0006 — The wallet as an evidence participant

## Context

The recipient's confirmation that a message was verified or accepted is
produced by the wallet, in an authenticated session, and is what the RDP
relies on to issue delivery evidence. The sender's act, by contrast, was
attested only by the sender's provider, so the recipient's act was
independently provable and the sender's was not, in a system whose legal
argument covers sending by the identified sender as much as delivery.

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
narrowed accordingly. Two limits are part of the decision: a session-bound
confirmation attributes the act only through RDP(in)'s record and a
provider-attested submission only through RDP(out)'s, and the TS narrows the
claim for both; and a signature in any mode attributes a statement to a device
without showing that the endpoint behaved honestly — that assumption lives in
the wallet assurance profile, not in the signature.

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

Wallet providers and entities carry key custody and the assurance floor of
the wallet assurance profile; suspension and revocation of a member binding
fail the member closed at the directory and trigger MLS removal, and evidence
produced before a credential's suspension keeps its standing under the TS's
credential-validity baseline. The legal weight of each authentication
combination, and whether a mandatory sender signature sits well beside the
provider-attestation model of the regulation, are questions for counsel and
stay flagged.

## Status

- **Decision:** accepted; the normative clause's legal standing awaits
  counsel, and the TS says so where it applies.
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
