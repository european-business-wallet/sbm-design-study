<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Reviewer guide

**For:** an expert new to this specification who has a few hours, not a few weeks. **It answers:** what should I read, what exists today, and which questions need my expertise?

## What you are reviewing

A design study of registered delivery between legal entities: end-to-end encrypted messaging (a profile of MLS) with qualified evidence of sending and delivery, issued by providers that cannot read the message content; the evidence itself is readable and verifiable by anyone who holds it. The edition you are asked to review is the git tag named in the README's [*Feedback*](../README.md#feedback) section; versions are in the README's [version table](../README.md#current-versions) and the repository's counts in [`project-counts.json`](project-counts.json) — generated, so they are not repeated here. Two of those numbers are countings of different things, and reading them as one is a mistake two readers have now made: `rounds` counts the completed **adversarial design reviews** of the whole specification, while an ordinal in the CHANGELOG — “the n-th review” — names a **drafting revision** of a document. Neither series is derived from the other, and the second is history: it appears in the CHANGELOG and in the review records, not in the specification a reader meets.

| State | What it covers |
|---|---|
| **Specified** | the umbrella profile, the Internet-Draft, the TS-shaped binding, the companion contracts and the schemas — the [document map](../Secure-Business-Messaging-Profile.md#document-map) says which governs what |
| **Demonstrated** | the reference tooling and samples here are consistent and the shipped artefacts valid against demo keys — claims 1 and 2 of the README's [claim matrix](../README.md#what-a-green-bar-means--and-what-it-does-not); a proof of concept by the same author ran deployment profile 1, against an earlier edition and not re-pinned since. **No independent implementation has exercised the published contracts** — that is claim 4, and it is not established |
| **Planned** | the Messaging Service Provider as a federation participant on the wire (Batch B) — decided, not implemented |
| **Open** | everything on the [review agenda](REVIEW_AGENDA.md): architecture questions A1–A10, the implementer guide G1–G4, production trust P1, legal questions L1–L8 |

**The minimum viable profile** is deployment profile 1 (Annex P): one operator running the delivery and evidence roles, the default scope, two wallets, the four delivery states S1–S4. Everything else is layered on it and can wait.

## The short path — one route for everyone

1. [**Architecture, identity and trust**](architecture-identity-trust.md) — who does what, who talks to whom, and why any key or claim is trusted.
2. [**Message lifecycle**](message-lifecycle.md) — how the public operations compose, the three different acknowledgements, the five clocks, and where a trace stops at an open question.
3. [**The evidence layer, in brief**](evidence-layer-explainer.md#in-brief--what-each-grade-and-proof-establishes) — what each grade and each proof establishes, and what it does not.
4. [**Decisions index**](decisions-index.md) — today's choices, the alternative weighed, what each costs, what is undecided.
5. [**Review agenda**](REVIEW_AGENDA.md) — the questions, each with the assumption it rests on and whose expertise would settle it.

Terms are in the umbrella's [glossary (§2)](../Secure-Business-Messaging-Profile.md#2-terminology); its [six trade-offs (§0.1)](../Secure-Business-Messaging-Profile.md#01-design-trade-offs-informative) are the one-page version of the index.

## Then one branch

| If you work on… | Read next |
|---|---|
| **Protocol and MLS** | the index's rows on groups, encoding and suites → the [four-corner walkthrough](federated-flow-explainer.md) → the Internet-Draft and the companion contracts |
| **Security and privacy** | trust and visibility (architecture note §3–§6) → the claim limits (evidence explainer, in brief) → agenda A3, A5, A9, A10, and, for the three S2 observer models, the agenda's A9 entry (the historical RDP/MSP trust analysis, `docs/rdp-msp-trust-analysis/`, is not a selected design) |
| **PKI, QERDS and law** | the evidence explainer → the [production verifier](production-verifier-architecture.md), with what must accompany a package years later → the TS → agenda P1 and L1–L8. A successful demonstration answers none of the legal questions |
| **Wallet and provider operations** | the lifecycle primer → [lifecycle and custody](lifecycle-and-custody.md) → the [minimum wallet assurance profile](wallet-assurance-profile.md) → the companion contracts |
| **Organisations and agents** | the [scope examples](scope-resolution-examples.md) → the [agent profile](agent-profile-explainer.md) → the [wallet–agent interface outline](wallet-agent-interface.md) |

Nobody needs to read everything before contributing. A finding that names the document and section it is about can be acted on; the README's [*Feedback*](../README.md#feedback) section says where to send it.
