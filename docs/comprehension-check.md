<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Comprehension check — eight questions, and where the route must answer them

**What this is.** Eight questions from the r42 clarity review, each beside the
place on the short reading route that has to answer it. The review's own test:
*ask an expert who has not followed the drafting rounds to answer these from the
short route — if the answers require recovering qualifications from a distant
specialist section, the first-reading layer still needs work.*

**What this is not.** It is not a test, and it is **not wired into the
conformance bar**: nothing here is machine-checkable, and a gate that scored
prose would be scoring the wrong thing. **The answers are deliberately not
written down.** A checklist that carries its own answers checks the checklist.
Read the named place and see whether it answers; if it does not, that is the
finding.

**Why it is in the repository at all.** The questions are the most reusable part
of the review, and in a review document they are used once. Here, a later
edition can be checked against the same eight instead of against a new
reviewer's taste.

---

| # | The question | Where the route must answer it |
|---|---|---|
| 1 | Can the sender submit while the recipient is offline? | [`message-lifecycle.md`](message-lifecycle.md) §1, the ordinary case and the minimal run; and the *Assumptions of this illustrated path* before the sequence in [`federated-flow-explainer.md`](federated-flow-explainer.md) |
| 2 | Are the Delivery Service and the RDP two independent provider roles, or functions within a provider? | [`architecture-identity-trust.md`](architecture-identity-trust.md) §1, and [SBM-ADR-0015](adr/SBM-ADR-0015.md) through [`decisions-index.md`](decisions-index.md) |
| 3 | Which devices receive a message sent to a role-confined scope? | [SBM-ADR-0003](adr/SBM-ADR-0003.md)'s decision, and cases 2 and 3 of [`scope-resolution-examples.md`](scope-resolution-examples.md) |
| 4 | Which digest can a provider recompute, and which content check remains an endpoint assertion? | [`evidence-layer-explainer.md`](evidence-layer-explainer.md) §5, the mapping of commitment → octets → who can recompute it |
| 5 | What is learned from a sealed commitment before and after a reveal? | [`evidence-layer-explainer.md`](evidence-layer-explainer.md) §7.1, and case 5 of [`scope-resolution-examples.md`](scope-resolution-examples.md) |
| 6 | Whose human acceptance policy governs an agent-sent message? | [`agent-profile-explainer.md`](agent-profile-explainer.md) §3.3 and the worked example in §5 |
| 7 | What does a clean demonstration verdict still not establish for production? | [`production-verifier-architecture.md`](production-verifier-architecture.md) — the demonstration verdict, then the second stage |
| 8 | Which parts of the four-corner story are illustrated assumptions rather than resolved contracts? | [`federated-flow-explainer.md`](federated-flow-explainer.md), *Assumptions of this illustrated path*, and [A1](REVIEW_AGENDA.md) on the review agenda |

---

**If a question cannot be answered from the place beside it**, the finding is
about that place, not about the reader. The review's phrasing is kept verbatim;
the right-hand column is this repository's claim about where each answer now
lives, and it is the half that can be wrong.

*The review itself is recorded unchanged in the source repository, at
`docs/reviews/R42_REVIEW_2026-10-09.md`. It is **not** linked here and not
carried into the published export, which leaves the review bodies behind by
design — the questions travel, the review that asked them stays where the work
is done.*
