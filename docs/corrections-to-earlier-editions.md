<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Corrections, for readers of earlier editions

**What this is.** Claims that earlier editions of the explanatory companions
made, and that were wrong in a way a reader could have acted on. They are
collected here, out of the documents whose job is to explain the design as it
stands, and kept rather than erased: someone who read an earlier edition may
still be working from them.

**What is not here.** Bookkeeping. A corrections list that keeps everything
stops being read, so what survives is the entries where an earlier edition
would have led a reader to a wrong conclusion. Where something was trimmed, it
is stated.

---

## `evidence-layer-explainer.md`

Two claims were wrong in a way a reader could have acted on:

- §7 said availability was the moment content was "made available to (or
  retrieved by)" a recipient endpoint. That is broader than the event the
  protocol records, and a reader who took it literally would expect the grade to
  attach to an act this profile does not attest.
- §7.1 said a recipient "proves misuse" by a failing reveal. It does not: a
  failing reveal is an attributable assertion that *starts* a dispute, and
  reading it as proof would put weight on it that the cryptography does not
  carry.

*(Two further corrections — a superseded sentence about the sender's signature,
and a `version` literal since bound to `versions.json` — are dropped from this
list: both were bookkeeping, neither changed what a reader could conclude, and a
corrections list that keeps everything stops being read.)*

## `federated-flow-explainer.md`

- Phase 3 denied a content signature by the sender; the sender's signature has
  been the default since evidence 2.3.
- Phase 4 and the diagram drew the ciphertext relayed between two transport
  providers, a relay no contract publishes and the federation model rejects.

## `agent-profile-explainer.md`

- §3.2 called the mandate commitment "optional"; it is required for an opposable
  act and forbidden for `opposable: false` (Annex R.2). §5's worked example
  concluded that "non-repudiation binds the buyer"; it now keeps Annex R.5's
  three layers.

---

*Where the rest of the process history lives: `CHANGELOG.md` in the source
repository records every change by the cycle that made it. This document holds
only the corrections a reader of an earlier edition needs.*
