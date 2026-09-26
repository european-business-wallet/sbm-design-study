# Scope Resolution — Worked Examples
## Seven end-to-end cases

**Status:** informative companion, draft for discussion · **Applies to:** Secure Business Messaging Profile (SBM), §8.3/§8.3a, Annex R, at the versions in the README's version table (not restated here, so they cannot drift) · **Audience:** implementers

> **Exploratory design study — not an official proposal.** These examples illustrate how a sender resolves a message to a (pair, scope) group and how a verifier reads the result. They are informative; the normative rules are §8.3/§8.3a, the I-D *Sender Resolution* / *Roster Transparency*, the TS, and Annex R. In any conflict the normative documents prevail.

---

Each case follows the same arc: the sender resolves the **recipient's** scope map to a scope, computes the eligible device set, forms or reuses the group, and sends; a verifier later reads the roster and evidence. The recipient entity here is **EU-FR-…** with roles `invoices`, `procurement`, `legal`, `finance`, `records`.

## 1. Default scope

- **Setup:** the recipient publishes no `scope_map` (or the content class matches no scope and `fallback: default` is declared).
- **Resolution:** the message routes to the reserved `default` scope (`scope_ref = {default, "1"}`); the group is the whole entity pair; every active member's devices are eligible.
- **Evidence:** SE/DE carry `scope_ref = default/1`. No role gating, no records leaf.
- **Reads as:** the pre-scope baseline — nothing to verify beyond the standard roster.

## 2. Role scope, `strict`

- **Setup:** scope `legal` — `roles: [legal]`, `recoverability: strict`, `content_classes: [legal-notice]`.
- **Resolution:** a `legal-notice` message routes to `legal`; eligible devices = the devices of active members holding `legal`; **no** records or other non-role leaf may be present.
- **Roster check (recipient-side):** every leaf of the recipient entity resolves (via the member-enumeration surface) to a member holding `legal`; the sender's own leaves follow the I-D's sender-side scope rules and do not count towards the recipient's audience. Any extra recipient leaf ⇒ the sender **MUST NOT** send.
- **Reads as:** confidentiality confined to the legal role — verified, not merely declared.

## 3. Role scope, `records` (with `records_role`)

- **Setup:** scope `finance` — `roles: [finance, procurement]`, `recoverability: records`, `records_role: records`, `content_classes: [invoice, x-payment-order]`.
- **Resolution:** an `invoice` message routes to `finance`; eligible = devices of `finance`/`procurement` holders **plus** the devices of the `records`-role holders (the records leaf).
- **Roster check (recipient-side):** the recipient's roster is exactly {`finance`/`procurement` holders' devices} ∪ {`records` holders' devices}; the sending wallet **surfaces the records leaf** as part of the effective audience (A10).
- **Acceptance:** the `records` holder **recovers but does not accept** — SCOPE-8 counts scope-role holders only, so a records leaf's acknowledgement satisfies no acceptance policy.

## 4. `human_acceptance` scope

- **Setup:** scope `finance` additionally declares `human_acceptance: true`; its acceptance policy is `quorum:2` over `finance`.
- **Resolution:** as case 3, but **system members are excluded** from the acceptance eligible set.
- **Acceptance:** a human `finance` quorum accepts (S4). An agent (`member_type=system`) in the group may decrypt and re-verify (S3) but its acknowledgement **never** satisfies the class (`bundle_lint` LINT-BND-18). A `human_acceptance` scope whose eligible set is all agents is rejected (LINT-BND-16).
- **Reads as:** automation up to verification; a human where money moves.

## 5. Availability-grade content class

- **Setup:** the recipient declares `delivery_grades: { "legal-notice": "availability" }`.
- **Resolution:** a `legal-notice` message is delivery-graded `availability`; the DE is issued at authenticated **S2** (`D.1-ContentConsignment`), `integrity_basis: sender-declared-digest`, and carries a **grade commitment** (salt in the envelope).
- **Verification:** on dispute, either party reveals `(salt, content_class)`; a verifier recomputes the commitment, checks that it equals the sealed `grade_commitment`, and checks that the class maps to `availability` in the referenced BW-ORG. Before a dispute the **commitment** discloses no class; the reveal discloses this one message's class to the parties of that dispute. The evidence as a whole is a weaker statement: the echoed `scope_ref` resolves, against the recipient's published scope map, to the set of classes that scope covers — a set of one where the scope covers one class. A reveal that fails to match proves nothing on its own — the recipient's signed assertion starts a dispute (TS clause 6).
- **What is checked, and what is attributed:** the reveal independently checks the *declared grade* — that the sealed commitment opens to a class the recipient declared availability-grade. It does not check the *handover*: the S2 instant that dates the DE is the Delivery Service's signed observation, which the RDP seals without re-witnessing (review agenda A9).
- **Reads as:** the DE is dated at the acknowledged handover to an authenticated endpoint; that the class qualified for this grade is verifiable without trusting the issuer, while the handover itself rests on the Delivery Service's observation.

## 6. Agent within mandate

- **Setup:** a procurement **agent** (`member_type=system`, standing `mandate_ref.scope: [invoice]`, valid this year) sends an `invoice`.
- **Resolution:** the agent **instructs its wallet** (wallet-agent interface); the wallet checks the instruction is in mandate scope, forms/reuses the `finance` group, and sends. The SE records `auth_context.identity=system`, the acting `mid`, `mandate_ref`, and — being opposable — a `mandate_commitment`.
- **Verification:** `evidence_lint` confirms the opposable agent SE carries a well-formed commitment (LINT-DE-15); a verifier with the discovery documents confirms the SE mandate matches the standing mandate and was valid at `sent_at` (LINT-BND-15); a reveal shows `invoice ∈ scope`.
- **Reads as:** a provable, in-mandate agent act.

## 7. Agent outside mandate (refused)

- **Setup:** the same agent is instructed to send a `legal-notice` (not in its `mandate_ref.scope`).
- **Resolution:** the **wallet refuses** the instruction at the wallet-agent interface (mandate-scope enforcement, Annex R.4) — the message is never sent. Nothing crosses the channel.
- **If a non-conformant wallet sent it anyway:** on reveal the commitment recomputes but `legal-notice ∉ scope`, so the reveal establishes **overreach** (LINT-BND-15); and the act is not opposable beyond what the participation agreement allows (A3).
- **Reads as:** the mandate is a gate, and overreach is provable, not deniable.

---

*Normative sources: §8.3/§8.3a, the I-D `draft-sbm-mls-erd` (*Sender Resolution*, *Roster Transparency*, *Mandate Commitment*), the TS `TS-SBM-QERDS-Binding`, and Annex R. Informative — the normative documents prevail.*
