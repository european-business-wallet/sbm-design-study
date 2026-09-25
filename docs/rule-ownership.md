<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

<!-- GENERATED FILE — do not edit by hand. Source of truth: docs/rule-ownership.json. Regenerate with `make rule-ownership` (scripts/rule_ownership.py --render). -->

# Rule-ownership inventory (X-34)

Each normative rule family below has exactly **one owning document**. Other documents carry only *informative* summaries that reference the owner — never a second normative statement. `scripts/rule_ownership.py` (`make rule-ownership`) and `tests/test_rule_ownership.py` enforce this: the owner states the rule, no non-owner document carries a bare normative (MUST/SHALL) restatement, and the Internet-Draft's deployment-defined-interface count matches the interfaces it lists.

This complements the verbatim-duplication guard (`tests/test_no_normative_duplication.py`), which catches identical sentences copied across the three specification documents; this inventory catches the same rule *reworded* and restated normatively in more than one place.

**Out of scope (deferred to X-25, Batch 4):** the registry and well-known-resource ownership split. This inventory covers rule ownership and the interface-count correction only.

Document keys: `umbrella` = `Secure-Business-Messaging-Profile.md`, `id` = `ietf/draft-sbm-mls-erd-00.md`, `ts` = `etsi/TS-SBM-QERDS-Binding-v0.1.md`.

## Rule families

### Intermediaries (MSP / Delivery Service / RDP) never access plaintext

- **Family id:** `intermediary-plaintext-prohibition`
- **Normative owner:** `id` — Object model, Delivery-Service mapping, and Security Considerations
- **Informative summaries (must reference the owner):**
    - `umbrella` — §7.3 actor list and the §9 privacy summary describe the property and defer to the I-D
    - `ts` — ICS row 051 (Evidence carries no plaintext) tagged [I-D]
- **Note:** An E2EE property, not a sample-checkable LINT rule; owned by the wire/security document.

### KeyPackages are single-use; the MSP removes a consumed KeyPackage and rejects reuse

- **Family id:** `keypackage-single-use`
- **Normative owner:** `id` — KeyPackage rules ({{keypackage-rules}})
- **Informative summaries (must reference the owner):**
    - `ts` — ICS rows 024 and 149 tagged [I-D] (single-use / pool integrity)
    - `id` — the Deployment-Defined-Interfaces Delivery-Service bullet adds the DISTINCT pool-integrity rule (idempotent reserve->commit, per-peer quota) and explicitly complements {{keypackage-rules}}; the Security-Considerations key-substitution mention is an in-document analytical echo
- **Note:** The reserve->commit pool-integrity rule is a distinct, complementary I-D-owned requirement, not a restatement of single-use.

### The availability delivery grade is declared per content class in the signed BW-ORG and is never implicit or default

- **Family id:** `availability-grade-declaration`
- **Normative owner:** `umbrella` — §8.3b (delivery grades)
- **Machine-checked by:** `LINT-DISC-17`, `LINT-DISC-18`, `LINT-BND-11`
- **Informative summaries (must reference the owner):**
    - `id` — the delivery-state model owns the DISTINCT anchoring rule: availability anchors at authenticated S2 -> event D.1-ContentConsignment
    - `ts` — clause 6 owns the DISTINCT legal-effect rule (Article 44(1)(c) gating); ICS row 113 (GRD-1) indexes the declaration rule to [UMB]
- **Note:** Not one rule in three documents but three ASPECTS with three owners: declaration (umbrella §8.3b), state anchoring (I-D), legal effect (TS clause 6). The inventory records the decomposition that resolves the apparent duplication.

### Federation registries (reason codes, content classes) are owned by the design authority under umbrella §13.4, as machine-readable artefacts

- **Family id:** `registry-ownership`
- **Normative owner:** `umbrella` — §13.4 (registry operation) + the registries/ artefacts
- **Machine-checked by:** `LINT-NDE-07`, `LINT-NDE-W1`, `LINT-DISC-16`
- **Informative summaries (must reference the owner):**
    - `id` — the I-D defines the FIELDS, the lexical value spaces and the unknown-code ingest rule only (IANA Considerations, X-25 registry layering); registry contents/governance are not restated
    - `ts` — clause 8.1/8.3 owns the ERD event mappings the registered reasons bind to
- **Note:** X-25 / X-34 residual: the transport I-D previously claimed to BE the registry ('initially this document') and registered well-known resources defined elsewhere; the split gives each registry one owner and moves the well-known registration to umbrella §8.1.

### RDP(in) is the sole evidence-authoritative acceptance-policy evaluator

- **Family id:** `acceptance-policy-evaluator`
- **Normative owner:** `ts` — Acceptance-policy evaluation — the evaluator of record
- **Informative summaries (must reference the owner):**
    - `umbrella` — §7.2 responsibility table and the §8.3 bullet describe the split and defer to the TS
    - `id` — the delivery-state model consumes the evaluated outcome; it does not evaluate
- **Note:** X-10: the former two-owner text (umbrella: the MSP evaluates; TS: RDP(in) evaluates) is collapsed to one owner. A prose-ownership family, not a sample-checkable LINT rule.

### Legal-effect issuance is gated on the signed short-lived status assertion (D6)

- **Family id:** `status-capability`
- **Normative owner:** `umbrella` — Legal-effect gating (fail-closed, capability-bounded — D6
- **Machine-checked by:** `LINT-DISC-25`
- **Informative summaries (must reference the owner):**
    - `ts` — ICS row 172 tags the requirement [UMB]
    - `id` — the delivery-state model consumes the gate; the hold note defers to the umbrella
- **Note:** D6 (F-10/X-07): one mechanism, two findings. The capability object is STATUS-v1; the EDD contract v1.8.0 serves it; LINT-DISC-25 checks it.

### Every defined payload hash mode is mandatory to implement; the mode is not negotiated

- **Family id:** `hash-mode-mandatory-to-implement`
- **Normative owner:** `id` — Canonicalisation and Payload Hashing
- **Machine-checked by:** `LINT-HASH-01`
- **Informative summaries (must reference the owner):**
    - `ts` — ICS row 192 tagged [I-D]
    - `umbrella` — §7.1's layer description names the modes without restating the obligation
- **Note:** Closes review-agenda A11 (25 September 2026). The linter can refuse a mode outside the profile (LINT-HASH-01) but cannot prove a receiver implemented one, so the obligation is stated where the wire rules live and assessed through the TS ICS row.

## Interface count

- **Owner:** `id` — the *Deployment-Defined Interfaces* section.
- **Rule:** The prose count of deployment-defined HTTP surfaces MUST equal the number of interface bullets in the section (the review found 'Two' while four are listed).
- **Expected count:** 4 (Wallet-RDP, Delivery Service, RDP-RDP relay, Wallet-agent).
