<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Minimum Wallet Assurance Profile — MWAP (informative)

The wallet is a trust component of the registered-delivery process (umbrella §7.5): it produces the recipient confirmation the RDP relies on, holds the MLS leaf keys, and is the authenticated endpoint availability-grade delivery anchors on (TS clause 6). This note converts the §7.5 open items into a **named baseline** deployment profiles can reference. It is informative in this edition — the concrete assurance floor a deployment adopts by contract or scheme rule — and it is **REQUIRED from the production-baseline deployment profile onward, RECOMMENDED for pilots** (umbrella Annex P). The source of that obligation is the **deployment scheme / federation rule** — the governance instrument (umbrella §13.1) — not the technical specification: this document stays informative and defines *what* the baseline is; the scheme decides that it binds (Annex P states the same from its side).

## 1. Key protection

- The **confirmation-signature key** (the key behind `wallet_signature_b64`) and the **MLS leaf private keys** are generated on-device and are non-exportable; storage is hardware-backed (TEE / secure element / HSM) or protected at an equivalent, assessable level.
- Keys are **per device**: no confirmation or leaf key is shared across devices — a member with several devices has several leaves (the counting-unit rule, umbrella §8.3, depends on this).
- The `device_class` signal published in BW-MEMBER (`software` / `tee` / `secure-element` / `hsm`, in ascending hardware-custody assurance) truthfully reflects the storage class; under MWAP it is backed by attestation (§5), which is what makes `device-class:` acceptance policies usable (umbrella §8.3 — prohibited in baseline deployments without MWAP). The **`secure-element`** class names a certified secure element — Android StrongBox, the Apple Secure Enclave — which is exactly the storage class the "hardware-backed (TEE / secure element / HSM)" phrase above admits and the one a **P-256** MLS leaf key (the I-D `0x0002` suite, twenty-first-review finding I) can be held in; before the twenty-third review (finding G) the vocabulary jumped from `tee` to `hsm`, so a phone secure element could only misdeclare as one or the other.

## 2. Device binding

- The MLS leaf credential is bound to the device at enrolment (`mls_leaf_node_ref` in BW-MEMBER, umbrella §8.4); the binding event is recorded in the organisational accountability log (§8.4).
- Re-binding is a **new enrolment** (new leaf, new KeyPackages), never a key transfer; a device that leaves the organisation's control is suspended, not re-assigned.

## 3. Confirmation-key lifecycle

- **Published, per device, in BW-MEMBER.** The confirmation-signing key is anchored in `devices[].confirmation_key` (BW-MEMBER v1.5; finding D) — the channel through which a verifier resolves and checks a wallet advanced electronic signature on a recipient confirmation (`wallet_signature_b64`; TS clause 6 INTF-1(a)). Before v1.5 there was **no** such channel: BW-MEMBER published only a hash of the *leaf* key, which is neither the confirmation key nor usable to verify a signature — so this clause was unimplementable for the key it is about. The anchor carries the public key (verification in every profile) and, at the production profile, an `x5chain` binding it to the entity QSealC / a Trusted List (which makes it *advanced*, TS clause 5.1, and gives it a validity window).
- Generated at enrolment; rotation aligned with the KeyPackage lifetime bounds (I-D, *KeyPackage Rules*; TS clause on maximum validity). A rotation publishes a new `confirmation_key`; the superseded anchor is retained (next bullet).
- Retirement follows the member lifecycle: suspending or retiring the member binding fails the member closed at the directory (umbrella §5.7) and triggers MLS removal (I-D, *Role Lifecycle*).
- **Public verification material remains available after retirement, and the anchor is that material.** Evidence validity is evaluated **at evidence time** (TS clause 6, CMP-1/CMP-2), so a verifier must be able to verify a confirmation signed before the key's retirement. The `confirmation_key` anchor **MUST survive member retirement** — preserved in the historical sealed BW-MEMBER that was current at the confirmation's `verified_at` — so the signature stays verifiable; at the production profile the x5chain's validity window is evaluated as of that instant. A live directory that only ever serves the *current* binding does not satisfy this; the historical binding must remain resolvable for the retention period.

## 4. Compromise handling and revocation latency

- On suspected compromise: suspend the member binding immediately; directory propagation is bounded (≤ 5 min, ICS row EDD-1) and the resolver's member endpoint fails closed; MLS Remove + Commit evicts the leaf, and MLS post-compromise security bounds forward exposure.
- **Latency bounds (the MWAP floor):** directory suspension visible ≤ 5 min; MLS removal at the next Commit of each affected group, target ≤ 1 h for groups with active traffic.
- Disputed windows — a claimed compromise predating formal suspension — are reviewed via the accountability log (umbrella §8.4) under the dispute path (§13.2); the evidence-validity baseline is TS clause 6.

## 5. Build and instance attestation

- The wallet build is integrity-protected (signed builds, verifiable provenance); the wallet **instance** attests its build and key-storage class at enrolment, and RECOMMENDED periodically thereafter.
- Attestation is what upgrades `device_class` from a self-declared signal to an assurance input; acceptance policies using `device-class:` and any advanced-profile capability depend on it.

## 6. Relation to EUDI Wallet certification

MWAP is **narrower and purpose-built**: it covers exactly the wallet's role in delivery evidence (confirmation keys, leaf keys, binding, attestation), not the full EUDI Wallet certification surface. A certified EUDI Wallet instance whose certification covers key storage and attestation presumptively meets MWAP; a purpose-built business-wallet implementation MAY meet MWAP by assessment without EUDI Wallet certification. Whether a jurisdiction or federation requires full certification on top of MWAP is a governance decision this profile does not pre-empt (umbrella §7.5) — no new certification requirement is introduced here.

## 7. Applicability by deployment profile (umbrella Annex P)

| Profile | MWAP status |
|---|---|
| 1 — Minimal pilot | RECOMMENDED (demo keys acceptable; declare deviations) |
| 2 — Federated pilot | RECOMMENDED (per-operator assessment) |
| 3 — Production baseline | **REQUIRED** |
| 4 — Production advanced | **REQUIRED**, plus attestation-backed `device-class` policies |

## Where the normative anchors live

| Concern | Normative home |
|---|---|
| Recipient session gating, auth recording, compromise baseline | TS clause 6 |
| Member binding, accountability log, `device_class` signal | Umbrella §8.4 |
| Directory fail-closed + propagation bounds | Umbrella §5.7 / ICS EDD-1 |
| KeyPackage lifetime and replenishment | I-D, *KeyPackage Rules* |
| `device-class:` policy prohibition outside advanced profiles | Umbrella §8.3 |
