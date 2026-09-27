<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

<!-- GENERATED FILE — do not edit by hand. Source of truth: docs/lint-catalogue.json. Regenerate with `make lint-catalogue` (scripts/lint_catalogue.py --render). -->

# Normative lint catalogue (X-20)

This catalogue is the **normative definition** of every `LINT-*` conformance rule referenced by the umbrella (§9.4) and the TS (Annex A ICS pro forma). It exists so an assessor can build an independent checker that reproduces every verdict from this document and the sample vectors **without reading the reference Python**. The scripts under `scripts/` (`evidence_lint.py`, `discovery_lint.py`, `bundle_lint.py`, `lint_cli.py`) are the **versioned reference implementation** of this catalogue, not its definition: a change to a rule's behaviour MUST be accompanied by a change to this catalogue and its tests (enforced by `tests/test_lint_catalogue.py`).

**Rules:** 160 · **with a naming test:** 149/160 · **catalogue version:** 1.

**Profile applicability.** `core` rules apply to every deployment; `production` rules apply only under `--profile production`; `agent` rules apply only where a system member (Annex R) is enrolled; `four-corner` rules apply only to relay/federated (profile-2) evidence.

**Error outcome.** Every rule is *fail-closed*: a violation makes the artefact non-conformant (the reference tools exit non-zero and emit the message shown). The one exception is `LINT-BND-W1`, a non-fatal WARNING.

## Dispatch / unknown-type guards

### LINT-000 · `core`

- **Input:** any evidence object (top-level or an EP outcome/change)
- **Precondition:** always — runs on every object dispatched through lint_object
- **Predicate (PASS iff):** The object's `type` MUST be one of {SE-v1, DE-v1, NDE-v1, RE-v1, CE-v1, EP-v1, RelayEvidence-v1}; any other or missing type fails.
- **Error outcome:** unknown or missing evidence type: {t!r}
- **Reference implementation:** `lint_object`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

## Authentication-context coherence (AUTH)

### LINT-AUTH-01 · `core`

- **Input:** SE evidence object
- **Precondition:** type == SE-v1
- **Predicate (PASS iff):** se.auth_context.method (a missing auth_context treated as {}) MUST equal se.auth_method.
- **Error outcome:** SE auth_context.method != auth_method
- **Reference implementation:** `lint_se`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-AUTH-02 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1
- **Predicate (PASS iff):** de.auth_context.method (missing auth_context treated as {}) MUST equal de.recipient_auth_method.
- **Error outcome:** DE auth_context.method != recipient_auth_method
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-AUTH-03 · `core`

- **Input:** evidence object carrying an auth_context (SE, DE, RE, GCM)
- **Precondition:** auth_context.method is REGISTERED in registries/auth-assurance.json
- **Predicate (PASS iff):** The (identity, method, loa) tuple MUST be admissible — (a) the registered method's own admissible_loa set bounds what it can truthfully claim (no scalar ordering: password-otp never claims high, mls-x509 never very-high); (b) the evidence context's tuple row bounds the combination: se-submission split by origin_proof, de-confirmation split by wallet-signed vs session, de-availability, re-member-refusal, gcm-dispute — with combined-factor ELEVATION stated where a wallet signature admits a substantial session that the session-only/provider-attested arm does not. The floors are the pilot profile's provisional set; their legal adoption is TODO(legal) and left open. Fail-closed.
- **Error outcome:** a registered method claiming a loa outside its admissible set, or an (identity, method, loa) tuple outside the evidence context's admissible row (X-27)
- **Reference implementation:** `check_auth_assurance`
- **Tests:** `test_auth_assurance.py`, `test_oid4vp_binding.py`

### LINT-AUTH-W1 · `core`

- **Input:** evidence object carrying an auth_context
- **Precondition:** auth_context.method is a non-empty string NOT registered in registries/auth-assurance.json
- **Predicate (PASS iff):** The safe-generic-processing convention: an UNREGISTERED well-formed method is accepted, preserved verbatim, and treated as UNASSESSED — a WARNING, not a violation. Registering the method (with its admissible loa set) in registries/auth-assurance.json is a registry action.
- **Error outcome:** auth method is not registered — the assurance claim is unassessed (warning)
- **Reference implementation:** `check_auth_assurance`
- **Tests:** `test_auth_assurance.py`, `test_oid4vp_binding.py`

## Delivery / sending evidence invariants (DE)

### LINT-DE-01 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1 AND s3_attestation present
- **Predicate (PASS iff):** s3_attestation.message_id MUST equal de.message_id.
- **Error outcome:** s3_attestation.message_id != message_id
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-DE-02 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1 AND s3_attestation present
- **Predicate (PASS iff):** s3_attestation.payload_hash MUST equal de.payload_hash.
- **Error outcome:** s3_attestation.payload_hash != payload_hash
- **Reference implementation:** `lint_de`
- **Tests:** `test_confirmation_kinds.py`, `test_evidence_lint_negative.py`

### LINT-DE-03 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1 AND s3_attestation present
- **Predicate (PASS iff):** s3_attestation.acceptance_policy_ref MUST equal de.acceptance_policy_ref.
- **Error outcome:** s3_attestation.acceptance_policy_ref != acceptance_policy_ref
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-DE-04 · `core`

- **Input:** DE evidence object with enclosing SE context (DE nested in an EP)
- **Precondition:** type == DE-v1 AND s3_attestation present AND an SE context is supplied
- **Predicate (PASS iff):** s3_attestation.mls_group_id MUST equal se.mls_group_id AND s3_attestation.mls_epoch MUST equal se.mls_epoch.
- **Error outcome:** s3_attestation MLS session != se.mls_group_id/mls_epoch
- **Reference implementation:** `lint_de`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

### LINT-DE-05 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1
- **Predicate (PASS iff):** If acceptance_policy_kind in {quorum, all}, event MUST be 'C.3-ConsignmentAcceptance'; if in {any-one, device-class}, event MUST be in {D.6-ContentAccessTracking, E.1-ContentHandover}.
- **Error outcome:** acceptance_policy_kind={kind} requires event {expected}, got {ev}
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-DE-06 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1 AND acceptance_policy_kind == 'quorum'
- **Predicate (PASS iff):** de.quorum MUST be a list of length >= 1.
- **Error outcome:** acceptance_policy_kind=quorum requires a non-empty quorum array
- **Reference implementation:** `lint_de`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

### LINT-DE-07 · `core`

- **Input:** DE evidence object (optionally with enclosing SE context)
- **Precondition:** type == DE-v1
- **Predicate (PASS iff):** The `scope_ref` key MUST be present; and when an SE context is supplied and se.scope_ref is not None, de.scope_ref MUST equal se.scope_ref.
- **Error outcome:** DE missing scope_ref | DE scope_ref != SE scope_ref for the same message
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint.py`

### LINT-DE-08 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1
- **Predicate (PASS iff):** delivery_grade MUST be one of {availability, verification, acceptance}; and event MUST be in that grade's set: availability->{D.1-ContentConsignment}, verification->{D.6-ContentAccessTracking, E.1-ContentHandover}, acceptance->{C.3-ConsignmentAcceptance}.
- **Error outcome:** missing or unknown delivery_grade: {grade!r} | delivery_grade={grade} requires event in {expected}, got {ev}
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-DE-09 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1 AND delivery_grade == 'availability'
- **Predicate (PASS iff):** An availability-grade DE MUST NOT contain s3_attestation, acceptance_policy_kind or quorum; and integrity_basis MUST equal 'sender-declared-digest'.
- **Error outcome:** availability-grade DE must not carry {f} (no recipient confirmation exists at this grade — TS clause 6) | availability-grade DE requires integrity_basis=sender-declared-digest
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-DE-10 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1 AND delivery_grade in {verification, acceptance}
- **Predicate (PASS iff):** s3_attestation MUST be present; integrity_basis MUST equal 'recipient-verified-digest'; grade==acceptance requires acceptance_policy_kind in {quorum, all}; grade==verification requires acceptance_policy_kind in {any-one, device-class}.
- **Error outcome:** {grade}-grade DE requires an s3_attestation | {grade}-grade DE requires integrity_basis=recipient-verified-digest | acceptance-grade DE requires acceptance_policy_kind quorum/all, got {kind!r} | verification-grade DE requires acceptance_policy_kind any-one/device-class, got {kind!r}
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-DE-11 · `core`

- **Input:** DE evidence object (optionally with enclosing SE context)
- **Precondition:** type == DE-v1
- **Predicate (PASS iff):** If delivery_grade == 'availability', grade_commitment MUST match ^[a-f0-9]{64}$; otherwise grade_commitment MUST be absent. When an SE context is supplied, se.grade_commitment MUST equal de.grade_commitment.
- **Error outcome:** availability-grade DE requires a well-formed grade_commitment (64 lowercase hex) | grade_commitment is only defined at the availability grade | DE grade_commitment != SE grade_commitment for the same message
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-DE-12 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1 AND s3_attestation.session_authenticated truthy AND s3_attestation.wallet_signature_b64 absent
- **Predicate (PASS iff):** de.auth_context.identity MUST be 'member' or 'device' (a session-only confirmation requires member/device-granularity auth_context).
- **Error outcome:** session-authenticated s3_attestation requires the DE auth_context at member/device identity granularity (TS clause 6 INTF-1)
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-DE-13 · `core`

- **Input:** DE evidence object with enclosing SE context
- **Precondition:** type == DE-v1 AND s3_attestation present AND an SE context is supplied
- **Predicate (PASS iff):** s3_attestation.acceptance_policy_ref MUST equal se.acceptance_policy_ref.
- **Error outcome:** s3_attestation.acceptance_policy_ref != se.acceptance_policy_ref
- **Reference implementation:** `lint_de`
- **Tests:** `test_evidence_lint_negative.py`, `test_policy_key_evidence.py`

### LINT-DE-14 · `agent`

- **Input:** SE evidence object
- **Precondition:** type == SE-v1
- **Predicate (PASS iff):** system-identity <=> mandate_ref present: if auth_context.identity=='system' a mandate_ref MUST be present; if a mandate_ref is present the acting identity MUST be system.
- **Error outcome:** SE with a system acting identity must carry a mandate_ref (Annex R, A2) | SE carries a mandate_ref but its acting identity is not system (Annex R, A2)
- **Reference implementation:** `lint_se`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-DE-15 · `agent`

- **Input:** SE evidence object
- **Precondition:** type == SE-v1 AND auth_context.identity == 'system' AND mandate_ref present
- **Predicate (PASS iff):** Let opposable = mandate_ref.opposable (default True). If opposable, mandate_ref.mandate_commitment MUST match ^[a-f0-9]{64}$; if not opposable, it MUST be absent.
- **Error outcome:** opposable agent SE requires a well-formed mandate_commitment (64 lowercase hex; A1) | non-opposable agent SE must not carry a mandate_commitment (A1)
- **Reference implementation:** `lint_se`
- **Tests:** `test_evidence_lint_negative.py`, `test_opposable_coherence.py`

### LINT-DE-16 · `core`

- **Input:** DE evidence object with enclosing SE context
- **Precondition:** type == DE-v1 AND s3_attestation present AND an SE context is supplied
- **Predicate (PASS iff):** s3_attestation.envelope_hash MUST equal se.envelope_hash AND s3_attestation.mls_state MUST equal se.mls_state. Since evidence 2.2 (R-02/D3) both are dedicated fixed types: EnvelopeHash = {format: 'mls10-message', hex} — SHA-256 over the TLS-serialized RFC 9420 MLSMessage as transmitted — and MlsStateHash = {format: 'mls10-group-context', hex} — SHA-256 over the TLS-serialized §8.1 GroupContext (cipher suite/version/extensions inside). Reference serializer: scripts/mls_wire.py.
- **Error outcome:** s3_attestation.envelope_hash != se.envelope_hash | s3_attestation.mls_state != se.mls_state
- **Reference implementation:** `lint_de`
- **Tests:** `test_mls_binding.py`, `test_mls_commitments.py`

### LINT-DE-17 · `core`

- **Input:** DE evidence object with enclosing SE context (DE nested in an EP)
- **Precondition:** type == DE-v1 AND delivery_grade == 'availability' AND an SE context is supplied
- **Predicate (PASS iff):** Evidence 2.2: the availability-grade DE carries the transmitted-octet commitment itself (no confirmation exists at that grade); de.envelope_hash MUST equal se.envelope_hash, so the chain SE = DE holds at every grade (confirmed grades bind via s3_attestation, LINT-DE-16).
- **Error outcome:** availability DE envelope_hash != se.envelope_hash — the transmitted-octet chain breaks at the delivery boundary (F-02)
- **Reference implementation:** `lint_de`
- **Tests:** `test_envelope_chain.py`

### LINT-DE-18 · `core`

- **Input:** SE evidence object
- **Precondition:** type == SE-v1 AND sent_at and expires_at present
- **Predicate (PASS iff):** The sender-computed expiry is validated, not echoed — expires_at MUST be strictly later than sent_at (a reversed or zero TTL is rejected at intake). The policy-maximum bound is bundle-level (LINT-BND-27).
- **Error outcome:** expires_at {exp} is not later than sent_at {sent} — a reversed or zero TTL (X-22)
- **Reference implementation:** `lint_se`
- **Tests:** `test_expiry_validation.py`, `test_instants.py`, `test_intake_expiry.py`

### LINT-DE-19 · `core`

- **Input:** SE evidence object
- **Precondition:** type == SE-v1 AND sender_confirmation is present
- **Predicate (PASS iff):** D4 (evidence 2.3): the sender confirmation's copied tuple MUST equal the SE's own values — message_id, sender_uid, recipient_uid, payload_hash, envelope_hash, mls_state, acceptance_policy_ref, scope_ref, sent_at, expires_at — so the sender's wallet signed the EXACT submission the provider sealed (including the byte-exact transmitted-octet commitments). The signature itself is checked as every wallet confirmation is (LINT-PKG-05/06 payload binding); roster/anchor resolution is bundle-level (LINT-BND-28). The compared set includes `recipient_addr` and `sender_addr`, which are the input to the §8.3 selection — a tuple agreeing with its SE on everything except who the message was addressed to describes a different submission.
- **Error outcome:** a sender_confirmation field diverges from the SE — the sender's signed act and the sealed SE describe different submissions (X-03/D4)
- **Reference implementation:** `lint_se`
- **Tests:** `test_cross_service_transaction.py`, `test_explicit_addressing.py`, `test_production_signature_claims.py`, `test_sender_confirmation.py`

### LINT-DE-20 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1 AND (a session-authenticated s3_attestation OR a wallet-signed quorum entry is present)
- **Predicate (PASS iff):** Evidence 2.3: a bare session boolean cannot claim the stronger proof mode. A session-authenticated confirmation whose DE auth_context claims wallet/eID member-grade authentication (a wallet-* method or high/very-high LoA) MUST retain a verifiable session_binding (token digest / TLS exporter / transcript digest, kept under the §4.3 duty); without one it is the provider-attested (narrowed) mode and the claim must be narrowed to match. A wallet-signed quorum entry MUST cover this DE's message_id — it is a portable proof of THIS acceptance, not a replayable one.
- **Error outcome:** member-grade session claim with no retained session_binding, or a wallet-signed quorum entry covering a different message_id (X-05)
- **Reference implementation:** `lint_de`
- **Tests:** `test_quorum_proofs.py`

### LINT-DE-21 · `core`

- **Input:** DE evidence object
- **Precondition:** type == DE-v1 AND delivery_grade in {verification, acceptance} AND delivered_at present
- **Predicate (PASS iff):** At the verification and acceptance grades `delivered_at` is the instant RDP(in) observed the confirmation that completed the policy, so it MUST NOT precede any act the DE rests on — the s3_attestation's verified_at and every quorum entry's ack_at. The Delivery Service receipt's server_time is the S2 instant and dates delivery at the availability grade only. An unreadable instant is a finding, never a pass.
- **Error outcome:** delivered_at precedes an act it rests on, or an instant is unreadable (R11-04)
- **Reference implementation:** `lint_de`
- **Tests:** `test_delivery_clock.py`, `test_round11_closure.py`

## Evidence Package structure (EP)

### LINT-EP-01 · `core`

- **Input:** EP evidence object
- **Precondition:** type == EP-v1
- **Predicate (PASS iff):** se.message_id MUST equal ep.message_id, and every outcomes[i].message_id MUST equal ep.message_id.
- **Error outcome:** se.message_id != EP message_id | outcomes[{i}].message_id != EP message_id
- **Reference implementation:** `lint_ep`
- **Tests:** `test_evidence_lint_negative.py`, `test_federated_fixture.py`

### LINT-EP-02 · `core`

- **Input:** EP evidence object
- **Precondition:** type == EP-v1
- **Predicate (PASS iff):** The set of rdp_ids referenced by se.rdp_id and each outcomes[].rdp_id MUST be fully covered by the rdp_ids present in rdp_chain.
- **Error outcome:** rdp_chain does not cover rdp_ids {missing}
- **Reference implementation:** `lint_ep`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

### LINT-EP-03 · `core`

- **Input:** EP evidence object
- **Precondition:** type == EP-v1
- **Predicate (PASS iff):** ep.seal MUST contain a 'qualified_timestamp' key.
- **Error outcome:** EP seal missing qualified_timestamp
- **Reference implementation:** `lint_ep`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

### LINT-EP-04 · `core`

- **Input:** EP evidence object (its states[] entries)
- **Precondition:** type == EP-v1, per states[i]
- **Predicate (PASS iff):** Each state record's keys MUST be a subset of {state, event, at, mid, device_id}; no other fields.
- **Error outcome:** states[{i}] has non-state-record fields {extra} (state records establish no delivery and carry no Article 43(2) effect)
- **Reference implementation:** `lint_ep`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-EP-05 · `core`

- **Input:** EP evidence object (outcomes[] entries)
- **Precondition:** type == EP-v1, per outcomes[i] whose scope_ref is not None
- **Predicate (PASS iff):** outcomes[i].scope_ref MUST equal se.scope_ref (all outcomes share the enclosed SE's confidentiality scope).
- **Error outcome:** outcomes[{i}].scope_ref {a!r} != se.scope_ref {b!r}
- **Reference implementation:** `lint_ep`
- **Tests:** `test_evidence_lint.py`

### LINT-EP-06 · `four-corner`

- **Input:** EP evidence object (rdp_chain[] relay-evidence references)
- **Precondition:** type == EP-v1, per rdp_chain[i] whose `evidence` is a dict
- **Predicate (PASS iff):** evidence.message_id MUST equal ep.message_id; evidence.event MUST be in {B.1-RelayAcceptance, B.2-RelayRejection}; evidence.seal_digest.hex MUST be 64 lowercase-hex chars.
- **Error outcome:** rdp_chain[{i}].evidence.message_id {a!r} != EP message_id {b!r} | rdp_chain[{i}].evidence.event {e!r} is not a B.x relay event | rdp_chain[{i}].evidence.seal_digest.hex is not lowercase 64-hex
- **Reference implementation:** `lint_ep`
- **Tests:** `test_bundle_lint.py`, `test_evidence_lint.py`

### LINT-EP-07 · `core`

- **Input:** EP evidence object
- **Precondition:** type == EP-v1
- **Predicate (PASS iff):** The number of outcomes whose type is in {DE-v1, NDE-v1, RE-v1} (terminal outcomes) MUST be at most 1.
- **Error outcome:** EP carries {n} terminal outcomes {kinds} for one message — at most one is allowed (finding R4)
- **Reference implementation:** `lint_ep`
- **Tests:** `test_evidence_lint.py`, `test_grade_mismatch.py`

### LINT-EP-08 · `core`

- **Input:** EP evidence object
- **Precondition:** type == EP-v1 AND changes[] or disputes[] present
- **Predicate (PASS iff):** Every nested change (CE) and dispute (GCM) binds THIS package's message — its message_id MUST equal the EP's. Outcomes and the SE were already bound; changes were unchecked, and the shipped federated fixture carried a foreign message's CE. A package never carries another message's evidence.
- **Error outcome:** a nested change/dispute whose message_id differs from the EP's (X-31)
- **Reference implementation:** `lint_ep`
- **Tests:** `test_federated_fixture.py`

## Multipart manifest (MAN)

### LINT-MAN-01 · `agent`

- **Input:** SE manifest array (and nested manifests)
- **Precondition:** SE has a `manifest` list
- **Predicate (PASS iff):** All part_id values within the manifest MUST be unique.
- **Error outcome:** duplicate part_id in manifest
- **Reference implementation:** `lint_manifest`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-MAN-02 · `agent`

- **Input:** SE manifest array (and nested manifests)
- **Precondition:** SE has a `manifest` list
- **Predicate (PASS iff):** The sequence of part_id values MUST already be in byte-wise ascending (sorted) order.
- **Error outcome:** manifest is not in byte-wise ascending part_id order
- **Reference implementation:** `lint_manifest`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-MAN-04 · `core`

- **Input:** any evidence object carrying a `manifest` (SE, or an EP sub-object)
- **Precondition:** a `manifest` list is present and non-empty
- **Predicate (PASS iff):** `payload_hash.hash_mode` MUST be a manifest-* mode, and `payload_hash.hex` MUST equal SHA-256 (or SHA-512, per `alg`) over the deterministic-CBOR encoding of the manifest the object carries — a list of maps, each with the full hash descriptor, as cddl/sm-mls-erd.cddl defines it. This is the half of the multipart binding that a party WITHOUT the plaintext can verify; that each part carries the digest of its own octets cannot be verified from evidence, the parts being end-to-end encrypted and absent, and the two claims must not be conflated.
- **Error outcome:** payload_hash {declared} is not the digest of the manifest present ({computed}) — SHA-256/512 over the deterministic-CBOR encoding of the manifest, a list of maps per the CDDL
- **Reference implementation:** `lint_manifest_digest`
- **Tests:** `test_manifest_digest.py`

## Non-delivery evidence (NDE)

### LINT-NDE-01 · `core`

- **Input:** NDE evidence object
- **Precondition:** type == NDE-v1 AND reason == 'payload-hash-mismatch'
- **Predicate (PASS iff):** recipient_confirmation.result MUST equal 'mismatch'.
- **Error outcome:** reason=payload-hash-mismatch requires recipient_confirmation.result == 'mismatch'
- **Reference implementation:** `lint_nde`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

### LINT-NDE-02 · `core`

- **Input:** NDE evidence object
- **Precondition:** type == NDE-v1 AND reason == 'uid-merged'
- **Predicate (PASS iff):** redirect_uid MUST be a well-formed EU UID (UID_RE).
- **Error outcome:** reason=uid-merged requires a well-formed redirect_uid
- **Reference implementation:** `lint_nde`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

### LINT-NDE-03 · `core`

- **Input:** NDE evidence object
- **Precondition:** type == NDE-v1 AND reason == 'payload-hash-mismatch'
- **Predicate (PASS iff):** recipient_confirmation.message_id MUST equal nde.message_id.
- **Error outcome:** recipient_confirmation.message_id != NDE message_id
- **Reference implementation:** `lint_nde`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-NDE-04 · `core`

- **Input:** NDE evidence object with enclosing SE context
- **Precondition:** type == NDE-v1 AND reason == 'payload-hash-mismatch' AND an SE context is supplied
- **Predicate (PASS iff):** recipient_confirmation.mls_group_id MUST equal se.mls_group_id AND recipient_confirmation.mls_epoch MUST equal se.mls_epoch. The proof's `mls_state` must equal the SE's as well — the confirmation carries it, and the S3 arm already bound it (LINT-DE-16); the issuing path runs this rule before an NDE is sealed.
- **Error outcome:** recipient_confirmation MLS session != se.mls_group_id/mls_epoch
- **Reference implementation:** `lint_nde`
- **Tests:** `test_confirmation_delivery.py`, `test_evidence_lint_negative.py`

### LINT-NDE-05 · `core`

- **Input:** NDE evidence object with enclosing SE context
- **Precondition:** type == NDE-v1 AND reason == 'payload-hash-mismatch' AND an SE context is supplied
- **Predicate (PASS iff):** recipient_confirmation.acceptance_policy_ref MUST equal se.acceptance_policy_ref.
- **Error outcome:** recipient_confirmation.acceptance_policy_ref != se.acceptance_policy_ref
- **Reference implementation:** `lint_nde`
- **Tests:** `test_confirmation_delivery.py`, `test_evidence_lint_negative.py`

### LINT-NDE-06 · `core`

- **Input:** NDE evidence object
- **Precondition:** type == NDE-v1 AND reason == 'payload-hash-mismatch'
- **Predicate (PASS iff):** recipient_confirmation.payload_hash MUST DIFFER from nde.payload_hash (equality would contradict the mismatch claim).
- **Error outcome:** recipient_confirmation.payload_hash must differ from the NDE (sender) payload_hash
- **Reference implementation:** `lint_nde`
- **Tests:** `test_evidence_lint_negative.py`, `test_validation_failure_outcome.py`

### LINT-NDE-07 · `core`

- **Input:** NDE evidence object
- **Precondition:** type == NDE-v1 AND reason has a defined event mapping
- **Predicate (PASS iff):** nde.event MUST be in the allowed EN 319 522-1 event set REGISTERED for that reason in registries/reason-codes.json (the reason->event binding table is loaded from the machine-readable registry artefact owned by the design authority, umbrella §13.4 — registering or re-binding a code is a registry action, not a lint-code change). A reason with no registered binding (allowed_events null, or unregistered) is skipped here; unregistered codes are LINT-NDE-W1's concern.
- **Error outcome:** reason {reason!r} requires event in {allowed}, got {ev!r}
- **Reference implementation:** `lint_nde`
- **Tests:** `test_channel_convergence.py`, `test_evidence_lint_negative.py`, `test_expiry_validation.py`, `test_merge_lifecycle.py`, `test_reason_event_table.py`, `test_registry_extension.py`, `test_relay_stage_event.py`, `test_schema_negative.py`, `test_suspension_hold.py`

### LINT-NDE-08 · `core`

- **Input:** NDE evidence object (+ its SE where available)
- **Precondition:** type == NDE-v1 AND reason == 'payload-validation-failed'
- **Predicate (PASS iff):** The NDE carries a recipient_validation_failure and NOT a recipient_confirmation; its `failure`, and each entry in `parts[]`, is a registered cause; a part claiming part-digest-mismatch carries BOTH `declared` and `observed` and they differ, and no other part cause carries an `observed` digest; the assertion's message_id equals the NDE's; and, where the SE is available, its declared_payload_hash equals se.payload_hash and its mls_group_id / mls_epoch / mls_state / acceptance_policy_ref equal the SE's.
- **Error outcome:** the recipient validation failure does not bind to the message it is about, or asserts a comparison it did not make
- **Reference implementation:** `lint_nde_semantics`
- **Tests:** `test_validation_failure_outcome.py`

### LINT-NDE-W1 · `core`

- **Input:** NDE evidence object
- **Precondition:** type == NDE-v1 AND reason is a well-formed lowercase-kebab token NOT present in registries/reason-codes.json
- **Predicate (PASS iff):** Safe generic processing: a well-formed but UNREGISTERED reason code is accepted structurally, preserved verbatim and treated as a generic non-delivery. This rule emits a WARNING (the -W convention: printed, never counted as a violation) so an additive registration is safe for an older verifier — the I-D's unknown-code ingest rule, made implementable. A REGISTERED reason still enforces its event binding via LINT-NDE-07.
- **Error outcome:** reason {reason!r} is not a REGISTERED reason code — accepted and preserved verbatim; treat as a generic non-delivery (registries/reason-codes.json; the I-D, IANA Considerations)
- **Reference implementation:** `lint_nde`
- **Tests:** `test_expiry_validation.py`, `test_registry_extension.py`, `test_schema_negative.py`

## Packaging, canonical bytes and projection (PKG)

### LINT-PKG-01 · `core`

- **Input:** SE/DE/NDE/RE/CE evidence object seal
- **Precondition:** type in {SE-v1,DE-v1,NDE-v1,RE-v1,CE-v1}
- **Predicate (PASS iff):** obj.seal MUST be an object; seal.cose_b64 MUST be valid Base64, decode to CBOR, and be a 4-element COSE_Sign1 array. (Structural CBOR checks require cbor2.)
- **Error outcome:** seal container missing or not an object | {field} is not valid Base64 | {field} does not decode to CBOR | {field} is not a 4-element COSE_Sign1 array
- **Reference implementation:** `_check_evidence_seal/_check_cose`
- **Tests:** `test_evidence_lint_negative.py`, `test_manifest_digest.py`

### LINT-PKG-02 · `core`

- **Input:** EP evidence object seal
- **Precondition:** type == EP-v1
- **Predicate (PASS iff):** ep.seal MUST be an object; seal.cose_b64 MUST be valid Base64, decode to CBOR, and be a 4-element COSE_Sign1 array.
- **Error outcome:** seal container missing or not an object | {field} is not valid Base64 | {field} does not decode to CBOR | {field} is not a 4-element COSE_Sign1 array
- **Reference implementation:** `_check_evidence_seal/_check_cose`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

### LINT-PKG-03 · `core`

- **Input:** any evidence object seal's qualified_timestamp
- **Precondition:** any evidence object with a seal
- **Predicate (PASS iff):** seal.qualified_timestamp.token_b64 MUST be valid Base64 AND decode to a non-empty byte string whose first byte is 0x30 (a DER SEQUENCE).
- **Error outcome:** qualified_timestamp.token_b64 is not valid Base64 | qualified_timestamp.token_b64 does not decode to a DER SEQUENCE (leading 0x30)
- **Reference implementation:** `_check_token`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-PKG-05 · `core`

- **Input:** any COSE_Sign1: a seal.cose_b64 or a confirmation's wallet_signature_b64
- **Precondition:** a seal (any evidence object) or a confirmation carrying wallet_signature_b64; cbor2 required
- **Predicate (PASS iff):** The COSE protected header MUST decode to CBOR and its alg (label 1) MUST be in the allowlist {EdDSA(-8), ES256(-7), ES384(-35)}; a wallet_signature_b64 MUST be valid Base64, decode to CBOR, and be a 4-element COSE_Sign1.
- **Error outcome:** {field} protected header is not decodable CBOR | {field} COSE alg {alg!r} not in allowlist | {field} is not valid Base64 | {field} does not decode to CBOR | {field} is not a 4-element COSE_Sign1 array
- **Reference implementation:** `_check_cose/_check_wallet_sig`
- **Tests:** `test_evidence_lint_negative.py`

### LINT-PKG-06 · `core`

- **Input:** a sealed object + its seal.cose_b64, or a confirmation + its wallet_signature_b64
- **Precondition:** cbor2 available AND the COSE b64 is valid Base64 (else deferred to LINT-PKG-01/02)
- **Predicate (PASS iff):** The COSE_Sign1 payload MUST be embedded bytes (not detached) and MUST byte-for-byte equal the deterministic-CBOR (dCBOR) encoding of the reconstructed signed payload: for an EP, dcbor(ep_signed_body) with sub-objects embedded as artefact bytes; otherwise dcbor(obj minus the strip field(s) — 'seal', or 'wallet_signature_b64' for a confirmation).
- **Error outcome:** {label} COSE payload is detached (not embedded) | {label} COSE payload does not match the object's canonical signed payload (stale or tampered evidence)
- **Reference implementation:** `_check_payload_binding`
- **Tests:** `test_discovery_lint.py`, `test_evidence_lint.py`, `test_evidence_lint_negative.py`, `test_manifest_digest.py`

### LINT-PKG-08 · `core`

- **Input:** a seal's cose_b64 + qualified_timestamp
- **Precondition:** cose_b64 and token_b64 valid Base64 AND the token is in the demo/mock format (len==36, first 4 bytes 0x30 0x22 0x04 0x20)
- **Predicate (PASS iff):** The token's 32-byte message imprint (bytes[4:]) MUST equal SHA-256 of the decoded inner-COSE bytes (SHA-256(b64decode(cose_b64))).
- **Error outcome:** {label} qualified_timestamp imprint != SHA-256(seal)
- **Reference implementation:** `_check_imprint`
- **Tests:** `test_evidence_lint.py`, `test_evidence_lint_negative.py`, `test_federation_gate.py`

### LINT-PKG-09 · `core`

- **Input:** the whole evidence or discovery document (recursively)
- **Precondition:** always
- **Predicate (PASS iff):** No JSON number anywhere may be a float, and no integer may exceed |2^53-1| (9007199254740991); bool is ignored (I-JSON: integers only; carry large counters as decimal strings).
- **Error outcome:** floating-point number (I-JSON: integers only) at {p} | integer {n} outside the safe range +/-(2^53-1) at {p}
- **Reference implementation:** `find_unsafe_numbers`
- **Tests:** `test_evidence_lint_negative.py`, `test_ijson_constraints.py`

### LINT-PKG-10 · `core`

- **Input:** the raw JSON file text (evidence or discovery)
- **Precondition:** always — enforced at parse time (strict loader)
- **Predicate (PASS iff):** No JSON object may contain a duplicate key; a duplicate is rejected and the file failed.
- **Error outcome:** [FAIL] {f}: LINT-PKG-10 duplicate object key(s): {sorted keys}
- **Reference implementation:** `load_ijson`
- **Tests:** `test_ijson_constraints.py`

### LINT-PKG-11 · `core`

- **Input:** any wrapped artefact {sm_artifact_b64, projection} (evidence, discovery, or an EP with wrapped sub-artefacts)
- **Precondition:** the input is a dict carrying both 'sm_artifact_b64' and 'projection' (non-wrapped input passes silently)
- **Predicate (PASS iff):** The wire `projection` MUST equal decode(payload) EXACTLY under recursive structural equality: dicts by key-SET (order-independent) recursing each shared key, lists by length AND positional order, scalars by type-and-value, and a bool NEVER equal to an int. The authoritative payload is decoded from sm_artifact_b64 (discovery: COSE_Sign1 payload of the raw bytes; evidence: dcbor([cose,qts]) then the COSE payload). For an EP the comparison is de-zipped: non-sub keys must match; `se` presence must match and its projection compared to the decoded sub-artefact; `outcomes` and `changes` MUST have equal length and each element compared by decoding its sub-artefact bytes. Any decode failure fails closed.
- **Error outcome:** cannot decode the authoritative payload: {exc} | {path}.{k} present on only one side | {path}.{k} differs between projection and payload | {path}.se present on only one side | {path}.{k}: projection carries {n} element(s), the signed payload carries {m} | {path}: projection differs from decode(payload)
- **Reference implementation:** `projection_equals_decode`
- **Tests:** `test_federated_fixture.py`, `test_ingress_forms.py`, `test_projection_integrity.py`, `test_uid_toolkit.py`

### LINT-PKG-12 · `core`

- **Input:** any wrapped artefact {sm_artifact_b64, projection} (evidence or discovery)
- **Precondition:** the input is a dict carrying both 'sm_artifact_b64' and 'projection' (the linters' ingest path; also run per-sample by the cddl-check gate)
- **Predicate (PASS iff):** N-02: the decoded body MUST validate against its AUTHORITATIVE JSON Schema (resolved from the body's `type` via the type->schema map; Draft 2020-12, format-asserting, local $ref store). The CDDL is only the structural outer bound, so a body that is CDDL-valid and projection-equal but Schema-invalid — e.g. a minimal {type, version} discovery body — is rejected fail-closed at the verifier entry point.
- **Error outcome:** decoded body does not validate against its authoritative JSON Schema ({schema_file}): {path}: {message} (+{n} more)
- **Reference implementation:** `validate_body`
- **Tests:** `test_body_schema_authority.py`, `test_constraint_matrix.py`, `test_hash_mode_removed.py`, `test_ingress_forms.py`, `test_uid_toolkit.py`

## Production-profile evidence prechecks (PROD)

### LINT-PROD-01 · `production`

- **Input:** a production evidence seal.cose_b64 (and each confirmation's wallet_signature_b64)
- **Precondition:** profile == 'production' AND type in EVIDENCE_DOC_TYPES; cbor2 available and COSE b64 valid
- **Predicate (PASS iff):** The COSE protected header MUST embed a verifier-resolvable QSealC identity — x5chain (label 33) or x5t (label 34).
- **Error outcome:** {label}: production seal must embed a verifier-resolvable QSealC identity (COSE x5chain/x5t)
- **Reference implementation:** `_production_identity`
- **Tests:** `test_production_lint.py`

### LINT-PROD-02 · `production`

- **Input:** a production evidence seal.qualified_timestamp
- **Precondition:** profile == 'production' AND qualified_timestamp is a dict
- **Predicate (PASS iff):** qualified_timestamp.tsa_id MUST be present and truthy.
- **Error outcome:** production qualified_timestamp must carry a tsa_id
- **Reference implementation:** `_production_object`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

### LINT-PROD-03 · `production`

- **Input:** a production evidence object (COSE kid, profile, tsa_id, rdp_id, policy_id; nested EP sub-objects/wallet sigs)
- **Precondition:** profile == 'production' AND type in EVIDENCE_DOC_TYPES
- **Predicate (PASS iff):** The COSE kid (label 4) MUST NOT be a demo kid (b'rdp'/b'wallet'); a present `profile` field MUST equal 'production'; tsa_id MUST NOT contain a demo marker (example.eu/MockEU/example.); rdp_id and policy_id MUST NOT contain a demo marker.
- **Error outcome:** {label}: demo COSE kid {kid!r} in production evidence | profile is {p!r}, not 'production' | tsa_id contains a demo marker: {v} | {f} contains a demo marker: {v}
- **Reference implementation:** `_production_identity/_production_object`
- **Tests:** `test_production_lint.py`

## Relay evidence (RLY)

### LINT-RLY-01 · `four-corner`

- **Input:** RelayEvidence-v1 object
- **Precondition:** type == RelayEvidence-v1
- **Predicate (PASS iff):** If event == 'B.2-RelayRejection', reason MUST be one of {malformed, policy-violation, uid-suspended, unknown-uid}; if event == 'B.1-RelayAcceptance', reason MUST be absent.
- **Error outcome:** B.2-RelayRejection reason {r!r} is not a typed relay-rejection reason {set} | B.1-RelayAcceptance must not carry a rejection reason
- **Reference implementation:** `lint_relay`
- **Tests:** `test_evidence_lint.py`

### LINT-RLY-02 · `four-corner`

- **Input:** RelayEvidence-v1 object
- **Precondition:** type == RelayEvidence-v1
- **Predicate (PASS iff):** sending_rdp_id and receiving_rdp_id MUST both be present and MUST NOT be equal (a relay hop is between two distinct providers).
- **Error outcome:** relay evidence must name both sending_rdp_id and receiving_rdp_id | sending_rdp_id == receiving_rdp_id ({s!r}) — a relay hop is between two distinct providers
- **Reference implementation:** `lint_relay`
- **Tests:** `test_evidence_lint.py`, `test_trust_store.py`

## Trust-store resolution (TRUST)

### LINT-TRUST-01 · `core`

- **Input:** any evidence or discovery object + its seal + the loaded trust store
- **Precondition:** a trust store was supplied (--trust-store)
- **Predicate (PASS iff):** The seal MUST decode as a COSE_Sign1; its kid (protected-header label 4) MUST resolve to a store entry; and the Ed25519 signature over ['Signature1', protected, b'', payload] MUST verify against that entry's pubkey_b64. Fail-closed (the signature step is skipped only if the signing library is unimportable).
- **Error outcome:** seal is not a decodable COSE_Sign1 — cannot resolve a signer against the trust store (fail-closed) | seal kid {kid!r} does not resolve to a trust-store entry (fail-closed: unknown signer) | seal signature does not verify against the trust-store key for kid {kid!r}
- **Reference implementation:** `check_trust`
- **Tests:** `test_federation_gate.py`, `test_trust_store.py`

### LINT-TRUST-02 · `core`

- **Input:** any evidence or discovery object + resolved trust-store entry + signer identity
- **Precondition:** a trust store was supplied AND the seal kid resolved to an entry
- **Predicate (PASS iff):** The entry's role MUST equal the expected role for the family ('evidence-rdp' for evidence, 'discovery-publisher' for discovery); and if a signer identity (rdp_id for SE/DE/NDE/RE/CE, receiving_rdp_id for RelayEvidence, se.rdp_id for EP, uid for discovery) is supplied and the entry declares identities, that identity MUST be among them.
- **Error outcome:** kid {kid!r} has store role {role!r}, expected {expected!r} for this document type | signer identity {id!r} is not among the trust-store identities for kid {kid!r}
- **Reference implementation:** `check_trust`
- **Tests:** `test_ep_composer.py`, `test_federation_gate.py`, `test_trust_store.py`

### LINT-TRUST-03 · `core`

- **Input:** any evidence or discovery object + resolved trust-store entry
- **Precondition:** a trust store was supplied, the kid resolved, AND the object declares at least one instant
- **Predicate (PASS iff):** The object's latest declared RFC 3339 Zulu instant (issuance-style keys: at/valid_from/last_seen/timestamp or *_at except expires_at) MUST lie within [entry.not_before, entry.not_after] by string comparison (no wall clock).
- **Error outcome:** object instant {inst} lies outside the trust-store validity window [{nb}, {na}] for kid {kid!r}
- **Reference implementation:** `check_trust`
- **Tests:** `test_federation_gate.py`, `test_trust_store.py`

### LINT-TRUST-04 · `four-corner`

- **Input:** RelayEvidence-v1 object + the loaded trust store
- **Precondition:** a trust store was supplied AND type == RelayEvidence-v1 AND sending_rdp_id present AND the known evidence-rdp identity set is non-empty
- **Predicate (PASS iff):** The relaying peer named in sending_rdp_id MUST resolve to a known evidence-rdp identity — the union of identities across all store entries whose role == 'evidence-rdp'.
- **Error outcome:** relay sending_rdp_id {peer!r} does not resolve to a known evidence-rdp identity in the trust store {known} — FC-3 peer authentication
- **Reference implementation:** `_relay_peer_trust`
- **Tests:** `test_federation_gate.py`, `test_trust_store.py`

### LINT-TRUST-05 · `core`

- **Input:** any discovery document + its seal + the trust store + the directory-pin fixture (--trust-store + --directory)
- **Precondition:** a trust store AND a directory fixture were supplied
- **Predicate (PASS iff):** The discovery seal's signing key (resolved from the COSE kid via the store) MUST be an authorized seal key pinned by the directory for THIS document's UID: its spki_sha256 (SHA-256 of the raw seal public key; production pins the QSealC x5t#S256) MUST appear in DirectoryRecord.authorized_seal_keys for the document's uid, and the object's latest instant MUST lie within that pinned key's window. A key not pinned for this UID — including a valid QSealC authorised for another UID — is rejected fail-closed; a UID with no directory pin is rejected fail-closed. (Pilot/demo scope; the production QSealC-chain / Trusted-List validation is a production-verifier duty.)
- **Error outcome:** no directory record pins an authorized seal key for UID {uid!r} (fail-closed: unbound discovery-seal authority) | discovery seal key (spki-sha256 …) is not an authorized seal key for UID {uid!r} in the directory record (a key authorised for another UID cannot seal here) | discovery seal key for UID {uid!r} is pinned but the object instant {inst} lies outside its authorised key-set window (rotation/retirement)
- **Reference implementation:** `check_directory_pin`
- **Tests:** `test_directory_pin.py`, `test_federation_gate.py`

### LINT-TRUST-06 · `core`

- **Input:** a loaded bundle + the federation membership register (manifest `federation_register`)
- **Precondition:** a federation register was supplied; its ABSENCE is the declared `federation-admission` gap, reported INCOMPLETE by the required-property registry rather than by this rule
- **Predicate (PASS iff):** For every provider identifier the bundle's evidence names — the set of fields DERIVED from the evidence Schemas by `rdp_identity_inventory`, so `rdp_id`, relay's `sending_rdp_id`/`receiving_rdp_id` and each EP `rdp_chain[]` entry are covered without a hand-written list — the register MUST attribute status `admitted` to that participant AT THE INSTANT OF ITS OWN ACT (`sent_at`, `delivered_at`, `observed_at`, `refused_at`, `changed_at`, `read_at`, `hop_at`, or the chain entry's own `timestamp`), resolved over half-open `[from, until)` windows and compared as INSTANTS (umbrella §13.1; `lint_cli.admission_at`). `suspended`, `excluded`, no status at that instant, a register that cannot answer, and a provider whose act this verifier cannot date are each a violation. Admission is NOT qualification: this establishes no Trusted-List status. A record is relied on only for acts at or before its `asserted_at`; for a later act it establishes nothing, and that act is reported as the `federation-admission` gap (LINT-BND-I6), never as admitted and never as a violation. An Evidence Package's COMPOSER (se.rdp_id) is resolved at the instant the package's own qualified timestamp attests — composition is an act, distinct from the acts the package records; a timestamp with no readable instant leaves it unestablished (LINT-BND-I6).
- **Error outcome:** {type} {where} names provider {pid!r}, which the register records as {status!r} at {at}, the instant of the act itself | … to which the register attributes no status at {at} — the provider is unknown to the federation, or acted before it was admitted | … but no act instant is in scope for it, so admission cannot be evaluated at the moment of the act | … the register cannot answer for {pid!r} at {at}: {exc}
- **Reference implementation:** `check_bundle`
- **Tests:** `test_federation_gate.py`

### LINT-TRUST-07 · `core`

- **Input:** a BW-PROVIDER-v1 descriptor + its seal + the trust store + the federation membership register (--trust-store + --federation-register)
- **Precondition:** a trust store AND a federation register were supplied AND the document is a BW-PROVIDER-v1
- **Predicate (PASS iff):** `LINT-TRUST-05` one level up. The descriptor's signing key (resolved from the COSE kid via the store) MUST be an authorized seal key pinned by the participant's `MembershipRecord` — its `spki_sha256` MUST appear in `authorized_seal_keys`, and the descriptor's `asserted_at` MUST fall within that pinned key's own `[not_before, not_after]` window — AND the register MUST attribute status `admitted` to the participant at that same `asserted_at`. A participant with no record is rejected fail-closed. One rule because both arms answer one question: does the register authorise THIS descriptor? Instants, never strings. (Pilot/demo scope; the production QSealC-chain / Trusted-List validation is a production-verifier duty.) A register record asserted BEFORE the descriptor cannot speak for the descriptor's instant; with no third verdict in this linter, that fails closed.
- **Error outcome:** no membership record pins an authorized seal key for participant {pid!r} (fail-closed: a descriptor nobody in the federation vouches for) | descriptor seal key (spki-sha256 …) is not an authorized seal key for participant {pid!r} in the membership register | descriptor seal key for participant {pid!r} is pinned but the descriptor is asserted at {asserted}, outside the pinned key's window (rotation / retirement) | the register attributes status {status!r} / NO status to participant {pid!r} at {asserted}, so it does not authorise this descriptor | the register's record for {pid!r} was asserted before the descriptor ({asserted}), so it cannot speak for the instant the descriptor asserts itself
- **Reference implementation:** `check_register_pin`
- **Tests:** `test_federation_gate.py`

### LINT-TRUST-08 · `core`

- **Input:** a federation membership register + the configured Federation Authority anchors (every trust-store entry whose role is `federation-authority`, keyed by kid)
- **Precondition:** a membership register was supplied to a check that would consult it (bundle admission, LINT-TRUST-06; descriptor pinning, LINT-TRUST-07)
- **Predicate (PASS iff):** The register is authenticated AT INGRESS, before any status or pinned key in it is read, against an anchor that is configuration and never part of the input. Every record MUST carry a seal and a timestamp; the seal MUST be a COSE_Sign1 whose kid names a configured Federation Authority anchor (an anchor SET, so the authority can rotate its key: each record is verified under the key its own kid names); its payload MUST equal the deterministic CBOR of the record minus {signature, timestamp}; the signature MUST verify under the anchor's key; that anchor MUST be valid at the record's asserted_at — a retired key does not keep speaking; the timestamp MUST imprint SHA-256 of the seal (demo token; full RFC 3161 validation is the production verifier's); the record MUST validate against MembershipRecord; its status_history MUST be well-formed; and the register MUST carry one record per participant. All or nothing: one failing record means the register is not consulted at all. A register supplied with no anchor configured is not authenticated and not consulted.
- **Error outcome:** membership record {i} ({pid!r}) carries no seal/timestamp | …is sealed under kid {kid!r}, not the configured Federation Authority | …differs from what its seal signed — a field was changed after sealing | …seal does not verify under the Federation Authority's key | …asserted outside the anchor's validity window | …timestamp does not imprint SHA-256 of the seal | …is not a valid MembershipRecord | …{history reason} | the register carries N records for {pid!r} | no Federation Authority anchor is configured | a register was supplied with no trust store
- **Reference implementation:** `authenticate_register`
- **Tests:** `test_federation_gate.py`, `test_ingress_forms.py`

## Demo cryptographic verification (VERIFY)

### LINT-VERIFY-01 · `core`

- **Input:** a seal.cose_b64, or a confirmation's wallet_signature_b64
- **Precondition:** --verify-demo mode; cbor2 and pynacl available and COSE b64 valid
- **Predicate (PASS iff):** The COSE_Sign1 Ed25519 signature over ['Signature1', protected, b'', payload] MUST verify against the published demo public key ('demo' for object seals, 'wallet-demo' for wallet signatures).
- **Error outcome:** {label}: COSE signature does not verify against the demo {seed!r} key
- **Reference implementation:** `_verify_cose`
- **Tests:** `test_evidence_lint.py`, `test_validation_failure_outcome.py`

## Discovery documents (DISC)

### LINT-DISC-000 · `core`

- **Input:** any document passed to the discovery linter
- **Precondition:** type not in {BW-MED-v1, BW-ORG-v1, BW-MEMBER-v1}
- **Predicate (PASS iff):** doc.type MUST equal one of the three recognised discovery types; otherwise the linter returns immediately with no further checks.
- **Error outcome:** not a discovery document: {t!r}
- **Reference implementation:** `lint`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

### LINT-DISC-01 · `core`

- **Input:** any discovery document
- **Precondition:** always (the doc_cose_b64 field is examined)
- **Predicate (PASS iff):** doc.doc_cose_b64 MUST be valid Base64, decode to a 4-element COSE_Sign1 array, and its embedded payload (cose[2]) MUST byte-equal dcbor(doc minus the doc_cose_b64 key).
- **Error outcome:** doc_cose_b64 is not valid Base64 | doc_cose_b64 does not decode to CBOR | doc_cose_b64 is not a 4-element COSE_Sign1 array | doc_cose_b64 payload does not match the canonical document (stale/tampered)
- **Reference implementation:** `_check_doc_seal`
- **Tests:** `test_discovery_lint.py`, `test_federation_stage1.py`

### LINT-DISC-02 · `core`

- **Input:** any discovery document
- **Precondition:** doc_cose_b64 decodes to a 4-element COSE_Sign1 (cbor2 available)
- **Predicate (PASS iff):** The COSE_Sign1 protected-header alg (label 1) MUST be in the allowlist {-8, -7, -35}.
- **Error outcome:** doc_cose_b64 COSE alg {alg!r} not in the allowlist
- **Reference implementation:** `_check_doc_seal`
- **Tests:** _(no dedicated test names this id — coverage gap, tracked)_

### LINT-DISC-03 · `core`

- **Input:** any discovery document
- **Precondition:** always
- **Predicate (PASS iff):** doc.uid MUST be a well-formed EU UID (UID_RE = ^EU-[A-Z]{2}-(EOID|PSBID)-[0-9A-HJ-NP-TV-Z]{14}$) AND its two check characters C1 C2 MUST verify as the GF(2^5) Reed-Solomon check symbols (umbrella Annex F). A checksum-invalid UID is rejected.
- **Error outcome:** uid is not a well-formed EU UID: {uid!r} | uid {uid!r} has an invalid check symbol (C1C2) — the GF(2^5) Reed-Solomon check does not verify
- **Reference implementation:** `_check_uid`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-04 · `core`

- **Input:** BW-ORG document
- **Precondition:** type == BW-ORG-v1
- **Predicate (PASS iff):** policy_version and valid_from MUST be present; acceptance_policy MUST be a non-empty object; every value MUST match ^(any-one|all|quorum:\d+|device-class:.+)$.
- **Error outcome:** BW-ORG must carry policy_version | BW-ORG must carry valid_from | BW-ORG acceptance_policy must be a non-empty object | BW-ORG acceptance_policy[{role!r}] is not a valid policy: {pol!r}
- **Reference implementation:** `lint_org`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-05 · `core`

- **Input:** BW-MED document
- **Precondition:** type == BW-MED-v1
- **Predicate (PASS iff):** mls.cipher_suites MUST be a non-empty list; mls.keypackage_url and mls.ds_url MUST be https URLs; expires_at MUST be present; mls.scopes_supported, if present, MUST be boolean.
- **Error outcome:** BW-MED mls.cipher_suites must be a non-empty list | BW-MED mls.{url_field} must be an https URL | BW-MED must declare expires_at (freshness bound) | BW-MED mls.scopes_supported must be a boolean when present
- **Reference implementation:** `lint_med`
- **Tests:** `test_discovery_lint.py`, `test_uid_toolkit.py`

### LINT-DISC-06 · `core`

- **Input:** BW-MEMBER document
- **Precondition:** type == BW-MEMBER-v1
- **Predicate (PASS iff):** doc.mid MUST match MID_RE (^[0-9A-HJ-NP-TV-Z]{9}$) AND its 9th character MUST verify as the GF(2^5) Reed-Solomon check symbol of the 8 payload symbols; devices MUST be a non-empty list; every device MUST contain mls_leaf_node_ref.
- **Error outcome:** BW-MEMBER mid is not a well-formed MID: {mid!r} | BW-MEMBER mid {mid!r} has an invalid check symbol — the GF(2^5) Reed-Solomon check does not verify | BW-MEMBER must list at least one device | BW-MEMBER devices[{i}] missing mls_leaf_node_ref
- **Reference implementation:** `lint_member`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-07 · `core`

- **Input:** any discovery document
- **Precondition:** doc_cose_b64 decodes to a 4-element COSE_Sign1 (cbor2 available)
- **Predicate (PASS iff):** The COSE payload element (cose[2]) MUST be an embedded byte string, not detached.
- **Error outcome:** doc_cose_b64 COSE payload is detached (not embedded)
- **Reference implementation:** `_check_doc_seal`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-08 · `core`

- **Input:** BW-ORG document
- **Precondition:** scope_map present
- **Predicate (PASS iff):** scope_map.scopes MUST be a non-empty list of objects; each scope MUST contain scope_id, version, valid_from, roles, content_classes, recoverability, acceptance_policy_ref; recoverability MUST be in {strict, records}.
- **Error outcome:** scope_map.scopes must be a non-empty list | scope_map.scopes[{i}] is not an object | scope_map.scopes[{i}] missing {f} | scope_map.scopes[{i}] recoverability {r!r} not in {strict, records}
- **Reference implementation:** `_check_scope_map`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-09 · `core`

- **Input:** BW-ORG document
- **Precondition:** scope_map present
- **Predicate (PASS iff):** Any present fallback (per-scope scope.fallback or map-level scope_map.fallback) MUST equal 'default'.
- **Error outcome:** scope_map.scopes[{i}] fallback must be 'default' when present | scope_map.fallback must be 'default' when present
- **Reference implementation:** `_check_scope_map`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-10 · `core`

- **Input:** BW-ORG document
- **Precondition:** scope_map present
- **Predicate (PASS iff):** The scope_id values across scope_map.scopes MUST be unique.
- **Error outcome:** scope_map has a duplicate scope_id {sid!r}
- **Reference implementation:** `_check_scope_map`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-11 · `core`

- **Input:** BW-ORG document
- **Precondition:** scope_map present
- **Predicate (PASS iff):** Each content_class MUST route to at most one scope (it must not appear in two scopes with different scope_ids).
- **Error outcome:** content_class {cc!r} maps to more than one scope ({a!r} and {b!r})
- **Reference implementation:** `_check_scope_map`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-12 · `core`

- **Input:** BW-ORG document
- **Precondition:** scope_map present
- **Predicate (PASS iff):** For each scope, a non-null acceptance_policy_ref MUST be a key present in doc.acceptance_policy.
- **Error outcome:** scope_map.scopes[{i}] acceptance_policy_ref {apr!r} is not an acceptance_policy key
- **Reference implementation:** `_check_scope_map`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-13 · `core`

- **Input:** BW-ORG document
- **Precondition:** scope_map present
- **Predicate (PASS iff):** Every role listed in a scope's roles MUST exist in the organisation-level roles (doc.roles).
- **Error outcome:** scope_map.scopes[{i}] role {r!r} is not an organisation-level role
- **Reference implementation:** `_check_scope_map`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-14 · `core`

- **Input:** BW-ORG document
- **Precondition:** scope_map present
- **Predicate (PASS iff):** No scope may declare scope_id == 'default' (that id is reserved for the implicit scope).
- **Error outcome:** scope_map.scopes[{i}] scope_id 'default' is reserved (implicit scope)
- **Reference implementation:** `_check_scope_map`
- **Tests:** `test_discovery_lint.py`, `test_schema_negative.py`

### LINT-DISC-15 · `core`

- **Input:** any discovery document
- **Precondition:** --verify-demo mode; cbor2 available and doc_cose_b64 valid
- **Predicate (PASS iff):** The seal's COSE kid MUST equal 'entity-admin' AND the Ed25519 signature MUST verify against the published entity-admin demo key.
- **Error outcome:** discovery doc sealed with kid {kid!r}, expected 'entity-admin' (entity wallet-administration signer) | discovery seal signature does not verify against the entity-admin demo key
- **Reference implementation:** `_check_demo_signer`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-16 · `core`

- **Input:** BW-ORG document
- **Precondition:** scope_map present; per content_class within each scope
- **Predicate (PASS iff):** Each content_class in a scope MUST match CONTENT_CLASS_RE (lowercase-kebab, optionally x- prefixed with a non-empty name); a non-x- class MUST be a TIER-1 class REGISTERED in registries/content-classes.json (the tier-1 set is loaded from the machine-readable registry artefact, umbrella §13.4 — promoting a class is a registry action, not a lint-code release). Private classes MUST carry the x- prefix.
- **Error outcome:** scope_map.scopes[{i}] content_class {cc!r} is not lowercase-kebab (optionally x- prefixed) | scope_map.scopes[{i}] content_class {cc!r} is neither a standard registry class nor x- prefixed
- **Reference implementation:** `_check_scope_map`
- **Tests:** `test_discovery_lint.py`, `test_schema_negative.py`

### LINT-DISC-17 · `core`

- **Input:** BW-ORG document
- **Precondition:** delivery_grades present
- **Predicate (PASS iff):** delivery_grades MUST be a non-empty object; each key MUST be a well-formed content class; each value MUST be in {availability, verification, acceptance}.
- **Error outcome:** delivery_grades must be a non-empty object | delivery_grades key {cls!r} is not a well-formed content class | delivery_grades[{cls!r}] = {g!r} not in {availability, verification, acceptance}
- **Reference implementation:** `_check_delivery_grades`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-18 · `core`

- **Input:** BW-ORG document
- **Precondition:** delivery_grades present; per scope whose acceptance_policy_ref resolves to a policy
- **Predicate (PASS iff):** For each scope, the implied grade is 'acceptance' if its policy == 'all' or starts 'quorum:', else 'verification'; every content_class in that scope declared verification/acceptance MUST equal the implied grade.
- **Error outcome:** content class {cls!r} declared {g}-grade but routes to scope {sid!r} whose policy {pol!r} implies {implied}-grade (§8.3b)
- **Reference implementation:** `_check_delivery_grades`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-19 · `core`

- **Input:** BW-ORG document
- **Precondition:** scope_map present
- **Predicate (PASS iff):** A BW-ORG publishing a scope_map MUST also declare a member_endpoint (so the scope's member/device set and roster leaves are resolvable cross-provider).
- **Error outcome:** BW-ORG publishes a scope_map but no member_endpoint (§8.3a, F14)
- **Reference implementation:** `_check_scope_map`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-20 · `agent`

- **Input:** BW-MEMBER document
- **Precondition:** type == BW-MEMBER-v1 AND member_type == 'system'
- **Predicate (PASS iff):** A system member MUST carry a mandate_ref (publishing its scoped authority).
- **Error outcome:** BW-MEMBER member_type=system without a mandate_ref (Annex R, A2)
- **Reference implementation:** `lint_member`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-21 · `core`

- **Input:** BW-ORG document
- **Precondition:** scope_map present; per scope on its recoverability
- **Predicate (PASS iff):** recoverability=='records' MUST declare a records_role that is an org-level role and is NOT also one of the scope's own roles; recoverability=='strict' MUST NOT declare a records_role.
- **Error outcome:** scope_map.scopes[{i}] recoverability=records requires a records_role (§8.3a, F16) | records_role {rr!r} is not an organisation-level role | records_role {rr!r} is also a scope role (SCOPE-8) | recoverability=strict must not declare a records_role
- **Reference implementation:** `_check_scope_map`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-22 · `core`

- **Input:** BW-MEMBER document
- **Precondition:** type == BW-MEMBER-v1; per device whose capabilities include 'ack' or 'sign'
- **Predicate (PASS iff):** An ack/sign-capable device MUST carry a confirmation_key whose public_key_b64 is base64-decodable and whose alg is one of {EdDSA, ES256, ES384}.
- **Error outcome:** BW-MEMBER devices[{i}] is ack/sign-capable but has no confirmation_key anchor (finding D) | devices[{i}].confirmation_key.public_key_b64 is not base64-decodable | devices[{i}].confirmation_key.alg {a!r} is not a permitted COSE algorithm
- **Reference implementation:** `lint_member`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-23 · `core`

- **Input:** BW-MEMBER document (per device carrying an mls_leaf_binding)
- **Precondition:** type == BW-MEMBER-v1; a device has an mls_leaf_binding (OPTIONAL in pilot, REQUIRED in production)
- **Predicate (PASS iff):** The device's signed binding MUST satisfy: (i) the RFC 9420 rule that the credential key IS the LeafNode signature key — mls_leaf_node_ref.signature_key_hash == SHA-256(mls_leaf_binding.leaf_sig_pubkey_b64); (ii) the binding COSE payload MUST equal dCBOR({uid, mid, device_id, leaf_sig_pubkey_b64}) of THIS device (it binds exactly this device's leaf key to this uid/mid/device_id); and (iii, demo/pilot) when the binding kid is the entity seal signer ('entity-admin'), the COSE signature MUST verify against the entity seal key. The production certificate profile (Basic Constraints/KU/EKU/name constraints/revocation) and the QSealC-chain / Trusted-List validation remain production-verifier duties.
- **Error outcome:** BW-MEMBER devices[{i}].mls_leaf_binding.leaf_sig_pubkey_b64 is not base64-decodable | BW-MEMBER devices[{i}]: mls_leaf_node_ref.signature_key_hash != SHA-256(mls_leaf_binding.leaf_sig_pubkey_b64) — the MLS LeafNode signature key is not the bound credential key (RFC 9420) | BW-MEMBER devices[{i}].mls_leaf_binding.binding_cose_b64 is not a decodable COSE_Sign1 | BW-MEMBER devices[{i}] mls_leaf_binding does not bind this device's (uid, mid, device_id, leaf key) — content mismatch | BW-MEMBER devices[{i}] mls_leaf_binding signature does not verify against the entity seal key — the binding was not authorised by the entity (F-04)
- **Reference implementation:** `_check_leaf_binding`
- **Tests:** `test_leaf_binding.py`

### LINT-DISC-24 · `core`

- **Input:** BW-ORG discovery document
- **Precondition:** type == BW-ORG-v1
- **Predicate (PASS iff):** BW-ORG 2.4: the acceptance_policy map MUST be present, non-empty, and carry the reserved key 'default' — the deterministic selection for entity-addressed default-scope messages (umbrella §8.3), whose eligible set is the ENTIRE active membership. Without it that addressing case selects no policy. Satisfiability of the default key is bundle-level (LINT-BND-07..09, eligible set = all active members).
- **Error outcome:** BW-ORG without an acceptance_policy, or without the REQUIRED 'default' key (X-12)
- **Reference implementation:** `lint_org`
- **Tests:** `test_policy_selection.py`

### LINT-DISC-25 · `core`

- **Input:** STATUS-v1 status-assertion artefact (+ optional directory, optional verification time)
- **Precondition:** type == STATUS-v1
- **Predicate (PASS iff):** D6: the signed short-lived status capability is well-formed and anchored. STATIC always: validity window non-empty and ≤ the 5-minute suspension-propagation bound (the bound is what makes the concealment window bounded); merged ⇒ redirect_uid; ULID replay guard. With a directory: the seal verifies against a pinned registry_seal_keys entry — only the EDD core registry issues status; an entity's key (even validly pinned for its own documents) cannot. With a verification time: the assertion must be within its validity — outside it an RDP MUST fail closed (umbrella §5.7).
- **Error outcome:** empty/overlong validity, merged without redirect, an unanchored or non-verifying registry seal, or reliance outside the validity window (D6)
- **Reference implementation:** `lint_status`
- **Tests:** `test_policy_in_force.py`, `test_status_assertion.py`

### LINT-DISC-26 · `core`

- **Input:** ROSTER-v1 snapshot artefact (+ optional member-doc digests, optional expected tree hash)
- **Precondition:** type == ROSTER-v1
- **Predicate (PASS iff):** The signed atomic roster snapshot. STATIC always: sealed, non-empty, no duplicate mids. With the entity's sealed BW-MEMBER digests supplied, BOTH directions are enforced — a supplied active member absent from the snapshot is an OMITTED MEMBER (the completeness the signature attests is false); a snapshot digest matching no supplied doc is a MIXED-VERSION enumeration. With the expected ratchet-tree hash (from the retained GroupContext the evidence mls_state commits to), tree_hash must match — enumeration ↔ tree ↔ evidence, one chain. Fail-closed.
- **Error outcome:** omitted active member, mixed-version enumeration, duplicate mid, or a tree_hash that does not chain to the evidenced epoch (F-12)
- **Reference implementation:** `lint_roster`
- **Tests:** `test_roster_snapshot.py`

### LINT-DISC-27 · `core`

- **Input:** BW-MEMBER discovery document
- **Precondition:** type == BW-MEMBER-v1 AND two or more devices carry confirmation_key
- **Predicate (PASS iff):** One confirmation key per device — two devices of ONE member publishing the same confirmation_key.public_key_b64 collapse device-bound assurance to member-bound and make attribution ambiguous (a signature would verify against both records, including across security classes). Cross-member/cross-entity duplicates are bundle-level (LINT-BND-32). Rollover republishes the SAME device record; a key never moves between devices.
- **Error outcome:** two device records of one member publish the same confirmation key (X-32)
- **Reference implementation:** `lint_member`
- **Tests:** `test_key_uniqueness.py`

### LINT-DISC-28 · `core`

- **Input:** BW-ORG-v1 document, plus the retrieval/verification instant (--now)
- **Precondition:** a `now` is supplied (the check is about what a party retrieving the document at that instant may rely on) and the document carries valid_from
- **Predicate (PASS iff):** A BW-ORG served AS CURRENT MUST already be in force — valid_from <= now. The decision settled the open question by PROHIBITING pre-publication rather than adding an `as_of` retrieval API: a relying party fetching the current document cannot tell that a version does not yet bind, and would evaluate an act under rules not yet in force. Parametric on `now` like LINT-DISC-25, because an archived version legitimately has a valid_from in the past of its own service window. Fail-closed on an unparsable instant.
- **Error outcome:** BW-ORG served as current takes force at {vf}, AFTER the retrieval time {now} (DR-04/R2-M6)
- **Reference implementation:** `_check_in_force`
- **Tests:** `test_policy_in_force.py`

### LINT-DISC-29 · `core`

- **Input:** BW-MEMBER-v1 device record
- **Precondition:** the document is a BW-MEMBER (every device record is checked)
- **Predicate (PASS iff):** BW-MEMBER 2.2: each device publishes `cipher_suites`, the suites its KeyPackages are served for, and that list MUST contain the mandatory baseline and MUST NOT repeat a suite. The normative selector has always required per-member/device capability sets; nothing published them, so the tests supplied synthetic arrays and the algorithm could not be executed from discovery at all. Requiring the baseline preserves the invariant the selector rests on — the baseline is in every intersection, so a selection always exists — which one device could otherwise break for the whole federation.
- **Error outcome:** device publishes no cipher_suites | omits the REQUIRED baseline | repeats a suite (DR-08)
- **Reference implementation:** `_check_device_suites`
- **Tests:** `test_group_establishment.py`

### LINT-DISC-30 · `core`

- **Input:** BW-MEMBER-v1 device record carrying min_cipher_suite
- **Precondition:** the device publishes an optional min_cipher_suite
- **Predicate (PASS iff):** A device's published floor may only RAISE the mandatory mls-suite-floor/v1, never lower it, and MUST be a suite the device also publishes in cipher_suites. The mandatory floor binds every conforming deployment INCLUDING one that publishes nothing — which is the majority case and exactly where a provider-induced downgrade lands — so this field is a raise and nothing else. A weaker published value is not a weaker policy the federation honours; it is non-conformant, and accepting it would restore the per-participant floor the mandatory floor replaced. Demanding a suite the device cannot use makes every group unformable: a denial of service wearing a policy's clothes.
- **Error outcome:** min_cipher_suite is not in the current mls-suite-preference vector (its id, e.g. mls-suite-preference/v2) | is WEAKER than the mandatory floor | is not among the device's own cipher_suites (DR-15)
- **Reference implementation:** `_check_device_floor`
- **Tests:** `test_suite_floor.py`

### LINT-DISC-31 · `production`

- **Input:** BW-MEMBER-v1 device confirmation_key anchor, under --profile production
- **Precondition:** the production profile is selected and the device publishes a confirmation_key
- **Predicate (PASS iff):** The anchor MUST carry an `x5chain`, and the LEAF CERTIFICATE MUST HOLD THE SAME PUBLIC KEY as `public_key_b64`, in the encoding the declared `alg` defines (raw Ed25519; SEC1 uncompressed P-256 / P-384). The I-D required this equality and the prose required the chain, but the schema required neither and production lint checked only that some x5chain identity was present on the document SEAL — so a production deployment could publish a bare asserted raw key and the advanced-signature identity claim rested on an assertion. SCOPE: this proves the certificate carries this key; it does NOT validate the chain to a trust anchor, the QSealC qualification, SCD certification or Trusted-List status. Those are the EXTERNAL production trust policy and remain Partial — completing the parsing locally is not completing them.
- **Error outcome:** no x5chain in the production profile | the certificate's subject public key is not the published confirmation key | wrong key type or curve for the declared alg (R3-05)
- **Reference implementation:** `_production_confirmation_keys`
- **Tests:** `test_certificate_binding.py`

### LINT-DISC-32 · `production`

- **Input:** BW-PROVIDER-v1 `asserted_at` / `expires_at`, and the verification instant
- **Precondition:** a BW-PROVIDER-v1 descriptor is validated
- **Predicate (PASS iff):** Batch A / A3: the descriptor's validity window MUST run forwards, and where a verification instant is supplied the descriptor MUST be in force at it. Both bounds are parsed to INSTANTS and compared as instants, never as strings — an earlier round closed a defect where a lexically ordered window was chronologically inverted, and a document carrying two timestamps is exactly where that would return.
- **Error outcome:** no x5chain in the production profile | the certificate's subject public key is not the published confirmation key | wrong key type or curve for the declared alg (R3-05)
- **Reference implementation:** `_production_confirmation_keys`
- **Tests:** `test_federation_stage1.py`

### LINT-DISC-33 · `production`

- **Input:** BW-PROVIDER-v1 `roles`
- **Precondition:** a BW-PROVIDER-v1 descriptor is validated
- **Predicate (PASS iff):** Batch A / A3: every role the descriptor claims MUST be one this version defines. Closed to `rdp` in Batch A, matching the membership register's `role` enum and the descriptor Schema. A role nobody defines is a claim no verifier can act on.
- **Error outcome:** no x5chain in the production profile | the certificate's subject public key is not the published confirmation key | wrong key type or curve for the declared alg (R3-05)
- **Reference implementation:** `_production_confirmation_keys`
- **Tests:** `test_federation_stage1.py`

## Production-profile discovery prechecks (DISC-P)

### LINT-DISC-P-01 · `production`

- **Input:** any discovery document
- **Precondition:** --profile production; cbor2 available and doc_cose_b64 valid; protected header decodes
- **Predicate (PASS iff):** The production discovery seal's COSE protected header MUST embed a verifier-resolvable QSealC identity — label 33 (x5chain) or 34 (x5t).
- **Error outcome:** production discovery seal must embed a verifier-resolvable QSealC identity (COSE x5chain/x5t)
- **Reference implementation:** `_production_check`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-P-02 · `production`

- **Input:** any discovery document
- **Precondition:** --profile production; protected header decodes
- **Predicate (PASS iff):** The seal's COSE kid MUST NOT equal 'rdp' — discovery documents are entity-published, not sealed by the RDP evidence signer.
- **Error outcome:** discovery document sealed by the RDP evidence signer; discovery documents are entity-published (signer-type mismatch)
- **Reference implementation:** `_production_check`
- **Tests:** `test_discovery_lint.py`

### LINT-DISC-P-03 · `production`

- **Input:** any discovery document
- **Precondition:** --profile production; protected header decodes
- **Predicate (PASS iff):** The seal's COSE kid MUST NOT be a demo kid {rdp, entity-admin, wallet, demo} (rdp handled by P-02); and the document JSON MUST NOT contain any demo/example URL marker {example.eu, example.fr, example.com, example.org}.
- **Error outcome:** demo COSE kid {kid!r} in production discovery document | demo/example URL ({m}) in production discovery document
- **Reference implementation:** `_production_check`
- **Tests:** `test_discovery_lint.py`

## Cross-document bundle (BND)

### LINT-BND-01 · `core`

- **Input:** bundle: MED (mls.scopes_supported) + ORG (scope_map)
- **Precondition:** always (any bundle)
- **Predicate (PASS iff):** The MED MUST declare scope support (mls.scopes_supported truthy) if and only if the ORG publishes a scope_map object.
- **Error outcome:** MED scopes_supported={s} but ORG scope_map present={h}
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-02 · `core`

- **Input:** ORG scope_map scopes + BW-MEMBER set
- **Precondition:** per scope, per role in scope.roles
- **Predicate (PASS iff):** Every role of every scope MUST be held by at least one active member (status=='active' whose roles include the role).
- **Error outcome:** scope {sid!r} role {role!r} is held by no active member
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-03 · `core`

- **Input:** ORG scope roles + BW-MEMBER device capabilities
- **Precondition:** role has >=1 active holder / scope has role holders
- **Predicate (PASS iff):** A role with active holders MUST have at least one holder with a 'receive'-capable device; and each scope's members MUST include at least one 'ack'-capable device (else acceptance is impossible).
- **Error outcome:** scope {sid!r} role {role!r}: no active member device can 'receive' | scope {sid!r}: no member device can 'ack' (acceptance impossible)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-04 · `core`

- **Input:** ORG scope acceptance_policy_ref; evidence acceptance_policy_ref.policy_version
- **Precondition:** scope.acceptance_policy_ref present / evidence addressed to this entity with a dict acceptance_policy_ref
- **Predicate (PASS iff):** A scope's acceptance_policy_ref MUST be a key of org.acceptance_policy; and an evidence acceptance_policy_ref.policy_version MUST equal org.policy_version.
- **Error outcome:** scope {sid!r} acceptance_policy_ref {apr!r} is not an acceptance_policy key | {type} acceptance_policy_ref.policy_version {a!r} != ORG policy_version {b!r}
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`, `test_policy_selection.py`

### LINT-BND-05 · `core`

- **Input:** evidence scope_ref vs ORG scope map
- **Precondition:** evidence addressed to this entity AND ev.scope_ref is a dict
- **Predicate (PASS iff):** If scope_ref.scope_id == 'default', version MUST == '1'; otherwise some ORG scope MUST have both scope_id and version equal to the reference.
- **Error outcome:** {type} scope_ref default/{v!r} — the implicit default scope is fixed at descriptor version '1' (§8.3a) | {type} scope_ref {sid!r}/{v!r} does not resolve against the ORG scope map
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-06 · `core`

- **Input:** bundle: MED, ORG and every MEMBER vs manifest entity_uid
- **Precondition:** always (any bundle)
- **Predicate (PASS iff):** For each named document (MED, ORG, each MEMBER), doc.uid MUST equal the bundle's entity_uid.
- **Error outcome:** {name} uid {a!r} != bundle entity {b!r}
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-07 · `core`

- **Input:** ORG acceptance_policy entries and scope-referenced policy strings
- **Precondition:** per acceptance_policy value; per top-level policy key not naming an org role
- **Predicate (PASS iff):** Each policy MUST match ^(any-one|all|quorum:(\d+)|device-class:.+)$; a 'quorum:n' with n<1 is malformed.
- **Error outcome:** {ctx}: acceptance_policy {name!r} = {pol!r} is not any-one|all|quorum:<n>|device-class:<class> | {ctx}: {pol!r} is malformed (quorum n must be >= 1) | acceptance_policy[{key!r}] = {pol!r} is not any-one|all|quorum:<n>|device-class:<class>
- **Reference implementation:** `check_policy/check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-08 · `core`

- **Input:** acceptance policy 'any-one'/'quorum:n' + eligible active ack-capable members
- **Precondition:** policy matches grammar and is any-one or quorum:n
- **Predicate (PASS iff):** Let ackers = distinct-by-mid eligible members holding an ack-capable device. For 'quorum:n', len(ackers) MUST be >= n; for 'any-one', ackers MUST be non-empty.
- **Error outcome:** {ctx}: {pol!r} unsatisfiable — {k} distinct active, ack-capable member(s) eligible, {n} required | {ctx}: 'any-one' unsatisfiable — no active, ack-capable member is eligible
- **Reference implementation:** `check_policy`
- **Tests:** `test_bundle_lint.py`, `test_policy_selection.py`

### LINT-BND-09 · `core`

- **Input:** acceptance policy 'all' + eligible active members
- **Precondition:** policy == 'all'
- **Predicate (PASS iff):** The eligible set (distinct-by-mid) MUST be non-empty AND every distinct member MUST hold an ack-capable device.
- **Error outcome:** {ctx}: 'all' over an empty eligible set is ambiguous — rejected | {ctx}: 'all' unreachable — eligible member(s) {lacking} have no ack-capable device
- **Reference implementation:** `check_policy`
- **Tests:** `test_bundle_lint.py`, `test_policy_selection.py`

### LINT-BND-10 · `core`

- **Input:** evidence acceptance_policy_ref.doc_digest vs ORG signed payload
- **Precondition:** evidence addressed to this entity; acceptance_policy_ref.policy_version == org.policy_version
- **Predicate (PASS iff):** doc_digest.hex MUST equal SHA-256 hex of dcbor(ORG minus doc_cose_b64) AND doc_digest.hash_mode MUST == 'raw-sha256'.
- **Error outcome:** {type} acceptance_policy_ref.doc_digest does not match the ORG signed payload (raw-SHA-256 …, hash_mode raw-sha256) — §8.3
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-11 · `core`

- **Input:** availability-grade evidence + ORG delivery_grades (+ optional grade-reveal fixture)
- **Precondition:** evidence addressed to this entity; delivery_grade == 'availability'
- **Predicate (PASS iff):** With a reveal for the message_id: grade_commitment MUST == compute_grade_commitment(salt, content_class, org_digest) AND delivery_grades[content_class] MUST == 'availability'. Without a reveal: 'availability' MUST appear among delivery_grades values.
- **Error outcome:** {type} grade_commitment does not match the reveal … | revealed content class {cc!r} is not declared availability-grade … (availability is never implicit) | {type} is availability-grade but ORG declares no availability-grade content class
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-12 · `core`

- **Input:** evidence recipient confirmation + quorum ackers vs BW-MEMBER roster
- **Precondition:** evidence addressed to this entity; confirmation/quorum entries carry a mid
- **Predicate (PASS iff):** The confirmation's mid (and device_id when present) and every quorum acker mid MUST resolve to an active member of this entity that is ack-capable (the named device enrolled with 'ack', or any ack-capable device when no device_id). Evidence 2.3: a wallet-signed quorum entry names its device — the (mid, device_id) pair is resolved; a provider entry resolves the member alone. The member and device are resolved AS OF THE ACT (the confirmation's own instant), not from the current-status map — a confirmation valid when it was made does not become unresolvable when the member later retires, and a member who was NOT active at the act still fails. Where no version history is supplied the bundle's single current version is used and the behaviour is unchanged.
- **Error outcome:** {type} confirmation mid {mid!r} does not resolve to an active, ack-capable member of {entity!r} ({why}) — TS clause 6 INTF-2 | {type} quorum acker {mid!r} does not resolve … INTF-2
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`, `test_federated_fixture.py`, `test_historical_resolution.py`, `test_quorum_proofs.py`

### LINT-BND-13 · `core`

- **Input:** the whole evidence set (message_id, recipient_uid, payload_hash)
- **Precondition:** an evidence object has a message_id already seen on another object
- **Predicate (PASS iff):** For a repeated message_id, the recipient_uid MUST agree and the payload_hash MUST agree across all objects sharing it (global message_id uniqueness per issuing environment, S4).
- **Error outcome:** message_id {mid!r} maps to two recipients ({a!r}, {b!r}) — must be globally unique (S4) | message_id {mid!r} maps to two payload_hash values — must be globally unique (S4)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-14 · `agent`

- **Input:** evidence auth_context (identity=system) vs BW-MEMBER roster
- **Precondition:** auth_context.identity == 'system' and the acting mid resolves in this entity's roster
- **Predicate (PASS iff):** The resolved acting member MUST have status=='active' AND member_type=='system'.
- **Error outcome:** {type} auth_context.identity=system names mid {amid!r}, not an active system member of {entity!r} (status={s!r}, member_type={t!r}) — Annex R (A1)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-15 · `agent`

- **Input:** SE mandate_ref vs the acting system member's standing mandate (+ optional mandate-reveal fixture)
- **Precondition:** auth_context.identity=='system'; type=='SE-v1'; mandate_ref is a dict; acting member resolves
- **Predicate (PASS iff):** mandate_ref issuer/id MUST match the standing mandate; when sent_at is present it MUST lie in the standing validity window; with a reveal, the mandate_commitment MUST match compute_mandate_commitment(salt, id, content_class, doc_digest) AND the revealed content_class MUST be in the standing mandate scope.
- **Error outcome:** SE mandate_ref (issuer/id) does not match the standing mandate of {amid!r} (A2) | SE acted under mandate {id!r} outside its validity window at sent_at {t!r} (A2) | SE mandate_commitment does not match the reveal … | revealed content class {cc!r} is not in the mandate scope of {amid!r} — agent overreach (A1)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-16 · `agent`

- **Input:** human_acceptance ORG scope + its eligible active members
- **Precondition:** scope.acceptance_policy_ref is a policy key; scope.human_acceptance truthy; eligible set non-empty
- **Predicate (PASS iff):** At least one eligible member MUST be a human (member_type != 'system') — a human-gated policy MUST NOT be unsatisfiable by agents alone.
- **Error outcome:** scope {sid!r} is human_acceptance but every eligible member is a system member (Annex R, A3)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-17 · `core`

- **Input:** ORG scope recoverability=records + BW-MEMBER roster
- **Precondition:** scope.recoverability=='records' and records_role set
- **Predicate (PASS iff):** The records_role MUST be held by at least one active member (so the records leaf resolves).
- **Error outcome:** scope {sid!r} is recoverability=records but its records_role {rr!r} is held by no active member (§8.3a, F16)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-18 · `agent`

- **Input:** evidence acknowledgement on a human_acceptance scope vs roster
- **Precondition:** evidence addressed to this entity; scope_ref resolves to a scope with human_acceptance
- **Predicate (PASS iff):** No acking mid (the confirmation's mid or any quorum acker) may resolve to an active system member — agents may verify S3 but not legally accept S4 a human-gated class. The member's standing is resolved AT THE ACT, not from the current roster. The act-time resolver was added BESIDE this gate rather than replacing it, so the gate went on deciding attribution from today's membership. At THIS rule the current-state read failed OPEN: a member who had since retired was absent from the map, so a SYSTEM member's acknowledgement in a human_acceptance scope was never checked at all.
- **Error outcome:** {type} acknowledgement by system member {amid!r} does not satisfy the human_acceptance scope {sid!r} (Annex R, A8, §8.3)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`, `test_no_current_state_gates.py`

### LINT-BND-19 · `four-corner`

- **Input:** RelayEvidence B.2-RelayRejection + the sender-facing NDE for the same message_id
- **Precondition:** RelayEvidence-v1 event=='B.2-RelayRejection'; an NDE exists for the message_id; the reason has a mapping
- **Predicate (PASS iff):** The paired NDE's reason MUST equal RELAY_B2_TO_NDE[relay.reason] (the typed relay-rejection reason maps to the correct sender-facing NDE reason).
- **Error outcome:** B.2 RelayRejection reason {r!r} for message {mid!r} maps to sender NDE reason {expected!r}, but the NDE carries {actual!r} — TS clause 4.1
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`

### LINT-BND-20 · `four-corner`

- **Input:** EP rdp_chain[i].evidence reference + the referenced RelayEvidence object in the bundle
- **Precondition:** type=='EP-v1'; the hop evidence resolves to a RelayEvidence-v1 present in the bundle
- **Predicate (PASS iff):** hop.evidence.seal_digest.hex MUST equal compute_seal_digest(target.seal.cose_b64) = SHA-256 over the DECODED COSE_Sign1 bytes (not the base64 text).
- **Error outcome:** EP rdp_chain[{i}].evidence.seal_digest.hex {a!r} does not match the referenced object's seal: expected {b!r} = SHA-256 over the DECODED COSE_Sign1 bytes (TS clause 4.1)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`, `test_federated_fixture.py`

### LINT-BND-21 · `core`

- **Input:** wallet-signed recipient confirmation + the device's published confirmation_key anchor
- **Precondition:** evidence addressed to this entity; the confirmation carries wallet_signature_b64 OR a quorum entry has attestation == 'wallet-signed'
- **Predicate (PASS iff):** The confirmation MUST carry a device_id; (mid, device_id) MUST resolve to a device with a confirmation_key.public_key_b64; and the wallet signature MUST verify against that key under the algorithm the anchor DECLARES — EdDSA, ES256 or ES384, with THREE-WAY AGREEMENT between the COSE protected `alg`, the published `confirmation_key.alg` and the key's actual type/curve (one encoding per algorithm, I-D Confirmation-key encodings). This predicate said 'Ed25519' after the verifier became algorithm-neutral, and the generated catalogue is NORMATIVE — an assessor could reject a conforming EC confirmation on it. Fail-closed. Evidence 2.3 extends the same check to wallet-signed quorum entries: each is an independently portable per-member proof, resolved per (mid, device_id) and verified against that member's published anchor.
- **Error outcome:** {type} confirmation by {mid!r} is wallet-signed but carries no device_id (finding D) | {type} confirmation by {mid!r}/{did!r} has no resolvable confirmation_key anchor (finding D) | {type} wallet_signature_b64 does not verify against the published confirmation key of {mid!r}/{did!r} (INTF-1/S1)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`, `test_certificate_binding.py`, `test_historical_resolution.py`, `test_quorum_proofs.py`, `test_sender_confirmation.py`

### LINT-BND-22 · `core`

- **Input:** SE expires_at + the DE/NDE outcome for the same message_id (or an EP's se + outcomes)
- **Precondition:** an SE with expires_at exists for the outcome's message_id; outcome type is DE-v1 or NDE-v1
- **Predicate (PASS iff):** An NDE with reason=='expired' MUST have observed_at >= expires_at (no premature expiry); a DE at EVERY grade — availability INCLUDED (the former exemption is removed) — MUST have delivered_at <= expires_at, where delivered_at is the S2/S4 EVENT time (the artefact's qualified timestamp is the possibly-later issuance time). A tie (delivered_at == expires_at) is delivered.
- **Error outcome:** NDE `expired` for {mid!r} observed at {obs} BEFORE SE.expires_at {exp} — premature expiry (R1) | {grade}-grade DE for {mid!r} delivered at {d} AFTER SE.expires_at {exp} — delivery past the authenticated deadline (R1/X-21; the event time bounds every grade, availability included)
- **Reference implementation:** `_check_expiry`
- **Tests:** `test_bundle_lint.py`, `test_delivery_clock.py`, `test_delivery_timing.py`, `test_expiry_one_rule.py`, `test_instants.py`, `test_round11_closure.py`, `test_suspension_hold.py`

### LINT-BND-23 · `core`

- **Input:** bundle manifest (its BW-MEMBER set)
- **Precondition:** always (any bundle)
- **Predicate (PASS iff):** MID non-reuse: within the bundle's UID, no MID may be bound to two BW-MEMBER documents carrying different accountability.authorisation_ref values. A MID is a permanent attribution key in indefinitely-retained evidence; reassigning it to a different member/authorisation chain would silently re-attribute old confirmations. Checked across ALL members (any status), which also surfaces the duplicate-MID case the active-member map would otherwise silently collapse.
- **Error outcome:** MID {mid!r} is bound to two different accountability.authorisation_ref ({a!r} and {b!r}) — a MID MUST NOT be reassigned to a different member/authorisation chain within a UID (X-17)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_mid_lifecycle.py`

### LINT-BND-24 · `core`

- **Input:** bundle manifest (its evidence recipient_addr addresses)
- **Precondition:** always (any bundle); evaluated for each evidence object (and each EP's embedded se) carrying a recipient_addr
- **Predicate (PASS iff):** Address resolution: a recipient_addr MUST be a well-formed bw: address (umbrella Annex A). When it is addressed to this bundle's entity, a role address (.../r/<role>) MUST name a declared role of the entity's BW-ORG (its roles[], acceptance_policy keys, or any scope roles/records_role), and a member address (.../u/<MID>) MUST name a published member — so every address resolves. (Schema tightening already guarantees the converse: every declared role is addressable.). The address's UID MUST equal the UID of the object it addresses. This was a bare `continue` commented "addressed to a different entity — not this bundle's org" — true, irrelevant, and exactly wrong: the object is THIS bundle's evidence addressed to THIS entity, so a foreign UID is the defect, not someone else's business. Selection read only the /r/<role> tail, so an address naming another entity selected a role out of this entity's acceptance_policy map.
- **Error outcome:** {type} recipient_addr {addr!r} is not a well-formed bw: address (X-16) | {type} recipient_addr names role {role!r}, not a declared role of {entity!r} — an address MUST resolve to a declared role (X-16) | {type} recipient_addr names member {mid!r}, not a published member of {entity!r} (X-16)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_address_entity_binding.py`, `test_bw_address.py`, `test_helper_integration.py`

### LINT-BND-25 · `four-corner`

- **Input:** bundle manifest (RelayEvidence hops vs the SE / EP-embedded SE)
- **Precondition:** a RelayEvidence-v1 in the bundle shares its message_id with an SE (standalone or EP-embedded) carrying envelope_hash
- **Predicate (PASS iff):** Evidence 2.2: a relay hop's envelope_hash MUST equal the SE's for the same message_id — each hop attests the exact TLS-serialized MLSMessage octets it handled, so a substituted ciphertext under unchanged metadata fails at every hop.
- **Error outcome:** relay hop for {message_id!r} attests a different envelope_hash than the SE — substituted ciphertext under the same metadata (F-02)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_envelope_chain.py`

### LINT-BND-26 · `core`

- **Input:** bundle manifest (GCM-v1 objects, standalone or EP disputes[], vs the ORG and the sealed SE/DE)
- **Precondition:** a GCM-v1 in the bundle is pinned to THIS bundle's ORG policy_version and carries a reveal
- **Predicate (PASS iff):** Evidence 2.7, rewritten: a grade-mismatch dispute is valid only when BOTH (a) PROOF OF ATTRIBUTION holds — the reveal_confirmation verifies against the disputing device's published confirmation_key as of read_at (INTF-1/1a/2) and its signed tuple (message_id, envelope_hash, grade_commitment, salt, content_class, read_at, recipient_uid, mid) matches the disputed evidence — AND (b) MISMATCH holds — the recomputation differs from the sealed commitment, or it matches but the revealed class is not availability-declared. The former rule accepted (b) alone; inequality is manufacturable by inventing a salt, so any recipient provider could rebut any availability-grade DE. Malformed commitment input yields a TYPED violation, never an uncaught exception in the validator. Scope: (a) proves an attributable assertion, not objective extraction from the ciphertext. The member's standing is resolved AT THE ACT, not from the current roster. The act-time resolver was added BESIDE this gate rather than replacing it, so the gate went on deciding attribution from today's membership.
- **Error outcome:** dispute without a verifying recipient confirmation, a signed tuple not covering the disputed values, malformed commitment input, or a void (matching + availability-declared) reveal (DR-03)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_gcm_proof_model.py`, `test_grade_mismatch.py`, `test_no_current_state_gates.py`

### LINT-BND-27 · `core`

- **Input:** bundle manifest (SEs addressed to this entity vs the ORG max_ttl)
- **Precondition:** an SE (standalone or EP-embedded) addressed to this entity carries sent_at and expires_at in order
- **Predicate (PASS iff):** The TTL (expires_at - sent_at) MUST NOT exceed the recipient's declared maximum — BW-ORG.max_ttl (ISO 8601 duration, days/time designators), absent = the profile default P30D.
- **Error outcome:** SE for {message_id!r} carries a TTL of {ttl} — beyond the recipient's maximum {max_ttl} (X-22: expires_at is validated against policy, not echoed)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_expiry_validation.py`, `test_intake_expiry.py`

### LINT-BND-28 · `core`

- **Input:** assembled bundle (entity, med, org, members, evidence)
- **Precondition:** an evidence object has type == SE-v1 AND sender_uid == entity_uid AND sender_confirmation is present
- **Predicate (PASS iff):** D4 (evidence 2.3): the sender-side mirror of LINT-BND-21 (INTF-1b). The sender_confirmation's mid MUST resolve to an ACTIVE member of the sender entity, and its wallet signature MUST verify against that member's published confirmation_key anchor per (mid, device_id) — so a provider cannot mint 'the sender authorised these bytes' under its own key. Fail-closed on unknown mid, no resolvable anchor, or a non-verifying signature. The member's standing is resolved AT THE ACT, not from the current roster. The act-time resolver was added BESIDE this gate rather than replacing it, so the gate went on deciding attribution from today's membership.
- **Error outcome:** sender_confirmation mid unknown to the sender entity, no (mid, device_id) anchor, or a signature that does not verify against the published confirmation key (X-03/D4)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_no_current_state_gates.py`, `test_sender_confirmation.py`

### LINT-BND-29 · `core`

- **Input:** assembled recipient bundle (entity, med, org, members, evidence)
- **Precondition:** an evidence object has type == RE-v1 AND refusal_kind == 'member'
- **Predicate (PASS iff):** Evidence 2.3: a member refusal is an attributable act. The refusing mid MUST resolve to an ACTIVE member of the recipient entity (no ack capability required — declining is not acknowledging), and a wallet-signed refusal_confirmation MUST verify against the member's published confirmation_key anchor resolved per (mid, device_id) from BW-MEMBER — the same finding-D machinery as an acceptance, so a provider cannot mint 'the user refused' under its own key. Fail-closed on no device_id, no resolvable anchor, or a non-verifying signature. The member's standing is resolved AT THE ACT, not from the current roster. The act-time resolver was added BESIDE this gate rather than replacing it, so the gate went on deciding attribution from today's membership.
- **Error outcome:** refusing mid unknown/inactive, no (mid, device_id) anchor, or a refusal_confirmation signature that does not verify against the published confirmation key (X-29)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_no_current_state_gates.py`, `test_refusal_identity.py`

### LINT-BND-30 · `core`

- **Input:** assembled bundle (entity, med, org, members, evidence)
- **Precondition:** an evidence object's acceptance_policy_ref.doc_digest pins THIS bundle's BW-ORG
- **Predicate (PASS iff):** Evidence 2.4: the evidence names the EXACT policy selected, recomputably. (a) acceptance_policy_ref.policy_key MUST exist in the pinned ORG's acceptance_policy map; (b) where the message's SE is available (in the bundle, or the enclosing EP's), policy_key MUST equal the deterministic umbrella §8.3 selection recomputed from the SE's (scope_ref, recipient_addr) and the ORG (lint_cli.select_policy_key — scoped: the scope's acceptance_policy_ref key; default-scope role-addressed: the role's key else 'default'; entity-addressed: 'default'); (c) a DE carrying acceptance_policy_kind MUST carry the kind of acceptance_policy[policy_key]. Two keys in one BW-ORG can never produce indistinguishable evidence. The recomputation FAILS CLOSED where the SE carries no `recipient_addr` — absence used to resolve to 'default' exactly as an explicit entity address did, so the recomputation confirmed a downgrade rather than catching it (it used the same stripped input).
- **Error outcome:** policy_key unknown to the pinned ORG, differing from the recomputed selection, or a DE kind differing from the keyed policy (F-08)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_explicit_addressing.py`, `test_policy_key_evidence.py`

### LINT-BND-31 · `core`

- **Input:** assembled bundle (entity, med, org, members, evidence)
- **Precondition:** a B.2-RelayRejection RelayEvidence and the sender-side NDE for the same message_id are both in the bundle
- **Predicate (PASS iff):** The translated NDE is a RELAY-stage outcome — it follows the sender-side A.1 SubmissionAcceptance, so its event MUST be B.3-RelayFailure. An A.2-SubmissionRejection here makes the EP's timeline read as accepted-then-rejected-BEFORE-submission — chronologically invalid when the EP is read alone. Complements LINT-BND-19 (which binds the reasons); the mapping is the TS clause 4.1 table, documented as a translation pending standards-owner (ETSI TC ESI) review.
- **Error outcome:** sender NDE translating a B.2 RelayRejection carries a non-relay-stage event (X-28)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_relay_stage_event.py`

### LINT-BND-32 · `core`

- **Input:** assembled bundle (entity, med, org, members, evidence)
- **Precondition:** two device records anywhere in the member set carry a confirmation_key
- **Predicate (PASS iff):** Confirmation-key uniqueness across the whole member set — the same public key on two (mid, device_id) records, across devices, members or entities, makes a signature resolve to more than one device and security class; device-bound assurance collapses. Fail-closed.
- **Error outcome:** a confirmation key shared by two device records in the bundle (X-32)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_key_uniqueness.py`

### LINT-BND-33 · `core`

- **Input:** assembled bundle (entity, med, org, members, evidence)
- **Precondition:** an evidence object's acceptance_policy_ref.doc_digest pins THIS bundle's BW-ORG, and the governing SE carries sent_at
- **Predicate (PASS iff):** The pinned version was IN FORCE at the act. (a) BW-ORG.valid_from <= SE.sent_at; (b) for a scoped message, the matched scope_map entry's valid_from <= SE.sent_at (a scope can be introduced into an already-in-force ORG, so the arms are independent). Deterministic selection and a recomputable selected key did not, by themselves, bound the version in TIME, so evidence could be evaluated under rules that did not yet exist when the act took place. Parsed instants; a tie (valid_from == sent_at) is in force.
- **Error outcome:** evidence pins a BW-ORG in force from {vf} for a message sent at {sent} | evidence is scoped to {sid} v{ver} in force from {svf} for a message sent at {sent} (DR-04, umbrella §8.3)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_intake_obligations.py`, `test_policy_in_force.py`, `test_policy_maximality.py`, `test_release_probes.py`

### LINT-BND-34 · `core`

- **Input:** assembled bundle, plus (optional) a per-MID BW-MEMBER version history and the ROSTER-v1 snapshot covering the evidence epoch
- **Precondition:** a confirmation names (mid, device_id) — sender, s3/acceptance, wallet-signed quorum entry, member refusal, or GCM reveal
- **Predicate (PASS iff):** The member version AND the device key are resolved AS THEY STOOD AT THE ACT (sent_at / verified_at / read_at / refused_at per object), not as they stand now. (a) exactly ONE history version is in force at the act — overlapping windows, a history that does not cover the act, and unparsable bounds are REJECTED rather than resolved by manifest order; (b) where a ROSTER-v1 snapshot covers the epoch, the selected version's digest MUST equal the snapshot's member_doc_digest; (c) device.added_at <= act_time and any removal boundary is honoured, so a key minted after the fact cannot anchor an earlier act. Without a history the bundle's single current version is used, so an old-style bundle behaves as before while (c) still runs.
- **Error outcome:** ambiguous/uncovered/unparsable member history for {mid} at {act} | selected version disagrees with the signed ROSTER member_doc_digest | device {device_id} was added after (or removed before) the act (DR-11)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_historical_resolution.py`

### LINT-BND-35 · `core`

- **Input:** assembled bundle, plus (optional) the ordered BW-ORG policy history from the manifest
- **Precondition:** an evidence object's acceptance_policy_ref pins THIS bundle's BW-ORG and the governing SE carries sent_at
- **Predicate (PASS iff):** The pinned policy version was the LATEST one in force at the act. Windows are [valid_from, successor.valid_from) — the upper bound is DERIVED FROM THE CHAIN and MUST NOT be stored. Storing it created a deadlock for the ordinary publication, because a published BW-ORG is pinned by content: leaving v1 unbounded made this rule reject it, and bounding it changed its digest so evidence already pinning the document stopped resolving. Both branches were closed. With a chain: no duplicate valid_from boundaries, no stored valid_until, predecessors named by policy_version AND content digest, and the pinned version equal to the latest whose derived window contains sent_at. The digest chain makes a fork VISIBLE WHEN BOTH DOCUMENTS ARE OBSERVED; it does not prevent equivocation. A PREFIX is not a history. Every `supersedes` must resolve to another document in the supplied set and the earliest must be a first publication with none — a fragment presented as a history is a FAIL, because the claimant chose what to show and the documents themselves say a version is missing. An earlier rule guarded ABSENCE and left truncation open: the fix had been applied to the reproduction rather than to the class. NOT the rule first proposed (the head must equal the manifest's `org`), which cannot fire — LINT-BND-10 already forces that org to BE the pinned document.
- **Error outcome:** pinned version was superseded before the act | duplicate valid_from | stored valid_until | unlinked or equivocated succession | a later version was in force (R3-02/R4-02)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_policy_maximality.py`

### LINT-BND-37 · `core`

- **Input:** assembled bundle; every evidence object (and EP-nested SE) carrying sender_addr
- **Precondition:** the object carries both sender_addr and sender_uid
- **Predicate (PASS iff):** The SENDER arm, which did not exist — `sender_addr` appeared zero times in bundle_lint. (a) sender_addr is a well-formed bw: address; (b) its UID EQUALS sender_uid, or the signed act names an entity it does not belong to; (c) where this bundle is the sender's, a role or member in the address resolves on this roster, mirroring LINT-BND-24. An address is only as good as its binding to the identity it claims, and having that binding on one side only is the asymmetry the finding names.
- **Error outcome:** sender_addr malformed | names an entity that is not sender_uid | names a role/member that does not resolve (R4-01)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_address_entity_binding.py`

### LINT-BND-38 · `core`

- **Input:** assembled bundle plus (optional) retained DS delivery receipts, {message_id: receipt}
- **Precondition:** a receipt is supplied for a message in this bundle
- **Predicate (PASS iff):** A retained DS receipt is resolved against the DS operator's published `ds_receipt_keys` and VERIFIED against the resolved key — the verifier reaches its own verdict instead of taking RDP(out)'s word. An earlier round published the keys and mock_rdp resolved them, then verified by re-deriving the demo key from `kid` and a hard-coded seed, so the resolved public key was never used and substituting it changed nothing. A VALID SIGNATURE IS STILL NOT ENOUGH: the COSE payload is EMBEDDED, so the signature covers the bytes inside the structure, not the object presented beside it — moving `server_time` on the outer receipt left the signature perfectly valid while the receipt asserted a delivery instant nobody had signed. Every asserted field must EQUAL the signed payload, as LINT-DE-19 compares the D4 tuple with its SE. This rule and the live issuing path are ONE implementation (`lint_cli.verify_ds_receipt`); they were two, and the payload comparison landed in this one only, so the paths disagreed about what a receipt proves. The key is resolved at the receipt's own SIGNED `server_time`, which means the payload is parsed before it is authenticated — everything read first is untrusted and only selects what must verify. LIMIT: a party holding a DS key that WAS valid in a past window can mint a receipt dated inside it; that is inherent in retention-era verification and the counterweight is DS key management and revocation, which stays external.
- **Error outcome:** no ds_kid/server_time | no published keys | unresolvable or out-of-window kid | algorithm disagreement | the signature does not verify against the published key | an asserted field differs from the SIGNED payload (R4-03)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_production_signature_claims.py`

### LINT-BND-39 · `core`

- **Input:** assembled bundle; every confirmation whose device publishes an x5chain
- **Precondition:** the resolved device carries confirmation_key.x5chain and the act has a time
- **Predicate (PASS iff):** The leaf certificate holds the published confirmation key AND was within its own validity AT THE ACT. `check_certificate_binds_key(..., at=)` existed already and the one production call omitted `at`, so the validity-at-the-act half was reachable only from its own test. It runs on the anchor-resolution path because that is the path that knows WHEN — discovery lint sees a document, not an event. SCOPE: this is the certificate's OWN window. Path validation to a trust anchor, QSealC qualification, revocation and SCD policy are the EXTERNAL production trust model and remain Partial.
- **Error outcome:** the confirming device's certificate does not hold at the act (R4-04)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_production_signature_claims.py`

### LINT-BND-40 · `core`

- **Input:** assembled bundle plus the retained GroupContext octets named by the manifest's `group_contexts` file, {(mls_group_id, mls_epoch): bytes}
- **Precondition:** a retained GroupContext is supplied for a group the evidence references
- **Predicate (PASS iff):** The pinned cipher-suite decision is RECOMPUTED, not read. An earlier round put the decision into `sbm_group_params` so `mls_state` would commit to it, and the only decoder lived inside a test — so the bytes were pinned and the DECISION THEY ENCODE was never checked. Hashing the GroupContext proves those bytes were retained; a creator could commit a self-consistent but FALSE or DOWNGRADED record and a verifier would validate the hash rather than the selection rule. Checked: the record names the registry's vector and floor; `selected_suite` EQUALS the GroupContext's actual cipher suite; the device raises match the addressable participants' published values EXACTLY (none invented, omitted, duplicated or stale); `effective_floor` is the MAXIMUM of the mandatory floor and those raises; and the selection is not below it. RETENTION: everything is judged against the material the record pins — its own `floor_version` — because checking a historical decision against today's registry is exactly how registry evolution would invalidate a correct one. The material now REACHES this rule. The first version of this rule added the parameter to check_bundle and never passed it from lint_bundle, and no manifest carried the bytes, so the rule was reachable only from a hand-built unit test. Every positive bundle now retains the GroupContext whose hash its evidence already pins as mls_state, so retaining it adds no trust — it lets the decision be RECOMPUTED rather than merely committed to. SCOPE: the strongest-usable arm needs the per-device package availability AT FORMATION, and the pool it describes is long gone by the time a bundle is verified — so it runs over the availability the retained formation records, and without that formation the whole recomputation is INCOMPLETE (LINT-BND-I5), not partially run. Two further defect classes: the map key was taken on TRUST — the context's own group id and epoch were never decoded and compared, and the bytes were never hashed against the evidence commitment, so a valid context from a FOREIGN group filed under this key produced no finding: the evidence committed to one state while the verifier inspected another. Now every committed (group, epoch) must have exactly one retained context, its hash must equal the commitment, its decoded identity must equal the key, and an extra context nothing commits to is reported rather than silently inspected. Raises, publications and availability are keyed by the device's WHOLE principal (uid, mid, device_id) — keyed by (mid, device_id), two entities' equal labels collided and member order decided the verdict. The members and availability recomputed over are the retained formation the record's `inputs_digest` commits to, never the members a verifier holds today.
- **Error outcome:** no sbm_group_params in the retained context | undecodable | selected_suite is not the group's suite | invented, omitted, duplicated or stale device raise | effective_floor is not the maximum | the selection is below the floor or is not the strongest usable (R4-06)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_group_params_semantics.py`, `test_historical_suites.py`, `test_publication_gates.py`, `test_round11_closure.py`, `test_round12_closure.py`, `test_suite_formation.py`

### LINT-BND-41 · `core`

- **Input:** assembled bundle, the recipient BW-ORG, the entity roster and the counterparty roster
- **Precondition:** an SE-v1 is present
- **Predicate (PASS iff):** The submission's identity statements must name ONE entity, member, role and authorisation state — and this is THE SAME resolver intake runs (`lint_cli.check_identity_coherence`), because the finding exists at all through a check that lived on one side of a boundary. Checked: recipient_uid == uid(recipient_addr) == the governing BW-ORG's uid; sender_uid == uid(sender_addr) == the signing BW-MEMBER's uid; a /u/<mid> sender address names the member that SIGNED and a /r/<role> address a role that member holds; the signing member is active at the act and the signing device exists, is not removed, and declares the `sign` capability at that instant; and the exact scope descriptor (id AND version) was in force. The earlier rule verified each statement individually and never compared them, so a RE-SIGNED tuple naming a German recipient_uid with a French recipient_addr and BW-ORG was accepted, transported and SEALED. A valid signature authenticates a contradiction; it does not make it true.
- **Error outcome:** identity-incoherent | member-not-active | device-not-sign-capable | device-not-in-force | no-matching-scope | scope-not-in-force (R6-01)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_intake_obligations.py`

### LINT-BND-I1 · `core`

- **Input:** assembled bundle whose evidence pins this BW-ORG, with NO policy history supplied
- **Precondition:** acceptance_policy_ref pins this bundle's BW-ORG and the governing SE carries sent_at
- **Predicate (PASS iff):** Formerly LINT-BND-W2, a WARNING. Maximality is NOT PROVEN and the verification says so — and SAYING SO IS NOT SUCCESS. Without a chain a verifier can show the pinned version was in force at the act; it cannot show it was the LATEST such version, which is the property that decides which policy governs the message. An earlier fix made the outcome typed instead of a silent early return, and left the release bar untouched in as many words ('requiring the full chain inside every bundle is a separate decision nobody has taken') — so four shipped positive bundles printed MAXIMALITY IS NOT PROVEN, then '[OK] ✓', then exit 0, with `make conformance` green over all of them. The decision taken: INCOMPLETE is a THIRD verdict. It is not a violation — nothing is wrong with the evidence — and it is not a pass: no [OK], exit 3. SCOPE: a retained chain proves linkage and LOCAL maximality only. Proving no further successor exists needs an authenticated head, i.e. a log, i.e. the same missing primitive as key transparency, so that residual is recorded as the key-transparency gap and is NOT closed here.
- **Error outcome:** no policy history for the pinned BW-ORG: the verification is INCOMPLETE, not a pass (R5-02)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`, `test_policy_maximality.py`, `test_release_probes.py`

### LINT-BND-I2 · `core`

- **Input:** assembled bundle whose SE-v1 carries a sender_confirmation, with NO counterparty roster
- **Precondition:** the signing member is not among the supplied members or member history
- **Predicate (PASS iff):** The SENDER's roster is the sender ENTITY's discovery document, and a recipient-side bundle carries the recipient's. Without it the sender-side half of the identity tuple is UNDECIDABLE from the retained material — so it is reported INCOMPLETE (the INCOMPLETE verdict) rather than passed over, and rather than failed as though the member were absent from its own entity's roster. Supply `counterparty_members`; that is what lets a verifier check the sender's side years later.
- **Error outcome:** the sender-side identity tuple cannot be checked from this material (R6-01)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_intake_obligations.py`, `test_release_probes.py`

### LINT-BND-I3 · `core`

- **Input:** assembled bundle with a structurally complete BW-ORG chain
- **Precondition:** the chain resolves, is unbroken back to a first publication, and the pinned version is in force at the act
- **Predicate (PASS iff):** Linkage and in-force are proven; MAXIMALITY IS NOT. The truncation that defeats maximality is a hidden SUCCESSOR, not a dropped predecessor — if the entity published v2 before the act and the claimant supplies [v0, v1], every backward link resolves, the chain is structurally perfect, and the verifier concludes v1 was latest. A complete chain and a successor-truncated chain are BYTE-IDENTICAL from inside the bundle. The earlier rule made the ABSENT history a gap and left the CLAIM overstated: its [OK] asserted a property no local material can establish. This states what is actually proven and leaves the rest with the key-transparency gap, whose scope had already been widened for the same reason. Excluding a later successor needs an authenticated head, which is a log.
- **Error outcome:** maximality is not locally provable; the verification is INCOMPLETE, not a pass (R6-02)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_policy_maximality.py`, `test_release_probes.py`

### LINT-BND-I4 · `core`

- **Input:** assembled bundle whose evidence carries mls_state, with NO group_contexts
- **Precondition:** an evidence object commits to an MLS state
- **Predicate (PASS iff):** The state the evidence commits to cannot be inspected without the retained GroupContext. The first version wired the material from the manifest and left ABSENCE unguarded — removing the key from a positive manifest still printed [OK] and exited 0, while the same manifest without `policy_history` reported a gap. Same verdict machinery, same manifest, one property guarded and one not: the fix had been applied to the reproduction rather than to the class. Declared in docs/required-properties.json, which check_bundle ITERATES, so a property added there fails closed until it is wired.
- **Error outcome:** no retained GroupContext for an evidenced MLS state; the verification is INCOMPLETE (R6-05)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_group_params_semantics.py`, `test_release_probes.py`

### LINT-BND-I5 · `core`

- **Input:** a retained GroupContext carrying sbm_group_params, without the retained formation inputs its v2 decision commits to, or the registry revision it pinned; or a v1 decision
- **Precondition:** the cipher-suite decision is to be recomputed
- **Predicate (PASS iff):** A third defect class: the recomputation needs the per-device KeyPackage availability AT GROUP CREATION and the registry revision as it stood then. `_bnd40` passed only the current roster, so the STRONGEST-USABLE arm never ran from the CLI — a later fixture made every device support the stronger suite and supply a package, direct verification reported the downgrade, and the bundle path reported nothing. Without these inputs the arm cannot run and the bundle says so rather than reporting a verdict it did not reach. A v2 decision is recomputed only from the retained formation (members of both entities and per-device package availability) whose digest it commits to; a v1 decision, which binds no inputs, and a v2 decision whose formation is not retained, are INCOMPLETE — never recomputed from current data.
- **Error outcome:** the suite selection cannot be fully recomputed; the verification is INCOMPLETE (R6-05)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_group_params_semantics.py`, `test_historical_suites.py`, `test_round11_closure.py`, `test_round12_closure.py`, `test_suite_formation.py`

### LINT-BND-I6 · `core`

- **Input:** a bundle with no `federation_register`
- **Precondition:** always: every bundle names at least the issuing provider
- **Predicate (PASS iff):** Batch A / A5. Federation admission (umbrella §13.1) is an independent gate, and the register is a SEPARATE verifier input. Without it the bundle cannot establish that the providers it names were admitted when they acted, so it says so: the verification is INCOMPLETE, not passed. Nothing is wrong with the evidence — the material to decide the question was not supplied. The substantive finding, a provider the register does NOT admit at the instant of its act, is LINT-TRUST-06 and is a violation. Also emitted when a register is supplied but no Federation Authority anchor is configured, and per act that lies after the register's assertion for its provider: in both cases admission is unestablished, not refuted.
- **Error outcome:** that every provider named in the bundle was admitted to the federation at the instant of its act — NOT ESTABLISHED: the bundle carries no `federation_register` (R6-05)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_federation_gate.py`

### LINT-BND-I7 · `core`

- **Input:** assembled bundle whose evidence carries a CE transformation
- **Precondition:** an evidence object carries a CE `transformation`
- **Predicate (PASS iff):** That the outputs a Change-Indication Evidence commits to are the transformation of the input it commits to CANNOT BE ESTABLISHED, and the profile does not claim it. Neither `re-packaging` nor `chunking` is a defined operation: the output commitment is typed `mls10-message`, SHA-256 over a COMPLETE TLS-serialized MLSMessage, which a fragment is not; re-packaging an unchanged message leaves its inner octets untouched, so the output commitment equals the input; and no published contract defines a fragment descriptor, a chunk order, a reassembly operation, or the boundary at which the original message is reconstructed. The seal still establishes WHO attested WHAT; the relation of outputs to input is the gap. Deferred as A15 on the review agenda, with what a definition must pin.
- **Error outcome:** the CE transformation is not established — the outputs are attested, their relation to the input is not
- **Reference implementation:** `check_bundle`
- **Tests:** `test_ce_transformation_deferred.py`

### LINT-BND-W1 · `production`

- **Input:** ORG acceptance_policy entries
- **Precondition:** per acceptance_policy value starting with 'device-class:'
- **Predicate (PASS iff):** WARNING (non-fatal; not counted as a violation): a 'device-class:' policy MUST NOT be used in baseline-profile deployments (it requires the MWAP and device attestation).
- **Error outcome:** acceptance_policy[{key!r}] uses device-class: — MUST NOT be used in baseline-profile deployments; requires the MWAP and device attestation (§8.3)
- **Reference implementation:** `check_bundle`
- **Tests:** `test_bundle_lint.py`
