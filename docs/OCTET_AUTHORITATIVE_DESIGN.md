<!--
SPDX-License-Identifier: CC-BY-4.0
SPDX-FileCopyrightText: 2026 Secure Business Messaging contributors
-->

# The octet-authoritative target — removing JCS from the profile

**Status: LANDED.** The target was approved and the migration M1→M4 has shipped —
evidence `2.0`, BW-MED/ORG/MEMBER `2.0`, umbrella edition `2026-07-22`, JCS
removed from every signing path, the CDDL published at `cddl/sm-mls-erd.cddl`
(PR #17 M1–M3, PR #18 M4/CDDL). This document is preserved as the **standing
design record** — the account of *why* the format was inverted; the Phase-1
analysis and recommendations below are kept verbatim as the historical basis.

**Basis pin:** sbm-spec `51258e5` (post evidence-integrity F1–F7; evidence `1.15`).
Baseline `make conformance` green (404 tests, 30/30 samples). Branch
`feature/octet-authoritative`.

**Provenance.** An external review objected to RFC 8785 (JCS). A first analysis
proposed a staged reduction (the "J0–J5" memo). A **second review corrected that
analysis on five substantive points (C1–C5 below); this document carries the
corrected position and supersedes the first.** In particular it retracts two
claims of the first memo: that forbidding decimals ("J0") neutralises the number
hazard (C1 — it does not), and that a length-prefixed concatenation is an
adequate encoding for the constructed inputs (C3 — it is not).

**Sequencing (changed).** This decision now comes **before** the CDDL cycle
(`CLAUDE_CODE_HANDOFF_SPEC_CDDL.md`), not alongside it. If the destination is an
octet-authoritative artefact whose COSE payload is CBOR defined by CDDL, then
authoring CDDL now against the current JSON+COSE duplication and inverting later
pays twice. It still runs *after* evidence-integrity (F1–F7, landed). Once this
lands, the CDDL cycle becomes the vehicle that defines the authoritative payload.

---

## 1. The objection, stated fairly

- **RFC 8785 (JCS) is an Independent Submission, Informational** — not Standards
  Track, no IETF consensus. That alone does not make it unfit; the real risks are
  its **data model** (§3, C1) and the **quality of implementations** (thin
  wrappers over a library serialiser drift between versions; lenient parsers
  silently normalise malformed input).
- **COSE already signs an exact `bstr` payload** (RFC 9052). Keeping a second,
  *authoritative* JSON representation alongside the signed bytes creates
  duplication and a permanent reconciliation burden — which is precisely why
  `LINT-PKG-06` (`evidence_lint.py:135`) and `LINT-DISC-07` (`discovery_lint.py:97`)
  had to be written: they exist only to police that the two representations agree.
- **The mainstream position is "sign the bytes you transmit"** (JOSE/JWS), with
  the XML-DSig / c14n signature-wrapping history as the cautionary precedent for
  signing a *re-serialised structure* rather than the octets.

The profile does not need JCS to be *wrong* to justify removing it. It needs the
octet-authoritative form to be *better* — fewer moving parts, one authoritative
representation, sharper types — which §5–§6 argue.

## 2. The eight uses — where, what canonicalisation buys, and family

| # | Use | Where | What JCS buys there | Family |
|---|---|---|---|---|
| 1 | Evidence **signed payload** (object − `rdp_cose_b64`/`ep_cose_b64` − `qualified_timestamp`, JCS, COSE) | `mock_rdp._seal`; `evidence_lint._check_payload_binding` | a reproducible byte range for a **derived subset** of the object (two fields excluded) | constructed subset |
| 2 | **EP seal** (`ep_cose_b64`) | `_seal` for EP | same, at bundle level | constructed subset |
| 3 | **Discovery seals** (`doc_cose_b64`) | `reseal_bw`; `discovery_lint._check_doc_seal` | verification after parse/re-serialise; re-seal stability | constructed subset |
| 4 | `acceptance_policy_ref.doc_digest` | `_org_digests`; `bundle_lint` LINT-BND-10 | content-addressing a published BW-ORG version | document digest |
| 5 | **Recipient confirmation** | `mock_rdp._wallet_sign` | a reproducible byte range for the wallet's signature | constructed subset |
| 6 | `payload_hash` `jcs-sha256`/`jcs-sha512` | I-D Mode A | digest is a property of JSON **semantic content**, not one serialisation | bytes-exist / structure-recomputable |
| 7 | **Multipart manifest** (`manifest-sha256`) | I-D Mode C; `evidence_lint.lint_manifest` | sender & recipient build the same manifest structure independently | constructed input |
| 8 | **Commitments** (grade, mandate) | `lint_cli.compute_grade_commitment` / `_mandate_commitment` | a reproducible byte range for a constructed tuple recomputed from a reveal | constructed input |

Two structural facts underlie the whole redesign, both **verified in the repo**:

- **`external_aad` is always empty.** The COSE `Sig_structure` third element is
  `b""` in both the toolkit (`lint_cli.py:212`) and the mock (`mock_rdp.py:99`).
- **The signed payload is duplicated on the wire.** Detached payloads are
  forbidden (LINT-PKG-06 / LINT-DISC-07), so every seal's bytes exist twice —
  inside the COSE `bstr` and outside as the transmitted JSON — and a lint rule
  exists solely to reconcile them.

## 3. The five corrections (settled — applied throughout)

### C1 — forbidding decimals is **not** enough; the integer domain is the defect

JCS serialises numbers through the ECMAScript/IEEE-754 **binary64** domain, in
which not every integer above `2^53 − 1` is exactly representable. The earlier
"J0" (forbid floats) does nothing about this: the hazard is *integers*, not just
fractions.

**Verified in the repo at this pin:**

- `MlsEpoch` is `{"type":"integer","minimum":0}` with **no maximum**
  (`evidence-common.schema.json`), while **MLS defines the group epoch as
  `uint64`** (RFC 9420). An epoch beyond `2^53 − 1` is a legal MLS value that
  the profile's canonical form cannot round-trip exactly.
- There is **not a single `maximum` (or `exclusiveMaximum`) constraint in any
  schema.** Every one of the six integer fields is bounded below and open above:

  ```
  evidence-common  MlsEpoch                 {minimum: 0}      ← MLS uint64
  evidence-common  Manifest.items.length    {minimum: 0}      ← byte count
  bw-member        …leaf_index              {minimum: 0}      ← MLS uint32
  envelope         ttl                       {minimum: 1}      ← seconds
  bw-med           policy.ttl_max_s          {minimum: 1}      ← seconds
  bw-med           policy.max_payload_kb     {minimum: 1}      ← KB
  ```

This is a **latent interoperability defect today**, independent of JCS's removal.
A correct constraint set must:

1. forbid any JSON number outside the safe-integer range `[−(2^53−1), 2^53−1]`;
2. represent genuinely-large counters (above all `mls_epoch`) as **decimal
   strings** — see the C1 decision list, §7;
3. **reject duplicate object keys** (JSON parsers silently keep the last, so a
   duplicate key is a signature-wrapping vector);
4. pin **UTF-8 / Unicode** handling explicitly (well-formed UTF-8, no unpaired
   surrogates, no BOM, a bounded key charset).

### C2 — the timestamp cannot simply move into the COSE unprotected header

Unprotected headers do not participate in `Sig_structure`, so an
independently-authenticated RFC 3161 token *may* live there — but it creates a
**circularity**. Verified: the QTS imprints the **whole COSE_Sign1 bytes**
(`mock_rdp._qts_over_seal`, line 163: `imprint = SHA-256(b64decode(seal))`).
Putting the token inside that same COSE changes the very bytes the token just
imprinted. The clean form is an **outer container**, the QTS a sibling imprinting
the exact, immutable inner COSE:

```
EvidenceArtifact = [
    cose_sign1_bytes,                          ; the immutable inner seal (bstr)
    qualified_timestamp_over(cose_sign1_bytes) ; RFC 3161 token imprinting them
]
```

This is T3. It also *dissolves the two-field exclusion* of use 1/2/3/5: the seal
no longer excludes `qualified_timestamp` (it is a sibling, not a signed field),
and the seal field itself is the container element, not an object property — so
"signed payload = object minus two fields" disappears, and with it the reason JCS
is needed for the seals.

### C3 — transmitting the commitment octets fixes the **hash**, not the **interpretation**

A JSON blob can have a perfectly verifiable hash and *two legal readings*
(duplicate keys, unexpected types, ambiguous number forms). A raw hash over
"whatever bytes were sent" authenticates the bytes but not their meaning.
Constructed inputs therefore need a deterministic **typed** encoding, not merely
a deterministic byte layout. Use **CDDL + deterministic CBOR (RFC 8949 §4.2)**
with **fixed-position arrays** and **domain separation** (§8). This is why a
pure length-prefixed concatenation (the first memo's "J2") is rejected: it fixes
the byte layout but leaves the field *types and ranges* unstated — exactly the
gap C1 shows is already biting the profile.

### C4 — `doc_digest = hash(payload bytes)` is stable only under **byte identity**

A digest over the payload bytes is *not* automatically stable across a re-seal of
the same semantic object: a producer re-serialising with different key order or
whitespace produces different bytes and a different digest. This must be decided,
not left implied. **Decision (§7):** under the octet-authoritative target a
re-seal **MUST reuse the identical payload bytes** — the authoritative artefact
*is* those bytes, so byte-identity is natural, and `doc_digest = SHA-256(payload
bstr)` then identifies the object unambiguously. Until the inversion lands, JCS
supplies that byte-identity by canonicalisation, so `doc_digest` keeps its
current JCS form in the interim.

### C5 — the argument against `raw` (the first memo's "J1") was overstated

If the original payload is retained **as a byte string**, a raw digest is
perfectly recomputable in a dispute. What raw loses is only the ability to
present a *semantically equivalent but differently serialised* JSON — and for
legal evidence, producing the **original** content is preferable to an equivalent
re-serialisation. **So `raw` over original bytes is the better default;
`jcs-sha256` survives only as an OPTIONAL profile** for applications that
genuinely want JSON semantic-equivalence recomputation (T5).

## 4. The target (approved direction — a corrected, gradual J5)

- **T1 — the COSE_Sign1 is the authoritative artefact.** Its bytes are
  authoritative; JSON becomes a **non-authoritative projection** for APIs and
  debugging (decode → view; never re-serialise-then-verify).
- **T2 — the COSE payload is CBOR defined by CDDL.** This is why the CDDL cycle
  now *follows* and defines the authoritative payload.
- **T3 — the qualified timestamp is a sibling / outer object** imprinting the
  exact inner COSE bytes (C2); never a field inside the signed structure.
- **T4 — commitments and the manifest use typed, domain-separated, deterministic
  CBOR** (C3; exact structures in §8).
- **T5 — the application content digest is over the original bytes;**
  `jcs-sha256` remains an optional profile (C5).
- **T6 — during migration, a strict `J0+`** constrains the current JCS-based
  schemas (C1) — above all `mls_epoch`. It **ships first** and is worth doing
  even if T1–T5 slipped: it closes a live defect.

## 5. Options considered and rejected

- **Keep JCS everywhere, add J0+ only.** Cheapest; closes the integer defect and
  answers the number objection. *Rejected as the destination* because it retains
  the JSON/COSE duplication (LINT-PKG-06/07), keeps two authoritative
  representations, and leaves the profile defending an Informational
  canonicalisation with a fragile data model. *Retained as M1* — the constraint
  work is valuable regardless and ships first.
- **Pure length-prefixed concatenation for the constructed inputs** (the first
  memo's J2). Rejected by C3: deterministic bytes without deterministic *types*.
  It would also add a **third** encoding style (JSON + CBOR + concat) when a CBOR
  encoder is already a mandatory dependency (`cbor2`); dCBOR reuses it and adds
  types and ranges.
- **Move the timestamp into the COSE unprotected header** (the first memo's J5
  keystone). Rejected by C2: circular with the imprint. The outer container (T3)
  achieves the same end without the circularity.
- **Transmit the commitment JSON octets and hash them** (the first memo's J5,
  use 8). Rejected by C3: verifiable hash, ambiguous reading. Superseded by typed
  CBOR (T4).
- **The octet-authoritative inversion (T1–T6).** Accepted as the destination:
  one authoritative representation, sign-the-bytes, sharp types, no
  canonicalisation. Its costs (octet storage, decode-to-inspect, four-repo sync)
  are stated in §6 and are cheapest to pay now (pre-production).

## 6. Migration — sequenced, not big-bang

Each step is independently shippable, `make conformance` green at each commit,
with a negative fixture for each new machine-checkable rule. **Every step changes
digests; each states its evidence-version bump and needs a sync cycle in sbm-poc,
sbm-services and sbm-wallet.**

| Step | Content | Breaking? | Evidence version | Downstream |
|---|---|---|---|---|
| **M1 = T6 (J0+)** | safe-integer bound all numbers; `mls_epoch` (and the fields in §7) → **decimal strings**; reject duplicate keys; pin UTF-8/Unicode; `LINT-PKG-09`+ | **Yes** — the string-encoding changes canonical bytes (see below) | `1.15 → 1.16` | all three |
| **M2 = T3** | outer `EvidenceArtifact` container; QTS becomes a sibling over the immutable inner COSE; retire the two-field seal exclusion | **Yes** — artefact structure changes | `1.16 → 1.17` | all three |
| **M3 = T4** | typed deterministic-CBOR commitments + manifest (§8); reveal procedure recomputes over dCBOR | **Yes** — commitment/manifest digests change | `1.17 → 1.18` | all three |
| **M4 = T1/T2/T5** | the inversion proper: COSE `bstr` authoritative, JSON a projection, `payload_hash` default `raw`, `jcs-sha256` optional — **with the CDDL cycle defining the payload** | **Yes** — every digest; major | major bump | all three + CDDL |

**Does M1 alone change any digest?** Yes. Adding a `maximum` to the small integer
fields is pure validation and changes nothing. But the essential fix — encoding
`mls_epoch` as a decimal **string** (`3 → "3"`) — changes the object's canonical
bytes, so every seal over an object carrying `mls_epoch` changes. M1 is therefore
breaking and carries the `1.15 → 1.16` bump. (Bounding `mls_epoch` to `2^53−1`
instead would be *wrong* — MLS legitimately uses the full `uint64` range — so the
string encoding, not a maximum, is the correct fix.)

**Timing.** The profile is **pre-production**: no qualified evidence has been
issued, no legal presumption is in play. This is the cheapest moment there will
ever be to break the format **once, deliberately**, rather than repeatedly by
drift — and doing it before the CDDL cycle means CDDL describes the destination,
not an interim shape.

## 7. Decisions to confirm in this Phase 1

### C1 decision list — which integer fields become decimal strings

`safe_max = 2^53 − 1 = 9007199254740991`. Decimal-string pattern:
`^(0|[1-9][0-9]*)$` (no leading zeros, no sign, no exponent), with a digit-length
bound per field.

| Field | Today | Decision | Why |
|---|---|---|---|
| `MlsEpoch` (`mls_epoch`) | `integer, min 0`, no max | **decimal string**, ≤ 20 digits (`uint64`) | MLS `uint64` (RFC 9420) — the actual defect; genuinely exceeds `2^53` |
| `Manifest.items.length` | `integer, min 0` | **decimal string**, ≤ 20 digits (`uint64`) *(recommended)* | a byte count has no natural sub-`2^53` cap; future-proof and typed. Alt: bounded integer `≤ safe_max` if the WG prefers |
| `…mls_leaf_node_ref.leaf_index` | `integer, min 0` | **bounded integer**, add `maximum: 4294967295` | MLS leaf index is `uint32` — always safe |
| `envelope.ttl` | `integer, min 1` | **bounded integer**, add `maximum: 4294967295` | seconds; ~136 yr ceiling, far below `2^53` |
| `bw-med policy.ttl_max_s` | `integer, min 1` | **bounded integer**, add `maximum: 4294967295` | seconds |
| `bw-med policy.max_payload_kb` | `integer, min 1` | **bounded integer**, add `maximum: 4294967295` | KB; ~4 TB ceiling |

Plus a **global** lint rule (extending the float check): reject any JSON number
that is not a safe integer, and reject a duplicate object key. The one genuine
judgment call is `Manifest.length` (string vs bounded integer); the recommendation
is **string** for type-uniformity with `mls_epoch` and future-proofing.

### C4 decision — re-seal stability

**Require byte-identical re-seal.** A re-seal MUST reuse the identical payload
bytes; `doc_digest`/seal digests then identify the object unambiguously. In the
interim (pre-M4, JSON still authoritative) JCS provides that byte-identity by
canonicalisation, so use 4 keeps its JCS form until M4; from M4 the payload
`bstr` is authoritative and byte-identity is intrinsic. Written down, not implied.

## 8. Exact CBOR structures for T4 (deterministic CBOR, RFC 8949 §4.2)

Encoding rules (normative for these structures): definite-length arrays and
strings; no floats; integers in shortest form; **deterministic encoding per RFC
8949 §4.2**; domain-separation tag as array element 0; fixed positions (no maps,
so no key-ordering question). `SHA-256` over the dCBOR bytes, lowercase hex.

```cddl
; grade commitment (v2 = deterministic CBOR; v1 was SHA-256(JCS({...})), retired)
grade-commitment-input = [
    dst           : "sm-mls:grade-commitment:v2",  ; tstr, fixed
    salt          : bstr .size 16,                 ; the E2EE grade_commitment_salt (raw 16 bytes)
    content_class : tstr,
    grade         : tstr,                           ; "availability"
    org_digest    : bstr .size 32,                 ; SHA-256 of the BW-ORG signed payload
]
grade_commitment = base16( SHA-256( dCBOR(grade-commitment-input) ) )

; mandate commitment
mandate-commitment-input = [
    dst           : "sm-mls:mandate-commitment:v2",
    salt          : bstr .size 16,
    mandate_id    : tstr,
    content_class : tstr,
    org_digest    : bstr .size 32,
]
mandate_commitment = base16( SHA-256( dCBOR(mandate-commitment-input) ) )

; multipart manifest (typed; digests over decoded octets)
manifest = [ + manifest-part ]
manifest-part = [
    part_id    : tstr .regexp "[A-Za-z0-9._-]{1,64}",
    role       : &( body: 0, attachment: 1, evidence-bundle: 2, signature: 3, metadata: 4 ),
    media_type : tstr,
    length     : uint,          ; safe-range byte count (see §7); dCBOR shortest-form
    digest     : bstr .size 32, ; SHA-256 of the part's decoded octets
]
manifest_digest = base16( SHA-256( dCBOR(manifest) ) )
```

Notes: `salt`/`org_digest` move from hex **text** to raw `bstr` (typed, half the
size) — the reveal discloses the raw bytes, and a verifier hashes the dCBOR
directly. `role` becomes a small typed enum. The manifest MUST remain in byte-wise
ascending `part_id` order (unchanged) so the encoding is canonical.

## 9. Security Considerations note (draft for the I-D)

> **Canonicalisation decision.** Earlier revisions relied on RFC 8785 (JCS), an
> Independent-Submission, Informational canonicalisation, for every signed byte
> string. This profile removes that dependency in favour of an
> octet-authoritative design: the COSE_Sign1 (RFC 9052) is the authoritative
> artefact, its payload is deterministic CBOR (RFC 8949 §4.2) described by CDDL,
> the qualified timestamp is an outer sibling imprinting the immutable inner COSE
> (avoiding the imprint circularity of an in-COSE token), and constructed inputs
> (commitments, manifest) use typed, domain-separated, fixed-position CBOR. The
> data model is I-JSON-restricted to safe-range integers with genuinely large
> counters (e.g. the MLS `uint64` epoch) carried as decimal strings, duplicate
> keys rejected, and Unicode handling pinned — closing a latent defect
> independent of canonicalisation. Application content is digested over the
> original transmitted bytes (`raw`); JSON semantic-equivalence hashing
> (`jcs-sha256`) remains an optional profile. Rationale: one authoritative
> representation removes the JSON/COSE duplication (and the rules that policed
> it), aligns with "sign the bytes you transmit", and gives constructed inputs
> sharp types and ranges.

## 10. Hard rules

Naming (never "eIDAS"); modal verbs per document; no normative duplication (the
commitment construction and the number-model rule each have ONE home);
`make conformance` green at every commit; a **negative fixture per new
machine-checkable rule** (M1: an out-of-safe-range integer and a duplicate key;
M2: a QTS whose imprint does not match the inner COSE; M3: a commitment whose
dCBOR reveal does not verify). Every step is breaking — per-step evidence-version
bump (§6), and sbm-poc / sbm-services / sbm-wallet each need a sync cycle.

---

> **Historical — Phase 1 close (superseded).** The recommendation below was
> accepted and the migration M1→M4 shipped (see the **LANDED** status at the top).
> Retained verbatim as the record of what was proposed.

**Phase 1 ends here. Recommendation: approve the target (T1–T6) and the migration
M1→M4, and authorise implementation to begin with M1 (J0+) — the decimal-string
list of §7 (with `Manifest.length` as a string, the one open call), the
require-byte-identical-re-seal decision of §7/C4, and the CBOR structures of §8.
M1 is breaking (`mls_epoch` becomes a string), evidence `1.15 → 1.16`, three
downstream syncs. Please confirm §7's decisions (especially `Manifest.length`) and
approve M1, or adjust the sequence. No implementation until then.**
