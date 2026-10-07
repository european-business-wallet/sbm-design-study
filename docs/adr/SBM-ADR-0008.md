---
id: SBM-ADR-0008
title: "Octet-authoritative encoding, JSON as a projection"
label: "The signed bytes are authoritative; JSON is a view"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference
choice: >-
  What gets signed is one canonical binary encoding of the object — deterministic CBOR. The JSON everyone reads is a projection of those bytes, not the thing itself. The qualified timestamp attests the seal from outside it rather than sitting within it · the I-D
alternative: >-
  Five, each rejected below: sign the JSON, canonicalised with the JSON Canonicalization Scheme — the model this profile moved away from; keep that scheme but narrow which numbers may appear; build the constructed inputs by length-prefixed concatenation; put the timestamp inside the COSE header; hash the transmitted commitment JSON rather than the canonical bytes
benefit: >-
  The same bytes verify the same way everywhere, and nothing has to be re-canonicalised at verification time — which is where canonicalisation schemes go wrong
cost: >-
  The bytes themselves must be retained, tooling has to handle binary, and debugging happens through a projection rather than the real object — for implementers and archivists
open_questions: []
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0008 — Octet-authoritative encoding, JSON as a projection

## Context

The profile began by signing JSON documents canonicalised with the JSON
Canonicalization Scheme (RFC 8785) at signing and again at verification. A
canonicalisation step at verification is a place where two conforming
implementations can disagree about which bytes a signature covers.

External review then found a concrete defect of that kind in the model. The
scheme represents numbers as IEEE 754 binary64, in which not every integer above
2^53 − 1 is exactly representable. So a legal MLS epoch — a `uint64` — could not
round-trip exactly through the canonical form. Forbidding decimals does not
close that gap.

Three further facts weighed. RFC 8785 is an Informational Independent Submission, not a
standards-track specification with IETF consensus, and its implementations
are thin wrappers over library serialisers that drift between versions. COSE
already signs an exact byte-string payload, so keeping a second,
authoritative JSON representation beside the signed bytes created a permanent
reconciliation burden — two linter rules existed only to police that the two
representations agreed. And the mainstream position, JOSE's included, is to
sign the bytes transmitted; signing a re-serialised structure is the model
whose signature-wrapping history XML-DSig canonicalisation supplied.

## Requirement and constraint

A verifier anywhere, years later, must verify exactly the bytes that were
signed, without re-deriving them; the qualified timestamp must attest the
seal without being inside it; and the machine-readable definition of the
authoritative bytes must be checkable by tooling.

## Decision

The authoritative artefact is a COSE_Sign1 whose payload is deterministic
CBOR defined in CDDL; JSON is a non-authoritative projection of it. Every
evidence object and the evidence package carry one `seal`, in which the
qualified timestamp is a sibling that imprints the immutable inner COSE
bytes. Commitments over transmitted MLS octets and group state are
byte-exact dedicated types.

**Extended 25 September 2026 to the last exception.** The `payload_hash`
modes kept one place where a digest was a property of semantic content rather
than of octets, and `jcs-sha256` / `jcs-sha512` are removed with it. They
hashed a JSON payload after canonicalising it, for applications that had
stored the payload parsed and no longer held its bytes. Every mode the profile
defines digests octets — `raw-*` the transmitted bytes, `manifest-*` a deterministic-CBOR
manifest whose part digests are themselves over octets — and an application
whose original bytes are gone is answered the way this record answers every
other artefact: retain them. Deterministic CBOR is the profile's only
canonicalisation.

## Alternatives considered

- **Signing JSON canonicalised with the JSON Canonicalization Scheme.**
  The model the profile left: re-canonicalisation at verification is where
  implementations diverge, and the number domain was under-specified.
- **Keep the canonicalised-JSON model and tighten it** — forbid decimals,
  constrain every integer field to the safe range, keep everything else.
  Rejected as the destination: it closes the integer defect and answers the
  number objection, but retains the JSON/COSE duplication and its policing
  rules, keeps two authoritative representations, and leaves the profile
  defending an Informational canonicalisation with a fragile data model. The
  tightening was applied anyway, as the first migration step, because it
  closed a live defect.
- **Pure length-prefixed concatenation for the constructed inputs** — the
  commitments and the manifest as concatenated, length-prefixed fields.
  Rejected: deterministic bytes without deterministic *types*, so a verifier
  fixes the hash but not the interpretation; and it would add a third
  encoding style beside JSON and CBOR when a CBOR encoder is already a
  mandatory dependency that gives types and ranges for free.
- **Carry the qualified timestamp inside the COSE unprotected header.**
  Rejected: circular — the timestamp imprints the seal's bytes, so it cannot
  sit inside the structure whose bytes it imprints. A sibling outside the
  sealed bytes achieves the same end without the circularity.
- **Transmit the commitment's JSON octets and hash them.** Rejected: the
  hash becomes verifiable, but the reading of what was hashed stays
  ambiguous; superseded by typed, domain-separated deterministic CBOR for
  every constructed input.

## Trade-off

Bytes that verify identically everywhere, at the price of binary tooling,
byte retention and debugging through projections.

## Consequences and residual limit

Implementers and archivists retain and handle bytes; the reference checks
that every sample's authoritative artefact and its projection agree, and a
pre-inversion mechanism reintroduced in prose fails the documentation guard.

The 25 September extension is **breaking** for any implementation that emitted
a canonicalisation mode: such an artefact is now refused by name (LINT-HASH-01)
rather than ignored, because the profile no longer states a rule by which its
digest could be recomputed. There is no substitute mode; introducing a
deterministic-CBOR mode over the restricted data model would be a new decision
and a new record, not a silent replacement.

## Status

- **Decision:** accepted.
- **Implementation:** specified; in the reference.
- **Amended 25 September 2026**, following an external publication review: the
  canonicalisation hash modes `jcs-sha256` / `jcs-sha512` were removed, and
  RFC 8785 left the profile entirely. The review's argument was that the mode
  was optional for a sender but obligatory for every receiver — a receiver that
  met it without an implementation of the scheme could neither recompute the
  digest nor say so, the profile having no reason code for it.

## Supersedes

The canonicalised-JSON signing model of the profile's earlier editions,
replaced within the study before any deployment.

## Normative owner

The Internet-Draft, *CBOR Structure Definitions* and the evidence packaging
sections; the CDDL under `cddl/`. The migration was planned and sequenced in
a design record of the study, `docs/OCTET_AUTHORITATIVE_DESIGN.md`, which is
historical: this record carries the reasoning, and the migration it describes
is complete.
