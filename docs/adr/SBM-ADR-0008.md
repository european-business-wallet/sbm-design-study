---
id: SBM-ADR-0008
title: "Octet-authoritative encoding, JSON as a projection"
label: "Octet-authoritative encoding"
decision_status: accepted
implementation_status: [specified, in-reference]
implementation: >-
  specified; in the reference
choice: >-
  the deterministic-CBOR payload is what is signed; JSON is a projection; the qualified timestamp attests the seal from outside ·
  the I-D; [the design record](../OCTET_AUTHORITATIVE_DESIGN.md)
alternative: >-
  signing JSON canonicalised with the JSON Canonicalization Scheme — the model the profile left — and the other options
  [that record rejects](../OCTET_AUTHORITATIVE_DESIGN.md#5-options-considered-and-rejected)
benefit: >-
  the same bytes verify everywhere; nothing is re-canonicalised at verification
cost: >-
  byte retention, binary tooling, debugging through projections — implementers, archivists
open_questions: []
author_questions: []
supersedes: []
---

<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SBM-ADR-0008 — Octet-authoritative encoding, JSON as a projection

## Context

The profile began by signing JSON documents canonicalised at signing and
again at verification. A canonicalisation step at verification is a place
where two conforming implementations can disagree about the bytes a
signature covers, and a number-domain defect in that model was found by
external review.

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

## Alternatives considered

- **Signing JSON canonicalised with the JSON Canonicalization Scheme.**
  The model the profile left: re-canonicalisation at verification is where
  implementations diverge, and the number domain was under-specified.
- **The other options** weighed and rejected in
  [the design record](../OCTET_AUTHORITATIVE_DESIGN.md#5-options-considered-and-rejected),
  which is the authority for the comparison.

## Trade-off

Bytes that verify identically everywhere, at the price of binary tooling,
byte retention and debugging through projections.

## Consequences and residual limit

Implementers and archivists retain and handle bytes; the reference checks
that every sample's authoritative artefact and its projection agree, and a
pre-inversion mechanism reintroduced in prose fails the documentation guard.

## Status

- **Decision:** accepted.
- **Implementation:** specified; in the reference.

## Supersedes

The canonicalised-JSON signing model of the profile's earlier editions,
replaced within the study before any deployment.

## Normative owner

The Internet-Draft, *CBOR Structure Definitions* and the evidence packaging
sections; the CDDL under `cddl/`; the
[design record](../OCTET_AUTHORITATIVE_DESIGN.md) for the reasoning.
