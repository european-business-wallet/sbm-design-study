# SPDX-License-Identifier: MIT
"""F-15 — the profile-2 companion contracts are published and complete.

Former gap, verbatim in the tree: the KeyPackage lifecycle was DESCRIBED
(reserve → commit → release) with no reservation identifier, no idempotency
key, no commit/release operation and no error model; the wallet-RDP and
relay companion contracts did not exist; the evidence byte commitments and
the D4 sender tuple were in no normative submission contract; the F-09
receipt acknowledgement and the F-03 retained reads had no API home.

Now: three companion contracts (v1.0.0, versions.json-governed) — every
named gap asserted below, and the acceptance's "reservation timeout and
idempotent commit have wire-level tests" expressed at the contract's
semantic layer (the declared operations, idempotency and typed expiry).
The two-implementation interop re-run is the downstream sync
(sbm-poc/sbm-services).
"""
import json
import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]

WR = yaml.safe_load((ROOT / "wallet-rdp-openapi.yaml").read_text())
DS = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
RL = yaml.safe_load((ROOT / "rdp-relay-openapi.yaml").read_text())


def _resolve(doc, schema):
    """R9-B6: response bodies are NAMED components now — an inline schema is
    one nothing can reference and therefore nothing validates against. Follow
    the `$ref` so these assertions test the shape rather than where it is
    written."""
    if isinstance(schema, dict) and "$ref" in schema:
        return doc["components"]["schemas"][schema["$ref"].rsplit("/", 1)[1]]
    return schema


def test_the_three_contracts_exist_and_are_versioned():
    for spec in (WR, DS, RL):
        # DR-02 reshaped the submission (1.1.0); DR-10 the DS receipt (1.2.0);
        # DR-07/DR-08 were breaking (2.0.0); R3-01 adds two REQUIRED
        # submission fields (2.1.0). One shared dimension, so all three move.
        expected = json.loads((ROOT / "versions.json").read_text())[
            "dimensions"]["companion_contracts"]["value"]
        assert spec["info"]["version"] == expected
        # DR-09: `startswith("3.")` is the check that let two structurally
        # INVALID documents ship green. The exact dialect is pinned here and
        # the documents are meta-validated in tests/test_openapi_validity.py.
        assert spec["openapi"] == "3.1.0"


# ---------------------------------------------------------------------------
# The reservation lifecycle is COMPLETE (every named gap of the finding)
# ---------------------------------------------------------------------------

def test_the_reservation_model_has_every_formerly_missing_piece():
    res = DS["paths"]["/keypackages/{uid}/reservations"]["post"]
    # the idempotency key
    idem = next(p for p in res["parameters"]
                if isinstance(p, dict) and p.get("name") == "Idempotency-Key")
    assert idem["required"] is True
    assert "SAME reservation" in res["description"]
    # the reservation identifier
    schema = DS["components"]["schemas"]["Reservation"]
    assert "reservation_id" in schema["required"]
    assert "expires_at" in schema["required"]          # the TTL
    # the commit and release operations
    assert "post" in DS["paths"]["/reservations/{reservation_id}/commit"]
    assert "delete" in DS["paths"]["/reservations/{reservation_id}"]
    # the error model
    assert "Error" in DS["components"]["schemas"]


def test_wire_level_idempotent_commit_and_timeout_semantics():
    """The acceptance criterion at the contract's semantic layer."""
    commit = DS["paths"]["/reservations/{reservation_id}/commit"]["post"]
    assert "IDEMPOTENT" in commit["description"]
    assert "SAME\n        result" in commit["description"] or \
        "SAME result" in " ".join(commit["description"].split())
    assert "409" in commit["responses"]
    assert "reservation-expired" in commit["responses"]["409"]["description"]
    release = DS["paths"]["/reservations/{reservation_id}"]["delete"]
    assert "idempotent" in release["description"].lower()


def test_per_suite_pools_and_quotas():
    avail = DS["paths"]["/keypackages/{uid}"]["get"]["responses"]["200"]
    body = _resolve(DS, avail["content"]["application/json"]["schema"])
    assert "suites" in body["required"]                 # N-03 per-suite counts
    res = DS["paths"]["/keypackages/{uid}/reservations"]["post"]
    assert "429" in res["responses"]                    # R7 per-peer quota
    assert "keypackage-pool-exhausted" in res["responses"]["409"]["description"]


# ---------------------------------------------------------------------------
# The submission contract carries the stabilized evidence inputs
# ---------------------------------------------------------------------------

def test_the_submission_metadata_is_evidence_complete():
    sub = WR["components"]["schemas"]["SubmissionMetadata"]
    # DR-02: the OCTETS are required; the commitments are RDP-computed, so
    # envelope_hash/mls_state are optional cross-checks rather than required
    # sender claims (that requirement is what let RDP(out) attest bytes it
    # never saw).
    for field in ("mls_message_b64", "origin_proof", "expires_at",
                  "scope_ref", "payload_hash"):
        assert field in sub["required"], field
    for field in ("envelope_hash", "mls_state"):
        assert field in sub["properties"] and field not in sub["required"], field
    assert "sender_confirmation" in sub["properties"]   # the D4 tuple
    # DR-07: this description used to claim the WALLET computed and signed
    # policy_key while the operation said the RDP computed the deterministic
    # selection. Asserting the word in BOTH places is what let the two
    # statements drift into a contradiction; the owner is stated once, in the
    # operation, and the wallet's input is the ref it signs.
    assert "policy_key" not in sub["description"]
    assert "acceptance_policy_ref" in sub["required"]
    post = WR["paths"]["/submissions"]["post"]
    assert "IDEMPOTENT by message_id" in post["description"]
    assert "duplicate-message-id" in post["description"]


def test_confirmation_delivery_and_evidence_retrieval_exist():
    assert "post" in WR["paths"]["/confirmations"]
    assert "INTF-1" in WR["paths"]["/confirmations"]["post"]["description"]
    ev = WR["paths"]["/evidence/{message_id}"]["get"]
    assert "application/cbor" in ev["responses"]["200"]["content"]   # M4


# ---------------------------------------------------------------------------
# The F-09 / F-03 machinery has its API home; the relay is peer-authenticated
# ---------------------------------------------------------------------------

def test_the_receipt_ack_is_the_s2_event():
    ack = DS["paths"]["/messages/{issuing_rdp_id}/{message_id}/receipt-ack"]["post"]
    assert "F-09" in ack["description"]
    assert "FIRST" in ack["description"] and "idempotent" in ack["description"]
    assert "401" in ack["responses"]                    # session-bound replay


def test_the_retained_material_read_exists():
    ctx = DS["paths"]["/groups/{group_id}/context"]["get"]
    assert "mls_state" in ctx["description"]            # the D3 recompute anchor


def test_the_relay_is_peer_authenticated_and_idempotent():
    scheme = RL["components"]["securitySchemes"]["peerRdpAuth"]
    assert "Trusted Lists AND the federation membership register" in scheme["description"]
    relay = RL["paths"]["/relay/messages"]["post"]
    assert "IDEMPOTENT per (origin RDP, message_id)" in relay["description"]
    assert "post" in RL["paths"]["/relay/messages/{message_id}/result"]
    assert "get" in RL["paths"]["/relay/evidence/{message_id}"]


def test_no_operation_is_anonymous():
    for spec in (WR, DS, RL):
        for path, ops in spec["paths"].items():
            for method, op in ops.items():
                if method in ("get", "post", "delete", "put"):
                    assert op.get("security"), f"{path} {method} lacks security"
