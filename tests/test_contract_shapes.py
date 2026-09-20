# SPDX-License-Identifier: MIT
"""DR-07 — the wallet-RDP contract encodes the interoperability claim.

Former defect (round-2 review, High). `SubmissionMetadata` omitted normative
submission fields (`sender_uid`, `sent_at`, `acceptance_policy_ref`,
`sender_addr`, `auth_context`); hashes, scope refs, MLS state and the sender
tuple were unconstrained generic objects; nothing expressed that
`origin_proof = sender-signed` REQUIRES `sender_confirmation`;
`ConfirmationDelivery.confirmation` was a bare object; evidence retrieval
returned one wrapper for either an Evidence Package or an unspecified
"available evidence set" with no discriminator; most objects admitted
arbitrary additional properties. The contract also CONTRADICTED ITSELF on who
computes `policy_key` — the schema said the wallet, the operation said the RDP.

So two independent profile-2 implementations could exchange mutually
incompatible payloads while both claimed conformance to one version.

**And the tests were the other half of the finding**: they asserted the
presence of field names and prose fragments, never that a request or response
actually validates. This module therefore validates REPRESENTATIVE PAYLOADS
against the published contract, resolving its `$ref`s to the authoritative
evidence schemas — which is possible at all because the contracts moved to
OpenAPI 3.1 (R2-M4), whose schemas are JSON Schema 2020-12.
"""
import copy
import json
import pathlib

import pytest
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = yaml.safe_load((ROOT / "wallet-rdp-openapi.yaml").read_text())
SCHEMAS = CONTRACT["components"]["schemas"]

SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
DE = json.loads((ROOT / "samples" / "sample-DE.json").read_text())["projection"]
RE_ = json.loads((ROOT / "samples" / "sample-RE.json").read_text())["projection"]


# ---------------------------------------------------------------------------
# Resolve the contract's $refs against the repository, offline
# ---------------------------------------------------------------------------

def _retrieve(uri):
    """Local-file resolution for `schemas/...` refs — the same tree a client
    generator would be handed."""
    path = ROOT / uri
    if not path.exists():
        raise LookupError(uri)
    from referencing.jsonschema import DRAFT202012 as _D
    return Resource.from_contents(json.loads(path.read_text()),
                                  default_specification=_D)


from referencing.jsonschema import DRAFT202012

# The whole contract is registered as one resource, so an internal
# `#/components/schemas/...` ref resolves exactly as a generator would resolve
# it — the document, not a schema lifted out of it.
CONTRACT_URI = "wallet-rdp-openapi.yaml"
REGISTRY = Registry(retrieve=_retrieve).with_resource(
    CONTRACT_URI, Resource.from_contents(CONTRACT, default_specification=DRAFT202012))


def _validator(name):
    return Draft202012Validator(
        {"$ref": f"{CONTRACT_URI}#/components/schemas/{name}"}, registry=REGISTRY)


def _errors(name, payload):
    return sorted(_validator(name).iter_errors(payload), key=str)


def _valid(name, payload):
    return not _errors(name, payload)


# ---------------------------------------------------------------------------
# A representative submission, built from the shipped SE
# ---------------------------------------------------------------------------

WALLET_SUPPLIED = ("message_id", "sender_uid", "recipient_uid", "scope_ref",
                   "payload_hash", "mls_group_id", "mls_epoch", "auth_method",
                   "auth_context", "sent_at", "expires_at", "origin_proof",
                   "acceptance_policy_ref")


def _submission(**over):
    meta = {k: copy.deepcopy(SE[k]) for k in WALLET_SUPPLIED}
    meta["mls_message_b64"] = "AAEC" * 8
    if SE.get("sender_confirmation"):
        meta["sender_confirmation"] = copy.deepcopy(SE["sender_confirmation"])
    for k in ("recipient_addr", "sender_addr", "grade_commitment", "mandate_ref"):
        if SE.get(k) is not None:
            meta[k] = copy.deepcopy(SE[k])
    meta.update(over)
    return meta


def test_a_representative_submission_validates():
    """The test the review asked for: a real payload against the contract, not
    a list of field names."""
    assert _valid("SubmissionMetadata", _submission()), \
        [e.message for e in _errors("SubmissionMetadata", _submission())]


@pytest.mark.parametrize("field", WALLET_SUPPLIED)
def test_every_full_tuple_field_is_required(field):
    """'reject each missing full-tuple field' — including the four the review
    found absent from the contract entirely."""
    meta = _submission()
    meta.pop(field)
    assert not _valid("SubmissionMetadata", meta), \
        f"{field} may be omitted — the contract does not require it"


def test_the_four_missing_fields_are_now_declared():
    """Named explicitly, because their absence was the finding."""
    for field in ("sender_uid", "sent_at", "acceptance_policy_ref",
                  "sender_addr", "auth_context"):
        assert field in SCHEMAS["SubmissionMetadata"]["properties"], field


def test_the_structured_types_are_not_bare_objects():
    """Each one `$ref`s its authoritative definition, so the contract and the
    evidence schemas cannot drift apart."""
    props = SCHEMAS["SubmissionMetadata"]["properties"]
    for field in ("scope_ref", "payload_hash", "envelope_hash", "mls_state",
                  "sender_confirmation", "acceptance_policy_ref", "auth_context",
                  "mandate_ref"):
        assert "$ref" in props[field], f"{field} is still an untyped object"
        assert props[field]["$ref"].startswith("schemas/"), field


def test_a_structurally_wrong_value_is_rejected():
    """The `$ref`s do work — a malformed hash is caught by the authoritative
    definition, not merely declared to be an object."""
    assert not _valid("SubmissionMetadata",
                      _submission(payload_hash={"alg": "SHA-256", "hex": "zz"}))
    assert not _valid("SubmissionMetadata", _submission(sender_uid="not-a-uid"))


def test_unknown_properties_are_rejected():
    assert not _valid("SubmissionMetadata", _submission(x_private_extension=1))


# ---------------------------------------------------------------------------
# The origin_proof conditional, both arms
# ---------------------------------------------------------------------------

def test_a_sender_signed_submission_without_a_sender_confirmation_is_rejected():
    """The review's own acceptance test. The claim 'the sender signed this' with
    no signature was structurally valid before."""
    meta = _submission(origin_proof="sender-signed")
    meta.pop("sender_confirmation", None)
    assert not _valid("SubmissionMetadata", meta)


def test_a_sender_signed_submission_with_the_tuple_validates():
    meta = _submission(origin_proof="sender-signed")
    assert meta.get("sender_confirmation"), "the fixture lost its D4 tuple"
    assert _valid("SubmissionMetadata", meta)


def test_a_provider_attested_submission_must_not_carry_a_sender_tuple():
    """The opposite arm, stated rather than implied: the tuple asserts exactly
    what this arm says was not done."""
    meta = _submission(origin_proof="provider-attested")
    assert not _valid("SubmissionMetadata", meta), \
        "a provider-attested submission carrying a sender tuple was accepted"
    meta.pop("sender_confirmation")
    assert _valid("SubmissionMetadata", meta)


# ---------------------------------------------------------------------------
# The confirmation union
# ---------------------------------------------------------------------------

def _delivery(kind, obj):
    return {"issuing_rdp_id": SE["rdp_id"], "message_id": SE["message_id"],
            "confirmation_kind": kind, "confirmation": obj}


def test_each_permitted_confirmation_shape_validates():
    assert _valid("ConfirmationDelivery",
                  _delivery("s3", copy.deepcopy(DE["s3_attestation"])))
    if RE_.get("refusal_confirmation"):
        assert _valid("ConfirmationDelivery",
                      _delivery("refusal", copy.deepcopy(RE_["refusal_confirmation"])))


def test_an_unknown_confirmation_shape_is_rejected():
    """The review's acceptance test. `confirmation` was a bare object, so this
    passed."""
    assert not _valid("ConfirmationDelivery",
                      _delivery("s3", {"whatever": "shape I like"}))
    assert not _valid("ConfirmationDelivery",
                      _delivery("telepathy", copy.deepcopy(DE["s3_attestation"])))


def test_a_confirmation_of_the_wrong_declared_kind_is_rejected():
    """The discriminator is load-bearing: an s3 object announced as a refusal
    must not pass just because some union arm accepts it."""
    assert not _valid("ConfirmationDelivery",
                      _delivery("refusal", copy.deepcopy(DE["s3_attestation"])))


# ---------------------------------------------------------------------------
# One artefact, a package and a set are three things
# ---------------------------------------------------------------------------

ARTIFACT = {"sm_artifact_b64": "AAEC", "projection": {"type": "SE-v1"}}


def test_the_three_evidence_responses_are_discriminated():
    assert _valid("EvidenceResponse", {"form": "latest", "artifact": ARTIFACT})
    assert _valid("EvidenceResponse", {"form": "package", "package": ARTIFACT})
    assert _valid("EvidenceResponse", {"form": "set", "artifacts": [ARTIFACT]})


def test_a_set_cannot_be_returned_as_a_package():
    """The confusion the single wrapper allowed: an incomplete set read as a
    sealed Evidence Package."""
    assert not _valid("EvidenceResponse", {"form": "package",
                                           "artifacts": [ARTIFACT]})
    assert not _valid("EvidenceResponse", {"form": "set", "package": ARTIFACT})


def test_an_undiscriminated_response_is_rejected():
    assert not _valid("EvidenceResponse", {"artifacts": [ARTIFACT]})


def test_the_retrieval_operation_lets_the_client_ask_for_a_form():
    params = CONTRACT["paths"]["/evidence/{message_id}"]["get"]["parameters"]
    form = next(p for p in params if p["name"] == "form")
    assert set(form["schema"]["enum"]) == {"set", "package", "latest"}


# ---------------------------------------------------------------------------
# The contradiction
# ---------------------------------------------------------------------------

def test_the_contract_states_one_owner_for_the_policy_selection():
    """It used to say both: the schema said the wallet computed and signed
    policy_key, the operation said the RDP computed the deterministic
    selection."""
    op = CONTRACT["paths"]["/submissions"]["post"]["description"]
    flat = " ".join(op.replace("`", "").split())
    assert "the RDP RECOMPUTES the selection" in flat
    assert "The wallet's copy is a commitment" in flat
    sub = " ".join(SCHEMAS["SubmissionMetadata"]["description"].replace("`", "").split())
    assert "computed and signed by the wallet" not in sub, \
        "the contradicting claim is back in the schema description"


# ---------------------------------------------------------------------------
# Two independent clients agree
# ---------------------------------------------------------------------------

def test_two_independently_generated_clients_exchange_the_same_payload():
    """The review's fifth criterion. Two builders driven ONLY by the contract —
    one walking `required` in declaration order, one walking `properties` in
    reverse and filling every declared field — must produce payloads the
    contract accepts and that agree field for field. Before DR-07 they could
    not: the fields either builder needed were not all declared."""
    schema = SCHEMAS["SubmissionMetadata"]
    source = _submission()

    client_a = {k: copy.deepcopy(source[k]) for k in schema["required"]}
    client_a["mls_message_b64"] = source["mls_message_b64"]
    client_a["sender_confirmation"] = copy.deepcopy(source["sender_confirmation"])

    client_b = {}
    for k in reversed(list(schema["properties"])):
        if k in source:
            client_b[k] = copy.deepcopy(source[k])

    assert _valid("SubmissionMetadata", client_a), \
        [e.message for e in _errors("SubmissionMetadata", client_a)]
    assert _valid("SubmissionMetadata", client_b), \
        [e.message for e in _errors("SubmissionMetadata", client_b)]
    shared = set(client_a) & set(client_b)
    assert shared >= set(schema["required"])
    for k in shared:
        assert client_a[k] == client_b[k], f"the two clients disagree on {k}"
