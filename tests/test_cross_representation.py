# SPDX-License-Identifier: MIT
"""The cross-representation gate, checked against defects it must detect.

A gate that cannot be shown to fail is a gate nobody can trust, so every probe
here builds its OWN schema, its own vector and its own reference and asserts the
detection on those — invariant 13, "a probe builds its world; it does not copy
ours". Two probes then assert the live tree agrees, which is the claim the
conformance bar actually makes.

The defects reproduced here are not invented. XREP-02's is G1, verbatim in
shape: at 86d9c3c the reference required `refusal_proof` and the published
contract did not describe it, so nobody holding only the contract could build
the request. XREP-01's is `disputes`: the first vector ever written for it found
that `ep_artifact` sealed the dispute artefacts into the body and left them out
of the projection, a half-written branch that had shipped because no vector
carried one.
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import cross_representation as xrep  # noqa: E402


# ---------------------------------------------------------------------------
# XREP-01 — what "declared" and "exercised" mean
# ---------------------------------------------------------------------------

def test_a_name_reachable_only_through_a_combinator_is_still_published():
    """The granularity claim. A field published only inside one `anyOf` arm, or
    only through a `$defs` reference, is a field an implementer can meet — so it
    is a field the gate must demand a vector for."""
    schema = {
        "properties": {"plain": {}},
        "$defs": {"Nested": {"properties": {"through_defs": {}}}},
        "anyOf": [{"properties": {"in_an_arm": {}}}],
        "allOf": [{"if": {"properties": {"in_a_condition": {}}},
                   "then": {"properties": {"in_a_consequent": {}}}}],
        "items": {"properties": {"in_items": {}}},
    }
    assert xrep.declared_names(schema) == {
        "plain", "through_defs", "in_an_arm", "in_a_condition",
        "in_a_consequent", "in_items"}


def test_a_packages_nested_sub_bodies_count_as_exercised():
    """An EP carries its SE, outcomes, changes and disputes as nested bodies. A
    name exercised only there is exercised: `cddl_check` validates each nested
    body against its own CDDL rule and its own Schema."""
    projection = {"type": "EP-v1",
                  "se": {"envelope_hash": {"format": "mls10-message"}},
                  "outcomes": [{"delivery_grade": "availability"}],
                  "disputes": [{"reveal": {"content_class": "invoice"}}]}
    names = xrep.vector_names(projection)
    for expected in ("se", "envelope_hash", "format", "outcomes",
                     "delivery_grade", "disputes", "reveal", "content_class"):
        assert expected in names, expected


def test_a_name_no_vector_carries_is_the_finding():
    """The measurement itself: declared minus exercised. Both sides synthetic,
    so this probe says what the gate computes and nothing about our tree."""
    declared = xrep.declared_names({"properties": {"held": {}, "unheld": {}}})
    exercised = xrep.vector_names({"held": "some value"})
    assert sorted(declared - exercised) == ["unheld"]


# ---------------------------------------------------------------------------
# XREP-02 — the reference's request surface against the published contract
# ---------------------------------------------------------------------------

def _doc(properties, *, path_params=(), component="DemoRequest"):
    """A published contract with one operation, built here rather than read."""
    return {
        "paths": {"/demo/{demo_id}": {"post": {
            "parameters": [{"name": n, "in": "path"} for n in path_params],
            "requestBody": {"content": {"application/json": {
                "schema": {"$ref": f"#/components/schemas/{component}"}}}}}}},
        "components": {"schemas": {component: {
            "properties": {p: {} for p in properties}}}},
    }


def test_a_field_the_reference_requires_and_the_contract_omits_is_caught():
    """G1's defect, in shape. The reference demands a proof; the contract does
    not describe it; an implementer holding only the contract is stuck."""
    def refuse_welcome(demo_id, *, credential, reason, refusal_proof):
        raise AssertionError("never called — only its signature is read")

    findings = xrep.compare_request(
        "DemoRequest", refuse_welcome,
        _doc(["reason"], path_params=["demo_id"]), non_body={})
    assert len(findings) == 1, findings
    assert "refusal_proof" in findings[0]
    assert "cannot build the request" in findings[0]


def test_a_field_the_contract_publishes_and_the_reference_cannot_accept_is_caught():
    """The other direction, which is just as broken: the contract promises a
    field and the reference has nowhere to put it."""
    def accept(demo_id, *, credential, reason):
        raise AssertionError("never called")

    findings = xrep.compare_request(
        "DemoRequest", accept,
        _doc(["reason", "promised_but_unimplemented"], path_params=["demo_id"]),
        non_body={})
    assert len(findings) == 1, findings
    assert "promised_but_unimplemented" in findings[0]
    assert "cannot execute what was published" in findings[0]


def test_path_parameters_are_derived_from_the_contract_not_listed_by_hand():
    """A path parameter is not a body field. It is subtracted from the OpenAPI
    document, so a path that gains one needs no edit in the gate — and a
    parameter the contract does NOT declare is still reported."""
    def accept(demo_id, undeclared_id, *, credential, reason):
        raise AssertionError("never called")

    doc = _doc(["reason"], path_params=["demo_id"])
    assert xrep.path_parameters(doc, "DemoRequest") == {"demo_id"}
    findings = xrep.compare_request("DemoRequest", accept, doc, non_body={})
    assert len(findings) == 1, findings
    assert "undeclared_id" in findings[0]


def test_a_declared_non_body_source_excuses_exactly_one_name():
    """The escape hatch, bounded: NON_BODY excuses the name it names and no
    other, and every entry carries the reason it is not a body field."""
    def accept(demo_id, *, credential, reason, server_clock, smuggled):
        raise AssertionError("never called")

    doc = _doc(["reason"], path_params=["demo_id"])
    non_body = {"DemoRequest": {"server_clock": "the server observes it"}}
    findings = xrep.compare_request("DemoRequest", accept, doc, non_body=non_body)
    assert len(findings) == 1, findings
    assert "smuggled" in findings[0]


def test_an_unpublished_component_is_not_silently_skipped():
    def accept(*, credential):
        raise AssertionError("never called")

    findings = xrep.compare_request("Missing", accept, _doc([]), non_body={})
    assert findings and "nobody can read" in findings[0]


@pytest.mark.parametrize("component", sorted(xrep.NON_BODY))
def test_every_declared_non_body_entry_states_its_reason(component):
    """A bare name in NON_BODY would be a switch with no argument behind it."""
    for name, reason in xrep.NON_BODY[component].items():
        assert isinstance(reason, str) and len(reason.split()) >= 4, (component, name)


# ---------------------------------------------------------------------------
# The live tree
# ---------------------------------------------------------------------------

def test_the_gates_scope_is_the_schemas_whose_bodies_have_two_descriptions():
    """The scope is a decision, recorded. `cddl_check` validates a sealed
    EVIDENCE body against a specific CDDL rule AND its Schema, so those two
    descriptions can be held together. It validates discovery bodies on their
    type/version discriminators only, and the CDDL describes no rule for the
    plaintext envelope at all — one strict description each, nothing to hold to
    anything. Asserted structurally, so widening the scope means changing this."""
    covered = {p.name for p in (ROOT / "schemas").glob("evidence-*.schema.json")}
    assert len(covered) >= 8, covered
    assert not any(n.startswith("bw-") or n == "envelope.schema.json"
                   for n in covered)
    # The exclusion is a stated decision, not an accident of a glob.
    assert "envelope.schema.json" in xrep.__doc__
    assert "discovery bodies on their type/version discriminators" in xrep.__doc__


def test_every_published_evidence_field_is_held_by_a_vector():
    assert xrep.check_vectors() == []


def test_the_reference_and_the_published_contract_describe_one_protocol():
    assert xrep.check_contract() == []
