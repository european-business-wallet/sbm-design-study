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


# ---------------------------------------------------------------------------
# XREP-03 — the normative access table against the contract's declared security
# ---------------------------------------------------------------------------

def _table(*rows):
    """A normative access table of our own, built the way the profile builds it."""
    header = xrep.ACCESS_TABLE_HEADER
    lines = [header, "|---|---|---|---|---|"]
    lines += [f"| `GET {path}` | op | owner | stored | {access} |" for path, access in rows]
    return "prose before\n\n" + "\n".join(lines) + "\n\nprose after\n"


def _contract(**paths):
    return {"paths": {p: {"get": ({"security": [{s: []} for s in schemes]}
                                  if schemes else {})}
                      for p, schemes in paths.items()}}


def test_a_path_the_table_protects_and_the_contract_does_not_is_caught(monkeypatch):
    """The defect, in shape: the umbrella required an authenticated counterparty
    for the roster snapshot and the contract declared nothing, so a generated
    client read an entity's complete roster anonymously."""
    monkeypatch.setattr(xrep, "access_table",
                        lambda _: [("/a", False, True)])
    monkeypatch.setattr(xrep, "declared_security", lambda _: {"/a": []})
    findings = xrep.check_access()
    assert len(findings) == 1, findings
    assert "calls it anonymously" in findings[0]


def test_a_path_the_contract_protects_and_the_table_calls_public_is_caught(monkeypatch):
    """The other direction: a caller the specification entitles is refused."""
    monkeypatch.setattr(xrep, "access_table", lambda _: [("/a", False, False)])
    monkeypatch.setattr(xrep, "declared_security", lambda _: {"/a": ["someAuth"]})
    findings = xrep.check_access()
    assert len(findings) == 1 and "entitled by the specification" in findings[0]


def test_a_published_path_no_rule_governs_is_caught(monkeypatch):
    monkeypatch.setattr(xrep, "access_table", lambda _: [("/a", False, True)])
    monkeypatch.setattr(xrep, "declared_security",
                        lambda _: {"/a": ["x"], "/unruled": []})
    assert any("/unruled" in f and "has none" in f for f in xrep.check_access())


def test_a_rule_governing_nothing_is_caught(monkeypatch):
    monkeypatch.setattr(xrep, "access_table", lambda _: [("/gone", False, True)])
    monkeypatch.setattr(xrep, "declared_security", lambda _: {})
    assert any("nothing to govern" in f for f in xrep.check_access())


def test_the_table_parser_survives_an_unescaped_pipe_in_a_code_span():
    """`bw/med|org|member` carries an unescaped `|` inside a code span. Splitting
    the row on `|` there shifts every column right, so the Access cell reads as
    something else and the row silently rules on nothing — which is how three
    paths went ungoverned until the parser protected code spans."""
    parsed = xrep.access_table(_table(
        ("/.well-known/bw/med|org|member/…", "Public; production MAY authenticate"),
        ("/uid/{uid}/members", "**Authenticated counterparty, REQUIRED**")))
    families = {path for path, is_prefix, _ in parsed if is_prefix}
    assert families == {"/.well-known/bw/med", "/.well-known/bw/org",
                        "/.well-known/bw/member"}, parsed
    assert ("/uid/{uid}/members", False, True) in parsed


def test_may_authenticate_is_an_option_and_not_a_requirement():
    """A row that PERMITS authentication must not be read as demanding it, or
    every public discovery path would be reported."""
    parsed = xrep.access_table(_table(("/pub", "Public; production MAY authenticate")))
    assert parsed == [("/pub", False, False)], parsed


def test_a_renamed_or_removed_table_stops_the_gate():
    """The failure this gate must not have: the heading changes, the parser finds
    nothing, and a comparison over zero rows passes."""
    with pytest.raises(SystemExit):
        xrep.access_table("a profile with no access table in it")


def test_the_live_contract_matches_the_normative_table():
    assert xrep.check_access() == []


def test_every_published_edd_path_is_governed():
    """The completeness half, on the live tree: the profile says every path has
    exactly one access rule, so the table must reach all of them."""
    import yaml
    doc = yaml.safe_load((ROOT / xrep.ACCESS_CONTRACT).read_text(encoding="utf-8"))
    assert len(xrep.declared_security(doc)) >= 13
