# SPDX-License-Identifier: MIT
"""R6-07 — release probes for the shapes that keep getting through.

Rounds 3-5 each built a gate, and round 6's finding is that the gates prove
EXISTENCE and SHAPE, not that a caller supplies the evidence a normative
property needs. Round 6's own pattern names it: **the fix was applied to the
reproduction, not to the class.**

So these are not tests of one rule. They are the four shapes that have each got
through at least once, run against the release surface:

* **absence** — a required input simply not supplied (R5-02, R6-05);
* **one-element lists** — a collection that satisfies a structural check
  vacuously because it has nothing to relate (R6-02's `[v1]`, and round 5's
  own note that a one-element chain "has nothing to link");
* **substituted keyed objects** — a valid object filed under a key that is
  never compared with the object's own identity (R6-05's foreign GroupContext,
  R6-03's receipt);
* **caller-context replay** — a valid object accepted for the wrong act
  because the caller could not say what it was expecting (R6-03).

A new required input should get a line in each shape it can take. That is
cheaper than discovering the shape again a round later.
"""
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _staged(mock, *, issuing_rdp_id, message_id, recipient_uid, mid, device_id,
            octets, session_binding):
    """R7-02: a receipt now requires an item the DS ACCEPTED, QUEUED and
    TRANSFERRED. These fixtures run that lifecycle rather than bypassing it —
    a helper that faked the state would reintroduce exactly the orphan the
    finding is about, one layer down."""
    import base64
    mock.ds_accept_message(message_id, "demo-group",
                           base64.b64encode(octets).decode(),
                           principal=issuing_rdp_id)
    mock.queue_delivery(issuing_rdp_id, message_id, recipient_uid=recipient_uid,
                        mid=mid, device_id=device_id)
    # R9-01/R9-02: collect through the PUBLIC operation and RETURN the token it
    # issued. These fixtures used to call the private `transfer_delivery()` and
    # then acknowledge with no token at all — which is why nothing noticed that
    # a value the published request declares REQUIRED was optional in the
    # reference. A fixture that can skip a wire value cannot test that it is
    # needed.
    got = mock.collect_messages(
        credential={"kind": "device", "uid": recipient_uid, "mid": mid,
                    "device_id": device_id,
                    "session": session_binding["digest"]},
        session_binding=session_binding)
    return next(i["collection_token"] for i in got["items"]
                if i["message_id"] == message_id)


def _cli(manifest_dict, *flags):
    t = ROOT / "samples" / "bundle.__probe.manifest.json"
    t.write_text(json.dumps(manifest_dict))
    try:
        r = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bundle_lint.py"), *flags,
             str(t)], capture_output=True, text=True)
        # R7-05: a fatal configuration error surfaces on STDERR, and a probe
        # that only read stdout would report "no output" as though nothing had
        # gone wrong — the same shape as the defect being tested.
        return r.returncode, r.stdout + r.stderr
    finally:
        t.unlink()


def _default():
    return json.loads(
        (ROOT / "samples" / "bundle.default.manifest.json").read_text())


REQUIRED_INPUTS = [p["input"] for p in json.loads(
    (ROOT / "docs" / "required-properties.json").read_text())["properties"]]


# ---------------------------------------------------------------------------
# Shape 1 — ABSENCE
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("missing", REQUIRED_INPUTS)
def test_absence_of_any_declared_input_is_never_a_pass(missing):
    """Driven from the DECLARED list, so a property added there is probed here
    automatically — the instrument and its probe do not drift apart."""
    m = _default()
    if missing not in m:
        pytest.skip(f"{missing} is not an input of this fixture")
    m.pop(missing)
    code, out = _cli(m)
    assert code != 0, f"removing {missing} still passed:\n{out}"
    assert "[OK  ]" not in out


# ---------------------------------------------------------------------------
# Shape 2 — ONE-ELEMENT LISTS
# ---------------------------------------------------------------------------

def test_a_one_element_chain_relates_nothing_and_is_refused():
    """R6-02. A one-element history satisfies an ordering check vacuously: it
    has nothing to link, so 'the chain is consistent' says nothing at all."""
    m = _default()
    m["policy_history"] = ["sample-BW-ORG.json"]
    code, out = _cli(m)
    assert code == 1 and "PREFIX" in out, out


# ---------------------------------------------------------------------------
# Shape 3 — SUBSTITUTED KEYED OBJECTS
# ---------------------------------------------------------------------------

def test_a_keyed_object_must_prove_it_belongs_under_its_key():
    """R6-05's GroupContext and R6-03's receipt were both filed under a key
    nothing compared with the object's own identity. The generic lesson: a map
    key is a claim by whoever assembled the bundle."""
    import mls_wire as w
    m = _default()
    doc = json.loads(
        (ROOT / "samples" / "group-contexts.demo.json").read_text())
    foreign = w.demo_group_context("XXwrongGroupXXXXXXXXXX", 99)
    import base64
    doc["contexts"][0]["group_context_b64"] = base64.b64encode(foreign).decode()
    t = ROOT / "samples" / "group-contexts.__probe.json"
    t.write_text(json.dumps(doc))
    m["group_contexts"] = t.name
    try:
        code, out = _cli(m)
    finally:
        t.unlink()
    assert code == 1 and "substituted context" in out, out


# ---------------------------------------------------------------------------
# Shape 4 — CALLER-CONTEXT REPLAY
# ---------------------------------------------------------------------------

def test_a_valid_object_cannot_be_accepted_for_the_wrong_act():
    """R6-03: the live receipt path had no parameter with which to notice."""
    spec = importlib.util.spec_from_file_location(
        "mock_rdp", ROOT / "scripts" / "mock_rdp.py")
    mock = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mock)
    import hashlib
    # SBM-ADR-0015: the DS receipt key is the issuing RDP's, published in its
    # BW-PROVIDER descriptor rather than on the customer's BW-MED.
    provider = json.loads(
        (ROOT / "samples" / "sample-BW-PROVIDER.json").read_text())["projection"]
    med = json.loads(
        (ROOT / "samples" / "sample-BW-MED.json").read_text())["projection"]
    se = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
    octets = b"probe" * 8
    session = {"kind": "token-digest", "digest": "a" * 64}
    token = _staged(mock, issuing_rdp_id="urn:sbm:rdp:demo-out",
                    message_id="01HZ6PROBE0000000000001",
                    recipient_uid=se["recipient_uid"], mid="F1N2C3D4P",
                    device_id="DEV-1", octets=octets, session_binding=session)
    receipt = mock.receipt_ack(
        message_id="01HZ6PROBE0000000000001", device_id="DEV-1",
        credential={"kind": "device", "uid": se["recipient_uid"],
                    "mid": "F1N2C3D4P", "device_id": "DEV-1",
                    "session": session["digest"]},
        session_binding=session, octets=octets,
        server_clock="2026-04-04T10:16:23Z", collection_token=token)
    digest = {"format": "mls10-message",
              "hex": hashlib.sha256(octets).hexdigest()}
    with pytest.raises(mock.AckRejected):
        mock.delivered_at_from_receipt(
            receipt, digest, provider=provider,
            expect={"message_id": "01HZ6DIFFERENT00000000002"})


# ===========================================================================
# R6-07 — the status ledger cannot outrun the behaviour
# ===========================================================================

def test_every_acceptance_criterion_names_a_COLLECTED_test_node():
    """R7-05 requirement 5, and it supersedes the round-6 version below.

    That one asserted a cited FILE exists and mentions the finding — so a
    finding could read remediated while any individual criterion went
    unexercised. That is exactly how R5-02's `[v1]` criterion was written down
    and never run, and round 6 closed on it.

    Each criterion names a pytest NODE, and the node is checked against the
    real collection rather than the filesystem: a renamed or deleted test
    breaks the claim that rests on it.
    """
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT, capture_output=True, text=True)
    collected = {line.strip() for line in r.stdout.splitlines()
                 if "::" in line}
    missing = []
    for finding, criteria in _matrix().items():
        assert criteria, f"{finding} names no criteria"
        for criterion, node, _, _paired in criteria:
            base = node.split("[")[0]
            if not any(c.split("[")[0] == base for c in collected):
                missing.append(f"{finding}: {criterion!r} -> {node}")
    assert not missing, (
        "acceptance criteria naming nodes that are not collected:\n  "
        + "\n  ".join(missing))


def _matrix():
    """finding -> [(criterion, node, proves, paired_with)]. R8-06 requirement 5:
    a criterion may declare WHAT EXTERNAL STATE its node asserts, so the release
    gate can report the assertion rather than only the node's existence."""
    raw = json.loads(
        (ROOT / "docs" / "acceptance-vectors.json").read_text())["findings"]
    out = {}
    for finding, criteria in raw.items():
        rows = []
        for criterion, value in criteria.items():
            if isinstance(value, dict):
                rows.append((criterion, value["node"], value.get("proves"),
                             value.get("paired_with")))
            else:
                rows.append((criterion, value, None, None))
        out[finding] = rows
    return out


def _test_source(node):
    """The body of the function a criterion names."""
    path, _, name = node.partition("::")
    src = (ROOT / path).read_text()
    name = name.split("[")[0]
    i = src.index(f"def {name}(")
    rest = src[i:]
    j = rest.find("\ndef ")
    return rest if j < 0 else rest[:j]


def test_no_acceptance_criterion_rests_on_a_source_inspection_test():
    """R8-06 requirement 5 — THE upgrade from node existence.

    The gate could tell that a node was collected; it could not tell whether
    that node exercises the criterion. Two of the nodes it was happy with read
    `mock_rdp.py` as TEXT and asserted that one statement appeared within 900
    characters of another. Neither could fail on the behaviour it was cited
    for, and both would have passed unchanged while R8-01 was reachable.

    A criterion may no longer rest on a test that inspects source. Such tests
    are legitimate — proving a verifier does not know a signing seed is one —
    but they are evidence about the CODE, and an acceptance criterion is a
    claim about BEHAVIOUR."""
    offenders = []
    for finding, criteria in _matrix().items():
        by_node = {node for _, node, _, _ in criteria}
        for criterion, node, _, paired in criteria:
            body = _test_source(node)
            reads_source = ('scripts" /' in body or "scripts\" /" in body
                            or 'read_text()' in body and 'src' in body)
            # R9-05: `subprocess.run` counts. A test that copies the
            # verifier, mutates the copy and EXECUTES it is behavioural — it
            # reads source only to build the mutant. The heuristic was
            # incomplete, and one such test passed it only by accident,
            # because its body happened to contain `m.` from `m.pop(...)`.
            drives = any(x in body for x in ("mock.", "lc.", "m.", "bl.",
                                             "_cli(", "inv.", "validator",
                                             "subprocess.run"))
            if not (reads_source and not drives):
                continue
            # A structural claim IS sometimes the criterion — "no branch
            # selects behaviour by rule id" cannot be shown any other way. It
            # may stand only when it NAMES the behavioural node that would
            # fail on the defect, and that node is itself in this matrix. The
            # same shape as a delegated required property: a claim somebody
            # else discharges has to say who.
            if paired and paired in by_node and paired != node:
                continue
            offenders.append(f"{finding}: {criterion!r} -> {node}")
    assert not offenders, (
        "acceptance criteria resting on source-inspection tests with no "
        "behavioural node named in `paired_with`:\n  " + "\n  ".join(offenders))


def test_every_round_eight_criterion_declares_what_it_proves():
    """R8-06 requirement 5, second half: the gate REPORTS which external state
    assertion each test makes. Round-7 criteria keep the bare-string form and
    the registry says why; everything from round 8 on must declare it."""
    thin = []
    for finding, criteria in _matrix().items():
        if not finding.startswith("R8-"):
            continue
        for criterion, node, proves, _paired in criteria:
            if not proves or len(proves) < 20:
                thin.append(f"{finding}: {criterion!r}")
    assert not thin, (
        "round-8 criteria that do not say what external state they assert:\n  "
        + "\n  ".join(thin))


def test_the_matrix_covers_an_exact_finding_set():
    """An EXACT set, so a finding cannot be dropped from the matrix as quietly
    as it was added. Round 8 grows this batch by batch; R8-06 requirement 3
    replaces the literal with a declared mandatory set."""
    matrix = json.loads(
        (ROOT / "docs" / "acceptance-vectors.json").read_text())["findings"]
    assert set(matrix) == {"R7-01", "R7-02", "R7-03", "R7-04", "R7-05",
                           "R8-01", "R8-02", "R8-03", "R8-04",
                           "R8-05", "R8-06", "R9-01", "R9-02", "R9-04", "R9-05", "R9-B6",
                           "R9-03"}


def test_every_round_six_finding_has_a_negative_vector_on_disk():
    """Each round-6 finding must be answerable by something runnable. The
    mapping is stated here rather than inferred, because a finding whose
    evidence cannot be named is a finding whose closure cannot be checked."""
    VECTORS = {
        "R6-01": "tests/test_intake_obligations.py",
        "R6-02": "tests/test_policy_maximality.py",
        "R6-03": "tests/test_production_signature_claims.py",
        "R6-04": "tests/test_current_claims.py",
        "R6-05": "tests/test_group_params_semantics.py",
        "R6-06": "tests/test_current_claims.py",
        "R6-07": "tests/test_release_probes.py",
    }
    for finding, path in VECTORS.items():
        p = ROOT / path
        assert p.exists(), f"{finding}: {path} is missing"
        assert finding in p.read_text(), \
            f"{finding}: {path} does not name the finding it answers"


# ===========================================================================
# R7-05 — the declaration DRIVES the behaviour, or the verification stops
# ===========================================================================
#
# The round-6 registry claimed "adding a property here fails closed until it is
# wired". It was false: `_gaps()` consulted a second, hard-coded `applies` map,
# so `applies.get(prop["id"])` returned None for any id it did not know and the
# property was skipped in silence. Cowork injected one whose input name already
# occurred in the source and whose gap rule was catalogued: the full suite
# passed and the verifier output was BYTE-IDENTICAL.
#
# The gate checked a substring, the verifier checked a hard-coded id, and
# neither checked the property. The map is deleted rather than extended
# (standing rule 3), and every unknown is fatal rather than skipped.

import contextlib
import shutil


@contextlib.contextmanager
def _injected(_declare_mandatory=True, **prop):
    """Add a required property to the real declaration, then restore it.

    R8-06: `strategy` and the `mandatory` set are part of a well-formed
    declaration now, so the fixture supplies them — adding a property means
    declaring it mandatory, and `_declare_mandatory=False` exercises the case
    where somebody forgets.
    """
    path = ROOT / "docs" / "required-properties.json"
    backup = path.read_text()
    doc = json.loads(backup)
    prop.setdefault("strategy", "report_gap")
    doc["properties"].append(prop)
    if _declare_mandatory and prop.get("id"):
        doc["mandatory"] = doc.get("mandatory", []) + [prop["id"]]
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    try:
        yield
    finally:
        path.write_text(backup)


def _run_default():
    return _cli(_default())


def test_a_valid_injected_property_EMITS_ITS_GAP():
    """Requirement 3, and the acceptance test: inject a property with an
    applicable precondition and an ABSENT input, and the verifier must emit its
    declared gap through the CLI — never skip it.

    The absence is now arranged HERE. This probe used to run the shipped default
    manifest and rely on its carrying no `receipts`; when that manifest gained a
    retained receipt — so that the receipt path would be exercised by the bar at
    all — the precondition it tests silently stopped applying and the probe
    tested nothing. A probe builds its world.
    """
    manifest = _default()
    manifest.pop("receipts", None)
    assert "receipts" not in manifest, "the input must be absent, or this proves nothing"
    with _injected(id="relay-chain-authenticity", input="receipts",
                   gap_rule="LINT-BND-I4", when={"kind": "always"},
                   precondition="always",
                   establishes="that the retained relay chain is authentic"):
        code, out = _cli(manifest)
    assert code == 3, out
    assert "the retained relay chain is authentic" in out
    assert "no `receipts`" in out


@pytest.mark.parametrize("bad,why", [
    ({"id": "x", "input": "evidence", "gap_rule": "LINT-BND-I4",
      "when": {"kind": "always"}, "establishes": "e"},
     "an input check_bundle does not accept"),
    ({"id": "x", "input": "receipts", "gap_rule": "LINT-BND-NOPE",
      "when": {"kind": "always"}, "establishes": "e"},
     "an uncatalogued gap rule"),
    ({"id": "x", "input": "receipts", "gap_rule": "LINT-BND-I4",
      "when": {"kind": "whenever-i-feel-like-it"}, "establishes": "e"},
     "an unknown precondition kind"),
    ({"id": "x", "input": "receipts", "gap_rule": "LINT-BND-I4",
      "establishes": "e"},
     "no executable precondition at all"),
    ({"id": "x", "input": "receipts", "gap_rule": "LINT-BND-I4",
      "when": {"kind": "any_input", "inputs": ["not_an_input"]},
      "establishes": "e"},
     "a `when` naming an unknown input"),
])
def test_a_misspelt_declaration_is_FATAL_not_skipped(bad, why):
    """Requirement 2. The previous design failed OPEN — an unrecognised
    declaration was treated as 'does not apply' — which is precisely why the
    injection was invisible. A declaration nobody can evaluate must stop the
    verification, not be assumed inapplicable."""
    with _injected(**bad):
        code, out = _run_default()
    assert code == 1, f"{why}: expected a fatal configuration error\n{out}"
    assert "R7-05" in out or "RequiredPropertyConfigError" in out


def test_cowork_s_exact_injection_no_longer_passes():
    """Their probe verbatim: an input name that already occurs in the source
    (`evidence`) and a catalogued gap rule. It gave a green suite and
    byte-identical output; it is a configuration error now."""
    with _injected(id="relay-chain-authenticity", input="evidence",
                   gap_rule="LINT-BND-I4",
                   precondition="always, for any bundle carrying relay evidence",
                   establishes="that the retained relay chain is authentic and "
                               "complete end to end"):
        code, out = _run_default()
    assert code == 1, out
    assert "check_bundle does not accept" in out


def test_the_hard_coded_applies_map_is_GONE():
    """Standing rule 3: when a fix supersedes a check, DELETE the superseded
    check. The map was the thing to delete, not to extend."""
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    assert "applies = {" not in src
    assert 'applies.get(prop["id"])' not in src
    assert "_precondition_holds" in src, "the vocabulary must be evaluated"


def test_the_supplied_inputs_are_not_restated_beside_the_signature():
    """A hand-written list beside the parameters is one more copy to keep in
    step — and `receipts` being missing from it made a legitimate declaration
    look like a configuration error while I was building this."""
    import inspect
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "bundle_lint_probe", ROOT / "scripts" / "bundle_lint.py")
    bl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bl)
    params = set(inspect.signature(bl.check_bundle).parameters)
    assert set(bl.RETAINED_MATERIAL_INPUTS) <= params, \
        "a declared retained input is not a parameter of check_bundle"
    declared = {p["input"] for p in json.loads(
        (ROOT / "docs" / "required-properties.json").read_text())["properties"]}
    assert declared <= set(bl.RETAINED_MATERIAL_INPUTS)


# ===========================================================================
# R8-06 — the declaration drives the behaviour, for EVERY row
#
# R7-05 removed the hard-coded `applies` map and made `when` executable. Two
# branches survived it, keyed on the identifier of the rule a row would EMIT:
#
#     if prop["gap_rule"] == "LINT-BND-I1": continue
#     if prop["gap_rule"] == "LINT-BND-I2": continue
#
# so three of five rows were driven by their declaration and two by their
# output rule id — and any FUTURE row choosing I1 or I2 was skipped whatever
# it said. Reproduced with a control: one injected row, five gap rules, the
# marker reported for I3/I4/I5 and silently dropped for I1/I2.
# ===========================================================================

REGISTRY = json.loads((ROOT / "docs" / "required-properties.json").read_text())
CATALOGUED_INCOMPLETE = sorted(
    r["id"] for r in json.loads(
        (ROOT / "docs" / "lint-catalogue.json").read_text())["rules"]
    if r["id"].startswith("LINT-BND-I"))


@pytest.mark.parametrize("rule", CATALOGUED_INCOMPLETE)
def test_one_declaration_behaves_the_same_under_every_incomplete_rule(rule):
    """THE control, as a release probe. The SAME row, changing only the rule it
    would emit. Any divergence means the identifier is selecting behaviour
    again — which is the defect, not a detail of it."""
    m = _default()
    m.pop("group_contexts", None)
    with _injected(id="future-property", input="group_contexts", gap_rule=rule,
                   when={"kind": "always"}, precondition="injected",
                   establishes="FUTURE MARKER MUST BE REPORTED"):
        code, out = _cli(m)
    assert code == 3, out
    assert "FUTURE MARKER MUST BE REPORTED" in out, \
        f"a row emitting {rule} was skipped for its rule id, not its semantics"


def test_no_source_branch_selects_behaviour_by_rule_id_or_property_id():
    """The review's third acceptance test. Structural, because the behavioural
    one above would also pass if the branching merely moved: nothing may
    compare `gap_rule` or `id` against a literal outside the closed strategy
    mapping."""
    # Comments are stripped first. The block that DELETED those two branches
    # quotes them, as the record of a defect should — and a check that no
    # BRANCH exists must read code, not the prose describing it. Otherwise
    # documenting a removal reintroduces the finding.
    src = "\n".join(l for l in
                    (ROOT / "scripts" / "bundle_lint.py").read_text().splitlines()
                    if not l.lstrip().startswith("#"))
    for literal in CATALOGUED_INCOMPLETE:
        assert f'== "{literal}"' not in src, \
            f"behaviour is selected by the output rule id {literal}"
    for pid in REGISTRY["mandatory"]:
        assert f'== "{pid}"' not in src, \
            f"behaviour is selected by the property id {pid}"


@pytest.mark.parametrize("prop", REGISTRY["properties"], ids=lambda p: p["id"])
def test_removing_a_rows_input_from_the_bundle_is_never_a_pass(prop):
    """Requirement 4, per row rather than for the one row someone probed."""
    m = _default()
    if prop["input"] not in m:
        pytest.skip(f"{prop['input']} is not an input of this fixture")
    m.pop(prop["input"])
    code, out = _cli(m)
    assert code != 0, f"removing {prop['input']} still passed:\n{out}"


@pytest.mark.parametrize("mutation", ["delete", "duplicate", "rename",
                                      "drop_strategy", "unknown_strategy",
                                      "undeclared_mandatory"])
def test_every_registry_mutation_fails_closed(mutation):
    """Requirement 3 and 4: the registry could previously lose a property as
    quietly as it gained one. Deletion, duplication and renaming are now fatal
    configuration errors, not a smaller set of things a green verdict means."""
    path = ROOT / "docs" / "required-properties.json"
    backup = path.read_text()
    doc = json.loads(backup)
    if mutation == "delete":
        doc["properties"] = doc["properties"][1:]
    elif mutation == "duplicate":
        doc["properties"].append(dict(doc["properties"][0]))
    elif mutation == "rename":
        doc["properties"][0]["id"] = "renamed-property"
    elif mutation == "drop_strategy":
        del doc["properties"][0]["strategy"]
    elif mutation == "unknown_strategy":
        doc["properties"][0]["strategy"] = "trust-me"
    elif mutation == "undeclared_mandatory":
        doc["properties"].append({
            "id": "sneaked-in", "input": "receipts", "gap_rule": "LINT-BND-I4",
            "when": {"kind": "always"}, "precondition": "injected",
            "establishes": "e", "strategy": "report_gap"})
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    try:
        code, out = _run_default()
    finally:
        path.write_text(backup)
    assert code == 1, f"{mutation} did not fail closed (exit {code}):\n{out}"
    assert "RequiredPropertyConfigError" in out or "R8-06" in out, out


def test_a_delegated_property_must_name_a_catalogued_owner():
    """Requirement 2: `delegated` says WHO establishes the property. A
    delegation naming nobody is the `continue` it replaced, spelled longer."""
    for bad in ({"strategy": "delegated"},
                {"strategy": "delegated", "delegated_to": ["LINT-BND-NOPE"]}):
        with _injected(id="delegated-nowhere", input="receipts",
                       gap_rule="LINT-BND-I4", when={"kind": "always"},
                       precondition="injected", establishes="e", **bad):
            code, out = _run_default()
        assert code == 1, out
        assert "delegation must say WHO" in out, out


def test_a_delegation_whose_owner_says_nothing_still_reports_the_gap():
    """Requirement 1, and the part that makes delegation checkable: the two
    branches this replaces could not be wrong, because they asserted nothing.
    A row claiming another rule establishes its property is a claim ABOUT A
    RUN, so it is confirmed against that run — and where the owner reported
    nothing, the property is unestablished and its own gap is emitted."""
    m = _default()
    m.pop("policy_history", None)
    with _injected(id="delegated-to-a-silent-rule", input="receipts",
                   gap_rule="LINT-BND-I4", when={"kind": "always"},
                   precondition="injected", strategy="delegated",
                   delegated_to=["LINT-BND-33"],
                   establishes="DELEGATION MARKER MUST BE REPORTED"):
        m.pop("receipts", None)
        code, out = _cli(m)
    assert code == 3, out
    assert "DELEGATION MARKER MUST BE REPORTED" in out, \
        "a delegation to a rule that said nothing was accepted on its word"
    # R9-05: the message names the PROPERTY the delegate failed to decide,
    # not merely that a rule was absent from the output.
    assert "recorded no result for this property" in out


# ===========================================================================
# R9-05 — establishment is PROPERTY-SPECIFIC
#
# R8-06 confirmed a delegation by asking whether any id from `delegated_to`
# appeared anywhere in the global emitted-rule set. That set is global: the
# emitting rule did not have to be reporting on this property, this input or
# this row. Pointing a row at `LINT-BND-I3` — which the ordinary bundle emits
# for X-33 maximality — established it for free, so a future security property
# could be declared mandatory, have no evidence input, and still pass.
# ===========================================================================

DELEGATED_ROWS = [p for p in REGISTRY["properties"]
                  if p.get("strategy") == "delegated"]


@pytest.mark.parametrize("rule", CATALOGUED_INCOMPLETE)
def test_an_unrelated_occurrence_of_any_rule_establishes_nothing(rule):
    """R9-05's first acceptance test, over EVERY catalogued rule rather than
    the one the review demonstrated. `LINT-BND-I3` was the reproduction;
    the property is that no rule identifier establishes anything by
    coincidence."""
    m = _default()
    m.pop("receipts", None)
    with _injected(id="future-authentic-receipt", input="receipts",
                   gap_rule="LINT-BND-I4", when={"kind": "always"},
                   precondition="injected", strategy="delegated",
                   delegated_to=[rule],
                   establishes="FUTURE MARKER MUST BE REPORTED"):
        code, out = _cli(m)
    assert code == 3, out
    assert "FUTURE MARKER MUST BE REPORTED" in out, \
        f"an unrelated occurrence of {rule} established an injected property"


def test_a_delegate_cannot_establish_a_property_nobody_declared():
    """R9-05 requirement 3. An establishment signal for an undeclared id is a
    claim about a property that does not exist, and it is fatal rather than
    ignored — the R7-05 fail-closed rule applied to the new register."""
    src = ROOT / "scripts" / "bundle_lint.py"
    probe = ROOT / "scripts" / "bundle_lint.__probe.py"
    text = src.read_text().replace(
        'establish("policy-chain",', 'establish("no-such-property",', 1)
    probe.write_text(text)
    try:
        m = _default()
        t = ROOT / "samples" / "bundle.__probe2.manifest.json"
        t.write_text(json.dumps(m))
        try:
            r = subprocess.run([sys.executable, str(probe), str(t)],
                               capture_output=True, text=True)
        finally:
            t.unlink()
    finally:
        probe.unlink()
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "not a declared required property" in out, out


@pytest.mark.parametrize("prop", DELEGATED_ROWS, ids=lambda p: p["id"])
def test_removing_one_establishment_signal_fails_that_property(prop):
    """R9-05's fourth acceptance test. Each signal is removed IN TURN from a
    COPY of the verifier — never the tree under test — and the run must report
    the gap of exactly the property whose signal was removed, and no other.

    This is the test the old mechanism could not have: with a global rule-id
    check, deleting the signal changed nothing at all."""
    src = ROOT / "scripts" / "bundle_lint.py"
    probe = ROOT / "scripts" / "bundle_lint.__probe.py"
    text = src.read_text()
    marker = f'establish("{prop["id"]}",'
    assert marker in text, f"no delegate records {prop['id']}"
    # neutralise just this one signal
    text = text.replace(marker, f'_skip_establish("{prop["id"]}",', 1)
    text = text.replace("    def establish(property_id, detail):",
                        "    def _skip_establish(property_id, detail):\n"
                        "        return None\n\n"
                        "    def establish(property_id, detail):", 1)
    probe.write_text(text)
    try:
        m = _default()
        m.pop(prop["input"], None)
        t = ROOT / "samples" / "bundle.__probe3.manifest.json"
        t.write_text(json.dumps(m))
        try:
            r = subprocess.run([sys.executable, str(probe), str(t)],
                               capture_output=True, text=True)
        finally:
            t.unlink()
    finally:
        probe.unlink()
    out = r.stdout + r.stderr
    assert r.returncode == 3, out
    assert prop["establishes"] in out, \
        f"removing {prop['id']}'s signal did not report ITS gap:\n{out}"
    for other in DELEGATED_ROWS:
        if other["id"] != prop["id"]:
            assert other["establishes"] not in out, \
                f"removing {prop['id']}'s signal also reported {other['id']}"


def test_the_delegated_rows_declare_an_owner_that_actually_records():
    """Requirement 3's third clause: a delegate that CANNOT produce the signal
    is a misconfiguration, not a silent pass. Structural, because the
    behavioural half is the mutation test above — which is why this criterion
    names it as its behavioural pair."""
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    for prop in DELEGATED_ROWS:
        assert f'establish("{prop["id"]}"' in src, \
            f"{prop['id']} is delegated to {prop['delegated_to']}, and no " \
            "check records establishing it — the row can only fail closed"


# ===========================================================================
# R9 — every published operation's RESPONSE, and schema shapes as surface
#
# Round 8 validated public REQUESTS. Cowork's round-9 verification answered the
# round-8 ask — send the rule for finding all occurrences, not a list of three
# — by sweeping the whole surface, and found TEN of fourteen operations wrong
# in three distinct ways. This keeps that sweep.
# ===========================================================================

def _sweep():
    return _load_script("response_conformance")


def _load_script(name):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_published_response_matches_its_contract():
    """The sweep, as a release probe. Five operations returned objects their
    own contract rejected — including the COMMIT response, which the review
    does not name — two declared `204` and returned a body, and three had no
    reference at all."""
    rows, problems = _sweep().check()
    assert problems == [], "\n".join(problems)
    # Every PUBLISHED Delivery-Service operation, derived from the contract:
    # this was a typed 14, and R12-X3's new operation made it 15 — a count
    # restated by hand is a count that drifts.
    import yaml
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    published = sum(1 for ops in doc["paths"].values() for m in ops
                    if m in ("get", "post", "put", "delete", "patch"))
    assert len(rows) == published, \
        f"the sweep drove {len(rows)} operations; the contract publishes {published}"
    # D12-02: and the README's own statement of it, which still said 13 after
    # the founder operation made the swept set 14.
    residuals = len(_sweep().DECLARED_RESIDUALS)
    m = re.search(r"— (\d+) operations, with (\d+) declared residual",
                  (ROOT / "README.md").read_text())
    assert m and (int(m.group(1)), int(m.group(2))) == (published - residuals, residuals), \
        f"README states {m and m.groups()}; the sweep drives {published - residuals} + {residuals}"


def test_an_undeclared_missing_reference_fails_the_sweep():
    """The guard on the guard. An operation with no reference behind it is
    tolerated ONLY when it is a declared residual carrying its reason — an
    unexplained absence is what this gate exists to stop."""
    sweep = _sweep()
    assert sweep.DECLARED_RESIDUALS, "the residual list is empty and vacuous"
    for name, why in sweep.DECLARED_RESIDUALS.items():
        assert len(why) > 80, f"{name} is declared without a reason"
    saved = dict(sweep.DECLARED_RESIDUALS)
    sweep.DECLARED_RESIDUALS.clear()
    try:
        _, problems = sweep.check()
        assert any("no reference behind it" in p for p in problems), \
            "an operation with no reference passed the sweep"
    finally:
        sweep.DECLARED_RESIDUALS.update(saved)


def test_a_response_body_under_a_no_content_code_is_caught():
    """The shape R9-X4 fixed twice: `POST /welcome/{id}/refusal` returned
    `{"outcome_id": ...}` under a promised `204`, and the outcome
    acknowledgement returned `{"acknowledged": true}`."""
    sweep = _sweep()
    doc = json.loads(json.dumps({}))          # placeholder for clarity
    rows, _ = sweep.check()
    by_name = {n: state for n, _, state in rows}
    assert by_name["POST /welcome/{welcome_id}/refusal"] == "ok (RefusalAccepted)"
    assert by_name["DELETE /group-establishment/outcomes/{outcome_id}"] == \
        "ok (no content)"


def test_schema_shapes_are_part_of_the_recorded_surface():
    """R9-B6, and a defect of this round's own making. `contract_shapes.py`
    fingerprinted operations and security alternatives and nothing else, so the
    three breaking SCHEMA changes round 9 made — a required response field
    added, `KeyPackageRef` gaining a grammar, `collection_token` becoming
    mandatory — passed it in silence and every version bump was manual."""
    shapes = json.loads((ROOT / "docs" / "contract-shapes.json").read_text())
    ds = shapes["contracts"]["delivery-service-openapi.yaml"]
    assert "schemas" in ds, "schema shapes are not recorded at all"
    res = ds["schemas"]["Reservation"]
    item = res["properties"]["keypackages"]["items"]
    assert "keypackage_ref" in item["required"], \
        "the fingerprint does not capture a required response field"
    kp = ds["schemas"]["InvitationDeposit"]["properties"]["keypackage_ref"]
    assert "$ref" in kp, "the fingerprint does not capture a $ref"
