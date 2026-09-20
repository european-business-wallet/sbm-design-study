# SPDX-License-Identifier: MIT
"""X-31 — one coherent, byte-reproducible federated fixture; recursive lint.

Former defects, all live in the shipped samples: the federated EP's
changes[] CE carried a DIFFERENT message's id; every EP outcome's
s3_attestation was attributed to the SENDER-side member (A1B2C3D4R) rather
than the FR recipient; and neither the evidence lint (changes unchecked)
nor the bundle lint (nested confirmations unswept) validated nested
objects recursively. (The relay-digest reproducibility half was already
closed by CF-5/LINT-BND-20.)

Now: the fixture set is coherent (recipient-side s3 = F1N2C3D4P; the CE
binds the EP's message; regen re-derives every digest from repository
bytes); LINT-EP-08 binds every nested change/dispute to the EP's message;
and check_bundle sweeps EP-nested outcomes through the SAME
roster/anchor checks as top-level evidence — mutating a nested message id
or member identity makes conformance fail.
"""
import copy
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402
import mls_wire as w  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


el = _load("evidence_lint", "evidence_lint.py")
bl = _load("bundle_lint", "bundle_lint.py")

EPF = json.load(open(ROOT / "samples" / "sample-EP-federated.json"))["projection"]


def _federated_bundle(mutate=None):
    m = json.loads((ROOT / "samples" / "bundle.federated.manifest.json").read_text())
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    evidence = [_rc(x) for x in m["evidence"]]
    if mutate:
        mutate(evidence)
    return [m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
            [_rc(x) for x in m["members"]], evidence]


def _ep08(ep):
    v = el.Violations()
    el.lint_ep(v, ep)
    return [msg for r, msg in v.items if r == "LINT-EP-08"]


# ---------------------------------------------------------------------------
# The fixture is coherent
# ---------------------------------------------------------------------------

def test_the_fixture_is_one_message_recipient_attributed():
    assert EPF["se"]["message_id"] == EPF["message_id"]
    for o in EPF["outcomes"]:
        assert o["message_id"] == EPF["message_id"]
        s3 = o.get("s3_attestation") or {}
        assert s3.get("mid") == "F1N2C3D4P", \
            "the confirmation belongs to the RECIPIENT member"
    for c in EPF.get("changes", []) or []:
        assert c["message_id"] == EPF["message_id"]


def test_every_digest_recomputes_from_repository_bytes():
    """The acceptance's first half: envelope/state hashes re-derive from the
    demo chain; hop seal digests recompute (LINT-BND-20, in-bundle); the
    whole bundle is clean."""
    se = EPF["se"]
    assert se["envelope_hash"] == w.envelope_hash(
        w.demo_mls_message(se["message_id"], se["mls_group_id"], se["mls_epoch"]))
    assert se["mls_state"] == w.mls_state_hash(
        w.demo_group_context(se["mls_group_id"], se["mls_epoch"],
                             scope_id=se["scope_ref"]["scope_id"],
                             scope_version=se["scope_ref"]["version"]))
    issues = bl.violations(bl.check_bundle(*_federated_bundle()))
    assert not [r for r, _ in issues], issues


# ---------------------------------------------------------------------------
# Mutations fail — one negative per original inconsistency
# ---------------------------------------------------------------------------

def test_negative_a_foreign_message_change_fails_ep08():
    """The first original defect verbatim: a changes[] CE from another
    message."""
    bad = copy.deepcopy(EPF)
    bad["changes"][0]["message_id"] = "01HZ3ABCDEFGH9JKMN0PQRSTVW"
    assert _ep08(bad), "a nested CE with a foreign message_id must fail"


def test_negative_a_sender_side_nested_confirmation_fails_recursively():
    """The second original defect verbatim: the nested s3 attributed to the
    sender-side member — now swept by check_bundle recursion."""
    def mutate(evidence):
        for ev in evidence:
            for o in ev.get("outcomes") or []:
                s3 = o.get("s3_attestation")
                if isinstance(s3, dict):
                    s3["mid"] = "A1B2C3D4R"   # the German (sender) member
    issues = bl.violations(bl.check_bundle(*_federated_bundle(mutate)))
    assert any(r == "LINT-BND-12" for r, _ in issues), \
        "a nested foreign-member confirmation must fail the recursive sweep"


def test_negative_a_mutated_nested_message_id_fails():
    """LINT-EP-01 (evidence level) binds every outcome to the EP's message —
    the recursive-coverage counterpart of LINT-EP-08 for changes."""
    bad = copy.deepcopy(EPF)
    bad["outcomes"][0]["message_id"] = "01HZ3OTHERMESSAGE00000000"
    v = el.Violations()
    el.lint_ep(v, bad)
    assert any(r == "LINT-EP-01" for r, _ in v.items),         "a mutated nested message id must break conformance"


def test_n01_regression_the_projection_corpus_is_intact():
    """The decomposition's rider: LINT-PKG-11 still guards the regenerated
    set — projection == decode(payload) for the federated artefact."""
    sample = json.loads((ROOT / "samples" / "sample-EP-federated.json").read_text())
    assert lc.projection_equals_decode(sample) == []
