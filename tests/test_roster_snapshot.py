# SPDX-License-Identifier: MIT
"""F-12 — the published roster becomes an atomic historical snapshot.

Former defect: the member-enumeration endpoint was a non-authoritative
mirror assembled from individually sealed BW-MEMBER documents — no signed
snapshot identifier or manifest proved completeness or atomicity at a
specific MLS epoch, so an omitted active member or a mixed-version
enumeration was undetectable, and nothing tied the enumeration to the tree
the evidence commits to.

Now: ROSTER-v1 — the entity's SIGNED per-epoch manifest. Completeness is
what the signature attests (no pagination of the signed set); each
member_doc_digest pins the exact sealed BW-MEMBER version; tree_hash chains
to the ratchet-tree hash inside the retained GroupContext committed by the
evidence mls_state (enumeration ↔ tree ↔ evidence). LINT-DISC-26 detects
both failure modes; the EDD serves snapshots current and as-of (contract
v1.9.0).
"""
import copy
import hashlib
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


dl = _load("discovery_lint", "discovery_lint.py")
mock = _load("mock_rdp", "mock_rdp.py")

ROSTER = lc.reconstruct(json.loads(
    (ROOT / "samples" / "sample-ROSTER.json").read_text()))
SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]

MEMBER_FILES = ("sample-BW-MEMBER-fr.json", "sample-BW-MEMBER-fr2.json",
                "sample-BW-MEMBER-records.json")


def _member_digests():
    out = {}
    for name in MEMBER_FILES:
        m = json.loads((ROOT / "samples" / name).read_text())["projection"]
        out[m["mid"]] = hashlib.sha256(mock._dcbor(m)).hexdigest()
    return out


def _disc26(doc, member_docs=None, expected_tree_hash=None):
    v = dl.Violations()
    dl.lint_roster(v, doc, member_docs=member_docs,
                   expected_tree_hash=expected_tree_hash)
    return [m for r, m in v.items if r == "LINT-DISC-26"]


# ---------------------------------------------------------------------------
# The shipped snapshot: valid, complete, chained
# ---------------------------------------------------------------------------

def test_the_shipped_snapshot_validates_and_resolves_completely():
    assert not lc.validate_body({k: v for k, v in ROSTER.items()
                                 if k != "doc_cose_b64"})
    assert not _disc26(copy.deepcopy(ROSTER), member_docs=_member_digests())


def test_the_snapshot_chains_to_the_evidenced_epoch():
    """tree_hash equals the ratchet-tree hash inside the GroupContext the
    evidence mls_state commits to — enumeration ↔ tree ↔ evidence."""
    expected = w.demo_tree_hash(ROSTER["mls_group_id"],
                                ROSTER["mls_epoch"]).hex()
    assert ROSTER["tree_hash"] == expected
    assert not _disc26(copy.deepcopy(ROSTER), expected_tree_hash=expected)
    # and the SAME (group, epoch) is what the shipped SE's mls_state covers:
    assert (SE["mls_group_id"], SE["mls_epoch"]) == \
        (ROSTER["mls_group_id"], ROSTER["mls_epoch"])


# ---------------------------------------------------------------------------
# The two failure modes the finding demands be detectable
# ---------------------------------------------------------------------------

def test_negative_an_omitted_active_member_is_detected():
    """The former defect: an enumeration silently missing an active member.
    The snapshot's signed completeness makes it detectable."""
    bad = copy.deepcopy(ROSTER)
    bad["members"] = [m for m in bad["members"] if m["mid"] != "F2X3Y4Z55"]
    msgs = _disc26(bad, member_docs=_member_digests())
    assert any("OMITTED" in m for m in msgs), msgs


def test_negative_a_mixed_version_enumeration_is_detected():
    """A snapshot pinning a STALE document version for one member."""
    bad = copy.deepcopy(ROSTER)
    bad["members"][0]["member_doc_digest"] = "f" * 64
    msgs = _disc26(bad, member_docs=_member_digests())
    assert any("mixed-version" in m for m in msgs), msgs


def test_negative_an_unknown_snapshot_member_is_detected():
    bad = copy.deepcopy(ROSTER)
    bad["members"].append({"mid": "ZZZZZZZZ0", "status": "active",
                           "member_doc_digest": "a" * 64,
                           "devices": [{"device_id": "dev-x",
                                        "signature_key_hash": "b" * 64}]})
    msgs = _disc26(bad, member_docs=_member_digests())
    assert any("no supplied sealed" in m for m in msgs), msgs


def test_negative_a_broken_tree_chain_is_detected():
    bad = copy.deepcopy(ROSTER)
    bad["tree_hash"] = "c" * 64
    expected = w.demo_tree_hash(ROSTER["mls_group_id"],
                                ROSTER["mls_epoch"]).hex()
    msgs = _disc26(bad, expected_tree_hash=expected)
    assert any("does not chain" in m for m in msgs), msgs


def test_negative_a_duplicate_mid_is_detected():
    bad = copy.deepcopy(ROSTER)
    bad["members"].append(copy.deepcopy(bad["members"][0]))
    assert _disc26(bad)


# ---------------------------------------------------------------------------
# Publication surfaces
# ---------------------------------------------------------------------------

def test_the_edd_contract_serves_snapshots_as_of():
    import yaml
    spec = yaml.safe_load((ROOT / "edd-resolver-openapi.yaml").read_text())
    path = spec["paths"]["/uid/{uid}/roster-snapshot"]
    assert "get" in path
    # Derived from versions.json — see test_schema_negative for the reasoning.
    assert spec["info"]["version"] == json.loads((ROOT / "versions.json").read_text())["dimensions"]["edd_openapi"]["value"]


def test_the_docs_name_the_snapshot_as_the_atomicity_anchor():
    umb = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
    idd = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "**Atomicity anchor:**" in umb
    assert "**Atomic snapshot.**" in idd
    assert "enumeration ↔ tree ↔ evidence" in idd
