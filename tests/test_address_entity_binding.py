# SPDX-License-Identifier: MIT
"""R4-01 (Blocker) — an address and the evidence it addresses name one entity.

Former defect (round-4 review), reproduced in one line:

    recipient_uid  = EU-FR-PSBID-…                       (the French entity)
    recipient_addr = bw:uid:EU-DE-EOID-…/r/procurement    (the German one)
    → select_policy_key(...) = 'procurement'   ACCEPTED

Selection read only the `/r/<role>` tail, so an address naming **another
entity** picked a role out of *this* entity's `acceptance_policy` map. R3-01
had made the address REQUIRED and put it inside the signed D4 tuple; nothing
made it *mean* anything.

Two root causes, both fixed here:

* `LINT-BND-24` did `if uid != entity: continue`, commented *"addressed to a
  different entity — not this bundle's org"* — true, irrelevant, and exactly
  wrong: the object being checked is **this** bundle's evidence, addressed to
  **this** entity, so a foreign UID is the defect rather than someone else's
  business. It is the same shape as R3-03's fourth site: a `continue` that
  silently converts "suspicious" into "not my problem".
* **`sender_addr` appeared zero times in `bundle_lint.py`.** The symmetric
  check was not weak, it was absent — so `LINT-BND-37` is new rather than
  strengthened.
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")

SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
DE = json.loads((ROOT / "samples" / "sample-DE.json").read_text())["projection"]
ORG = json.loads((ROOT / "samples" / "sample-BW-ORG.json").read_text())["projection"]

FR = ORG["uid"]
DE_UID = "EU-DE-EOID-7K3D9W0Q2M5FW0"
DEFAULT = {"scope_id": "default", "version": "1"}


def _rules(evidence, entity=FR, org=ORG, members=()):
    return [r for r, _ in bl.violations(
        bl.check_bundle(entity, {}, org, list(members), evidence))]


# ---------------------------------------------------------------------------
# The reproduction, closed at the source
# ---------------------------------------------------------------------------

def test_a_foreign_address_no_longer_selects_a_local_policy():
    """The finding verbatim."""
    assert lc.select_policy_key(ORG, DEFAULT, f"bw:uid:{FR}/r/procurement") == "procurement"
    with pytest.raises(lc.ForeignAddress) as exc:
        lc.select_policy_key(ORG, DEFAULT, f"bw:uid:{DE_UID}/r/procurement")
    assert "different entity" in str(exc.value)


def test_a_malformed_address_cannot_be_checked_so_it_is_refused():
    for bad in ("not-an-address", "bw:uid:NOPE/r/x", f"{FR}/r/procurement"):
        with pytest.raises(lc.ForeignAddress):
            lc.select_policy_key(ORG, DEFAULT, bad)


def test_the_entity_addressed_form_still_works():
    assert lc.select_policy_key(ORG, DEFAULT, f"bw:uid:{FR}") == "default"


# ---------------------------------------------------------------------------
# ...and at the bundle layer, because a verifier reaches its own verdict
# ---------------------------------------------------------------------------

def test_the_verifier_reports_a_foreign_recipient_address():
    """This is where the `continue` was. A verifier holding the evidence long
    after the RDP must not need the RDP's word for it."""
    se = copy.deepcopy(SE)
    se["recipient_addr"] = f"bw:uid:{DE_UID}/r/procurement"
    assert "LINT-BND-24" in _rules([se])


def test_the_shipped_evidence_is_clean():
    assert "LINT-BND-24" not in _rules([copy.deepcopy(SE), copy.deepcopy(DE)])
    assert "LINT-BND-37" not in _rules([copy.deepcopy(SE), copy.deepcopy(DE)])


# ---------------------------------------------------------------------------
# The sender arm, which did not exist
# ---------------------------------------------------------------------------

def test_a_sender_address_naming_another_entity_is_reported():
    se = copy.deepcopy(SE)
    se["sender_addr"] = f"bw:uid:{FR}/r/invoices"     # sender_uid is the DE one
    assert se["sender_uid"] != FR
    rules = _rules([se])
    assert "LINT-BND-37" in rules


def test_a_malformed_sender_address_is_reported():
    se = copy.deepcopy(SE)
    se["sender_addr"] = "bw:uid:NOT-A-UID/r/invoices"
    assert "LINT-BND-37" in _rules([se])


def test_the_sender_arm_exists_at_all():
    """The finding is that it was ABSENT, so its presence is the fix. Asserted
    structurally as well as behaviourally: a rule reachable only through one
    fixture is a rule one refactor from disappearing again."""
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    assert src.count("sender_addr") >= 4, \
        "sender_addr appeared ZERO times before R4-01"
    assert "LINT-BND-37" in src


def test_a_sender_role_must_resolve_on_its_own_roster():
    """The mirror of LINT-BND-24's role check, for the bundle that IS the
    sender's."""
    se = copy.deepcopy(SE)
    entity = se["sender_uid"]
    se["sender_addr"] = f"bw:uid:{entity}/r/no-such-role"
    org = copy.deepcopy(ORG)
    org["uid"] = entity
    assert "LINT-BND-37" in _rules([se], entity=entity, org=org)


# ---------------------------------------------------------------------------
# One grammar, not two spellings of it
# ---------------------------------------------------------------------------

def test_the_two_address_parsers_agree():
    """`lint_cli` needs the UID without importing `bundle_lint` (the dependency
    runs the other way), so there are two parsers. Two spellings of one grammar
    is the R4 family, so they are asserted equal rather than assumed equal."""
    cases = [
        f"bw:uid:{FR}", f"bw:uid:{FR}/r/procurement", f"bw:uid:{FR}/u/F1N2C3D4P",
        f"bw:uid:{DE_UID}/r/invoices",
        "bw:uid:NOPE", "not-an-address", "", f"bw:uid:{FR}/x/other",
    ]
    for addr in cases:
        mine = lc._parse_bw_address_uid(addr) if addr else None
        theirs = bl._parse_bw_address(addr)
        assert mine == (theirs[0] if theirs else None), addr
