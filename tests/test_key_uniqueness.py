# SPDX-License-Identifier: MIT
"""X-32 — one confirmation key per device, everywhere.

Former defect: ONE demo key (the global `wallet-demo` seed) was the
published confirmation_key of SIX device records across FOUR members, TWO
entities and THREE security classes — a software-device signature verified
against the secure-element and HSM records, collapsing device-bound
assurance to member-bound.

Now: a confirmation_key is unique per (mid, device_id) — the umbrella §8.4
rule prohibits sharing across devices, members and entities and defines
rollover (same device record, as-of history); the demo keys derive from
`wallet:{mid}:{device_id}`; LINT-DISC-27 catches intra-member duplicates,
LINT-BND-32 cross-member duplicates; and a signature now resolves to
exactly one device record and security class.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dl = _load("discovery_lint", "discovery_lint.py")
bl = _load("bundle_lint", "bundle_lint.py")
mock = _load("mock_rdp", "mock_rdp.py")

MEMBER_FILES = ("sample-BW-MEMBER.json", "sample-BW-MEMBER-agent.json",
                "sample-BW-MEMBER-fr.json", "sample-BW-MEMBER-fr2.json",
                "sample-BW-MEMBER-records.json")


def _members():
    return [lc.reconstruct(json.loads((ROOT / "samples" / f).read_text()))
            for f in MEMBER_FILES]


def _disc27(doc):
    v = dl.Violations()
    dl.lint_member(v, doc)
    return [m for r, m in v.items if r == "LINT-DISC-27"]


def _bnd32(members):
    issues = bl.check_bundle("EU-FR-PSBID-ZYWVTSRQPNM8M4", {}, {}, members, [])
    return [m for r, m in issues if r == "LINT-BND-32"]


# ---------------------------------------------------------------------------
# The acceptance: every key resolves to exactly one (member, device, class)
# ---------------------------------------------------------------------------

def test_every_shipped_key_resolves_to_exactly_one_device():
    seen = {}
    for m in _members():
        for d in m.get("devices") or []:
            pk = (d.get("confirmation_key") or {}).get("public_key_b64")
            if pk:
                assert pk not in seen, \
                    f"{pk[:12]} on both {seen[pk]} and {m['mid']}/{d['device_id']}"
                seen[pk] = f"{m['mid']}/{d['device_id']}"
                # and it IS the per-device derived key:
                assert pk == mock.demo_public_key_b64(
                    f"wallet:{m['mid']}:{d['device_id']}")
    assert len(seen) >= 5, "the shipped set publishes distinct per-device keys"


def test_negative_the_former_global_key_fixture_fails_both_lints():
    """The former defect verbatim: one key across devices and members."""
    members = _members()
    shared = mock.demo_public_key_b64("wallet-demo")
    bad = copy.deepcopy(members)
    for m in bad:
        for d in m.get("devices") or []:
            if isinstance(d.get("confirmation_key"), dict):
                d["confirmation_key"]["public_key_b64"] = shared
    assert _bnd32(bad), "cross-member duplicates must fail LINT-BND-32"
    fr = next(m for m in bad if m["mid"] == "F1N2C3D4P")   # two devices
    assert _disc27(fr), "intra-member duplicates must fail LINT-DISC-27"


def test_positive_the_shipped_set_is_duplicate_free():
    assert not _bnd32(_members())
    for m in _members():
        assert not _disc27(copy.deepcopy(m)), m["mid"]


def test_negative_a_software_signature_no_longer_verifies_against_the_hsm_record():
    """The collapse is gone: a signature under dev-01's (software) key does
    NOT verify against dev-02-hsm's published anchor."""
    fr = next(m for m in _members() if m["mid"] == "F1N2C3D4P")
    hsm = next(d for d in fr["devices"] if d["device_id"] == "dev-02-hsm")
    conf = {"mid": "F1N2C3D4P", "device_id": "dev-01", "result": "x"}
    sig = mock._wallet_sign(conf)   # signed under the dev-01 key
    # DR-12: the verifier takes the confirmation-key OBJECT, not the bare
    # public bytes — the declared ALGORITHM is half of what must be checked,
    # and passing only the bytes is what made it guess Ed25519 for every key.
    # It returns the REASON on failure and None on success.
    assert bl._verify_wallet_sig(sig, hsm["confirmation_key"]), \
        "a software-device signature must not verify against the HSM anchor"
    sw = next(d for d in fr["devices"] if d["device_id"] == "dev-01")
    assert bl._verify_wallet_sig(sig, sw["confirmation_key"]) is None


def test_the_rule_rollover_and_prohibition_are_normative():
    umb = " ".join((ROOT / "Secure-Business-Messaging-Profile.md")
                   .read_text().split()).replace("*", "").replace("`", "")
    assert "MUST be unique per (mid, device_id)" in umb
    assert "Intentional multi-device key sharing is PROHIBITED" in umb
    assert "a rollover never moves a key to a different device" in umb
