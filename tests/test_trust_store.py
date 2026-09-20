# SPDX-License-Identifier: MIT
"""--trust-store minimal slice (ninth review, P10): LINT-TRUST-01..03.

The store (samples/trust-store.demo.json) is DEMO-grade — kid -> role /
identities / Ed25519 key / validity window — not QSealC material. Fail-closed:
an unknown signer, a signature that does not verify against the store key, a
role/identity mismatch, or an out-of-window instant must each be rejected, on
BOTH linters.
"""
import copy
import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ev = _load("evidence_lint", "evidence_lint.py")
reconstruct = ev.reconstruct  # M4: decode artefacts
dv = _load("discovery_lint", "discovery_lint.py")
STORE = reconstruct(json.loads((ROOT / "samples" / "trust-store.demo.json").read_text(encoding="utf-8")))


def _doc(name):
    return reconstruct(json.loads((ROOT / "samples" / name).read_text(encoding="utf-8")))


def _run(script, *args):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script), *args],
        capture_output=True, text=True, cwd=ROOT)


# ------------------------------------------------------------------ positive

def test_demo_samples_verify_against_the_demo_store():
    assert ev.lint(_doc("sample-SE.json"), trust_store=STORE) == []
    assert ev.lint(_doc("sample-EP.json"), trust_store=STORE) == []
    assert ev.lint(_doc("sample-RELAY-b1.json"), trust_store=STORE) == []
    assert ev.lint(_doc("sample-RELAY-b2.json"), trust_store=STORE) == []
    assert dv.lint(_doc("sample-BW-ORG.json"), trust_store=STORE) == []
    assert dv.lint(_doc("sample-BW-MEMBER-fr.json"), trust_store=STORE) == []


# ----------------------------------------------------------------- negatives

def _rules(items):
    return [r for r, _ in items]


def test_trust_01_unknown_kid_fails_closed_on_both_linters():
    store = copy.deepcopy(STORE)
    del store["entries"]["rdp"]
    assert "LINT-TRUST-01" in _rules(ev.lint(_doc("sample-SE.json"), trust_store=store))
    store = copy.deepcopy(STORE)
    del store["entries"]["entity-admin"]
    assert "LINT-TRUST-01" in _rules(dv.lint(_doc("sample-BW-ORG.json"), trust_store=store))


def test_trust_01_signature_must_verify_against_the_store_key():
    store = copy.deepcopy(STORE)
    # swap in the OTHER demo key: kid resolves, but the signature cannot verify
    store["entries"]["rdp"]["pubkey_b64"] = STORE["entries"]["entity-admin"]["pubkey_b64"]
    assert "LINT-TRUST-01" in _rules(ev.lint(_doc("sample-SE.json"), trust_store=store))


def test_trust_02_discovery_identity_pinned_to_entity_uid():
    """F9 (PoC feedback, twelfth review): the discovery-publisher entry pins
    the entity uids the key may sign for; a discovery document from an entity
    outside the list fails closed (LINT-TRUST-02), exactly like an unknown
    rdp_id on evidence."""
    store = copy.deepcopy(STORE)
    store["entries"]["entity-admin"]["identities"] = ["EU-IT-EOID-AAAAAAAAAAAAQ0"]
    assert "LINT-TRUST-02" in _rules(dv.lint(_doc("sample-BW-ORG.json"), trust_store=store))
    assert "LINT-TRUST-02" in _rules(dv.lint(_doc("sample-BW-MEMBER-fr.json"), trust_store=store))


def test_trust_02_role_mismatch():
    store = copy.deepcopy(STORE)
    store["entries"]["rdp"]["role"] = "discovery-publisher"
    assert "LINT-TRUST-02" in _rules(ev.lint(_doc("sample-SE.json"), trust_store=store))
    store = copy.deepcopy(STORE)
    store["entries"]["entity-admin"]["role"] = "evidence-rdp"
    assert "LINT-TRUST-02" in _rules(dv.lint(_doc("sample-BW-MED.json"), trust_store=store))


def test_trust_02_identity_not_allowed():
    store = copy.deepcopy(STORE)
    store["entries"]["rdp"]["identities"] = ["urn:sbm:rdp:someoneelse-999"]
    assert "LINT-TRUST-02" in _rules(ev.lint(_doc("sample-SE.json"), trust_store=store))


def test_trust_02_relay_evidence_issuer_is_bound_cf6():
    """CF-6 (twenty-first review): a RelayEvidence-v1 names its issuer in
    `receiving_rdp_id`, NOT `rdp_id` — so the identity handed to check_trust used
    to be None, and the LINT-TRUST-02 binding was SILENTLY SKIPPED (check_trust
    gates it on `identity is not None`). A party holding a valid trust-store key
    could therefore seal a relay hop attributed to a DIFFERENT RDP — one the
    federation has never heard of — and the fail-closed mode would bless it.

    This is the attribution gap: per-hop evidence exists to prove which provider
    did what at which hop. The issuer is now bound."""
    import os
    os.environ["KEY_SEED"] = "demo"
    mock = _load("mock_rdp", "mock_rdp.py")
    b1 = _doc("sample-RELAY-b1.json")
    # the honest hop is clean in the STRICTEST mode
    assert ev.lint(b1, verify_demo=True, trust_store=STORE) == []
    # ...and a hop attributed to an RDP outside the store now FAILS, even though
    # it is sealed with a valid demo key and is otherwise perfectly formed.
    import base64
    evil = {k: v for k, v in b1.items() if k != "seal"}
    evil["receiving_rdp_id"] = "urn:sbm:rdp:evil-999"
    cose = mock.seal_cose(evil)   # M4: COSE over dCBOR(body)
    evil["seal"] = {"cose_b64": base64.b64encode(cose).decode("ascii"),
                    "qualified_timestamp": mock._qts_over_cose(cose, evil["hop_at"])}
    assert "LINT-TRUST-02" in _rules(ev.lint(evil, verify_demo=True, trust_store=STORE))


def test_trust_02_evidence_package_composer_is_bound():
    """Found while implementing CF-6: the EVIDENCE PACKAGE had the same gap, and
    it is the more consequential one. An EP carries NO rdp_id (the schema admits
    no such field), so its signer identity was None and the LINT-TRUST-02 binding
    was skipped for the AGGREGATE DISPUTE ARTEFACT — the object a verifier or a
    court actually reads. The EP is composed and sealed by the sender-side RDP
    that issued the SE (TS clause 4.1), so its signer is se.rdp_id."""
    store = copy.deepcopy(STORE)
    store["entries"]["rdp"]["identities"] = ["urn:sbm:rdp:someoneelse-999"]
    # the SE has always been bound...
    assert "LINT-TRUST-02" in _rules(ev.lint(_doc("sample-SE.json"), trust_store=store))
    # ...and now the EP that encloses it is too (it used to pass clean).
    assert "LINT-TRUST-02" in _rules(ev.lint(_doc("sample-EP.json"), trust_store=store))


def test_trust_04_relay_peer_must_resolve_in_the_store():
    """LINT-TRUST-04 (CF-6, twenty-first review): a relay hop's `sending_rdp_id` is
    a CLAIM about a federation peer. That peer is NOT the signer, so it is checked
    for MEMBERSHIP (is it a provider the federation knows?), never against the
    signer's own identity list. Makes FC-3 peer authentication machine-checkable.

    Deliberately a TRUST rule, not an extension of LINT-RLY-02: LINT-RLY-02 must
    keep working without a store, so its meaning must not depend on the mode."""
    b1 = _doc("sample-RELAY-b1.json")
    assert "LINT-TRUST-04" not in _rules(ev.lint(b1, trust_store=STORE))
    # a hop claiming it was relayed by a provider the federation has never heard of
    unknown = dict(b1, sending_rdp_id="urn:sbm:rdp:unknown-000")
    assert "LINT-TRUST-04" in _rules(ev.lint(unknown, trust_store=STORE))
    # ...and with NO store the relay rules still behave (LINT-RLY-02 unchanged)
    assert "LINT-TRUST-04" not in _rules(ev.lint(unknown))


def test_trust_03_instant_outside_validity_window():
    store = copy.deepcopy(STORE)
    store["entries"]["rdp"]["not_after"] = "2025-01-01T00:00:00Z"
    assert "LINT-TRUST-03" in _rules(ev.lint(_doc("sample-SE.json"), trust_store=store))
    store = copy.deepcopy(STORE)
    store["entries"]["entity-admin"]["not_before"] = "2026-12-01T00:00:00Z"
    assert "LINT-TRUST-03" in _rules(dv.lint(_doc("sample-BW-MED.json"), trust_store=store))


def test_trust_03_takes_the_CHRONOLOGICALLY_latest_instant():
    """R10-12, driven through the consuming linter (LINT-TRUST-03), not the
    helper. `_latest_declared_instant` chose the latest instant by STRING
    order, on the premise that "Zulu-form strings compare correctly as
    strings" — a premise DR-05 broke when it made the walk accept offsets.

    `09:45:00-02:00` is 11:45Z: ninety minutes AFTER `10:15:00Z`, and sorts
    BEFORE it as text. With the signer's window closing at 11:00Z, string
    order picked the in-window instant and passed a document whose true latest
    instant lies outside the window."""
    doc = _doc("sample-SE.json")
    doc["sender_confirmation"]["sent_at"] = "2026-04-04T09:45:00-02:00"
    assert "2026-04-04T09:45:00-02:00" < "2026-04-04T10:15:00Z", \
        "the probe no longer discriminates string order from time order"
    store = copy.deepcopy(STORE)
    store["entries"]["rdp"]["not_after"] = "2026-04-04T11:00:00Z"
    assert "LINT-TRUST-03" in _rules(ev.lint(doc, trust_store=store))
    # The control: the same document inside a window covering 11:45Z passes
    # this rule, so the refusal above is about the instant and nothing else.
    store["entries"]["rdp"]["not_after"] = "2026-04-04T12:00:00Z"
    assert "LINT-TRUST-03" not in _rules(ev.lint(doc, trust_store=store))


# ---------------------------------------------------------------- CLI level

@pytest.mark.parametrize("script,args", [
    ("evidence_lint.py", ("samples/sample-SE.json",)),
    ("discovery_lint.py", ("samples/sample-BW-ORG.json",)),
])
def test_cli_clean_run_with_the_demo_store(script, args):
    r = _run(script, "--trust-store", "samples/trust-store.demo.json", *args)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("script", ["evidence_lint.py", "discovery_lint.py"])
def test_cli_missing_store_fails_closed(script):
    r = _run(script, "--trust-store", "no-such-store.json", "samples/sample-SE.json")
    assert r.returncode == 2
    assert "cannot read/parse trust store" in r.stderr
