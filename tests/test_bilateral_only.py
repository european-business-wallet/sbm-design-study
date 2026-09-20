# SPDX-License-Identifier: MIT
"""F-07 / D1 — bilateral only: multiparty groups are prohibited.

Former defect: the I-D allowed three or more entities in one group while
the envelope, SE, DE, policy evaluation and directory resolution all use
SINGULAR sender/recipient identities — who is an addressee, which policy
governs delivery and what a DE means for partial delivery were undefined.

D1 (settled): prohibit. A channel is between exactly two entities; a group
containing devices of three or more entities is not conformant and is
rejected at creation, at join, and by any verifier. Multiparty is recorded
as future study (a possible SPECIFIED extension) — which is why the
SBMScopeExtension.entity_uids field remains in the wire struct, bound EMPTY
in this profile.
"""
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import mls_channel as ch  # noqa: E402
import mls_wire as w  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dl = _load("doc_lint", "doc_lint.py")

DE_UID = "EU-DE-EOID-7K3D9W0Q2M5FW0"
FR_UID = "EU-FR-PSBID-ZYWVTSRQPNM8M4"
IT_UID = "EU-IT-EOID-AAAAAAAAAAAAQ0"
IDD = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()


def test_negative_a_three_entity_channel_is_rejected():
    """The D1 negative fixture verbatim: a 3-entity group config."""
    with pytest.raises(ValueError, match="bilateral only"):
        ch.channel_id([DE_UID, FR_UID, IT_UID], "default")


def test_a_two_entity_channel_remains_valid():
    assert ch.channel_id([DE_UID, FR_UID], "default")


def test_negative_a_nonempty_entity_uid_list_is_the_multiparty_marker():
    """The extension's multiparty marker is rejected in this profile —
    the field survives only for the specified future-study extension."""
    with pytest.raises(ValueError, match="bilateral only"):
        w.serialize_scope_extension("default", "1", [DE_UID, FR_UID])
    # the future-study path stays buildable for fixtures, explicitly:
    assert w.serialize_scope_extension("default", "1", [DE_UID, FR_UID],
                                       bilateral=False)


def test_the_shipped_extension_is_bilateral():
    """Every sealed group context carries an EMPTY entity_uids vector."""
    assert w.sbm_scope_extensions("default", "1").hex().endswith("00")


def test_the_id_states_the_prohibition_and_the_future_study():
    assert "EXACTLY TWO entities" in IDD
    assert "NOT CONFORMANT to this profile version" in IDD
    assert "Future study:" in IDD and "multiparty" in IDD.lower()


def test_the_former_allowance_is_forbidden():
    former = ("A group MAY contain devices from three or more entities "
              "(multi-party channels)")
    assert any(p.search(former) for p in dl.FORBIDDEN), \
        "doc_lint must forbid the multiparty allowance phrasing"
    assert "MAY contain devices from three or more" not in IDD


def test_every_legal_claim_has_a_singular_addressee():
    """The evidence model is singular by construction: SE names ONE sender
    and ONE recipient UID (strings, not arrays)."""
    se = json.load(open(ROOT / "schemas" / "evidence-se.schema.json"))
    for field in ("sender_uid", "recipient_uid"):
        prop = se["properties"][field]
        ref = prop.get("$ref", "")
        assert "Uid" in ref or prop.get("type") == "string", field
