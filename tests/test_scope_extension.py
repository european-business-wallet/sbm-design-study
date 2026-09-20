# SPDX-License-Identifier: MIT
"""F-05 — the sbm_scope GroupContext extension has a wire definition.

Former defect: the I-D REQUIRED a scope extension (scope_id + descriptor
version; multiparty: all entity UIDs) but defined no ExtensionType, no TLS
syntax, no code point, no capability advertisement and no
required_capabilities rule — independent implementations could not
serialize identical bytes, and a non-supporting member could join silently.

Now: ExtensionType 0xF53B (RFC 9420 private use; IANA intent stated), the
SBMScopeExtension TLS struct with canonical UID ordering / duplicate
rejection / size bounds enforced BY THE SERIALIZER, presence REQUIRED in
every group (default scope included), capability + required_capabilities
normative. The D3 mls_state commitment covers the extension bytes, so scope
binding — and extension removal — is evidence-visible.
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import mls_wire as w  # noqa: E402

SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
SES = json.load(open(ROOT / "samples" / "sample-SE-scoped.json"))["projection"]


# ---------------------------------------------------------------------------
# Byte-identical serialization (the KAT)
# ---------------------------------------------------------------------------

def test_kat_the_default_scope_extension_bytes():
    """Two conforming implementations serialize IDENTICAL bytes: the whole
    extension list for (default, 1) is pinned."""
    ext = w.sbm_scope_extensions("default", "1")
    assert ext.hex() == "0ef53b0b0764656661756c74013100"
    assert w.SBM_SCOPE_EXTENSION_TYPE == 0xF53B


def test_kat_multiparty_uids_are_length_prefixed_and_ordered():
    # D1/F-07: a FUTURE-STUDY fixture (bilateral=False) — this profile
    # rejects non-empty entity_uids (test_bilateral_only.py).
    ext = w.serialize_scope_extension(
        "default", "1",
        ["EU-DE-EOID-7K3D9W0Q2M5FW0", "EU-FR-PSBID-ZYWVTSRQPNM8M4"],
        bilateral=False)
    # opaque scope_id<V> + version<V> + uid_vec<V> with two 25-byte entries
    assert ext.hex().startswith("0764656661756c740131")
    assert b"EU-DE-EOID" in ext and b"EU-FR-PSBID" in ext


# ---------------------------------------------------------------------------
# The serializer rejects what the wire forbids
# ---------------------------------------------------------------------------

def test_negative_reordered_entity_list_is_rejected():
    with pytest.raises(ValueError, match="bytewise-ascending"):
        w.serialize_scope_extension(
            "default", "1",
            ["EU-FR-PSBID-ZYWVTSRQPNM8M4", "EU-DE-EOID-7K3D9W0Q2M5FW0"],
            bilateral=False)


def test_negative_duplicate_entity_is_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        w.serialize_scope_extension(
            "default", "1",
            ["EU-DE-EOID-7K3D9W0Q2M5FW0", "EU-DE-EOID-7K3D9W0Q2M5FW0"],
            bilateral=False)


def test_negative_oversize_fields_are_rejected():
    with pytest.raises(ValueError, match="scope_id"):
        w.serialize_scope_extension("x" * 65, "1")
    with pytest.raises(ValueError, match="descriptor_version"):
        w.serialize_scope_extension("default", "v" * 33)
    with pytest.raises(ValueError, match="16-entry"):
        w.serialize_scope_extension("default", "1",
                                    [f"EU-XX-EOID-AAAAAAAAAAA{i:03d}"
                                     for i in range(17)], bilateral=False)


# ---------------------------------------------------------------------------
# The commitment makes the binding — and its removal — evidence-visible
# ---------------------------------------------------------------------------

def test_scope_binding_changes_the_mls_state():
    """A scoped group's state can never be mistaken for the default
    group's: same (group, epoch), different scope → different commitment."""
    default = w.demo_group_context(SE["mls_group_id"], SE["mls_epoch"])
    finance = w.demo_group_context(SE["mls_group_id"], SE["mls_epoch"],
                                   scope_id="finance")
    assert w.mls_state_hash(default) != w.mls_state_hash(finance)


def test_unknown_descriptor_version_changes_the_mls_state():
    v1 = w.demo_group_context(SE["mls_group_id"], SE["mls_epoch"])
    v2 = w.demo_group_context(SE["mls_group_id"], SE["mls_epoch"],
                              scope_version="2")
    assert w.mls_state_hash(v1) != w.mls_state_hash(v2)


def test_extension_removal_is_evidence_visible():
    """The former defect's silent-join direction: a context WITHOUT the
    extension commits to different bytes — removal cannot go unnoticed by
    any verifier holding the evidence."""
    with_ext = w.demo_group_context(SE["mls_group_id"], SE["mls_epoch"])
    without = w.demo_group_context(SE["mls_group_id"], SE["mls_epoch"],
                                   extensions=b"")
    assert w.mls_state_hash(with_ext) != w.mls_state_hash(without)


def test_the_shipped_evidence_commits_to_the_scope_extension():
    """The sealed samples' mls_state values ARE the extension-bearing
    contexts: default chain -> (default, 1); scoped chain -> (finance, 1)."""
    gc = w.demo_group_context(SE["mls_group_id"], SE["mls_epoch"])
    assert SE["mls_state"] == w.mls_state_hash(gc)
    gcs = w.demo_group_context(SES["mls_group_id"], SES["mls_epoch"],
                               scope_id=SES["scope_ref"]["scope_id"],
                               scope_version=SES["scope_ref"]["version"])
    assert SES["mls_state"] == w.mls_state_hash(gcs)


# ---------------------------------------------------------------------------
# Capability / lifecycle prose
# ---------------------------------------------------------------------------

def test_the_id_states_capability_and_immutability():
    idd = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "`required_capabilities` MUST include it" in idd
    assert "cannot join silently" in idd
    assert "`scope_id` is IMMUTABLE for a group" in idd
    assert "0xF53B" in idd
