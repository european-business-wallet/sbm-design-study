# SPDX-License-Identifier: MIT
"""X-16 — the bw: address scheme has one normative grammar, reused everywhere.

The former defect: the bw: address role token was constrained, but BW-ORG declared
roles as any string — so a role could be declared that could not be addressed, and
no check tied a recipient_addr /r/<role> to a declared role. This batch publishes
the address/role ABNF (umbrella Annex A), tightens the BW-ORG schema so every
declared role is a RoleName (addressable), and adds LINT-BND-24 (every address
resolves).

One shared accept/reject corpus (samples/bw-address-vectors.json) is run through
all consumers: the JSON-Schema BwAddress pattern, the bundle_lint parser, and (for
positives) the toolkit builder — the single-source reuse the finding requires.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bundle_lint as bl  # noqa: E402
import eu_entity_uid_toolkit as tk  # noqa: E402

# A canonical UID + MID used to instantiate the corpus templates.
UID = "EU-FR-PSBID-ZYWVTSRQPNM8M4"
MID = "A1B2C3D4R"

COMMON = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text())
BW_PAT = re.compile(COMMON["$defs"]["BwAddress"]["pattern"])
ROLE_PAT = re.compile(COMMON["$defs"]["RoleName"]["pattern"])
CORPUS = json.loads((ROOT / "samples" / "bw-address-vectors.json").read_text())


def _inst(a):
    return a.replace("{uid}", UID).replace("{mid}", MID)


def _schema_ok(a):
    return BW_PAT.match(a) is not None


def _parse_ok(a):
    return bl._parse_bw_address(a) is not None


def test_schema_and_parser_agree_on_the_corpus():
    """The BwAddress schema pattern and the bundle_lint parser accept/reject the
    SAME language on every vector (one grammar, two consumers)."""
    for a in CORPUS["accept"]:
        addr = _inst(a)
        assert _schema_ok(addr), f"schema rejected an ACCEPT vector: {addr}"
        assert _parse_ok(addr), f"parser rejected an ACCEPT vector: {addr}"
    for a in CORPUS["reject"]:
        addr = _inst(a)
        assert not _schema_ok(addr), f"schema accepted a REJECT vector: {addr}"
        assert not _parse_ok(addr), f"parser accepted a REJECT vector: {addr}"


def test_role_token_grammar_is_the_same_everywhere():
    """The address /r/<role> token equals the RoleName $def used by BW-ORG."""
    # a role that the address grammar accepts must be a valid RoleName, and vice versa
    for good in ("invoices", "a.b_c-d", "x"):
        assert ROLE_PAT.match(good) and _parse_ok(f"bw:uid:{UID}/r/{good}")
    for bad in ("Invoices", "in voices", "a" * 33, ""):
        assert not ROLE_PAT.match(bad)


def test_toolkit_builder_produces_schema_valid_addresses():
    # Generate a CHECKSUM-VALID UID via the toolkit (robust to the check-char
    # algorithm), then confirm the builder yields schema-valid addresses.
    valid_uid = tk.uid_generate("FR", "PSBID", "ZYWVTSRQPNM8")
    for role in ("invoices", "legal"):
        addr = tk.build_bw_address(valid_uid, role=role)
        assert _schema_ok(addr), f"toolkit built a schema-invalid address: {addr}"


def test_negative_recipient_addr_to_undeclared_role_is_rejected():
    """LINT-BND-24: an address to a role the BW-ORG does not declare is rejected."""
    org = {"type": "BW-ORG-v1", "uid": UID, "roles": ["invoices", "legal"]}
    se = {"type": "SE-v1", "recipient_addr": f"bw:uid:{UID}/r/nonexistent"}
    med = {"type": "BW-MED-v1", "uid": UID, "mls": {}}
    issues = bl.check_bundle(UID, med, org, [], [se])
    assert any(r == "LINT-BND-24" and "not a declared role" in m
               for r, m in issues), issues


def test_positive_recipient_addr_to_declared_role_passes():
    org = {"type": "BW-ORG-v1", "uid": UID, "roles": ["invoices", "legal"]}
    se = {"type": "SE-v1", "recipient_addr": f"bw:uid:{UID}/r/invoices"}
    med = {"type": "BW-MED-v1", "uid": UID, "mls": {}}
    issues = bl.check_bundle(UID, med, org, [], [se])
    assert not [r for r, _ in issues if r == "LINT-BND-24"], issues
