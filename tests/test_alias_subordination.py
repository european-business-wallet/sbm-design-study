# SPDX-License-Identifier: MIT
"""X-14 — aliases are locators, strictly subordinate to the DirectoryRecord.

Former defect: the WebFinger alias namespace had no governance or signed
binding; DNS TXT/SRV/SVCB discovery had no record formats, owner-name
derivation or precedence rule — both readable as alternative location
anchors beside the authoritative DirectoryRecord.

Chosen resolution (approved): DNS aliasing is REMOVED (future study — an
under-specified parallel trust path is worse than none); WebFinger is fully
specified as a subordinate LOCATOR: every alias resolution terminates in
the seal- and status-validated DirectoryRecord and substitutes neither; on
conflict the DirectoryRecord wins; caching is bounded; absence implies
nothing. Alias compromise can misdirect a lookup attempt but cannot
authorise a provider, key or endpoint.
"""
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dl = _load("doc_lint", "doc_lint.py")
UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()


def test_dns_aliasing_is_removed_and_recorded_as_future_study():
    assert "### 5.5 DNS aliasing — removed (future study)" in UMB
    assert "NOT part of this profile version" in UMB
    assert "DNS TXT + SRV + SVCB" not in UMB


def test_the_former_dns_phrasing_is_forbidden():
    former = ("Wallets and RPs MAY discover messaging endpoints via "
              "DNS TXT + SRV + SVCB records.")
    assert any(p.search(former) for p in dl.FORBIDDEN), \
        "doc_lint must forbid the DNS-aliasing phrasing"


FLAT = " ".join(UMB.split())   # whitespace-normalized (wrapping-insensitive)


def test_every_alias_resolution_terminates_in_the_directory_record():
    assert ("MUST terminate in the retrieval and validation of the "
            "authoritative DirectoryRecord" in FLAT.replace("**", ""))
    assert "MUST NOT substitute either" in FLAT.replace("**", "")
    assert "an alias authorises nothing" in FLAT


def test_the_conflict_caching_and_downgrade_rules_exist():
    assert ("the DirectoryRecord wins and the alias result is discarded"
            in FLAT.replace("**", ""))
    assert "MUST NOT be cached longer than the" in FLAT.replace("**", "")
    assert "implies nothing about the" in FLAT.replace("**", "")


def test_the_security_property_is_stated():
    flat = UMB.replace("\n", " ")
    assert "cannot authorise a provider, key or endpoint" in flat
    assert "**Security property:**" in UMB


def test_exactly_two_link_relations_are_defined():
    assert "urn:bw:uid" in UMB and "urn:bw:med" in UMB
    assert "Unknown relations **MUST** be ignored" in UMB
