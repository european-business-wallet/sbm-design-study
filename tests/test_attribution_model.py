# SPDX-License-Identifier: MIT
"""X-23 — attribution, not deniability.

Former defect: the I-D T3 claimed "MLS leaf signatures are deniable to
third parties" — inverted for this profile: the leaves carry X.509 QSealC
chains or the UID QEAA, transcripts/GroupContexts are retained (F-03) and
roster snapshots signed (F-12), so signed MLS content is STRONGLY
attributable; the privacy/legal analysis leaned on a property the profile
does not establish — and, as a registered-delivery profile, does not want.

Now: T3 states the attribution model per signed object (leaf / wallet
confirmation / evidence object, each with its chain), records what true
deniability would require (not offered), and re-runs the metadata, insider
and evidentiary analyses under attribution.
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
IDD = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
FLAT = " ".join(IDD.split()).replace("**", "").replace("`", "")


def test_negative_the_deniability_claim_is_gone_and_forbidden():
    assert "deniable to\n  third parties" not in IDD
    assert "MLS leaf signatures are deniable" not in FLAT
    former = "MLS leaf signatures are deniable to third parties"
    assert any(p.search(former) for p in dl.FORBIDDEN)


def test_the_attribution_model_names_object_and_chain():
    """The acceptance criterion: WHO can attribute WHICH signed object with
    WHAT credential chain."""
    # The heading carried the migration-step code `T3` until 25 September 2026;
    # the claim is the heading, not the step that produced it.
    assert "Attribution, not deniability." in FLAT
    assert "attributable to the signing LEAF" in FLAT
    assert "QSealC → EU Trusted List, or UID QEAA → issuing QTSP" in FLAT
    assert "attributable to the member's DEVICE via the published confirmation_key anchor" in FLAT
    assert "attributable to its issuing RDP or registry by its seal" in FLAT


def test_deniability_is_recorded_as_what_it_would_take():
    assert "would require a DIFFERENT credential design" in FLAT
    assert "not as a property offered" in FLAT


def test_the_three_analyses_are_rerun_under_attribution():
    assert "retention duty carries an ACCESS-CONTROL duty" in FLAT      # metadata
    assert "leaks ATTRIBUTABLE statements" in FLAT                      # insider
    assert "no legal analysis in the companion documents relies on deniability" in FLAT  # evidentiary


def test_the_profile_wants_attribution():
    assert "legal-effect chain RELIES on attribution" in FLAT
    umb = " ".join((ROOT / "Secure-Business-Messaging-Profile.md")
                   .read_text().split())
    assert "(attribution, not deniability)" in umb
