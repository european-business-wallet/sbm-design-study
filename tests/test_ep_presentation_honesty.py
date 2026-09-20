# SPDX-License-Identifier: MIT
"""X-18 — the EP presentation is non-selective, honestly.

Former defect: the EP SD-JWT-VC mapping marked `sender_uid` and
`recipient_uid` "Selective disclosure: Yes" while the always-disclosed
`sm_artifact_b64` claim embedded the complete sealed EP — both identifiers
remained readable when their disclosures were withheld. Transitive
disclosure defeated every SD claim. The sweep found the same defect in the
UID QEAA profile: `jurisdiction` was marked hideable while the
always-disclosed `uid` string embeds the country code (§3.1).

Chosen resolution (approved): the EP presentation is declared
NON-SELECTIVE — the SD column is removed, the transitive-disclosure
rationale is stated as a warning to future mappings, and a derived
presentation is future study; the QEAA `jurisdiction` row is corrected.
Nothing is claimed hidden that a mandatory carrier reveals.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
FLAT = " ".join(UMB.split()).replace("**", "").replace("`", "")


def _section(title, next_title):
    return UMB.split(title)[1].split(next_title)[0]


EP_SECTION = _section("### 10.3 Evidence Package as a Verifiable Credential",
                      "### 10.4")


def test_negative_no_ep_field_is_claimed_selectively_disclosable():
    """The former defect: 'Yes' rows under an always-disclosed full copy."""
    assert "Selective disclosure" not in EP_SECTION, \
        "the SD column must be gone from the EP mapping"
    assert not re.search(r"\|\s*Yes\s*\|", EP_SECTION)


def test_the_presentation_is_declared_non_selective_with_the_rationale():
    assert "NON-SELECTIVE: every claim is disclosed" in EP_SECTION
    assert "transitively disclosed" in " ".join(EP_SECTION.split())
    assert "no field of this presentation is claimed hidden" in \
        " ".join(EP_SECTION.split()).replace("**", "")


def test_the_artefact_claim_is_named_as_the_disclosure_source():
    assert "the source of the transitive disclosure" in \
        " ".join(EP_SECTION.split())


def test_the_future_study_derived_presentation_is_recorded():
    flat = " ".join(EP_SECTION.split()).replace("*", "")
    assert "Future study:" in flat
    assert "byte-exact binding to the sealed source" in flat
    assert "re-evaluate every claimed-hideable field" in flat


def test_the_qeaa_jurisdiction_row_is_corrected():
    """The sweep's catch: the uid embeds the CC, so 'jurisdiction' was
    never hideable."""
    qeaa = _section("**UID QEAA profile (SD-JWT-VC):**", "### 10.2")
    row = next(l for l in qeaa.splitlines() if "`jurisdiction`" in l)
    assert "Yes |" not in row
    assert "transitively disclosed" in row


def test_genuinely_hideable_qeaa_fields_stay_hideable():
    """entity_name / euid / lei are NOT embedded in any always-disclosed
    carrier — their SD claims are truthful and stay."""
    qeaa = _section("**UID QEAA profile (SD-JWT-VC):**", "### 10.2")
    for field in ("entity_name", "euid", "lei"):
        row = next(l for l in qeaa.splitlines() if f"`{field}`" in l)
        assert row.rstrip().endswith("Yes |"), row
