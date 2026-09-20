# SPDX-License-Identifier: MIT
"""X-13 — one owner per endpoint; redirect-only evidence.

Former defect: §5.3 said "the core registry MUST expose" every endpoint —
including ones "(delegated to MSP discovery layer)" — while the OpenAPI
split the surface differently; the evidence endpoint permitted a direct
200 EvidencePackage although the architecture says the registry/discovery
layers store no evidence; and `{uid}` in the evidence path was undefined.

Now: the §5.3 endpoint-to-owner TABLE names exactly one authoritative
operator, data owner, storage rule and access rule per path; the evidence
endpoint is a POINTER ONLY (302 to the composing RDP, or a uniform 404 —
the 200 is gone from the contract); `{uid}` is the SENDER-SIDE subject
(D2/F-13: the composer is always the sender-side RDP); access is
authenticated + authorised with no existence oracle.
"""
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]

UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
SPEC = yaml.safe_load((ROOT / "edd-resolver-openapi.yaml").read_text())


def test_the_ownership_table_exists_and_names_one_operator_per_path():
    assert "one owner per endpoint (normative)" in UMB
    assert "| Path | Authoritative operator | Data owner | Storage | Access |" in UMB
    # exactly one operator cell per row of the table (no A/B hedges)
    table = UMB.split("| Path | Authoritative operator |")[1].split("\n\n")[0]
    for line in table.splitlines():
        if line.startswith("| `GET"):
            operator = line.split("|")[2]
            assert " or " not in operator, line


def test_negative_the_direct_200_evidence_response_is_gone():
    """The former defect: a component prohibited from storing evidence was
    described as returning it."""
    ev = SPEC["paths"]["/uid/{uid}/evidence/{message_id}"]["get"]
    assert sorted(ev["responses"].keys()) == ["302", "404"]
    assert "POINTER, not a store" in ev["description"]


def test_the_uid_is_the_sender_side_subject():
    assert "the **sender-side subject**" in UMB
    ev = SPEC["paths"]["/uid/{uid}/evidence/{message_id}"]["get"]
    assert "SENDER-SIDE subject" in ev["description"]


def test_the_evidence_pointer_requires_auth_with_no_existence_oracle():
    ev = SPEC["paths"]["/uid/{uid}/evidence/{message_id}"]["get"]
    # R5-06: the operation offers a bearer credential OR its mutual-TLS
    # equivalent, which is how OpenAPI says 'either'. What matters is the
    # PROPERTY — every alternative binds the same party — so that is what
    # is asserted, rather than one spelling of the list.
    alts = {k for block in ev.get("security") or [] for k in block}
    assert alts == {"counterpartyAuth", "counterpartyMtls"} and alts, \
        "the evidence pointer must never be anonymous"
    assert "uniform 404" in ev["description"]
    assert "one uniform 404, no existence oracle" in UMB


def test_the_keypackages_endpoint_is_still_pointer_only():
    kp = SPEC["paths"]["/uid/{uid}/keypackages"]["get"]
    assert "200" not in kp["responses"], "the EDD serves no KeyPackage bytes"


def test_the_registry_owns_status_and_redirect_the_discovery_layer_the_mirror():
    assert re.search(r"status-assertion.*\*\*Core registry\*\*", UMB)
    assert re.search(r"/members.*\*\*Discovery layer\*\*", UMB)
    assert "the EDD serves a 302 pointer ONLY" in UMB
