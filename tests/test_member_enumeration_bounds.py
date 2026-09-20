# SPDX-License-Identifier: MIT
"""X-36 — member enumeration: authenticated, bounded, minimal.

Former defect: /uid/{uid}/members returned an unbounded active-member/
device set with only RECOMMENDED counterparty authentication — anonymous
organisation-chart and device-capability harvesting; no pagination, no
server bounds; the resolver Error enum retained `keypackage-replay`, a
delivery-time reason outside this API's responsibility.

Now (EDD contract 1.10.0): counterparty authentication REQUIRED in the
contract (anonymous access non-conformant), scope_id minimisation, cursor
pagination with a server-side maximum of 100, rate-limit + audit duties,
privacy-safe uniform 404, the dead reason removed, and the compliance-
checklist separation noted in the umbrella.
"""
import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = yaml.safe_load((ROOT / "edd-resolver-openapi.yaml").read_text())
MEM = SPEC["paths"]["/uid/{uid}/members"]["get"]
UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
FLAT = " ".join(UMB.split()).replace("**", "")


def _param(name):
    return next((p for p in MEM["parameters"]
                 if isinstance(p, dict) and p.get("name") == name), None)


def test_negative_anonymous_enumeration_is_impossible_in_the_contract():
    """The former defect: RECOMMENDED-only auth. Now the contract REQUIRES
    an authenticated counterparty."""
    # R5-06: the operation offers a bearer credential OR its mutual-TLS
    # equivalent, which is how OpenAPI says 'either'. What matters is the
    # PROPERTY — every alternative binds the same party — so that is what
    # is asserted, rather than one spelling of the list.
    alts = {k for block in MEM.get("security") or [] for k in block}
    assert alts == {"counterpartyAuth", "counterpartyMtls"} and alts, \
        "member enumeration must never be anonymous"
    scheme = SPEC["components"]["securitySchemes"]["counterpartyAuth"]
    assert "NON-CONFORMANT" in scheme["description"]


def test_responses_are_bounded_cursor_paginated():
    limit = _param("limit")
    assert limit is not None and limit["schema"]["maximum"] == 100
    assert _param("cursor") is not None
    assert "SERVER-SIDE maximum is 100" in limit["description"]


def test_access_is_minimised_to_the_requested_scope():
    scope = _param("scope_id")
    assert scope is not None and "minimisation" in scope["description"]
    assert "minimised to the requested relationship/scope" in FLAT


def test_negative_the_dead_delivery_reason_is_gone():
    enum = SPEC["components"]["schemas"]["Error"]["properties"]["reason"]["enum"]
    assert "keypackage-replay" not in enum, \
        "a delivery-time NDE reason does not belong in the directory error model"


def test_errors_are_privacy_safe():
    assert "one uniform 404" in " ".join(MEM["description"].split())
    assert "no existence oracle" in FLAT


def test_rate_limit_audit_and_the_compliance_separation_are_stated():
    assert "MUST rate-limit and MUST log access for audit" in FLAT
    assert "separate, sourced compliance checklist" in FLAT
    assert "does not exhaust them" in FLAT


def test_the_umbrella_posture_is_required_not_recommended():
    assert "REQUIRES an authenticated, authorised counterparty" in FLAT
    assert "RECOMMENDED posture is authentication to counterparties" not in FLAT
