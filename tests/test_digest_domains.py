# SPDX-License-Identifier: MIT
"""R16-03 / D1 — a hash mode is admissible only in the domain of its field.

One `Hash` type served fourteen reference sites across eight schemas, so every
field admitted every mode the profile defines, while the normative text assigned
each field a narrower one. The consequences were not theoretical:

- a policy reference could declare `manifest-sha256` — a digest of a structure —
  where a verifier recomputes SHA-256 over a published document's signed
  payload. The issuer accepted it and the bundle verifier refused it, so the two
  disagreed about the same artefact;
- an intake-stage NDE could declare `raw-sha512` or a manifest mode where the
  Internet-Draft requires SHA-256 over the exact submitted octets;
- a multipart part could declare `manifest-sha256` where its digest is over that
  part's own decoded octets, and no nested manifest is even expressible.

Three named types replace the one: `ContentHash` (the transmitted payload octets
or the manifest of a multipart payload — the only domain where a manifest mode
means anything), `RawHash` (octets a party observes directly), and
`RawSha256Hash` (SHA-256 over octets, for the fields the text pins to one
algorithm). The boundary is drawn per semantic field, which is the same
inventory `SBM-ADR-0014` needed for its do-not-salt list.
"""
import base64
import copy
import importlib.util
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli  # noqa: E402

COMMON = json.loads((ROOT / "schemas" / "evidence-common.schema.json").read_text())
ID = ROOT / "ietf" / "draft-sbm-mls-erd-00.md"
SE = json.loads((ROOT / "samples" / "sample-SE.json").read_text())["projection"]
MULTIPART = json.loads((ROOT / "samples" / "sample-SE-multipart.json").read_text())["projection"]
NDE = json.loads((ROOT / "samples" / "sample-NDE.json").read_text())["projection"]


def _mock():
    spec = importlib.util.spec_from_file_location("mock_rdp", ROOT / "scripts" / "mock_rdp.py")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:                       # pragma: no cover
        pytest.skip(f"mock_rdp not importable ({exc})")
    return mod


# --- the domains exist, and the shared shape is gone ------------------------

def test_the_three_domains_are_named_types():
    defs = COMMON["$defs"]
    assert "Hash" not in defs, "the shape that served every field must be gone, not aliased"
    assert set(defs["ContentHash"]["properties"]["hash_mode"]["enum"]) == {
        "raw-sha256", "raw-sha512", "manifest-sha256", "manifest-sha512"}
    assert set(defs["RawHash"]["properties"]["hash_mode"]["enum"]) == {"raw-sha256", "raw-sha512"}
    assert defs["RawSha256Hash"]["properties"]["hash_mode"]["const"] == "raw-sha256"
    assert defs["RawSha256Hash"]["properties"]["alg"]["const"] == "SHA-256"


def test_the_cddl_carries_the_same_three_and_no_generic():
    """The Schema's side of this is asserted above — `Hash` must be gone, "not
    aliased". The CDDL was doing exactly the aliasing: it kept the permissive
    shape as `hash` and wrote `content-hash = hash`, so the old name stayed
    reachable by any rule that cared to name it, and a new field could acquire
    every mode by writing four characters. The three domains are spelled out.
    """
    cddl = (ROOT / "cddl" / "sm-mls-erd.cddl").read_text()
    for rule in ("content-hash = {", "raw-hash = {", "raw-sha256-hash = {"):
        assert rule in cddl, rule
    assert not re.search(r"^hash\s*=", cddl, re.M), \
        "the permissive generic must be gone from the CDDL too, not aliased"
    # Anchored at a line start: the comment above the rules quotes the alias to
    # say it is gone, and a bare substring search would match the explanation.
    assert not re.search(r"^content-hash\s*=\s*hash\s*$", cddl, re.M)
    assert re.search(r"doc_digest: raw-sha256-hash", cddl)
    assert re.search(r"submission_hash: raw-sha256-hash", cddl)
    assert re.search(r"digest: raw-hash", cddl)
    assert "payload_hash: hash\b" not in cddl


def test_every_site_points_at_a_domain():
    """No site may still name the shape that served them all."""
    for path in sorted((ROOT / "schemas").glob("*.json")):
        assert "$defs/Hash\"" not in path.read_text(), path.name
    assert "$defs/Hash'" not in (ROOT / "wallet-rdp-openapi.yaml").read_text()


# --- a negative test per field, which is what the review asked for ----------

@pytest.mark.parametrize("mode", ["manifest-sha256", "manifest-sha512", "raw-sha512"])
def test_a_policy_reference_outside_its_domain_is_refused(mode):
    """Instance 1: the issuer accepted what the bundle verifier refused."""
    bad = copy.deepcopy(SE)
    bad["acceptance_policy_ref"]["doc_digest"]["hash_mode"] = mode
    if mode.endswith("512"):
        bad["acceptance_policy_ref"]["doc_digest"]["alg"] = "SHA-512"
        bad["acceptance_policy_ref"]["doc_digest"]["hex"] = "a" * 128
    problems = lint_cli.validate_body(bad)
    assert problems, f"a policy digest accepted {mode}"
    assert "doc_digest" in str(problems), f"refused, but not for its digest: {problems}"


def _intake_nde(**digest):
    """An A.2-SubmissionRejection NDE — the stage where `submission_hash` lives.

    The event carries an intake reason with it. A first draft of this fixture
    set only `event`, so every instance failed on `$.event: 'D.2-...' was
    expected` and the negative tests below passed without ever reaching the
    digest — as did a control with a perfectly good mode, which is how it was
    caught.
    """
    n = copy.deepcopy(NDE)
    n["event"] = "A.2-SubmissionRejection"
    n["reason"] = "malformed-envelope"
    n.pop("payload_hash", None)
    n["submission_hash"] = {"alg": "SHA-256", "hash_mode": "raw-sha256", "hex": "a" * 64}
    n["submission_hash"].update(digest)
    return n


def test_the_intake_digest_control_is_accepted():
    """The control the negative tests below rest on: with the one mode its
    domain admits, the same instance validates."""
    assert lint_cli.validate_body(_intake_nde()) == []


@pytest.mark.parametrize("mode,alg,hexlen", [("manifest-sha256", "SHA-256", 64),
                                             ("raw-sha512", "SHA-512", 128),
                                             ("manifest-sha512", "SHA-512", 128)])
def test_a_rejected_submission_digest_outside_its_domain_is_refused(mode, alg, hexlen):
    """Instance 2: the I-D requires SHA-256 over the exact submitted octets,
    for a request that may never have been parsed."""
    bad = _intake_nde(hash_mode=mode, alg=alg, hex="a" * hexlen)
    problems = lint_cli.validate_body(bad)
    assert problems, f"a submission digest accepted {mode}"
    assert "submission_hash" in str(problems), \
        f"refused, but not for its digest: {problems}"


@pytest.mark.parametrize("mode", ["manifest-sha256", "manifest-sha512"])
def test_a_part_digest_outside_its_domain_is_refused(mode):
    """Instance 3: a part's digest is over that part's decoded octets, and a
    part cannot carry a nested manifest in either machine-readable authority."""
    bad = copy.deepcopy(MULTIPART)
    bad["manifest"][0]["digest"]["hash_mode"] = mode
    if mode.endswith("512"):
        bad["manifest"][0]["digest"]["alg"] = "SHA-512"
        bad["manifest"][0]["digest"]["hex"] = "a" * 128
    problems = lint_cli.validate_body(bad)
    assert problems, f"a part digest accepted {mode}"
    assert "digest" in str(problems), f"refused, but not for its digest: {problems}"


def test_the_content_domain_still_admits_both_of_its_modes():
    """The restriction must not narrow the field that legitimately varies: a
    payload is committed by raw-* or, when multipart, by manifest-*."""
    assert lint_cli.validate_body(SE) == []
    assert lint_cli.validate_body(MULTIPART) == []
    assert SE["payload_hash"]["hash_mode"] == "raw-sha256"
    assert MULTIPART["payload_hash"]["hash_mode"] == "manifest-sha256"


# --- the acceptance criterion: the real intake, before an SE exists ---------

def test_the_intake_refuses_a_wrong_mode_policy_reference_before_sealing():
    """R16-03's acceptance criterion, driven through `submit()` rather than the
    validator: the submission is refused before the Delivery Service is
    contacted, so no transport acceptance and no SE exist. No new code was
    needed for this — the intake already validated the candidate against its own
    Schema, and the domain now lives in the type it validates against."""
    mock = _mock()
    import lint_cli as lc
    import mls_wire as w
    mock._SUBMISSION_LEDGER.clear(); mock._DS_LEDGER.clear(); mock._SE_LEDGER.clear()
    org = json.loads((ROOT / "samples" / "sample-BW-ORG.json").read_text())["projection"]
    members = [json.loads((ROOT / "samples" / "sample-BW-MEMBER.json").read_text())["projection"]]

    octets = b"the submission these octets are about"
    meta = {k: copy.deepcopy(SE[k]) for k in (
        "sender_uid", "sender_addr", "recipient_uid", "recipient_addr", "scope_ref",
        "payload_hash", "mls_group_id", "mls_epoch", "auth_method", "auth_context",
        "sent_at", "expires_at", "origin_proof", "acceptance_policy_ref")}
    meta["message_id"] = "01HZ5D1DOMAINS0000000001"
    meta["mls_message_b64"] = base64.b64encode(octets).decode()

    # A D4 tuple signed over what this submission carries, so the refusal below
    # cannot be the confirmation's. The policy digest is the only defect.
    sc = copy.deepcopy(SE["sender_confirmation"])
    derived = {"envelope_hash": w.envelope_hash(octets),
               "mls_state": w.mls_state_hash(w.demo_group_context(
                   meta["mls_group_id"], meta["mls_epoch"],
                   scope_id=meta["scope_ref"]["scope_id"],
                   scope_version=meta["scope_ref"]["version"]))}
    for field in lc.D4_COPIED_FIELDS:
        sc[field] = derived.get(field, meta.get(field))
    sc["wallet_signature_b64"] = mock._wallet_sign(sc)
    meta["sender_confirmation"] = sc

    assert mock.submit(copy.deepcopy(meta), org=org, members=members), \
        "the control must be accepted, or the refusal below proves nothing"
    mock._SUBMISSION_LEDGER.clear(); mock._DS_LEDGER.clear(); mock._SE_LEDGER.clear()

    meta["message_id"] = "01HZ5D1DOMAINS0000000002"
    meta["acceptance_policy_ref"]["doc_digest"]["hash_mode"] = "manifest-sha256"
    with pytest.raises(mock.SubmissionRejected) as caught:
        mock.submit(meta, org=org, members=members)
    # Refused by the PUBLISHED REQUEST SCHEMA, one stage earlier than the
    # evidence validator: `wallet-rdp-openapi.yaml` reaches `AcceptancePolicyRef`
    # through a `$ref`, so the contract inherited the domain without an edit of
    # its own. The message names the field and the value the domain admits.
    assert caught.value.reason == "submission-invalid", caught.value.reason
    assert "$.acceptance_policy_ref.doc_digest.hash_mode" in str(caught.value)
    assert "'raw-sha256' was expected" in str(caught.value)
    assert not mock._SE_LEDGER, "an SE was sealed for a submission that must have been refused"
    assert not mock._DS_LEDGER, "the Delivery Service was contacted before the refusal"


# --- the pair that was defined nowhere -------------------------------------

def test_the_undefined_generic_pair_is_gone():
    """`envelope_digest_before`/`_after` appeared in no normative text — only in
    the CDDL and the CE schema — and one of them carried a hand-typed value
    naming "the" output envelope on a chunking CE, which produces several."""
    ce = json.loads((ROOT / "schemas" / "evidence-ce.schema.json").read_text())
    assert "envelope_digest_before" not in ce["properties"]
    assert "envelope_digest_after" not in ce["properties"]
    assert "envelope_digest" not in (ROOT / "cddl" / "sm-mls-erd.cddl").read_text()
    assert ce["properties"]["envelope_hash_before"], "the defined commitments stay"


def test_the_consistency_rule_is_scoped_to_the_content_domain():
    """A rule that was loose before the domains, and false after them.

    "`hash_mode` ... MUST be consistent across all evidence for the same
    message" read literally over every hash object was already untrue of a
    multipart SE — `payload_hash` `manifest-sha256` beside a `raw-sha256`
    `doc_digest` — and the domains make the difference REQUIRED rather than
    merely usual, so the sentence would have contradicted the block above it.
    The Evidence Objects section already said what was meant, field by field
    (`payload_hash`/`hash_mode` across SE/DE/NDE/RE), so this scopes one
    sentence to match the other rather than introducing a rule.
    """
    id_text = " ".join(ID.read_text(encoding="utf-8").split())
    assert "The CONTENT commitment's mode MUST be consistent across all evidence for " \
           "the same message" in id_text
    assert "not** about every hash object an artefact carries" in id_text
    assert "`payload_hash`/`hash_mode` MUST be consistent across SE/DE/NDE/RE for the " \
           "same message" in id_text, "the field-by-field rule this is scoped to must stay"
    # The sample this rule is about: the two modes differ, and both are right.
    assert MULTIPART["payload_hash"]["hash_mode"] == "manifest-sha256"
    assert MULTIPART["acceptance_policy_ref"]["doc_digest"]["hash_mode"] == "raw-sha256"
    assert all(part["digest"]["hash_mode"].startswith("raw-") for part in MULTIPART["manifest"])
    assert lint_cli.validate_body(MULTIPART) == []


# --- the text says what the schemas enforce --------------------------------

def test_the_normative_text_assigns_the_domains():
    """A schema that restricted what the text never required would be enforcing
    a rule nobody wrote. The I-D states the three; the umbrella states the one
    that was previously only in `bundle_lint`."""
    id_text = " ".join((ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text().split())
    assert "The digest domains" in id_text
    assert "only domain in which a manifest mode is meaningful" in id_text
    assert "over the exact submitted octets before any parsing" in id_text
    umbrella = " ".join((ROOT / "Secure-Business-Messaging-Profile.md").read_text().split())
    assert "`doc_digest` is SHA-256 over the referenced document's signed payload and carries " \
           "`hash_mode` `raw-sha256`" in umbrella
