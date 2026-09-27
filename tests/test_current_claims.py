# SPDX-License-Identifier: MIT
"""R4-07 — current normative claims are inside the gate.

Former defect (round-4 review), and the third time this exact shape has been
found: DR-13 bound one paragraph, R3-09 built a sweep for the TS ICS table, and
the normative umbrella — which is where an assessor actually reads the field
definitions — was in neither. `make versions` was green while §8.2, §8.3 and
§8.4 stated BW-MED `2.0`, BW-ORG `2.4` and BW-MEMBER `2.2`'s predecessor
against a manifest at 2.1, 2.6 and 2.2.

The review reported the BW-ORG claim. Reproducing it found **five** stale
claims across the three clauses, so the fix generalises the mechanism rather
than adding a third special case: the sweep now reads a clause's DOCUMENT TYPE
from its own heading (`### 8.3 BW-ORG-v1 …`) instead of a restated map beside
it, because a restated map is the thing that drifts.

Two further contradictions the review names are closed here, and each is a
DRIFT between two statements of one fact — so each is closed by making the
second statement derived rather than by correcting it once:

* TS INTF-1b listed the D4 tuple by hand and lost the two address fields R3-01
  had added to it;
* the Delivery Service contract summary said every operation requires
  `memberAuth` while three correctly require `deviceAuth`.

History stays history: a changelog row records what was true then, and a gate
that forced it to say `2.6` would make the record false.
"""
import base64
import importlib.util
import json
import pathlib
import re
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402
import version_manifest as vm  # noqa: E402


def _resolve(doc, schema):
    """R9-B6: response bodies are NAMED components now — an inline schema is
    one nothing can reference and therefore nothing validates against. Follow
    the `$ref` so these assertions test the shape rather than where it is
    written."""
    if isinstance(schema, dict) and "$ref" in schema:
        return doc["components"]["schemas"][schema["$ref"].rsplit("/", 1)[1]]
    return schema


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ss = _load("schema_shapes", "schema_shapes.py")

UMBRELLA = "Secure-Business-Messaging-Profile.md"
MANIFEST = json.loads((ROOT / "versions.json").read_text())


# ---------------------------------------------------------------------------
# The umbrella is swept at all
# ---------------------------------------------------------------------------

def test_the_normative_umbrella_is_in_the_sweep():
    """It was not, which is why five stale claims survived a green gate."""
    assert UMBRELLA in MANIFEST["active_claim_sweep"]


def test_the_current_claims_are_clean():
    assert vm.sweep_section_claims(ROOT, MANIFEST) == []
    assert vm.sweep_active_claims(ROOT, MANIFEST) == []


ORG_NOW = MANIFEST["dimensions"]["discovery_bw_org"]["value"]
ORG_CLAIM = f"**Field definitions (v{ORG_NOW}).**"
# Derived, never spelled. These probes pinned `v2.6` until the digest-domain
# pass moved BW-ORG to 2.7, at which point the replacement they depend on
# matched nothing: the fixture went silently vacuous, and only the assertion
# guarding against exactly that said so. Invariant 13, in the suite that exists
# to catch stale version claims.


@pytest.mark.parametrize("shape,dimension", [
    ('`version` = `"{v}"`', "discovery_bw_org"),
    ('`version` = "{v}"', "discovery_bw_med"),
    ("**Field definitions (v{v}).**", "discovery_bw_org"),
    ("Full field list (v{v}):", "discovery_bw_org"),
])
def test_mutating_a_current_claim_to_an_old_value_fails_the_gate(tmp_path, shape, dimension):
    """The review's first acceptance test, run for each SHAPE of the claim —
    the version const, the clause title and the field-list header — because the
    original sweep matched one grammar and the umbrella states it in three."""
    current = MANIFEST["dimensions"][dimension]["value"]
    now, stale = shape.format(v=current), shape.format(v="2.0")
    text = (ROOT / UMBRELLA).read_text()
    assert now in text, f"no current claim matching {now!r}"
    (tmp_path / UMBRELLA).write_text(text.replace(now, stale, 1))
    assert vm.sweep_section_claims(tmp_path, dict(MANIFEST, active_claim_sweep=[UMBRELLA])), \
        f"a stale {dimension} claim spelled {stale!r} passed the gate"


def test_a_historical_value_is_still_allowed(tmp_path):
    """The review's last acceptance test. A changelog correctly records what
    was true then; a gate that forced it to say the current number would make
    the record false, so provenance is MARKED rather than inferred."""
    text = (ROOT / UMBRELLA).read_text()
    stale = "**Field definitions (v2.4).**"
    # How a historical note actually reads: the marker sits BETWEEN the label
    # and the version, where the prefix-anchored rule cannot see it.
    marked = text.replace(ORG_CLAIM,
                          "**Field definitions as of v2.4** described the shape "
                          "before the chain field.", 1)
    # The probe must be one the gate WOULD otherwise report — a sentence it
    # never matches proves nothing about the exemption.
    (tmp_path / UMBRELLA).write_text(text.replace(
        ORG_CLAIM, stale, 1))
    assert vm.sweep_section_claims(
        tmp_path, dict(MANIFEST, active_claim_sweep=[UMBRELLA])), \
        "the probe is not one the gate reports, so the exemption below is vacuous"
    (tmp_path / UMBRELLA).write_text(marked)
    assert vm.sweep_section_claims(
        tmp_path, dict(MANIFEST, active_claim_sweep=[UMBRELLA])) == []


def test_a_table_row_is_not_swept(tmp_path):
    """Change tables are excluded structurally, not by hoping the marker is
    there — the TS revision history is a table of past versions."""
    text = (ROOT / UMBRELLA).read_text()
    # The SAME sentence the gate reports in prose, inside a table row.
    row = "| **Field definitions (v2.4).** | the shape before the chain |"
    (tmp_path / UMBRELLA).write_text(text.replace(
        ORG_CLAIM, "**Field definitions (v2.4).**", 1))
    assert vm.sweep_section_claims(
        tmp_path, dict(MANIFEST, active_claim_sweep=[UMBRELLA])), \
        "the probe is not one the gate reports, so the exemption below is vacuous"
    (tmp_path / UMBRELLA).write_text(text.replace(
        ORG_CLAIM,
        f"{row}\n\n{ORG_CLAIM}", 1))
    assert vm.sweep_section_claims(
        tmp_path, dict(MANIFEST, active_claim_sweep=[UMBRELLA])) == []


# ---------------------------------------------------------------------------
# A "full field list" is a completeness claim, so it is checked for completeness
# ---------------------------------------------------------------------------

def test_the_field_list_matches_the_schema():
    assert ss.check_prose_field_lists([UMBRELLA]) == []


def test_the_field_list_is_actually_read(tmp_path):
    """Guards the parser, not the document: if `claimed_fields` returned
    nothing the gate above would pass vacuously for ever."""
    line = next(l for l in (ROOT / UMBRELLA).read_text().splitlines()
                if "Full field list" in l)
    fields = ss.claimed_fields(ss.FIELD_LIST.search(line).group(2))
    schema = json.loads((ROOT / "schemas" / "bw-org.schema.json").read_text())
    assert sorted(fields) == sorted(schema["properties"])
    # The annotations name fields too; they must not be read as list entries.
    assert "default" not in fields and "records_role" not in fields


def test_omitting_a_current_field_fails(tmp_path):
    """The review's second acceptance test. `supersedes` is the field the
    umbrella actually lost, so it is the one dropped here."""
    text = (ROOT / UMBRELLA).read_text().replace("`supersedes` (REQUIRED", "(REQUIRED", 1)
    (tmp_path / UMBRELLA).write_text(text)
    old_root, ss.ROOT = ss.ROOT, tmp_path
    try:
        (tmp_path / "schemas").symlink_to(ROOT / "schemas")
        problems = ss.check_prose_field_lists([UMBRELLA])
    finally:
        ss.ROOT = old_root
    assert problems and "OMITS" in problems[0][2] and "supersedes" in problems[0][2]


def test_inventing_a_field_fails(tmp_path):
    text = (ROOT / UMBRELLA).read_text().replace(
        f"Full field list (v{ORG_NOW}): `type`,", f"Full field list (v{ORG_NOW}): `valid_until`, `type`,", 1)
    (tmp_path / UMBRELLA).write_text(text)
    old_root, ss.ROOT = ss.ROOT, tmp_path
    try:
        (tmp_path / "schemas").symlink_to(ROOT / "schemas")
        problems = ss.check_prose_field_lists([UMBRELLA])
    finally:
        ss.ROOT = old_root
    assert problems and "does not define" in problems[0][2], \
        "`valid_until` is exactly the field a reader would expect beside " \
        "`supersedes`, and R4-U1 deliberately does not define it"


# ---------------------------------------------------------------------------
# The D4 tuple is stated once
# ---------------------------------------------------------------------------

def test_the_ts_tuple_equals_the_canonical_definition():
    """The review's third acceptance test: 'D4 tuple prose and the canonical
    D4 field definition cannot drift.' INTF-1b listed ten fields after R3-01
    made it twelve, so an implementer following the TS signed a tuple the
    Schema rejects."""
    t = (ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md").read_text()
    clause = t[t.index("[INTF-1b]"):t.index("[INTF-2]")]
    tup = clause[clause.index("full submission tuple"):clause.index("— so the sender")]
    assert re.findall(r"`([a-z_]+)`", tup) == list(lc.D4_COPIED_FIELDS), \
        "the TS states the D4 tuple in a different order or set than " \
        "lint_cli.D4_COPIED_FIELDS, which is what the Schema enforces"


def test_the_schema_agrees_too():
    """Three statements of one tuple; all three are compared, because two
    agreeing while the third drifts is precisely what happened."""
    schema = json.loads(
        (ROOT / "schemas" / "evidence-common.schema.json").read_text())
    conf = schema["$defs"]["SenderConfirmation"]["properties"]
    for field in lc.D4_COPIED_FIELDS:
        assert field in conf, f"SenderConfirmation does not carry {field}"


# ---------------------------------------------------------------------------
# A contract summary describes the contract
# ---------------------------------------------------------------------------

def _ds():
    return yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())


def _schemes_in_use(doc):
    used = set()
    for ops in doc["paths"].values():
        for method, op in ops.items():
            if not isinstance(op, dict) or method == "parameters":
                continue
            for block in op.get("security", doc.get("security") or []):
                used |= set(block)
    return used


def test_the_ds_summary_names_every_scheme_its_operations_require():
    """The review's fourth acceptance test: 'Operation-level security
    requirements may differ, but the contract summary must accurately describe
    those differences.' The summary claimed memberAuth for EVERY operation
    while three require deviceAuth."""
    doc = _ds()
    summary = doc["info"]["description"]
    used = _schemes_in_use(doc)
    assert used == {"memberAuth", "memberMtls", "deviceAuth", "deviceMtls",
                    "rdpAuth"}, used
    # The summary describes the KINDS of party, not every spelling: `*Mtls` is
    # the same party presenting a certificate instead of a token, and the
    # scheme it is an alternative to is the one a reader needs named.
    for scheme in ("memberAuth", "deviceAuth", "rdpAuth"):
        assert scheme in summary, \
            f"{scheme} is required by an operation and the summary never mentions it"
    assert "Every operation requires an authenticated federation member" not in summary


def test_the_summary_does_not_claim_uniformity_that_the_paths_contradict():
    """Structural, and the reason the sentence was wrong rather than merely
    incomplete: a uniform claim is falsified by any operation that differs."""
    doc = _ds()
    per_op = {tuple(sorted(b for block in
                           (op.get("security") or doc.get("security") or [])
                           for b in block))
              for ops in doc["paths"].values()
              for m, op in ops.items() if isinstance(op, dict) and m != "parameters"}
    assert len(per_op) > 1, "the fixture no longer exercises differing requirements"
    assert "differs by operation" in doc["info"]["description"]


# ---------------------------------------------------------------------------
# R5-06 — a scheme's DESCRIPTION may not contradict its TYPE
# ---------------------------------------------------------------------------

# DERIVED, not restated. This was a fourth hand-written copy of the published
# contract list, and it stopped covering everything the moment Batch A/A1
# published a fifth contract — so the scheme-description rule below simply did
# not run against it. `openapi_validate.CONTRACTS` is where a new contract is
# named ("a contract absent from this list is a contract nothing validates");
# every other list of them is a second source of truth (invariant 7).
from openapi_validate import CONTRACTS  # noqa: E402


@pytest.mark.parametrize("contract", CONTRACTS)
def test_a_security_scheme_describes_the_mechanism_it_declares(contract):
    """Cowork's observation, mechanised: this is the SECOND time a security
    scheme's description contradicted its type.

    `memberAuth` was `type: http` / `scheme: bearer` with a description saying
    "member-/entity-bound token OR MUTUAL TLS; the deployment binds the
    scheme". Generated clients and middleware read the type, so every one of
    them saw a bearer token for `/messages` — the single operation whose
    identity R4-U3 made load-bearing. Prose that widens what the type says is
    not documentation, it is a second specification that no tool reads.

    THE RULE, and it took two passes to state correctly. A bearer scheme may
    MENTION mutual TLS only where it names a sibling scheme that actually
    declares `type: mutualTLS` and that the operations offer as an alternative
    — OpenAPI's way of saying "either" is an OR of two schemes, not a sentence.
    What is forbidden is prose OFFERING a mechanism the declared type does not
    provide, because a generated client silently takes the weaker one.
    """
    doc = yaml.safe_load((ROOT / contract).read_text())
    schemes = (doc.get("components") or {}).get("securitySchemes") or {}
    mtls_schemes = {n for n, s in schemes.items() if s.get("type") == "mutualTLS"}
    offered = set()
    for ops in doc["paths"].values():
        for method, op in ops.items():
            if isinstance(op, dict) and method != "parameters":
                for block in op.get("security") or []:
                    offered |= set(block)
    for name, spec in schemes.items():
        if spec.get("type") == "mutualTLS":
            continue
        text = (spec.get("description") or "")
        if "mutual TLS" not in text and "mTLS" not in text:
            continue
        named = [m for m in mtls_schemes if m in text]
        assert named, (
            f"{contract}: securityScheme {name!r} is type {spec.get('type')!r}/"
            f"{spec.get('scheme')!r} and its description offers mutual TLS "
            "without naming a mutualTLS scheme — a client generated from this "
            "contract presents the weaker mechanism")
        assert any(m in offered for m in named), (
            f"{contract}: {name!r} points at {named} but no operation offers "
            "it, so the alternative exists only in prose")


def test_the_submission_operation_carries_the_issuing_rdp_identity():
    """R5-06/R4-U3 together: the namespace the DS is required to derive must
    come from a credential that actually carries an RDP identity."""
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    assert doc["paths"]["/messages"]["post"]["security"] == [{"rdpAuth": []}]
    scheme = doc["components"]["securitySchemes"]["rdpAuth"]
    assert scheme["type"] == "mutualTLS"
    d = scheme["description"]
    assert "CANONICAL IDENTIFIER" in d, "the derivation must be stated"
    assert "subjectAltName" in d and "EXACTLY ONE" in d
    assert "MUST be refused" in d, \
        "a certificate with no derivable identity must not share a namespace"
    # R6-06: the entity-only fallback is REMOVED. organizationIdentifier names
    # a LEGAL ENTITY, and one entity may operate several RDPs — so the fallback
    # collapsed distinct providers into a shared namespace, which is the
    # collision R4-U3 exists to prevent.
    assert "entity-only fallback is REMOVED" in d
    assert "AUTHORISATION IS NOT AUTHENTICATION" in d, \
        "the register dependency must be stated, not implied"


# ---------------------------------------------------------------------------
# R5-07 — a published contract's SURFACE cannot change without its version
# ---------------------------------------------------------------------------

cs = _load("contract_shapes", "contract_shapes.py")


def test_the_recorded_surfaces_match():
    assert cs.main(["contract_shapes.py"]) == 0


@pytest.mark.parametrize("mutate,label", [
    (lambda d: d["paths"].pop("/messages"), "an operation removed"),
    (lambda d: d["paths"].setdefault("/new", {"get": {"security": []}}),
     "an operation added"),
    (lambda d: d["paths"]["/messages"]["post"].__setitem__(
        "security", [{"memberAuth": []}]), "security rebound"),
    (lambda d: d["components"]["securitySchemes"]["rdpAuth"].__setitem__(
        "type", "http"), "a scheme's mechanism swapped under its name"),
])
def test_a_surface_change_without_a_bump_is_caught(mutate, label):
    """The gate is proved to detect before it is trusted. Each class is a way a
    client written against this contract silently breaks:

    * an operation vanishes or appears;
    * an operation's REQUIRED CREDENTIAL changes — which is exactly what
      round 5 did to `/messages` (memberAuth -> rdpAuth) while the version
      stood still and `make versions` stayed green;
    * a scheme keeps its name and changes its mechanism, so generated clients
      present something else entirely.
    """
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    recorded = json.loads((ROOT / "docs" / "contract-shapes.json").read_text())
    before = cs.surface(doc)
    mutate(doc)
    after = cs.surface(doc)
    assert after != before, f"the fixture did not change the surface: {label}"
    was = recorded["contracts"]["delivery-service-openapi.yaml"]
    assert after["version"] == was["version"], "the probe must not move the version"
    changed = (set(after["operations"]) != set(was["operations"])
               or any(after["operations"].get(k) != was["operations"].get(k)
                      for k in was["operations"])
               or after["security_schemes"] != was["security_schemes"])
    assert changed, label


def test_the_descriptions_are_deliberately_not_fingerprinted():
    """A gate that fires on prose gets suppressed, and a suppressed gate is
    worse than none. Descriptions change constantly; the R4-07 and R5-06 checks
    already compare prose with structure, which is the part that matters."""
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    before = cs.surface(doc)
    doc["paths"]["/messages"]["post"]["description"] = "entirely rewritten"
    doc["components"]["securitySchemes"]["rdpAuth"]["description"] = "changed"
    assert cs.surface(doc) == before


def test_the_breaking_change_is_versioned_as_breaking():
    """`/messages` moved from memberAuth to rdpAuth, so every existing client
    presenting a member token is refused. That is a MAJOR change, and calling
    it a minor one would be the same class of under-claim this round is about."""
    manifest = json.loads((ROOT / "versions.json").read_text())
    # R8-03: asserted as a PROPERTY rather than pinned to one literal. Two
    # breaking changes have landed on these contracts — `/messages` moving to
    # `rdpAuth` (major 4) and the R8-03 transfer boundary making
    # `collection_token` a required acknowledgement field (major 5) — so the
    # major component may not fall below 5. Pinning the literal made this test
    # a restatement that had to be edited on every bump, which is the drift
    # family it exists to catch.
    major = int(manifest["dimensions"]["companion_contracts"]["value"]
                .split(".")[0])
    assert major >= 5, "a breaking contract change was not versioned as breaking"
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    assert doc["paths"]["/messages"]["post"]["security"] == [{"rdpAuth": []}]
    ack = doc["paths"]["/messages/{issuing_rdp_id}/{message_id}/receipt-ack"]
    ref = ack["post"]["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    assert "collection_token" in \
        doc["components"]["schemas"][ref.rsplit("/", 1)[1]]["required"]
    # R9-03/R9-01: two more breaking changes since — the reservation response
    # gained a required field, and `collection_token` became mandatory at
    # runtime rather than optional in the reference.
    assert major >= 6
    # The resolver has never had a breaking change: every bump it has taken was
    # additive (an alternative gained) or transitive (a type it references
    # narrowed, which the digest-domain pass made visible). So the PROPERTY is
    # that its major stands at 1, not that its minor holds a particular value —
    # which is what this assertion pinned until that pass moved it, and the same
    # drift family the test exists to catch.
    edd = manifest["dimensions"]["edd_openapi"]["value"]
    assert edd.split(".")[0] == "1", f"the resolver took a breaking change: {edd}"


# ---------------------------------------------------------------------------
# R6-06 (W3) — one canonical RDP identity, and the register is external
# ---------------------------------------------------------------------------

def _rdp_auth():
    """The scheme description with whitespace normalised: it is a LITERAL YAML
    block, so line breaks survive and a phrase that wraps would otherwise be
    unfindable — a test that silently stops matching is the drift family."""
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    return " ".join(
        doc["components"]["securitySchemes"]["rdpAuth"]["description"].split())


def test_the_rdp_identity_binding_is_singular():
    """The entity-only fallback collapsed distinct providers into one
    namespace: `organizationIdentifier` names a LEGAL ENTITY, and one entity
    may operate several RDPs — which is the collision R4-U3 exists to
    prevent."""
    d = _rdp_auth()
    assert "EXACTLY ONE" in d and "MUST be refused" in d
    assert "entity-only fallback is REMOVED" in d
    # The removal note NAMES the field it removed, which is the record; what
    # must be gone is the field as a live derivation rule.
    assert "otherwise the subject DN's organizationIdentifier" not in d


def test_rotation_keeps_the_identity_and_a_different_uri_does_not():
    d = _rdp_auth()
    assert "ROTATION AND ALIASES" in d
    assert "The canonical identifier is the URI, not the certificate" in d


def test_the_authorisation_gap_is_stated_not_implied():
    """W3: deriving an identifier proves who presented the certificate. It does
    NOT establish that the RDP chains to an accepted anchor or is qualified.

    Batch A SPLIT this claim, and the test with it. The sentence read "the
    federation register does not exist yet" and made the check conditional on
    one existing — true when written, false the moment A1 published a
    contract. A stale exemption is worse than a missing one: it tells a reader
    the duty is not yet owed. The obligation is now unconditional, and what
    stays external is the narrower, still-true part: operating a production
    register, admitting a real participant, and every certificate question
    admission never answers."""
    d = _rdp_auth()
    assert "AUTHORISATION IS NOT AUTHENTICATION" in d
    assert "federation register does not exist yet" not in d, \
        "the claim outlived the gap it described"
    assert "federation register is now DEFINED" in d
    assert "no longer conditional on one existing" in d
    assert "X-01" in d


def test_the_acknowledgement_path_carries_the_namespace():
    """R6-03 point 1: the submission layer keys on (issuing RDP, message_id)
    and the receipt layer exposed a bare message_id."""
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    assert "/messages/{issuing_rdp_id}/{message_id}/receipt-ack" in doc["paths"]
    assert "/messages/{message_id}/receipt-ack" not in doc["paths"]


# ---------------------------------------------------------------------------
# R6-04 (W2) — the refusal reaches the creator
# ---------------------------------------------------------------------------

def test_the_creator_can_collect_group_establishment_outcomes():
    """R5-V2 moved the refusal onto the DS and it terminated there — the
    creator is not listening on the refusing device's queue, so a silent
    non-join stayed indistinguishable from an offline device."""
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    get = doc["paths"]["/group-establishment/outcomes"]["get"]
    schema = _resolve(doc, get["responses"]["200"]["content"]["application/json"]["schema"])
    # R9-04: the outcome item is a NAMED component now, so the reference can
    # project onto it and validate before returning. Follow the `$ref`.
    ref = schema["properties"]["outcomes"]["items"]["$ref"]
    item = doc["components"]["schemas"][ref.rsplit("/", 1)[1]]
    for field in ("welcome_id", "mls_group_id", "device_id", "reason",
                  "offered_suite", "refused_at"):
        assert field in item["required"], field
    # R10-05: a floor only for the floor reason — never claimed for a GroupInfo
    # mismatch, which is not a cipher-suite refusal.
    assert item["then"] == {"required": ["required_floor"]}
    assert item["else"] == {"not": {"required": ["required_floor"]}}
    reg = json.loads((ROOT / "registries" / "reason-codes.json").read_text())
    registered = sorted(k for k in reg["group_establishment_reasons"] if not k.startswith("$"))
    assert sorted(item["properties"]["reason"]["enum"]) == registered
    # explicit per-item acknowledgement, so a lost response converges on retry
    ack = doc["paths"]["/group-establishment/outcomes/{outcome_id}"]["delete"]
    assert "404" in ack["responses"], "no cross-creator existence oracle"


def test_the_invitation_record_is_required_not_assumed():
    """Requirement 1/4: the DS validates `offered_suite` against what was
    actually offered, which it can only do if it retained the invitation. A
    deployment without it must not synthesise the outcome from the refusal."""
    doc = yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())
    d = doc["paths"]["/group-establishment/outcomes"]["get"]["description"]
    assert "invitation record" in d.lower()
    assert "MUST NOT" in d and "synthesise" in d
    t = " ".join((ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text().split())
    assert "invitation record" in t.replace("**", "")
    assert "GET /group-establishment/outcomes" in t.replace("`", "")


# ---------------------------------------------------------------------------
# R7-03 (X2) — the invitation record exists, and the flow can be driven
# ---------------------------------------------------------------------------

def _ds_doc():
    return yaml.safe_load((ROOT / "delivery-service-openapi.yaml").read_text())


def test_the_invitation_record_has_a_schema_and_the_deposit_carries_it():
    """The finding: `GET /group-establishment/outcomes` declared the record
    REQUIRED while `POST /welcome` declared `unevaluatedProperties: false` over
    `[recipient_device, welcome_b64]` — so its inputs were not unspecified,
    they were REJECTED. No conforming implementation could serve the operation
    the record is required by."""
    doc = _ds_doc()
    schema = doc["components"]["schemas"]["InvitationDeposit"]
    body = doc["paths"]["/welcome"]["post"]["requestBody"]["content"][
        "application/json"]["schema"]
    assert body == {"$ref": "#/components/schemas/InvitationDeposit"}
    for field in ("invitation_id", "mls_group_id", "group_info_commitment",
                  "offered_suite", "reservation_id", "keypackage_ref",
                  "created_at", "expires_at"):
        assert field in schema["required"], field
    assert schema["unevaluatedProperties"] is False


def test_one_principal_for_deposit_collection_and_acknowledgement():
    """R7-X2. The four disagreed: deposit memberAuth, refusal deviceAuth,
    collection memberAuth, and the prose calling the creator a device."""
    doc = _ds_doc()
    def schemes(path, method):
        return {k for b in doc["paths"][path][method]["security"] for k in b}
    member = {"memberAuth", "memberMtls"}
    assert schemes("/welcome", "post") == member
    assert schemes("/group-establishment/outcomes", "get") == member
    assert schemes("/group-establishment/outcomes/{outcome_id}", "delete") == member
    # refusal stays device-bound, and the reason is written down
    assert schemes("/welcome/{welcome_id}/refusal", "post") == {"deviceAuth",
                                                               "deviceMtls"}
    d = " ".join(doc["paths"]["/group-establishment/outcomes"]["get"]
                 ["description"].split())
    assert "THE CREATOR IS A MEMBER" in d
    assert "no sibling can make for it" in d, \
        "the asymmetry must be justified, not merely present"


# --- the reference path can now be driven end to end ------------------------

# R11-01: a principal names its entity. A MID is unique only within one, and a
# device label only within its member, so a credential carrying either alone
# identifies nobody in particular.
FR_UID = "EU-FR-PSBID-ZYWVTSRQPNM8M4"
MEMBER_CRED = {"kind": "member", "uid": FR_UID, "mid": "F1N2C3D4P"}
OTHER_MEMBER = {"kind": "member", "uid": FR_UID, "mid": "F2X3Y4Z55"}
TARGET_DEV = {"kind": "device", "uid": FR_UID, "device_id": "DEV-1", "mid": "F1N2C3D4P"}
SIBLING_DEV = {"kind": "device", "uid": FR_UID, "device_id": "DEV-2", "mid": "F1N2C3D4P"}
SUITE = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
WELCOME = b"an MLS Welcome"

# R9-03/R9-X1: the fixtures DERIVE these the published way rather than
# inventing `kp-1` / `gi-000…`. A test that can make up a wire value is a test
# that cannot notice the value has no producer.
import mls_wire as _w  # noqa: E402
DEMO_KP_REF = _w.keypackage_ref(
    b"demo-keypackage:" + FR_UID.encode() + b"|F1N2C3D4P|DEV-1|" + SUITE.encode(),
    cipher_suite=SUITE)
OTHER_KP_REF = _w.keypackage_ref(
    b"demo-keypackage:" + FR_UID.encode() + b"|F1N2C3D4P|DEV-2|" + SUITE.encode(),
    cipher_suite=SUITE)
GI_COMMITMENT = _w.group_info_commitment(b"a demo GroupInfo", cipher_suite=SUITE)


def _mock():
    return _load("mock_rdp", "mock_rdp.py")


def _record(**over):
    """R8-04: the EXACT published `InvitationDeposit`. This fixture used to omit
    `recipient_device` and `welcome_b64` because the reference took them as
    separate arguments with a second required-field tuple — so the reference's
    own happy path was a request the contract REJECTED, and an implementer
    following the contract would have had these fixtures refused."""
    r = {"invitation_id": "inv-r7", "recipient_device": "DEV-1",
         "welcome_b64": base64.b64encode(WELCOME).decode(),
         "mls_group_id": "Zzw1S4pWq9T5n7xYbXc2dQ",
         "group_info_commitment": GI_COMMITMENT, "offered_suite": SUITE,
         "reservation_id": "res-0001", "keypackage_ref": DEMO_KP_REF,
         "created_at": "2026-04-04T09:00:00Z",
         "expires_at": "2026-04-05T09:00:00Z"}
    r.update(over)
    return r


# The refusing device's credential carries the KeyPackage it holds (R8-04
# requirement 6): naming the right `device_id` is not proof of holding the
# package this invitation consumed.
TARGET_DEV_KP = dict(TARGET_DEV, keypackage_ref=DEMO_KP_REF)
SIBLING_DEV_KP = dict(SIBLING_DEV, keypackage_ref=OTHER_KP_REF)
IN_WINDOW = "2026-04-04T10:05:00Z"

# The discovery material the floor is RESOLVED from (R8-04 requirement 5).
FLOOR_MEMBERS = [{"uid": FR_UID, "mid": "F1N2C3D4P",
                  "devices": [{"device_id": "DEV-1", "min_cipher_suite": SUITE},
                              {"device_id": "DEV-2", "min_cipher_suite": SUITE}]}]


def _reserved(m, device="DEV-1", suite=SUITE, key="idem-key-0000001",
              commit=True):
    """R9-03: reserve and commit through the PUBLIC operations, and take the
    reservation id and KeyPackage reference from the RESPONSE.

    The fixture used to invent both (`res-1`, `kp-1`) and hand them to a
    reservation that accepted whatever it was given — which is precisely why
    nobody noticed the public flow could not produce them. A client has only
    what the response returns."""
    res = m.reserve_keypackages("EU-FR-PSBID-ZYWVTSRQPNM8M4",
                                credential=MEMBER_CRED, cipher_suite=suite,
                                targets=[{"mid": "F1N2C3D4P",
                                          "device_id": device}],
                                idempotency_key=key)
    if commit:
        m.commit_reservation(res["reservation_id"], credential=MEMBER_CRED)
    pkg = next(k for k in res["keypackages"] if k["device_id"] == device)
    return res, pkg


def _deposited(m, **over):
    """The whole published lifecycle: reserve -> commit -> deposit. R8-04
    requirement 3 — an invitation may only be created against a COMMITTED
    reservation naming the exact KeyPackage consumed for the target device."""
    res, pkg = _reserved(m, device=over.get("recipient_device", "DEV-1"),
                         suite=over.get("offered_suite", SUITE))
    over.setdefault("reservation_id", res["reservation_id"])
    over.setdefault("keypackage_ref", pkg["keypackage_ref"])
    rec = _record(**over)
    return m.deposit_welcome(rec, credential=MEMBER_CRED), rec


def _refuse(m, welcome_id, *, credential=None, **over):
    kw = dict(reason="suite-below-published-floor", offered_suite=SUITE,
              required_floor=SUITE, refused_at=IN_WINDOW,
              members=FLOOR_MEMBERS)
    kw.update(over)
    return m.refuse_welcome(welcome_id,
                            credential=credential or TARGET_DEV_KP, **kw)


def test_the_whole_pre_join_flow_runs_in_the_reference_path():
    """Requirement 5, and requirement 1's acceptance test: deposit a bound
    invitation, refuse it pre-join, collect the result as the exact creator,
    acknowledge it. Before R7-03 the reference path had `deposit_welcome`,
    `collect_welcomes`, `ack_welcome` and NO refusal, invitation or outcome
    function whatsoever."""
    m = _mock()
    dep, rec = _deposited(m)
    # R9-04: `invitation_id` is INTERNAL. The public `WelcomeQueued` is closed
    # over (welcome_id, recipient_device), and the reference used to return the
    # invitation id as well — a field a conforming client would reject, and a
    # correlation handle between a device's queue and the creator's.
    assert set(dep) == {"welcome_id", "recipient_device"}
    assert rec["invitation_id"] == "inv-r7"
    out = _refuse(m, dep["welcome_id"])
    collected = m.collect_outcomes(credential=MEMBER_CRED)
    assert [o["outcome_id"] for o in collected] == [out["outcome_id"]]
    assert collected[0]["mls_group_id"] == "Zzw1S4pWq9T5n7xYbXc2dQ"
    assert m.ack_outcome(out["outcome_id"], credential=MEMBER_CRED) is None
    assert m.collect_outcomes(credential=MEMBER_CRED) == []


def test_the_refusal_is_VALIDATED_against_the_record_not_echoed():
    """The reason the record has to exist at all: a refusal states the suite it
    was offered, and the DS compares it with what was ACTUALLY offered."""
    m = _mock()
    dep, _ = _deposited(m)
    with pytest.raises(m.InvitationError) as exc:
        _refuse(m, dep["welcome_id"],
                offered_suite="MLS_128_DHKEMP256_AES128GCM_SHA256_P256")
    assert exc.value.reason == "invitation-suite-mismatch"


def test_a_sibling_device_cannot_refuse_another_devices_invitation():
    m = _mock()
    dep, _ = _deposited(m)
    with pytest.raises(m.InvitationError) as exc:
        _refuse(m, dep["welcome_id"], credential=SIBLING_DEV_KP)
    assert exc.value.reason == "invitation-unknown", \
        "a sibling must get the same answer as for an unknown id"


def test_another_creator_cannot_see_or_acknowledge_the_outcome():
    m = _mock()
    dep, _ = _deposited(m)
    out = _refuse(m, dep["welcome_id"])
    assert m.collect_outcomes(credential=OTHER_MEMBER) == []
    with pytest.raises(m.InvitationError) as exc:
        m.ack_outcome(out["outcome_id"], credential=OTHER_MEMBER)
    assert exc.value.reason == "outcome-unknown"


def test_lost_responses_converge_on_retry():
    """Requirement 4/6: a lost deposit and a lost acknowledgement both converge
    rather than creating a second invitation or failing the second time."""
    m = _mock()
    a, rec = _deposited(m)
    b = m.deposit_welcome(rec, credential=MEMBER_CRED)
    assert a == b, "a retried deposit must not create a second invitation"
    out = _refuse(m, a["welcome_id"])
    assert _refuse(m, a["welcome_id"]) == out, \
        "R8-04 requirement 7: a lost 204 converges on the same outcome rather " \
        "than being answered `invitation-unknown`"
    assert m.ack_outcome(out["outcome_id"], credential=MEMBER_CRED) is None
    assert m.ack_outcome(out["outcome_id"], credential=MEMBER_CRED) is None, \
        "acknowledgement is idempotent after deletion — aligned with the " \
        "refusal's rule rather than contradicting it. R9-X4: 204 means NO " \
        "CONTENT, so the reference returns nothing rather than a body the " \
        "contract never promised."


def test_an_incomplete_invitation_is_refused():
    m = _mock()
    with pytest.raises(m.InvitationError) as exc:
        m.deposit_welcome({"invitation_id": "inv-x"}, credential=MEMBER_CRED)
    assert exc.value.reason == "invitation-incomplete"
    # R8-04: and the omission the OLD fixture itself made — the two fields the
    # published Schema requires inside the request object.
    partial = _record()
    del partial["recipient_device"], partial["welcome_b64"]
    with pytest.raises(m.InvitationError) as split:
        m.deposit_welcome(partial, credential=MEMBER_CRED)
    assert split.value.reason == "invitation-incomplete"


# ===========================================================================
# R8-04 — the invitation is a server-validated TRANSACTION
#
# R7-03 gave the record a Schema and a nominal flow. The reference then kept
# most fields without checking the claims the contract says they establish:
# the happy-path request was invalid under its own Schema, `reservation_id`
# and `keypackage_ref` were read nowhere, expiry was never compared, `reason`
# and `required_floor` were retained verbatim from the refusing device, a
# retried refusal returned `invitation-unknown` where the contract promises
# another 204, and any unknown outcome id acknowledged by anybody at all
# returned success. Decision R8-X3.
# ===========================================================================

def test_the_reference_request_is_exactly_the_published_schema():
    """R8-04 requirement 1, and its first acceptance test: the OLD fixture must
    fail. It omitted `recipient_device` and `welcome_b64` because the reference
    took them as separate arguments with a second required-field tuple."""
    m = _mock()
    doc = _ds_doc()
    schema = doc["components"]["schemas"]["InvitationDeposit"]
    assert schema["unevaluatedProperties"] is False
    assert m.validate_invitation_deposit(_record()) == []
    old_shape = {k: v for k, v in _record().items()
                 if k not in ("recipient_device", "welcome_b64")}
    problems = m.validate_invitation_deposit(old_shape)
    assert len(problems) == 2, problems
    assert all("required property" in why for _, why in problems)


@pytest.mark.parametrize("field,bad", [
    ("mls_group_id", None),
    ("group_info_commitment", None),
    ("offered_suite", "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"),
    ("created_at", "2026-04-06T09:00:00Z"),      # after expires_at
    ("welcome_b64", "not base64 at all !!"),
])
def test_a_deposit_that_cannot_be_checked_is_refused_before_anything_is_queued(field, bad):
    """R8-04 requirement 4. Every one of these was retained verbatim."""
    m = _mock()
    rec = _record()
    if bad is None:
        del rec[field]
    else:
        rec[field] = bad
    _reserved(m)
    with pytest.raises(m.InvitationError):
        m.deposit_welcome(rec, credential=MEMBER_CRED)
    assert m._INVITATIONS == {} and m._WELCOME_QUEUE == {}


@pytest.mark.parametrize("kind,cred", [
    ("entity", {"kind": "entity", "uid": "EU-FR-PSBID-ZYWVTSRQPNM8M4"}),
    ("device", {"kind": "device", "device_id": "DEV-1"}),
    ("member without a mid", {"kind": "member"}),
])
def test_only_a_member_bound_credential_is_the_creator(kind, cred):
    """R8-X3 / R8-04 requirement 2. R7-X2 settled that the creator is a member
    at deposit, collection AND acknowledgement; the code accepted member,
    entity or device at deposit and did no kind check at collection. That was
    a settled decision the code had not been brought to."""
    m = _mock()
    with pytest.raises(m.WelcomeAccessDenied):
        m.deposit_welcome(_record(), credential=cred)
    with pytest.raises(m.WelcomeAccessDenied):
        m.collect_outcomes(credential=cred)
    with pytest.raises(m.WelcomeAccessDenied):
        m.ack_outcome("out-0001", credential=cred)


def test_the_member_scheme_says_it_is_member_bound():
    """The scheme itself, not just the reference: `memberAuth` described
    itself as 'member-/entity-bound' while R7-X2 required exactly a member."""
    doc = _ds_doc()
    for name in ("memberAuth", "memberMtls"):
        d = " ".join(doc["components"]["securitySchemes"][name]["description"]
                     .split())
        assert "MEMBER" in d, name
        assert "entity-level" in d and "NOT sufficient" in d, \
            f"{name} does not say an entity-level credential is insufficient"


@pytest.mark.parametrize("over,reason", [
    ({"reservation_id": "res-never-made"}, "reservation-unknown"),
    # R9-03: a VALID reference for a package this reservation did not consume.
    # `kp-invented` now fails the published `KeyPackageRef` grammar first, so
    # it would prove a structural refusal and never reach the rule named here.
    ({"keypackage_ref": OTHER_KP_REF}, "keypackage-not-consumed"),
    ({"recipient_device": "DEV-9"}, "keypackage-target-unrequested"),
])
def test_the_invitation_binds_a_committed_reservation_and_its_exact_package(over, reason):
    """R8-04 requirement 3. Both fields were REQUIRED at deposit and read
    nowhere — no reservation state existed in the reference at all."""
    m = _mock()
    _reserved(m)
    with pytest.raises(m.InvitationError) as exc:
        m.deposit_welcome(_record(**over), credential=MEMBER_CRED)
    assert exc.value.reason == reason
    assert m._INVITATIONS == {}


def test_an_uncommitted_reservation_cannot_carry_an_invitation():
    m = _mock()
    _reserved(m, commit=False)
    with pytest.raises(m.InvitationError) as exc:
        m.deposit_welcome(_record(), credential=MEMBER_CRED)
    assert exc.value.reason == "reservation-not-committed"


@pytest.mark.parametrize("at,creates", [
    ("2026-04-04T08:59:59Z", False),      # before created_at
    ("2026-04-04T09:00:00Z", True),       # the first instant in window
    ("2026-04-05T09:00:00Z", True),       # the last instant in window
    ("2026-04-05T09:00:01Z", False),      # one second after expiry
])
def test_only_an_in_window_refusal_creates_an_outcome(at, creates):
    """R8-04 requirement 4 and its third acceptance test. `expires_at` was
    retained and never read, so a refusal at any later time created an
    outcome carrying the attacker's values."""
    m = _mock()
    dep, _ = _deposited(m)
    if creates:
        assert _refuse(m, dep["welcome_id"], refused_at=at)["outcome_id"]
    else:
        with pytest.raises(m.InvitationError) as exc:
            _refuse(m, dep["welcome_id"], refused_at=at)
        assert exc.value.reason == "invitation-unknown"
        assert m._OUTCOMES == {}


def test_the_refusing_credential_must_hold_this_invitations_keypackage():
    """R8-04 requirement 6: bound to the KeyPackage, not to a caller-supplied
    `device_id`. The target device_id is public — holding the package is not."""
    m = _mock()
    dep, _ = _deposited(m)
    impostor = dict(TARGET_DEV, keypackage_ref="kp-somebody-elses")
    with pytest.raises(m.InvitationError) as exc:
        _refuse(m, dep["welcome_id"], credential=impostor)
    assert exc.value.reason == "invitation-unknown"
    assert m._OUTCOMES == {}


def test_an_invented_reason_is_refused():
    """The request enum has one member and the reference took any string, so an
    attacker-chosen value was retained in the creator's queue."""
    m = _mock()
    dep, _ = _deposited(m)
    with pytest.raises(m.InvitationError) as exc:
        _refuse(m, dep["welcome_id"], reason="i-just-do-not-want-to")
    assert exc.value.reason == "refusal-reason-unknown"
    assert m._OUTCOMES == {}


def test_the_floor_is_resolved_from_discovery_not_believed():
    """R8-04 requirement 5. `required_floor` was stored verbatim, so a target
    could publish one floor and claim another — and the creator is explicitly
    told it can verify the claim against published discovery."""
    m = _mock()
    dep, _ = _deposited(m)
    with pytest.raises(m.InvitationError) as exc:
        _refuse(m, dep["welcome_id"],
                required_floor="MLS_9999_INVENTED_FLOOR")
    assert exc.value.reason == "refusal-floor-mismatch"
    # ...and with no discovery material the answer is "I could not check",
    # never "it checks out".
    with pytest.raises(m.InvitationError) as unresolvable:
        _refuse(m, dep["welcome_id"], members=[])
    assert unresolvable.value.reason == "refusal-floor-unresolvable"
    assert m._OUTCOMES == {}
    # the stored outcome carries the RESOLVED value, not the caller's
    out = _refuse(m, dep["welcome_id"])
    assert m._OUTCOMES[out["outcome_id"]]["required_floor"] == SUITE


def test_a_conflicting_refusal_retry_fails_deterministically():
    """R8-04 requirement 7: the identical request converges (tested above);
    a DIFFERENT one must not silently replace the terminal result."""
    m = _mock()
    dep, _ = _deposited(m)
    first = _refuse(m, dep["welcome_id"])
    assert _refuse(m, dep["welcome_id"]) == first
    # The idempotency key is the REQUEST — `{reason, offered_suite,
    # required_floor}`. `refused_at` is server-observed and is deliberately NOT
    # part of it: a retry does not become a different request because time
    # passed.
    with pytest.raises(m.InvitationError) as exc:
        _refuse(m, dep["welcome_id"], required_floor="MLS_128_DHKEMP256_AES128GCM_SHA256_P256")
    assert exc.value.reason == "invitation-conflict"
    assert len(m._OUTCOMES) == 1


def test_an_unknown_outcome_is_not_acknowledged_by_just_anybody():
    """R8-04 requirement 8. `entry is None` returned success BEFORE any
    identity check, so every id in existence was 'already acknowledged' — and
    the 404 description says exactly that, which the reference made true."""
    m = _mock()
    with pytest.raises(m.InvitationError) as exc:
        m.ack_outcome("out-never-existed", credential=MEMBER_CRED)
    assert exc.value.reason == "outcome-unknown"
    dep, _ = _deposited(m)
    out = _refuse(m, dep["welcome_id"])
    assert m.ack_outcome(out["outcome_id"], credential=MEMBER_CRED) is None
    # idempotent for ITS OWNER after deletion...
    assert m.ack_outcome(out["outcome_id"], credential=MEMBER_CRED) is None
    # ...and indistinguishable from unknown for anyone else.
    with pytest.raises(m.InvitationError) as other:
        m.ack_outcome(out["outcome_id"], credential=OTHER_MEMBER)
    assert other.value.reason == "outcome-unknown"


# ===========================================================================
# R9-03 (Blocker) — the public transaction can be CONSTRUCTED
#
# `keypackage_ref` was required by `InvitationDeposit` and produced by nothing:
# the reservation request forbade it, the reservation response omitted it, and
# it occurred exactly once in the whole published surface — as that required
# property, described by what it BINDS rather than what it IS. Zero occurrences
# in the Internet-Draft, the TS, the umbrella, the CDDL and every JSON Schema.
# A conforming client could not build the next request at all. Decision R9-X1.
# ===========================================================================

def test_the_keypackage_reference_is_defined_once_and_is_MLS_own():
    """R9-03 requirement 1. MLS already defines a reference for this object, so
    SBM does not define a second one — two names for one thing is how the
    collision comes back (R7-X1)."""
    common = json.loads(
        (ROOT / "schemas" / "evidence-common.schema.json").read_text())
    ref = common["$defs"]["KeyPackageRef"]
    assert ref["pattern"] == "^[A-Za-z0-9_-]{43,86}$"
    assert "RefHash" in ref["description"] and "5.2" in ref["description"]
    doc = _ds_doc()
    for where in (doc["components"]["schemas"]["InvitationDeposit"]
                  ["properties"]["keypackage_ref"],
                  doc["components"]["schemas"]["Reservation"]["properties"]
                  ["keypackages"]["items"]["properties"]["keypackage_ref"]):
        assert where["$ref"].endswith("#/$defs/KeyPackageRef"), where


def test_the_reference_is_RFC_9420_ref_hash_and_suite_bound():
    """The construction, not just its name: label and value are each
    length-prefixed, and the hash is the suite's own."""
    import hashlib
    import mls_wire as w
    kp = b"a KeyPackage"
    suite = SUITE
    expect = hashlib.sha256(w.opaque_v(b"MLS 1.0 KeyPackage Reference")
                            + w.opaque_v(kp)).digest()
    got = w.keypackage_ref(kp, cipher_suite=suite)
    assert got == base64.urlsafe_b64encode(expect).decode().rstrip("=")
    # the suite decides the hash, so a 384 suite gives a different, longer value
    other = w.keypackage_ref(kp, cipher_suite="MLS_256_DHKEMP384_AES256GCM_SHA384_P384")
    assert other != got and len(other) > len(got)
    # ...and the two labels can never collide
    assert w.group_info_commitment(kp, cipher_suite=suite) != got


def test_a_client_can_derive_the_reference_the_server_returned():
    """R9-X1: the DS RETURNS it and a client can DERIVE it, so neither depends
    on the other's implementation and a substituted package is detectable."""
    import base64 as b64
    import mls_wire as w
    m = _mock()
    res, pkg = _reserved(m)
    derived = w.keypackage_ref(b64.b64decode(pkg["keypackage_b64"]),
                               cipher_suite=pkg["cipher_suite"])
    assert derived == pkg["keypackage_ref"], \
        "the client's derivation disagrees with the server's value"


def test_the_whole_public_flow_uses_only_values_public_operations_returned():
    """R9-03's first acceptance test. Nothing here is invented: the id and the
    reference both come out of the reservation response."""
    m = _mock()
    res = m.reserve_keypackages(
        "EU-FR-PSBID-ZYWVTSRQPNM8M4", credential=MEMBER_CRED,
        cipher_suite=SUITE, targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-1"}],
        idempotency_key="idem-flow-00000001")
    assert res["reservation_id"] and not res["committed"]
    committed = m.commit_reservation(res["reservation_id"], credential=MEMBER_CRED)
    assert committed["committed"] is True
    pkg = committed["keypackages"][0]
    dep = m.deposit_welcome(_record(reservation_id=res["reservation_id"],
                                    keypackage_ref=pkg["keypackage_ref"]),
                            credential=MEMBER_CRED)
    out = m.refuse_welcome(dep["welcome_id"],
                           credential=dict(TARGET_DEV,
                                           keypackage_ref=pkg["keypackage_ref"]),
                           reason="suite-below-published-floor",
                           offered_suite=SUITE, required_floor=SUITE,
                           refused_at=IN_WINDOW, members=FLOOR_MEMBERS)
    assert out["outcome_id"]


@pytest.mark.parametrize("schema,call", [
    ("Reservation", "reserve"),
    ("Reservation", "commit"),
])
def test_every_reservation_response_validates_against_its_contract(schema, call):
    """R9-03 requirement 4, and §2's addition: the COMMIT response is the fifth
    invalid one and fails the same four ways. Fixing the serializer once fixes
    both — covering only the first would miss it."""
    m = _mock()
    res = m.reserve_keypackages(
        "EU-FR-PSBID-ZYWVTSRQPNM8M4", credential=MEMBER_CRED,
        cipher_suite=SUITE, targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-1"}],
        idempotency_key="idem-resp-00000001")
    obj = res if call == "reserve" else \
        m.commit_reservation(res["reservation_id"], credential=MEMBER_CRED)
    assert lc.validate_contract_object(
        "delivery-service-openapi.yaml", schema, obj) == []


def test_the_response_carries_no_internal_field():
    """It used to return the DS's own row — `creator`, `uid`, `targets`,
    `state` — which the closed public object rejects and which leaks who holds
    the reservation."""
    m = _mock()
    res, _ = _reserved(m)
    for leaked in ("creator", "uid", "targets", "state"):
        assert leaked not in res, leaked


def test_the_idempotency_model_is_the_contracts_one():
    """R9-03 requirement 3. The reference took a CLIENT-supplied
    `reservation_id` while the contract called it server-assigned and exposed
    `Idempotency-Key` — two idempotency models, one operation."""
    m = _mock()
    a = m.reserve_keypackages(
        "EU-FR-PSBID-ZYWVTSRQPNM8M4", credential=MEMBER_CRED, cipher_suite=SUITE,
        targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-1"}],
        idempotency_key="idem-replay-000001")
    b = m.reserve_keypackages(
        "EU-FR-PSBID-ZYWVTSRQPNM8M4", credential=MEMBER_CRED, cipher_suite=SUITE,
        targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-1"}],
        idempotency_key="idem-replay-000001")
    assert a == b, "a replay opened a second reservation"
    with pytest.raises(m.ReservationError) as exc:
        m.reserve_keypackages(
            "EU-FR-PSBID-ZYWVTSRQPNM8M4", credential=MEMBER_CRED,
            cipher_suite=SUITE,
            targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-2"}],
            idempotency_key="idem-replay-000001")
    assert exc.value.reason == "reservation-conflict"
    with pytest.raises(m.ReservationError) as missing:
        m.reserve_keypackages(
            "EU-FR-PSBID-ZYWVTSRQPNM8M4", credential=MEMBER_CRED,
            cipher_suite=SUITE,
            targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-1"}],
            idempotency_key="short")
    assert missing.value.reason == "idempotency-key-required"


def test_ttl_expiry_and_release_return_packages_exactly_once():
    """R9-03 requirement 7, and the round-8 residual seen from the contract
    side: `DELETE /reservations/{id}` was PUBLISHED and unimplemented, so
    reservation exhaustion had no remedy even in the demo."""
    m = _mock()
    res, _ = _reserved(m, commit=False)
    # expiry is enforced, not merely published
    with pytest.raises(m.ReservationError) as exp:
        m.commit_reservation(res["reservation_id"], credential=MEMBER_CRED,
                             now="2026-04-04T09:10:00Z")     # TTL is 300 s
    assert exp.value.reason == "reservation-expired"
    # release exists, and returns nothing
    other, _ = _reserved(m, commit=False, key="idem-release-00001")
    assert m.release_reservation(other["reservation_id"],
                                 credential=MEMBER_CRED) is None
    with pytest.raises(m.ReservationError):
        m.commit_reservation(other["reservation_id"], credential=MEMBER_CRED)
    # a COMMITTED reservation's packages are consumed and never return
    done, _ = _reserved(m, key="idem-committed-0001")
    with pytest.raises(m.ReservationError) as cm:
        m.release_reservation(done["reservation_id"], credential=MEMBER_CRED)
    assert cm.value.reason == "reservation-committed"


def test_the_device_credential_binding_is_published():
    """R9-03 requirement 5. The binding `refuse_welcome()` enforces existed
    only as an extra member of a Python dictionary — enforced, and named by no
    published scheme, so an independent implementation had no way to know its
    refusals would be rejected."""
    doc = _ds_doc()
    d = " ".join(doc["components"]["securitySchemes"]["deviceAuth"]
                 ["description"].split())
    assert "KeyPackageRef" in d
    assert "possession of the private key" in d
    assert "does not read a reference out of the request" in d


def test_the_group_info_commitment_says_what_it_is_and_who_checks_it():
    """R9-03 requirement 6. It was `{type: string}` claiming an exact
    group-state binding, with no algorithm and no component able to verify
    it — a Welcome is encrypted to the invited device, so the DS cannot."""
    common = json.loads(
        (ROOT / "schemas" / "evidence-common.schema.json").read_text())
    gi = common["$defs"]["GroupInfoCommitment"]
    assert "RefHash" in gi["description"]
    assert "SBM 1.0 GroupInfo Commitment" in gi["description"]
    assert "invited DEVICE" in gi["description"]
    doc = _ds_doc()
    d = " ".join(doc["components"]["schemas"]["InvitationDeposit"]["properties"]
                 ["group_info_commitment"]["description"].split())
    assert "not this service" in d


# ===========================================================================
# R9-04 — instants, not strings; and responses their own contract accepts
#
# The reference compared RFC 3339 values with `>=` and `<=` on the raw
# strings. Lexical order is not chronological order once offsets are allowed,
# and `format: date-time` allows them. It also returned its own internal rows,
# which the closed public objects reject — so a generated client that
# correctly refuses unknown properties would have rejected the reference's
# SUCCESSFUL responses. Decision R9-X4.
# ===========================================================================

WINDOW_START = "2026-04-04T09:00:00Z"
WINDOW_END = "2026-04-04T10:00:00Z"


def _in_window(m, at):
    dep, _ = _deposited(m, created_at=WINDOW_START, expires_at=WINDOW_END)
    return _refuse(m, dep["welcome_id"], refused_at=at)


@pytest.mark.parametrize("label,at", [
    ("Z", "2026-04-04T09:30:00Z"),
    ("+02:00", "2026-04-04T11:30:00+02:00"),
    ("-02:00", "2026-04-04T07:30:00-02:00"),
    ("fractional", "2026-04-04T09:30:00.5Z"),
])
def test_equivalent_instants_decide_identically(label, at):
    """R9-04's first acceptance test. All four name the same instant, inside
    the window, so all four must create an outcome."""
    m = _mock()
    assert _in_window(m, at)["outcome_id"], label


def test_a_chronologically_inverted_window_is_refused_even_when_lexically_ordered():
    """`2026-04-04T08:00:00-02:00` is 10:00Z and sorts BEFORE
    `2026-04-04T09:00:00Z` as a string, so the invitation was born expired and
    accepted as ordered."""
    m = _mock()
    with pytest.raises(m.InvitationError) as exc:
        _deposited(m, created_at="2026-04-04T08:00:00-02:00",
                   expires_at="2026-04-04T09:00:00Z")
    assert exc.value.reason == "invitation-window-invalid"
    assert m._INVITATIONS == {}


def test_a_refusal_after_the_deadline_is_refused_however_it_is_written():
    """The reproduced defect: `09:30:00-02:00` is 11:30Z, ninety minutes past a
    10:00Z deadline, and sorts inside the window as a string."""
    m = _mock()
    dep, _ = _deposited(m, created_at=WINDOW_START, expires_at=WINDOW_END)
    with pytest.raises(m.InvitationError) as exc:
        _refuse(m, dep["welcome_id"], refused_at="2026-04-04T09:30:00-02:00")
    assert exc.value.reason == "invitation-unknown"
    assert m._OUTCOMES == {}


@pytest.mark.parametrize("label,at,creates", [
    ("one second before the start", "2026-04-04T08:59:59Z", False),
    ("exactly at the start", WINDOW_START, True),
    ("exactly at the end", WINDOW_END, True),
    ("one second after the end", "2026-04-04T10:00:01Z", False),
])
def test_each_boundary_follows_the_documented_rule(label, at, creates):
    """R9-04 requirement 2: the window is CLOSED at both ends, one rule, stated
    in the contract and applied at both boundaries."""
    m = _mock()
    if creates:
        assert _in_window(m, at)["outcome_id"], label
    else:
        with pytest.raises(m.InvitationError):
            _in_window(m, at)
        assert m._OUTCOMES == {}, label


def test_an_unparsable_instant_is_refused_rather_than_compared():
    m = _mock()
    with pytest.raises(m.InvitationError) as exc:
        _deposited(m, expires_at="next Tuesday")
    assert exc.value.reason in ("invitation-incomplete",
                                "invitation-window-invalid")


def test_every_generated_response_validates_against_its_closed_schema():
    """R9-04 requirement 5, and its fourth acceptance test. No validator caught
    these before: the reference returned internal rows, and a conforming client
    would have rejected its successful responses."""
    m = _mock()
    dep, _ = _deposited(m, created_at=WINDOW_START, expires_at=WINDOW_END)
    assert lc.validate_contract_object(
        "delivery-service-openapi.yaml", "WelcomeQueued", dep) == []

    queue = m.collect_welcomes(credential=TARGET_DEV_KP)
    assert lc.validate_contract_object(
        "delivery-service-openapi.yaml", "WelcomeQueue", queue) == []

    out = _refuse(m, dep["welcome_id"], refused_at="2026-04-04T09:30:00Z")
    assert lc.validate_contract_object(
        "delivery-service-openapi.yaml", "RefusalAccepted", out) == []

    for o in m.collect_outcomes(credential=MEMBER_CRED):
        assert lc.validate_contract_object(
            "delivery-service-openapi.yaml", "GroupEstablishmentOutcome",
            o) == []


def test_no_internal_field_reaches_a_public_response():
    """R9-04's fifth acceptance test. `invitation_id` is a correlation handle
    between a device's queue and the creator's, and `creator` names who owns
    the outcome; neither belongs on the wire and both were on it."""
    m = _mock()
    dep, _ = _deposited(m, created_at=WINDOW_START, expires_at=WINDOW_END)
    assert set(dep) == {"welcome_id", "recipient_device"}
    for item in m.collect_welcomes(credential=TARGET_DEV_KP)["welcomes"]:
        assert "invitation_id" not in item
    _refuse(m, dep["welcome_id"], refused_at="2026-04-04T09:30:00Z")
    for o in m.collect_outcomes(credential=MEMBER_CRED):
        assert "creator" not in o and "invitation_id" not in o


def test_the_refusal_returns_its_outcome_and_the_ack_returns_nothing():
    """R9-X4. The refusal declared `204 No Content` and returned
    `{"outcome_id": ...}`, so a generated client got nothing while the
    repository's own tests read the id from the return value — R9-03's shape a
    second time. The acknowledgement declared 204 and returned
    `{"acknowledged": true}`, which carries nothing the status code does not."""
    doc = _ds_doc()
    refusal = doc["paths"]["/welcome/{welcome_id}/refusal"]["post"]["responses"]
    assert "201" in refusal and "204" not in refusal
    assert refusal["201"]["content"]["application/json"]["schema"]["$ref"] \
        .endswith("/RefusalAccepted")
    ack = doc["paths"]["/group-establishment/outcomes/{outcome_id}"]["delete"]
    assert "content" not in ack["responses"]["204"]

    m = _mock()
    dep, _ = _deposited(m, created_at=WINDOW_START, expires_at=WINDOW_END)
    out = _refuse(m, dep["welcome_id"], refused_at="2026-04-04T09:30:00Z")
    assert set(out) == {"outcome_id"}
    assert m.ack_outcome(out["outcome_id"], credential=MEMBER_CRED) is None
