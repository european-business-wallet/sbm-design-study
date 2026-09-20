# SPDX-License-Identifier: MIT
"""DR-04 — the pinned policy version was in force when the act took place.

Former defect (round-2 review, High), visible in the SHIPPED fixtures: the
default bundle pinned a BW-ORG taking force `2026-06-01` for a message sent
`2026-04-04`, and the scoped bundle a scope taking force `2026-07-01` for the
same message. The GCM read on `2026-04-09` pinned the June policy too. Every
one of those bundles was lint-clean.

X-12 made selection deterministic and F-08 made the selected KEY recomputable,
but neither bounded the version in TIME, so evidence could be evaluated under
rules that did not yet exist when the message was sent — the one thing a
versioned, legally-decisive policy exists to prevent.

Two rules close it, from the two directions:

  LINT-BND-33  (bundle)     the pinned ORG *and* the matched scope entry were
                            in force at `sent_at`.
  LINT-DISC-28 (discovery)  an ORG served AS CURRENT is already in force —
                            R2-M6 prohibits pre-publication rather than adding
                            an `as_of` retrieval API.

The fixtures were corrected in the same commit, so the first test below would
have FAILED on the shipped samples before this change.
"""
import copy
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")
dl = _load("discovery_lint", "discovery_lint.py")


def _proj(name):
    return json.loads((ROOT / "samples" / f"{name}.json").read_text())["projection"]


SE = _proj("sample-SE")
DE = _proj("sample-DE")
ORG = _proj("sample-BW-ORG")
SE_SCOPED = _proj("sample-SE-scoped")
ORG_SCOPED = _proj("sample-BW-ORG-scoped")


def _org_digest(org):
    """The ORG's doc_digest as the I-D defines it: SHA-256 over the
    deterministic-CBOR body, the bytes the discovery seal covers (§8.1)."""
    import hashlib
    from lint_cli import dcbor
    return hashlib.sha256(
        dcbor({k: v for k, v in org.items() if k != "doc_cose_b64"})).hexdigest()


def _repin(org, evidence):
    """Mutating an ORG changes its digest, and LINT-BND-33 (like -30) only
    judges evidence that PINS this ORG. Re-point the refs so the in-force arm
    is what is under test, not the digest match."""
    out = []
    for ev in copy.deepcopy(evidence):
        for holder in (ev, ev.get("s3_attestation") or {}):
            apr = holder.get("acceptance_policy_ref")
            if isinstance(apr, dict) and isinstance(apr.get("doc_digest"), dict):
                apr["doc_digest"]["hex"] = _org_digest(org)
        out.append(ev)
    return out


def _bnd33(org, evidence, repin=True):
    ev = _repin(org, evidence) if repin else evidence
    issues = bl.check_bundle(SE["recipient_uid"], {}, org, [], ev)
    return [m for r, m in issues if r == "LINT-BND-33"]


# ---------------------------------------------------------------------------
# The shipped chains
# ---------------------------------------------------------------------------

def test_every_shipped_chain_is_in_force_at_its_own_sent_at():
    """The regression the corrected fixtures exist to hold. Reads the samples
    as shipped: no chain may pin a version that post-dates its own act."""
    from lint_cli import instant
    checked = 0
    for f in sorted((ROOT / "samples").glob("sample-SE*.json")):
        se = json.loads(f.read_text())["projection"]
        sent = instant(se["sent_at"])
        org = ORG_SCOPED if (se.get("scope_ref") or {}).get("scope_id") not in (
            None, "default") else ORG
        assert instant(org["valid_from"]) <= sent, \
            f"{f.name}: pinned ORG takes force after the message was sent"
        for entry in ((org.get("scope_map") or {}).get("scopes") or []):
            if entry["scope_id"] == (se.get("scope_ref") or {}).get("scope_id"):
                assert instant(entry["valid_from"]) <= sent, \
                    f"{f.name}: the matched scope takes force after sent_at"
        checked += 1
    assert checked >= 3, "the shipped SE fixtures were not found"


def test_the_shipped_bundles_raise_no_in_force_violation():
    assert not _bnd33(ORG, [SE, DE], repin=False)
    assert _org_digest(ORG) == SE["acceptance_policy_ref"]["doc_digest"]["hex"], \
        "the shipped SE really does pin the shipped ORG — so the clean result " \
        "above is the rule passing, not the precondition missing"


# ---------------------------------------------------------------------------
# LINT-BND-33 — the two arms, separately
# ---------------------------------------------------------------------------

def test_a_policy_taking_force_after_the_message_fails():
    org = copy.deepcopy(ORG)
    org["valid_from"] = "2026-06-01T00:00:00Z"       # the shipped defect
    issues = _bnd33(org, [SE, DE])
    assert issues, "a future-dated policy must not govern an earlier message"
    assert "did not yet exist when the message was sent" in issues[0]


def test_the_tie_is_in_force():
    org = copy.deepcopy(ORG)
    org["valid_from"] = SE["sent_at"]
    assert not _bnd33(org, [SE, DE])


def test_a_scope_taking_force_after_the_message_fails_on_its_own_arm():
    """A scope can be introduced into an ORG that is already in force, so the
    scope arm must be checked independently of the ORG arm."""
    org = copy.deepcopy(ORG_SCOPED)
    org["valid_from"] = "2026-01-01T00:00:00Z"        # the ORG itself is fine
    sid = (SE_SCOPED.get("scope_ref") or {}).get("scope_id")
    for entry in org["scope_map"]["scopes"]:
        if entry["scope_id"] == sid:
            entry["valid_from"] = "2026-07-01T00:00:00Z"
    issues = _bnd33(org, [SE_SCOPED])
    assert issues, "the scope arm did not fire"
    assert "scoped to" in issues[0] and "did not yet exist" in issues[0]


def test_a_de_is_bound_by_its_ses_sent_at_not_its_own_time():
    """A DE echoes its SE's ref; the act that fixes the version is the
    SUBMISSION, so the DE inherits the SE's bound."""
    org = copy.deepcopy(ORG)
    org["valid_from"] = "2026-04-04T10:15:30Z"        # after sent_at, before delivery
    assert _bnd33(org, [SE, DE]), \
        "the DE must be judged against its SE's sent_at, not delivered_at"


# ---------------------------------------------------------------------------
# LINT-DISC-28 — pre-publication as current is prohibited (R2-M6)
# ---------------------------------------------------------------------------

def _disc28(org, now):
    v = dl.Violations()
    dl._check_in_force(v, org, now=now)
    return [m for r, m in v.items if r == "LINT-DISC-28"]


def test_a_future_dated_current_org_is_non_conformant():
    assert _disc28({"valid_from": "2026-09-01T00:00:00Z"}, "2026-07-28T00:00:00Z")


def test_an_in_force_org_passes_and_the_tie_is_in_force():
    assert not _disc28({"valid_from": "2026-03-01T00:00:00Z"}, "2026-07-28T00:00:00Z")
    assert not _disc28({"valid_from": "2026-07-28T00:00:00Z"}, "2026-07-28T00:00:00Z")


def test_the_check_is_parametric_and_silent_without_a_retrieval_time():
    """An archived version legitimately has a valid_from in the past of its own
    service window, so the check is meaningless without `now` — the
    LINT-DISC-25 pattern."""
    assert not _disc28({"valid_from": "2026-09-01T00:00:00Z"}, None)


def test_an_unparsable_valid_from_fails_closed():
    assert _disc28({"valid_from": "next tuesday"}, "2026-07-28T00:00:00Z")


def test_the_shipped_orgs_are_in_force_today():
    for name in ("sample-BW-ORG", "sample-BW-ORG-scoped", "sample-BW-ORG-de"):
        assert not _disc28(_proj(name), "2026-07-28T00:00:00Z"), name


# ---------------------------------------------------------------------------
# The rule is stated where implementers read it
# ---------------------------------------------------------------------------

def test_the_umbrella_states_the_precondition_and_the_prohibition():
    t = " ".join((ROOT / "Secure-Business-Messaging-Profile.md")
                 .read_text().replace("**", "").replace("`", "").split())
    assert "in force at sent_at" in t
    assert "MUST NOT publish a not-yet-effective BW-ORG" in t
    assert "no as_of retrieval API is defined" in t
