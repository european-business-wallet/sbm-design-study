# SPDX-License-Identifier: MIT
"""R27-PUB-05 — what a mandate commitment establishes, said the same way everywhere.

A commitment binds the class the sender DECLARED. Opening it shows that declared
class and whether it falls inside the mandate's scope. It does not show what the
plaintext was: no party to a reveal inspects the content, so a sender could commit
to a permitted class and encrypt something else.

The previous pass corrected that in the agent explainer, Annex R.2 and the TS's
proof-strength paragraph, and left the normative I-D, the profile's threat table
and the verifier companion claiming the stronger thing. A reader following the
I-D and a reader following the TS got different answers about the same
construction, which is worse than either answer alone — and the reading path a
reviewer takes first is the normative one.

These probes pin the CLAIM, not the phrasing around it: each asserts the
qualification is present and the unqualified form is gone. The guarantee being
preserved matters as much as the limit — a reveal of an out-of-scope class IS
evidence of an out-of-scope declared act, and a correction that flattened this to
"the commitment proves nothing" would be its own overclaim in the other
direction, so the last probe asserts the guarantee survived.
"""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]

ID = "ietf/draft-sbm-mls-erd-00.md"
PROFILE = "Secure-Business-Messaging-Profile.md"
VERIFIER = "docs/production-verifier-architecture.md"
TS = "etsi/TS-SBM-QERDS-Binding-v0.1.md"
EXPLAINER = "docs/agent-profile-explainer.md"


def _text(rel):
    """One flattened line, so a claim split across a wrap still matches."""
    return " ".join((ROOT / rel).read_text(encoding="utf-8").split())


# ---------------------------------------------------------------------------
# The unqualified forms are gone
# ---------------------------------------------------------------------------

GONE = [
    (ID, "an out-of-scope reveal is provable agent overreach"),
    (ID, "cannot show the agent's message fell within the mandate's authorised class scope"),
    (PROFILE, "`mandate_commitment` makes overreach **provable** on reveal"),
    (VERIFIER, "or that an agent acted within its mandate"),
]


def test_no_document_still_claims_the_commitment_proves_the_conduct():
    stale = [f"{rel}: {phrase!r}" for rel, phrase in GONE if phrase in _text(rel)]
    assert not stale, (
        "a mandate claim still says the commitment establishes what the agent DID, "
        f"rather than what it declared: {stale}")


# ---------------------------------------------------------------------------
# The limit is stated on every reading path, not only in the TS
# ---------------------------------------------------------------------------

def test_the_normative_id_states_the_limit_where_it_defines_the_commitment():
    text = _text(ID)
    assert "the class the sender **committed to**" in text
    assert "does not certify what the encrypted content actually was" in text
    assert "commit to a permitted class and encrypt something else" in text
    assert "overreach in the declared act" in text


def test_the_threat_table_states_the_limit():
    text = _text(PROFILE)
    assert "out-of-scope **declaration** provable on reveal" in text
    assert "not the encrypted content" in text


def test_the_verifier_companion_states_the_limit():
    text = _text(VERIFIER)
    assert "the class an agent **declared** for its act lay within its mandate" in text
    assert "does not certify the agent's actual conduct" in text


def test_the_privacy_shorthand_says_what_it_hides_from():
    """"without either leaking" alone reads as a claim about the whole design;
    the mandate reference and the scope mapping are public by construction."""
    assert "without either leaking **from the commitment itself**" in _text(TS)


def test_the_places_corrected_in_the_previous_pass_stayed_corrected():
    explainer = _text(EXPLAINER)
    assert "not that the declared class describes the encrypted document" in explainer
    assert "commit to a permitted class and encrypt something else" in explainer
    ts = _text(TS)
    assert "Neither establishes what the encrypted document actually was" in ts
    assert "An in-scope opening therefore does not certify the agent's actual conduct" in ts


# ---------------------------------------------------------------------------
# And the guarantee that remains is still claimed
# ---------------------------------------------------------------------------

def test_the_out_of_scope_declaration_is_still_evidence_of_something():
    """The correction narrows the claim; it must not erase it. A reveal of an
    out-of-scope class establishes an out-of-scope DECLARED act, and both the
    normative text and the TS must still say so."""
    for rel in (ID, TS):
        text = _text(rel)
        assert "declaration" in text and "outside" in text, rel
        assert "overreach in the declared act" in text, rel
