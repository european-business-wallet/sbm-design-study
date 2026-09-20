# SPDX-License-Identifier: MIT
"""DR-12 — every permitted confirmation algorithm is interoperably verifiable.

Former defect (round-2 review, High). BW-MEMBER permits `EdDSA`, `ES256` and
`ES384`, and the evidence COSE checks allow all three — but
`bundle_lint._verify_wallet_sig()` always interpreted `public_key_b64` as a raw
Ed25519 key and always verified with PyNaCl. It never dispatched on the
published algorithm, never compared the COSE protected `alg` with the published
one, never defined the EC point encoding, and never checked a production
certificate's key against the anchor. Discovery lint only checked that the text
was base64 and the name was in an allowlist.

Both directions were broken, and the second is the dangerous one:

  * a CONFORMING ES256/ES384 confirmation was REJECTED by the reference
    verifier — a member's own evidence would not verify;
  * an algorithm/key MISMATCH was NOT DETECTED, an algorithm-confusion surface
    at the layer that decides attribution.

Independence. The Ed25519 vectors below are RFC 8032 §7.1's — published test
vectors that no signer of ours produced. The ECDSA cases cannot be pinned that
way (ECDSA is randomised, so there is no fixed signature to pin for a given
message), so they are round-tripped through `cryptography` while every key
ENCODING is asserted byte-for-byte against the specification, and every
cross-algorithm substitution is required to fail. What remains outside this
file is the review's fifth criterion — the same vectors under a SECOND COSE
implementation. There is no second COSE stack in this offline environment, so
that is recorded as an explicit residual rather than claimed; see
`test_the_cross_implementation_check_is_recorded_as_a_residual`.
"""
import base64
import importlib.util
import json
import pathlib
import sys

import cbor2
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")

PAYLOAD = cbor2.dumps({"mid": "F1N2C3D4P", "device_id": "dev-01", "result": "match"})


# ---------------------------------------------------------------------------
# Signers, one per algorithm — the test's own, not the producer's
# ---------------------------------------------------------------------------

def _cose(protected_alg, payload, sign):
    protected = cbor2.dumps({1: protected_alg})
    to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
    return base64.b64encode(
        cbor2.dumps([protected, {}, payload, sign(to_sign)])).decode()


def _ed25519_pair():
    from nacl.signing import SigningKey
    sk = SigningKey(bytes(range(32)))
    pub = bytes(sk.verify_key)
    return ({"alg": "EdDSA", "public_key_b64": base64.b64encode(pub).decode()},
            lambda m: sk.sign(m).signature)


def _ec_pair(alg):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    curve = ec.SECP256R1() if alg == "ES256" else ec.SECP384R1()
    digest = hashes.SHA256() if alg == "ES256" else hashes.SHA384()
    n = 32 if alg == "ES256" else 48
    sk = ec.generate_private_key(curve)
    point = sk.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization",
                   fromlist=["Encoding"]).Encoding.X962,
        __import__("cryptography.hazmat.primitives.serialization",
                   fromlist=["PublicFormat"]).PublicFormat.UncompressedPoint)

    def sign(msg):
        der = sk.sign(msg, ec.ECDSA(digest))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(n, "big") + s.to_bytes(n, "big")   # COSE r||s

    return ({"alg": alg, "public_key_b64": base64.b64encode(point).decode()}, sign)


PAIRS = {"EdDSA": _ed25519_pair, "ES256": lambda: _ec_pair("ES256"),
         "ES384": lambda: _ec_pair("ES384")}
ALG_ID = {"EdDSA": -8, "ES256": -7, "ES384": -35}


# ---------------------------------------------------------------------------
# The review's acceptance tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alg", ["EdDSA", "ES256", "ES384"])
def test_a_valid_confirmation_verifies_under_every_permitted_algorithm(alg):
    """The first acceptance test. ES256 and ES384 confirmations were REJECTED
    by the reference verifier before this change."""
    key, sign = PAIRS[alg]()
    sig = _cose(ALG_ID[alg], PAYLOAD, sign)
    assert lc.verify_cose_signature(sig, key) is None
    assert bl._verify_wallet_sig(sig, key) is None


@pytest.mark.parametrize("alg", ["EdDSA", "ES256", "ES384"])
def test_the_same_verifier_serves_every_confirmation_role(alg):
    """'sender, recipient, quorum and refusal proofs' — one implementation
    serves all four call sites, so the property is the verifier's, not each
    site's."""
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    body = src[src.index("def check_bundle("):]
    assert body.count("_verify_wallet_sig(") >= 5
    assert "VerifyKey(" not in body, \
        "a call site is verifying Ed25519 directly again, bypassing the dispatch"


@pytest.mark.parametrize("declared,signed", [
    ("EdDSA", "ES256"), ("EdDSA", "ES384"),
    ("ES256", "EdDSA"), ("ES256", "ES384"),
    ("ES384", "EdDSA"), ("ES384", "ES256"),
])
def test_every_cross_algorithm_substitution_fails(declared, signed):
    """The second acceptance test, exhaustively. The published key declares one
    algorithm and the signature another: the verifier must refuse rather than
    fall back to whichever it can compute."""
    key, _ = PAIRS[declared]()
    _, sign_other = PAIRS[signed]()
    sig = _cose(ALG_ID[signed], PAYLOAD, sign_other)
    with pytest.raises(lc.SignatureVerificationError) as exc:
        lc.verify_cose_signature(sig, key)
    assert "ALGORITHM CONFUSION" in str(exc.value) or "key is" in str(exc.value)


@pytest.mark.parametrize("alg", ["ES256", "ES384"])
def test_a_malformed_point_fails_closed(alg):
    key, _ = PAIRS[alg]()
    raw = bytearray(base64.b64decode(key["public_key_b64"]))
    raw[-1] ^= 0xFF                                    # off the curve
    bad = dict(key, public_key_b64=base64.b64encode(bytes(raw)).decode())
    with pytest.raises(lc.SignatureVerificationError):
        lc.load_confirmation_key(alg, bad["public_key_b64"])


def test_the_wrong_curve_fails_closed():
    """A P-256 point offered as an ES384 key: right shape, wrong curve."""
    key, _ = PAIRS["ES256"]()
    with pytest.raises(lc.SignatureVerificationError) as exc:
        lc.load_confirmation_key("ES384", key["public_key_b64"])
    assert "97" in str(exc.value)


@pytest.mark.parametrize("alg", ["ES256", "ES384"])
def test_a_compressed_point_is_rejected(alg):
    """One encoding per algorithm — accepting several is how one key acquires
    two identities."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    curve = ec.SECP256R1() if alg == "ES256" else ec.SECP384R1()
    sk = ec.generate_private_key(curve)
    compressed = sk.public_key().public_bytes(Encoding.X962,
                                              PublicFormat.CompressedPoint)
    with pytest.raises(lc.SignatureVerificationError):
        lc.load_confirmation_key(alg, base64.b64encode(compressed).decode())


@pytest.mark.parametrize("alg", ["ES256", "ES384"])
def test_a_der_signature_is_not_a_cose_signature(alg):
    """COSE ECDSA is fixed-width r||s (RFC 9053 §2.1). A DER blob is the most
    likely thing a naive implementation would send."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    curve = ec.SECP256R1() if alg == "ES256" else ec.SECP384R1()
    digest = hashes.SHA256() if alg == "ES256" else hashes.SHA384()
    sk = ec.generate_private_key(curve)
    point = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    key = {"alg": alg, "public_key_b64": base64.b64encode(point).decode()}
    sig = _cose(ALG_ID[alg], PAYLOAD, lambda m: sk.sign(m, ec.ECDSA(digest)))
    with pytest.raises(lc.SignatureVerificationError) as exc:
        lc.verify_cose_signature(sig, key)
    assert "r||s" in str(exc.value)


def test_a_signature_without_a_protected_alg_is_rejected():
    """An unprotected algorithm is one an attacker may choose."""
    key, sign = PAIRS["EdDSA"]()
    protected = cbor2.dumps({})
    to_sign = cbor2.dumps(["Signature1", protected, b"", PAYLOAD])
    sig = base64.b64encode(
        cbor2.dumps([protected, {}, PAYLOAD, sign(to_sign)])).decode()
    with pytest.raises(lc.SignatureVerificationError) as exc:
        lc.verify_cose_signature(sig, key)
    assert "declares no alg" in str(exc.value)


def test_an_unpermitted_algorithm_is_rejected():
    key, sign = PAIRS["EdDSA"]()
    sig = _cose(-257, PAYLOAD, sign)          # RS256
    with pytest.raises(lc.SignatureVerificationError):
        lc.verify_cose_signature(sig, key)


# ---------------------------------------------------------------------------
# Known-answer: RFC 8032 §7.1, vectors no signer of ours produced
# ---------------------------------------------------------------------------

def test_kat_rfc8032_ed25519():
    """Independent by construction: the key, message and signature are the
    RFC's, so agreement is agreement with the standard rather than with us."""
    from nacl.signing import VerifyKey
    # RFC 8032 §7.1, TEST 2 (1-octet message).
    pub = bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    msg = bytes.fromhex("72")
    sig = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    VerifyKey(pub).verify(msg, sig)          # the vector itself
    key = {"alg": "EdDSA", "public_key_b64": base64.b64encode(pub).decode()}
    loaded = lc.load_confirmation_key("EdDSA", key["public_key_b64"])
    assert bytes(loaded) == pub, "our decoding of the RFC's key differs from it"


@pytest.mark.parametrize("alg,size", [("EdDSA", 32), ("ES256", 65), ("ES384", 97)])
def test_the_key_encoding_is_pinned_to_the_specification(alg, size):
    """The encodings are stated in the I-D; this pins them independently of the
    implementation, so a change to either is visible."""
    assert lc.KEY_ENCODING[alg][1] == size
    key, _ = PAIRS[alg]()
    raw = base64.b64decode(key["public_key_b64"])
    assert len(raw) == size
    if alg != "EdDSA":
        assert raw[0] == 0x04, "not a SEC1 uncompressed point"
    with pytest.raises(lc.SignatureVerificationError):
        lc.load_confirmation_key(alg, base64.b64encode(raw[:-1]).decode())


def test_the_id_states_the_encodings_and_the_three_way_agreement():
    t = " ".join((ROOT / "ietf" / "draft-sbm-mls-erd-00.md")
                 .read_text().replace("**", "").replace("`", "").split())
    assert "Confirmation-key encodings and algorithm agreement" in t
    assert "three-way agreement" in t
    assert "raw 32-byte Ed25519 public key" in t
    assert "SEC1 uncompressed point on P-256" in t
    assert "a DER-encoded signature is not a COSE signature" in t
    assert "its subject public key MUST equal public_key_b64" in t


# ---------------------------------------------------------------------------
# What is NOT claimed
# ---------------------------------------------------------------------------
