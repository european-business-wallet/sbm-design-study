# SPDX-License-Identifier: MIT
"""R3-05 — the certificate authorises the key it is published beside.

Former defect (round-3 review, High), in three parts:

1. The normative lint catalogue still described `LINT-BND-21` as "Ed25519
   COSE_Sign1" **after DR-12 made the verifier algorithm-neutral**. The
   generated catalogue is normative, so an assessor could reject a conforming
   ES256/ES384 confirmation on it. That one was mine, and it is the round-3
   family again: the code was fixed, the artefact describing the code was not.
2. BW-MEMBER prose said `confirmation_key.x5chain` is required in production;
   the schema required only `alg` and `public_key_b64`.
3. The I-D required the certificate's subject public key to EQUAL
   `public_key_b64`, but production lint checked only that an x5chain identity
   was present — it never parsed the certificate or proved the equality.

Together: a production deployment could publish a bare asserted raw key beside
a certificate for a different key, and the advanced-signature identity claim —
that the certificate authorises the key confirmations are made under — rested
on an assertion.

**Scope, stated because it would otherwise be over-read.** What is proven here
is that the certificate carries this key, and that it was within its own
validity at the act. NOT proven: the chain to a trust anchor, the QSealC
qualification, SCD certification, Trusted-List status. Those are the external
production trust policy — **F-04 and X-01 stay Partial**, and completing the
parsing locally is not completing them. The review warns about exactly this.
"""
import base64
import datetime
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

ACT = "2026-04-04T10:16:23Z"


def _cert(private_key, *, not_before=None, not_after=None):
    """A self-signed leaf holding `private_key`'s public key. Self-signed on
    purpose: this function proves KEY BINDING, and a chain to a trust anchor is
    explicitly out of scope."""
    nb = not_before or datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    na = not_after or datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo-device")])
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(private_key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(nb).not_valid_after(na))
    algorithm = None if isinstance(private_key, ed25519.Ed25519PrivateKey) \
        else hashes.SHA256()
    return builder.sign(private_key, algorithm)


def _pair(alg):
    if alg == "EdDSA":
        sk = ed25519.Ed25519PrivateKey.generate()
        raw = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    else:
        curve = ec.SECP256R1() if alg == "ES256" else ec.SECP384R1()
        sk = ec.generate_private_key(curve)
        raw = sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return sk, base64.b64encode(raw).decode()


def _chain(cert):
    return [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()]


# ---------------------------------------------------------------------------
# The binding holds for every permitted algorithm
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alg", ["EdDSA", "ES256", "ES384"])
def test_a_certificate_holding_the_published_key_binds(alg):
    sk, pub = _pair(alg)
    assert lc.check_certificate_binds_key(_chain(_cert(sk)), alg, pub, at=ACT)


@pytest.mark.parametrize("alg", ["EdDSA", "ES256", "ES384"])
def test_a_certificate_for_a_DIFFERENT_key_is_rejected(alg):
    """The defect: production lint accepted an x5chain's PRESENCE, so a
    certificate for another key passed while the anchor asserted its own."""
    other_sk, _ = _pair(alg)
    _, published = _pair(alg)
    with pytest.raises(lc.CertificateBindingError) as exc:
        lc.check_certificate_binds_key(_chain(_cert(other_sk)), alg, published)
    assert "NOT the published confirmation key" in str(exc.value)


def test_a_certificate_of_the_wrong_type_for_the_declared_alg_is_rejected():
    sk, _ = _pair("EdDSA")
    _, ec_pub = _pair("ES256")
    with pytest.raises(lc.CertificateBindingError) as exc:
        lc.check_certificate_binds_key(_chain(_cert(sk)), "ES256", ec_pub)
    assert "not on secp256r1" in str(exc.value)


def test_a_certificate_on_the_wrong_curve_is_rejected():
    sk, pub = _pair("ES256")
    with pytest.raises(lc.CertificateBindingError):
        lc.check_certificate_binds_key(_chain(_cert(sk)), "ES384", pub)


def test_a_certificate_outside_its_validity_at_the_act_is_rejected():
    """Validity at the ACT, consistent with every other window in the profile."""
    sk, pub = _pair("EdDSA")
    expired = _cert(sk,
                    not_before=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
                    not_after=datetime.datetime(2026, 2, 1, tzinfo=datetime.timezone.utc))
    with pytest.raises(lc.CertificateBindingError) as exc:
        lc.check_certificate_binds_key(_chain(expired), "EdDSA", pub, at=ACT)
    assert "not valid at" in str(exc.value)


@pytest.mark.parametrize("bad", [None, [], ["not-base64!!"], ["aGVsbG8="]])
def test_malformed_input_fails_closed(bad):
    _, pub = _pair("EdDSA")
    with pytest.raises(lc.CertificateBindingError):
        lc.check_certificate_binds_key(bad, "EdDSA", pub)


# ---------------------------------------------------------------------------
# The production profile requires it
# ---------------------------------------------------------------------------

def _disc31(member):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "discovery_lint", ROOT / "scripts" / "discovery_lint.py")
    dl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dl)
    v = dl.Violations()
    dl._production_confirmation_keys(v, member)
    return [m for r, m in v.items if r == "LINT-DISC-31"]


def test_a_bare_asserted_key_fails_the_production_profile():
    member = {"devices": [{"device_id": "dev-01",
                           "confirmation_key": {"alg": "EdDSA",
                                                "public_key_b64": _pair("EdDSA")[1]}}]}
    issues = _disc31(member)
    assert issues and "no x5chain" in issues[0]


def test_a_bound_certificate_passes_the_production_profile():
    sk, pub = _pair("EdDSA")
    member = {"devices": [{"device_id": "dev-01",
                           "confirmation_key": {"alg": "EdDSA", "public_key_b64": pub,
                                                "x5chain": _chain(_cert(sk))}}]}
    assert not _disc31(member)


def test_a_mismatched_certificate_fails_the_production_profile():
    other, _ = _pair("EdDSA")
    _, pub = _pair("EdDSA")
    member = {"devices": [{"device_id": "dev-01",
                           "confirmation_key": {"alg": "EdDSA", "public_key_b64": pub,
                                                "x5chain": _chain(_cert(other))}}]}
    assert _disc31(member)


# ---------------------------------------------------------------------------
# The normative artefacts agree with the code
# ---------------------------------------------------------------------------

def test_the_catalogue_is_algorithm_neutral():
    """Gap 1, and my own: the code became algorithm-neutral in round 2 while
    the NORMATIVE catalogue kept saying Ed25519, so an assessor could reject a
    conforming EC confirmation on it."""
    rules = json.loads((ROOT / "docs" / "lint-catalogue.json").read_text())["rules"]
    pred = next(r for r in rules if r["id"] == "LINT-BND-21")["predicate"]
    assert "Ed25519 COSE_Sign1" not in pred
    assert "THREE-WAY AGREEMENT" in pred
    for alg in ("EdDSA", "ES256", "ES384"):
        assert alg in pred


def test_the_scope_limit_is_recorded_where_it_will_be_read():
    """What is NOT proven must be as legible as what is, or the local parsing
    gets read as completion of the external trust policy."""
    rules = json.loads((ROOT / "docs" / "lint-catalogue.json").read_text())["rules"]
    pred = next(r for r in rules if r["id"] == "LINT-DISC-31")["predicate"]
    assert "does NOT validate the chain to a trust anchor" in pred
    assert "EXTERNAL production trust" in pred and "remain Partial" in pred
