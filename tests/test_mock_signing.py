# SPDX-License-Identifier: MIT
"""M6: the mock RDP must fail loudly when real signing is requested but PyNaCl
is missing, instead of silently degrading to the HMAC placeholder (which would
emit structurally-valid-but-cryptographically-invalid evidence). The HMAC
placeholder is reachable ONLY behind an explicit REAL_SIGN=0, and warns."""
import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load_mock():
    try:
        spec = importlib.util.spec_from_file_location("mock_rdp", ROOT / "scripts" / "mock_rdp.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # e.g. no flask -> skip
        return mod
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"mock_rdp not importable ({exc})")


def test_evidence_id_is_a_valid_uuid_urn():
    """F13 (PoC feedback, twelfth review): _evidence_id() must emit RFC
    9562-valid urn:uuid syntax — 32 unhyphenated hex chars are not a UUID-URN
    (the schema only requires minLength 1, so this is the enforcing check)."""
    import re
    mock = _load_mock()
    urn = re.compile(
        r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    ids = {mock._evidence_id() for _ in range(8)}
    assert len(ids) == 8, "evidence ids must be unique"
    for eid in ids:
        assert urn.match(eid), f"not a valid RFC 9562 UUID-URN: {eid!r}"


def test_real_signing_without_pynacl_raises(monkeypatch):
    """REAL_SIGN default (real) + PyNaCl absent -> RuntimeError, never a placeholder."""
    mock = _load_mock()
    monkeypatch.delenv("REAL_SIGN", raising=False)
    # Force `from nacl.signing import SigningKey` (inside cose_sign) to fail.
    monkeypatch.setitem(__import__("sys").modules, "nacl", None)
    monkeypatch.setitem(__import__("sys").modules, "nacl.signing", None)
    with pytest.raises(RuntimeError, match="pynacl is not installed"):
        mock.cose_sign(b"payload", kid="rdp", seed="demo")


def test_real_sign_zero_uses_placeholder_with_warning(monkeypatch):
    """REAL_SIGN=0 -> the HMAC placeholder, emitting a dev warning."""
    mock = _load_mock()
    monkeypatch.setenv("REAL_SIGN", "0")
    with pytest.warns(UserWarning, match="NOT a cryptographically valid"):
        out = mock.cose_sign(b"payload", kid="rdp", seed="demo")
    assert isinstance(out, (bytes, bytearray)) and out, "placeholder must still produce a COSE structure"
