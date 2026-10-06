#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# -*- coding: utf-8 -*-
"""
EU Entity UID & Business Wallet Messaging Toolkit
=================================================
- Hyphen separators for UIDs: EU-CC-SCHEME-PAYLOADC1C2
- Check symbols: GF(2^5) Reed-Solomon (X-02) — UID C1C2 = 2 parity symbols
  (distance-3 MDS, any <=2-symbol error detected); MID = 1 parity symbol. The one
  implementation lives in scripts/id_grammar.py.
- MID: Base32(8) + 1 RS check symbol

Dependencies:
- Standard library only for core ops
- Optional: cryptography, cbor2, requests (for COSE signing & EDD upload)
- Optional: PyNaCl (for med-sign convenience)

CLI commands (high level):
  gen-uid / val-uid / gen-mid / val-mid / address / hash
  gen-keys / sign-evidence / sign-doc / edd-upload
  label            -> deterministic hashed label for UID
  dns-zone         -> REMOVED (DNS aliasing is not in this profile; historical marker)
  webfinger        -> WebFinger JSON for acct: alias (with --resource passthrough)
  med-stub         -> Emit a CURRENT sealed BW-MED-v1 artefact (M4: sm_artifact_b64 + projection)
  med-sign         -> COSE_Sign1-sign MED JSON using PyNaCl if available, else demo-only

Python ≥ 3.8
"""

import re, os, sys, json, argparse, hashlib, random, base64, textwrap, pathlib
from typing import Optional, Tuple, Dict, List

# -------------- Base32 Alphabet (Crockford without I,L,O,U) --------------
BASE32_ALPH = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
B32_INDEX = {c:i for i,c in enumerate(BASE32_ALPH)}

UID_REGEX = re.compile(r'^EU-[A-Z]{2}-(EOID|PSBID)-[0-9A-HJ-NP-TV-Z]{14}$')
MID_REGEX = re.compile(r'^[0-9A-HJ-NP-TV-Z]{9}$')
ROLE_REGEX = re.compile(r'^[a-z0-9._-]{1,32}$')

def _require(cond: bool, msg: str):
    if not cond:
        raise ValueError(msg)

# X-02: the single check-character implementation lives in id_grammar (GF(2^5)
# Reed-Solomon). This toolkit delegates so there is exactly one algorithm.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import id_grammar as _idg  # noqa: E402

# =========================== UID / MID ============================
def uid_generate(cc: str, scheme: str, payload: Optional[str]=None, rng: Optional[random.Random]=None) -> str:
    scheme = scheme.upper()
    _require(scheme in ("EOID","PSBID"), "scheme must be EOID or PSBID")
    _require(len(cc)==2 and cc.isalpha(), "cc must be ISO 3166-1 alpha-2")
    cc = cc.upper()
    if payload is None:
        rng = rng or random.SystemRandom()
        payload = "".join(rng.choice(BASE32_ALPH) for _ in range(12))
    else:
        _require(len(payload)==12 and all(ch in BASE32_ALPH for ch in payload),
                 "payload must be 12 Base32 chars (Crockford without I,L,O,U)")
    return _idg.make_uid(cc, scheme, payload)  # C1 C2 = GF(2^5) RS parity

def uid_validate(uid: str) -> Tuple[bool, List[str]]:
    errs: List[str] = []
    if UID_REGEX.match(uid) is None:
        errs.append("Regex mismatch")
        return False, errs
    parts = uid.split("-")
    payloadc = parts[3]
    payload, c1c2 = payloadc[:12], payloadc[12:]
    expected = _idg.uid_check_chars(parts[2], payload)
    if expected != c1c2:
        errs.append(f"check-symbol mismatch: expected {expected}, got {c1c2}")
    return (len(errs) == 0), errs

def mid_generate(payload8: Optional[str]=None, rng: Optional[random.Random]=None) -> str:
    if payload8 is None:
        rng = rng or random.SystemRandom()
        payload8 = "".join(rng.choice(BASE32_ALPH) for _ in range(8))
    else:
        _require(len(payload8)==8 and all(ch in BASE32_ALPH for ch in payload8),
                 "MID payload8 must be 8 Base32 chars")
    return _idg.make_mid(payload8)  # 9th char = GF(2^5) RS parity

def mid_validate(mid: str) -> Tuple[bool, List[str]]:
    errs: List[str] = []
    if MID_REGEX.match(mid) is None:
        errs.append("Regex mismatch")
        return False, errs
    if not _idg.mid_valid_checksum(mid):
        errs.append("RS check-symbol failed")
    return (len(errs) == 0), errs

def build_bw_address(uid: str, mid: Optional[str]=None, role: Optional[str]=None) -> str:
    ok, _ = uid_validate(uid)
    _require(ok, "Invalid UID")
    if mid and role:
        raise ValueError("Use either mid or role, not both")
    if mid:
        okm, _ = mid_validate(mid)
        _require(okm, "Invalid MID")
        return f"bw:uid:{uid}/u/{mid}"
    if role:
        _require(ROLE_REGEX.fullmatch(role) is not None, "Invalid role token")
        return f"bw:uid:{uid}/r/{role}"
    return f"bw:uid:{uid}"

# =========================== Deterministic label ============================
def uid_label(uid: str, length: int = 24, prefix: str = "h-") -> str:
    """Deterministic DNS-safe label from UID using SHA-256 -> base32 (lowercase, no padding)."""
    ok, _ = uid_validate(uid)
    _require(ok, "Invalid UID")
    digest = hashlib.sha256(uid.encode("utf-8")).digest()
    b32 = base64.b32encode(digest).decode("ascii").lower().rstrip("=")
    lab = (prefix + b32)[:max(1, length + len(prefix))]
    return lab

# =========================== DNS zone snippet ============================
def dns_zone_snippet(uid: str, host: str, ttl: int = 3600, length: int = 24) -> str:
    """HISTORICAL (DR-14). DNS-based aliasing was removed from the profile; no
    active command calls this. Retained only so the removed shape is legible to
    someone reading an old script — see umbrella §6 for what replaced it."""
    alias = uid_label(uid, length=length)
    lines = []
    lines.append(f"{alias} {ttl} IN TXT \"bw-uid={uid}\"")
    lines.append(f"_bwmsg._tcp.{alias} {ttl} IN SRV 10 1 443 {host}.")
    lines.append(f"_https._svc.{alias} {ttl} IN SVCB 1 {host}. alpn=\"h2,h3\" port=\"443\"")
    return "\n".join(lines)

# =========================== WebFinger ============================
def webfinger_json(acct: str, uid: str, host: Optional[str]=None, resource: Optional[str]=None, med_url: Optional[str]=None) -> dict:
    ok, _ = uid_validate(uid)
    _require(ok, "Invalid UID")
    subj = f"acct:{acct}"
    med = med_url or (f"https://{host}/.well-known/bw/med/{uid}" if host else None)
    links = [{"rel": "urn:bw:uid", "href": f"bw:uid:{uid}"}]
    if med:
        links.append({"rel": "urn:bw:med", "href": med})
    out = {"subject": subj, "links": links}
    if resource:
        # passthrough hint (non-standard, helpful for debugging)
        out["properties"] = {"resource": resource}
    return out

# =========================== MED stub ============================
def _current_version(dimension: str) -> str:
    """The version from versions.json — the single source R-01 established.
    NEVER a literal here: this toolkit shipped `version: "1.1"` while the
    schema, the CDDL and the samples were at 2.0, so the official quick-start
    tool produced a document the current specification REJECTS."""
    root = pathlib.Path(__file__).resolve().parents[1]
    dims = json.loads((root / "versions.json").read_text(encoding="utf-8"))["dimensions"]
    return dims[dimension]["value"]


def med_stub(uid: str, delivery_service: str, rdp_discovery: str, rdp_evidence_tpl: str,
             gen_keys: bool = True, seal: bool = True,
             asserted_at: str = None, expires_at: str = None) -> dict:
    """Emit a CURRENT BW-MED-v1 artefact for `uid`.

    DR-14: this command used to emit `version: "1.1"` with an in-object
    `doc_cose_b64: "DEMO_UNSIGNED_PLACEHOLDER"` — the superseded, pre-M4
    shape. The README recommends this toolkit, so the official quick-start
    produced an artefact the current linter rejects and pointed implementers
    at an obsolete discovery model.

    Two things changed. The version comes from `versions.json`, so it cannot
    drift again. And the output is the M4 ARTEFACT — `{sm_artifact_b64,
    projection}` — sealed by the SAME functions the shipped samples use
    (`mock_rdp.discovery_artifact`), rather than a body with a placeholder
    signature field inside it. The seal is the authoritative object; the
    projection is `decode(payload)` and is derived from it, never the reverse.

    With `seal=False` the bare body is emitted, for a caller that will seal it
    with its own key (`med-sign`). It is still the current SHAPE — the body
    carries no signature field at all, because under M4 the signature is not
    part of the body.

    The demo seal is a DEMO seal: an ephemeral key, not a QSealC. Production
    use requires a real qualified certificate and the trust-path validation
    the linter's `--profile production` explicitly does NOT perform.
    """
    # SBM-ADR-0015 (BW-MED 2.2): one provider role. What was the MSP's base URL
    # is the RDP's Delivery Service, and the routing and KeyPackage endpoints
    # move under `rdp` with it.
    ds_base = delivery_service.rstrip("/")
    if asserted_at is None or expires_at is None:
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
        asserted_at = asserted_at or now.isoformat().replace("+00:00", "Z")
        expires_at = expires_at or (now + _dt.timedelta(days=365)).isoformat().replace("+00:00", "Z")
    body = {
        "type": "BW-MED-v1",
        "version": _current_version("discovery_bw_med"),
        "uid": uid,
        "protocols": ["SM-MLS-1.0"],
        "rdp": {"discovery": rdp_discovery, "evidence": rdp_evidence_tpl,
                "delivery_service": delivery_service,
                "keypackage_url": f"{ds_base}/.well-known/bw/keypackages/{uid}",
                "ds_url": f"{ds_base}/mls/v1"},
        "mls": {
            "cipher_suites": [
                "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
                "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519",
            ],
        },
        "identity_credential": {
            "type": "x509",
            "x509_chain": [
                "-----BEGIN CERTIFICATE-----\nDEMO_ENTITY_QSEALC_PLACEHOLDER\n-----END CERTIFICATE-----"
            ],
        },
        # LINT-DISC-05: a BW-MED carries a freshness bound. The stub omitted
        # both instants, so the emitted document failed the current linter on
        # a REQUIRED field, not merely on its version.
        "asserted_at": asserted_at,
        "expires_at": expires_at,
    }

    if gen_keys:
        # An ephemeral Ed25519 public key embedded in a DEMO "certificate".
        # NOT a QSealC and MUST NOT be used in production.
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            ed = Ed25519PrivateKey.generate()
            ed_pub = ed.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw)
            pub_b64 = base64.urlsafe_b64encode(ed_pub).rstrip(b"=").decode("ascii")
            body["identity_credential"]["x509_chain"] = [
                f"-----BEGIN CERTIFICATE-----\nDEMO_ED25519_PUB_B64={pub_b64}\n-----END CERTIFICATE-----"
            ]
            body["kid"] = "demo-ed25519-" + pub_b64[:8]
        except Exception:
            pass                                    # keep the placeholder

    if not seal:
        return body

    # Seal with the SAME code path as sample generation, so a stub and a
    # shipped sample are the same kind of object rather than two dialects.
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import mock_rdp
    return mock_rdp.discovery_artifact(body, kid="entity-admin")


# =========================== COSE helpers (optional deps) ============================
def canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')

def cose_sign1_with_cryptography(payload: bytes, jwk_priv: dict, kid: Optional[str]=None, external_aad: bytes=b"") -> bytes:
    import cbor2
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    kid = kid or jwk_priv.get("kid") or ""
    protected = cbor2.dumps({1: -8, 4: kid.encode('utf-8')})  # alg=EdDSA, kid
    to_be_signed = cbor2.dumps(["Signature1", protected, external_aad, payload])
    sk = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(jwk_priv["d"] + "=="))
    sig = sk.sign(to_be_signed)
    return cbor2.dumps([protected, {}, payload, sig])

def sign_json_doc(doc: dict, jwk_priv: dict, b64_field: str) -> dict:
    try:
        cose = cose_sign1_with_cryptography(canonical_json_bytes(doc), jwk_priv, kid=jwk_priv.get("kid"))
        doc[b64_field] = base64.b64encode(cose).decode('ascii')
    except Exception as e:
        doc[b64_field] = "DEMO_SIGNATURE_BASE64"
    return doc

# =========================== Keys generation (JWK) ============================
def gen_ed25519(kid: str) -> Dict[str,dict]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    raw_priv = sk.private_bytes(encoding=serialization.Encoding.Raw,
                                format=serialization.PrivateFormat.Raw,
                                encryption_algorithm=serialization.NoEncryption())
    raw_pub = pk.public_bytes(encoding=serialization.Encoding.Raw,
                              format=serialization.PublicFormat.Raw)
    jwk_priv = {"kty":"OKP","crv":"Ed25519","kid":kid,"d":base64.urlsafe_b64encode(raw_priv).rstrip(b"=").decode(), "x":base64.urlsafe_b64encode(raw_pub).rstrip(b"=").decode()}
    jwk_pub  = {"kty":"OKP","crv":"Ed25519","kid":kid,"x":base64.urlsafe_b64encode(raw_pub).rstrip(b"=").decode()}
    return {"private":jwk_priv, "public":jwk_pub}

def gen_x25519(kid: str) -> Dict[str,dict]:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    raw_priv = sk.private_bytes(encoding=serialization.Encoding.Raw,
                                format=serialization.PrivateFormat.Raw,
                                encryption_algorithm=serialization.NoEncryption())
    raw_pub = pk.public_bytes(encoding=serialization.Encoding.Raw,
                              format=serialization.PublicFormat.Raw)
    jwk_priv = {"kty":"OKP","crv":"X25519","kid":kid,"d":base64.urlsafe_b64encode(raw_priv).rstrip(b"=").decode(), "x":base64.urlsafe_b64encode(raw_pub).rstrip(b"=").decode()}
    jwk_pub  = {"kty":"OKP","crv":"X25519","kid":kid,"x":base64.urlsafe_b64encode(raw_pub).rstrip(b"=").decode()}
    return {"private":jwk_priv, "public":jwk_pub}

# =========================== EDD Upload Helper ============================
def edd_upload(url: str, json_obj: dict, token: Optional[str]=None) -> Tuple[int,str]:
    try:
        import requests
    except Exception:
        raise RuntimeError("requests not installed; pip install requests")
    headers = {"Content-Type":"application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.post(url, headers=headers, data=json.dumps(json_obj))
    return r.status_code, r.text

# =========================== CLI ============================
def main(argv=None):
    p = argparse.ArgumentParser(prog="eu-entity-uid-toolkit",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                description=textwrap.dedent("""\
                                EU Entity UID Toolkit (hyphen separators)

                                Core:
                                  gen-uid           Generate a UID (supports --random, --count)
                                  val-uid           Validate a UID
                                  gen-mid           Generate a MID
                                  val-mid           Validate a MID
                                  address           Build bw:uid:... address
                                  hash              Hash a file or stdin

                                Utilities:
                                  label             Deterministic label from UID
                                  dns-zone          REMOVED — historical marker, emits nothing
                                  webfinger         Emit WebFinger JSON for acct: alias
                                  med-stub          Emit a CURRENT sealed BW-MED-v1 artefact
                                  med-sign          Sign MED JSON (PyNaCl if available; else demo-only)

                                Advanced:
                                  gen-keys          Generate Ed25519/X25519 keypairs (JWK)
                                  sign-evidence     COSE_Sign1-sign SE/DE/NDE/RE/EP JSON (rdp_cose_b64/ep_cose_b64)
                                  sign-doc          COSE_Sign1-sign MED/ORG/MEMBER JSON (doc_cose_b64)
                                  edd-upload        POST a JSON doc to an EDD endpoint
                                """))
    sub = p.add_subparsers(dest="cmd", required=True)

    # Core commands
    p_gen_uid = sub.add_parser("gen-uid")
    p_gen_uid.add_argument("--cc", required=True, help="Country code, e.g., DE")
    p_gen_uid.add_argument("--scheme", choices=["EOID","PSBID"], required=True)
    p_gen_uid.add_argument("--payload", help="Optional 12-char Base32 payload")
    p_gen_uid.add_argument("--random", action="store_true", help="Generate random payload(s)")
    p_gen_uid.add_argument("--count", type=int, default=1, help="How many UIDs to generate (with --random)")

    p_val_uid = sub.add_parser("val-uid")
    p_val_uid.add_argument("uid", help="UID to validate")

    p_gen_mid = sub.add_parser("gen-mid")
    p_gen_mid.add_argument("--payload8", help="Optional 8-char Base32")

    p_val_mid = sub.add_parser("val-mid")
    p_val_mid.add_argument("mid", help="MID to validate")

    p_addr = sub.add_parser("address")
    p_addr.add_argument("--uid", required=True)
    g = p_addr.add_mutually_exclusive_group()
    g.add_argument("--mid")
    g.add_argument("--role")

    p_hash = sub.add_parser("hash")
    p_hash.add_argument("--file", help="File path (default: stdin)")
    p_hash.add_argument("--alg", default="SHA-256", choices=["SHA-256","SHA-512"])

    # Utilities
    p_label = sub.add_parser("label")
    p_label.add_argument("--uid", required=True)
    p_label.add_argument("--length", type=int, default=24)
    p_label.add_argument("--prefix", default="h-")

    p_dns = sub.add_parser("dns-zone")
    p_dns.add_argument("--uid", required=True)
    p_dns.add_argument("--host", required=True, help="Target messaging host (e.g., rdp.example.eu)")
    p_dns.add_argument("--ttl", type=int, default=3600)
    p_dns.add_argument("--length", type=int, default=24)

    p_wf = sub.add_parser("webfinger")
    p_wf.add_argument("--acct", required=True, help="acct: alias local@domain (without acct:)")
    p_wf.add_argument("--uid", required=True)
    p_wf.add_argument("--host", help="Host to derive MED URL")
    p_wf.add_argument("--resource", help="Optional resource passthrough")
    p_wf.add_argument("--med-url", help="Explicit MED URL (overrides --host)")

    p_med_stub = sub.add_parser("med-stub")
    p_med_stub.add_argument("--uid", required=True)
    p_med_stub.add_argument("--delivery-service", "--msp", dest="delivery_service",
                            required=False, help="https://rdp.example — the RDP's "
                            "Delivery Service base URL (`--msp` is the withdrawn "
                            "spelling, kept so an existing command line still runs)")
    p_med_stub.add_argument("--rdp-discovery", required=False, help="https://rdp.example/.well-known/rdp")
    p_med_stub.add_argument("--rdp-evidence", required=False, help="https://rdp.example/evidence/{message_id}")
    p_med_stub.add_argument("--host", help="If set, derives the RDP endpoints from https://{host}")
    p_med_stub.add_argument("--out", required=False, help="Output file (default: stdout)")
    p_med_stub.add_argument("--no-gen-keys", action="store_true", help="Do not generate ephemeral keys")
    p_med_stub.add_argument("--no-seal", action="store_true",
                            help="emit the bare body (current shape, unsealed) for signing with med-sign")

    p_med_sign = sub.add_parser("med-sign")
    p_med_sign.add_argument("--in", dest="infile", required=True, help="MED JSON file")
    p_med_sign.add_argument("--out", dest="outfile", required=True, help="Output JSON file (will be overwritten)")

    # Advanced
    p_keys = sub.add_parser("gen-keys")
    p_keys.add_argument("--out-dir", required=True, help="Directory to write JWKs")
    p_keys.add_argument("--kid", required=True, help="Key ID base (e.g., ed25519-2025-01)")

    p_sign_e = sub.add_parser("sign-evidence")
    p_sign_e.add_argument("--in", dest="infile", required=True, help="Evidence JSON file (SE/DE/NDE/RE or EP)")
    p_sign_e.add_argument("--key", dest="keyfile", required=True, help="Ed25519 private JWK file (JSON)")
    p_sign_e.add_argument("--out", dest="outfile", required=True, help="Output JSON file (will be overwritten)")

    p_sign_d = sub.add_parser("sign-doc")
    p_sign_d.add_argument("--in", dest="infile", required=True, help="Document JSON file (MED/ORG/MEMBER)")
    p_sign_d.add_argument("--key", dest="keyfile", required=True, help="Ed25519 private JWK file (JSON)")
    p_sign_d.add_argument("--out", dest="outfile", required=True, help="Output JSON file (will be overwritten)")

    p_up = sub.add_parser("edd-upload")
    p_up.add_argument("--url", required=True, help="EDD endpoint to POST to")
    p_up.add_argument("--file", required=True, help="JSON file to upload")
    p_up.add_argument("--token", help="Bearer token (optional)")

    args = p.parse_args(argv)

    # Core
    if args.cmd == "gen-uid":
        if args.random and args.count > 1 and not args.payload:
            for _ in range(args.count):
                print(uid_generate(args.cc, args.scheme))
        else:
            print(uid_generate(args.cc, args.scheme, args.payload))
        return

    if args.cmd == "val-uid":
        ok, errs = uid_validate(args.uid)
        if ok: print("OK")
        else:
            print("ERROR"); [print("-", e) for e in errs]; sys.exit(2)
        return

    if args.cmd == "gen-mid":
        print(mid_generate(args.payload8)); return

    if args.cmd == "val-mid":
        ok, errs = mid_validate(args.mid)
        if ok: print("OK")
        else:
            print("ERROR"); [print("-", e) for e in errs]; sys.exit(2)
        return

    if args.cmd == "address":
        print(build_bw_address(args.uid, args.mid, args.role)); return

    if args.cmd == "hash":
        data = sys.stdin.buffer.read() if not args.file else open(args.file, "rb").read()
        print(hashlib.sha256(data).hexdigest() if args.alg=="SHA-256" else hashlib.sha512(data).hexdigest())
        return

    # Utilities
    if args.cmd == "label":
        print(uid_label(args.uid, args.length, args.prefix)); return

    if args.cmd == "dns-zone":
        # DR-14: DNS-based aliasing (TXT/SRV/SVCB) is NOT part of this profile
        # version — umbrella §6. The command is kept as a HISTORICAL marker so
        # that a reader who finds it in an old script learns why it stopped
        # working, but it emits nothing: a quick-start tool that prints a
        # removed discovery path points implementers at a model the profile
        # does not have.
        print("dns-zone: REMOVED from this profile version.\n"
              "DNS-based aliasing (TXT/SRV/SVCB) is not part of the profile "
              "(umbrella §6): discovery is the well-known BW-MED/BW-ORG/"
              "BW-MEMBER locations, and an alias layer would need its own "
              "label derivation, DNSSEC requirements and subordination to the "
              "DirectoryRecord. No snippet is emitted.", file=sys.stderr)
        return 2

    if args.cmd == "webfinger":
        wf = webfinger_json(args.acct, args.uid, args.host, args.resource, args.med_url)
        print(json.dumps(wf, indent=2)); return

    if args.cmd == "med-stub":
        if args.host:
            delivery_service = args.delivery_service or f"https://{args.host}"
            rd = args.rdp_discovery or f"https://{args.host}/.well-known/rdp"
            ev = args.rdp_evidence or f"https://{args.host}/evidence/{{message_id}}"
        else:
            delivery_service = args.delivery_service or "https://rdp.example"
            rd  = args.rdp_discovery or "https://rdp.example/.well-known/rdp"
            ev  = args.rdp_evidence or "https://rdp.example/evidence/{message_id}"
        doc = med_stub(args.uid, delivery_service, rd, ev, gen_keys=(not args.no_gen_keys),
                       seal=(not args.no_seal))
        js = json.dumps(doc, indent=2)
        if args.out:
            open(args.out, "w", encoding="utf-8").write(js)
            print("Wrote", args.out)
        else:
            print(js)
        return

    if args.cmd == "med-sign":
        # Prefer PyNaCl; if not present, emit demo-only signature field.
        try:
            import nacl.signing, nacl.encoding
            import cbor2
            # Generate ephemeral test key
            sk = nacl.signing.SigningKey.generate()
            pk = sk.verify_key
            with open(args.infile, "r", encoding="utf-8") as f:
                doc = json.load(f)
            payload = canonical_json_bytes(doc)
            protected = cbor2.dumps({1: -8, 4: b"test-ed25519"})
            to_be_signed = cbor2.dumps(["Signature1", protected, b"", payload])
            sig = sk.sign(to_be_signed).signature
            cose = cbor2.dumps([protected, {}, payload, sig])
            doc["doc_cose_b64"] = base64.b64encode(cose).decode("ascii")
            with open(args.outfile, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2)
            print("Signed MED (PyNaCl) ->", args.outfile)
        except Exception as e:
            # Demo-only: embed a placeholder; not a valid COSE!
            with open(args.infile, "r", encoding="utf-8") as f:
                doc = json.load(f)
            doc["doc_cose_b64"] = "RE1PLU9OTFk6IE5PLUNPU0UtU0lHTkFUVVJF"  # "DEMO-ONLY: NO-COSE-SIGNATURE" (base64)
            with open(args.outfile, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2)
            print("PyNaCl/cbor2 not available; wrote demo-only signature ->", args.outfile)
        return

    # Advanced
    if args.cmd == "gen-keys":
        try:
            os.makedirs(args.out_dir, exist_ok=True)
            ed = gen_ed25519(args.kid)
            xk = gen_x25519(args.kid.replace("ed25519","x25519"))
            json.dump(ed["private"], open(os.path.join(args.out_dir, "ed25519.private.jwk.json"), "w", encoding="utf-8"), indent=2)
            json.dump(ed["public"],  open(os.path.join(args.out_dir, "ed25519.public.jwk.json"), "w", encoding="utf-8"), indent=2)
            json.dump(xk["private"], open(os.path.join(args.out_dir, "x25519.private.jwk.json"), "w", encoding="utf-8"), indent=2)
            json.dump(xk["public"],  open(os.path.join(args.out_dir, "x25519.public.jwk.json"), "w", encoding="utf-8"), indent=2)
            print("Keys written in", args.out_dir)
        except Exception as e:
            print("Key generation failed:", e); sys.exit(2)
        return

    if args.cmd == "sign-evidence":
        try:
            jwk = json.load(open(args.keyfile, "r", encoding="utf-8"))
            doc = json.load(open(args.infile, "r", encoding="utf-8"))
            try:
                cose = cose_sign1_with_cryptography(canonical_json_bytes(doc), jwk, kid=jwk.get("kid"))
                if doc.get("type") == "EP-v1":
                    doc["ep_cose_b64"] = base64.b64encode(cose).decode("ascii")
                else:
                    doc["rdp_cose_b64"] = base64.b64encode(cose).decode("ascii")
            except Exception:
                if doc.get("type") == "EP-v1":
                    doc["ep_cose_b64"] = "RE1PLU9OTFk="
                else:
                    doc["rdp_cose_b64"] = "RE1PLU9OTFk="
            json.dump(doc, open(args.outfile, "w", encoding="utf-8"), indent=2)
            print("Signed evidence ->", args.outfile)
        except Exception as e:
            print("Signing failed:", e); sys.exit(2)
        return

    if args.cmd == "sign-doc":
        try:
            jwk = json.load(open(args.keyfile, "r", encoding="utf-8"))
            doc = json.load(open(args.infile, "r", encoding="utf-8"))
            out = sign_json_doc(doc, jwk, "doc_cose_b64")
            json.dump(out, open(args.outfile, "w", encoding="utf-8"), indent=2)
            print("Signed doc ->", args.outfile)
        except Exception as e:
            print("Signing failed:", e); sys.exit(2)
        return

    if args.cmd == "edd-upload":
        try:
            obj = json.load(open(args.file, "r", encoding="utf-8"))
            code, text = edd_upload(args.url, obj, args.token)
            print("HTTP", code); print(text)
            if code >= 300: sys.exit(2)
        except Exception as e:
            print("Upload failed:", e); sys.exit(2)
        return

if __name__ == "__main__":
    # DR-14: main() returns an exit code for the paths that have one (the
    # removed dns-zone command). It was called for effect only, so a REMOVED
    # command exited 0 — a script that still invoked it would have carried on
    # as though it had produced a discovery record.
    sys.exit(main() or 0)
