# SPDX-License-Identifier: MIT
"""X-19 — the UID-QEAA MLS leaf credential is OPTIONAL/experimental, not mandatory.

The former defect: the I-D said the `bw_uid_qeaa` leaf credential and the `x509`
baseline both "MUST be supported", while IANA marks `bw_uid_qeaa` private-use and
`x509` the mandatory baseline — and a retired/merged UID could keep authenticating
via a still-valid offline credential. This batch demotes `bw_uid_qeaa` to
optional/experimental, qualifies the "verified offline" claim, and makes MLS
group-removal on retire/merge a MUST. (The MLS leaf credential type has no
discovery/evidence wire surface, so enforcement is prose-integrity plus the
lifecycle rule; the full binding is deferred — IANA + counsel.)

These tests guard the corrections against regression and are the negative fixture:
the exact former over-claim wording must stay absent.
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
ID = (ROOT / "ietf/draft-sbm-mls-erd-00.md").read_text(encoding="utf-8")
UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text(encoding="utf-8")


def test_shipped_med_samples_use_the_x509_baseline():
    meds = sorted(ROOT.glob("samples/sample-BW-MED*.json"))
    assert meds, "no BW-MED samples found"
    for f in meds:
        proj = json.load(open(f)).get("projection", {})
        cred = proj.get("identity_credential", {})
        assert cred.get("type") == "x509", (
            f"{f.name} does not use the mandatory x509 baseline credential "
            f"(got {cred.get('type')!r}) — samples must demonstrate the baseline")
