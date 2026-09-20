# SPDX-License-Identifier: MIT
"""X-09 — the EN 319 522 interoperability claim is scoped; the matrix exists.

Former defect: the TS required the cross-provider relay to "be compatible
with the EN 319 522-2 Common Services Interface and EN 319 522-3 formats"
while supplying no mapping from the SM-MLS dCBOR/COSE objects, no gateway
rules and no transformation model — a normative target not implementable
from the repository.

Chosen resolution (approved): the claim is SCOPED to homogeneous SM-MLS
federations (both RDPs run this profile — the B.x objects and the X-30
table ARE the format), heterogeneous interoperation is explicitly NOT
claimed (future work with four named prerequisites), and the normative
claim matrix states exactly which combinations are implemented,
CAB-confirmable or future work — the acceptance criterion verbatim.
"""
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dl = _load("doc_lint", "doc_lint.py")
TS = (ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md").read_text()
FLAT = " ".join(TS.split()).replace("**", "").replace("`", "")


def test_the_unscoped_compatibility_claim_is_gone_and_forbidden():
    assert "relay shall be compatible with the EN 319 522-2" not in TS
    former = ("the relay shall be compatible with the EN 319 522-2 Common "
              "Services Interface (clause 9) and EN 319 522-3 formats.")
    assert any(p.search(former) for p in dl.FORBIDDEN)


def test_the_claim_is_scoped_to_homogeneous_federations():
    assert "scoped to homogeneous SM-MLS federations" in FLAT
    assert "ARE the interchange format" in FLAT


def test_heterogeneous_interoperation_is_explicitly_not_claimed():
    assert "is NOT claimed by this document" in FLAT
    for prereq in ("issuer attribution across the gateway boundary",
                   "event/reason translation",
                   "qualified-timestamp preservation",
                   "CE issuance for the transformation"):
        assert prereq in FLAT, prereq


def test_the_claim_matrix_has_three_rows_one_status_each():
    assert "Interoperability claim matrix (normative)" in TS
    rows = [l for l in TS.splitlines()
            if l.startswith("| Single-provider")
            or l.startswith("| Four-corner homogeneous")
            or l.startswith("| Heterogeneous via CSI")]
    assert len(rows) == 3
    statuses = [r.split("|")[2] for r in rows]
    assert "Implemented" in statuses[0]
    assert "CAB-confirmation pending" in statuses[1]
    assert "NOT claimed" in statuses[2]
    for s in statuses:
        # exactly one status keyword per row — no hedged double claims
        assert sum(k in s for k in ("Implemented", "pending", "NOT claimed")) == 1, s


def test_claims_beyond_a_row_are_non_conformant():
    assert "shall not claim any combination beyond its row" in FLAT
    assert "claims beyond a row's status are non-conformant" in FLAT
