
PY ?= python3

.PHONY: help preflight test schema schema-smoke lint lint-demo cddl-check cddl-check-lite doc-lint versions lint-catalogue rule-ownership adr-index conformance conformance-lite regen-samples id reuse licenses-report dev-tools

help:
	@echo "Targets:"
	@echo "  make preflight     - fail if a required test dependency is missing"
	@echo "  make test          - dependency preflight, then the full pytest suite"
	@echo "  make schema-smoke  - validate sample JSONs against JSON Schemas"
	@echo "  make lint          - semantic conformance validators (evidence + discovery + cross-document bundle)"
	@echo "  make lint-demo     - the linters in --verify-demo mode (crypto-verify every seal vs the published demo keys)"
	@echo "  make versions      - R-01: check every artefact's version agrees with versions.json (the single source of truth)"
	@echo "  make lint-catalogue - X-20: render + check the normative lint catalogue (docs/lint-catalogue.{json,md})"
	@echo "  make rule-ownership - X-34: one normative owner per rule + interface-count check (docs/rule-ownership.{json,md})"
	@echo "  make adr-index     - architecture decision records well-formed + docs/decisions-index.md current (generated from docs/adr/)"
	@echo "  make conformance   - THE conformance bar (requires the cddl tool): versions + lint-catalogue + rule-ownership + preflight+test + schema-smoke + lint + lint-demo + cddl-check + openapi-validate + doc-lint + reuse"
	@echo "  make conformance-lite - same gates but tolerates a missing cddl tool (for contributors without a Rust toolchain; NOT the release bar)"
	@echo "  make id            - lightweight structure check of the Internet-Draft (full kramdown-rfc+xml2rfc render in the render-id CI job)"
	@echo "  make dev-tools     - install the dev/CI tooling (reuse, pip-licenses) from requirements-dev.txt"
	@echo "  make reuse         - REUSE/SPDX licensing compliance check (make dev-tools first)"
	@echo "  make licenses-report - third-party dependency license report (pip install pip-licenses)"
	@echo "  make regen-samples - reseal samples with real COSE + DER timestamp tokens"

preflight:
	$(PY) scripts/check_env.py

# The canonical test run: preflight FAILS (does not skip) on a missing dependency.
test: preflight
	$(PY) -m pytest -q

# Alias for discoverability.
schema: schema-smoke

schema-smoke:
	$(PY) scripts/schema_smoke.py

lint:
	$(PY) scripts/evidence_lint.py samples/sample-*.json
	$(PY) scripts/discovery_lint.py samples/sample-BW-*.json
	$(PY) scripts/bundle_lint.py --allow-incomplete --trust-store samples/trust-store.demo.json samples/bundle.default.manifest.json samples/bundle.scoped.manifest.json samples/bundle.federated.manifest.json samples/bundle.walletsig.manifest.json

# R6-W1: --allow-incomplete. The shipped bundles CANNOT prove maximality —
# nothing in a retained prefix can exclude a successor the claimant did not
# supply — so the bar accepts INCOMPLETE and still refuses every violation.
# The [GAP] lines print either way; the flag changes the exit code, not the
# verdict. A deployment with an authenticated head should not pass it.

# The linters with cryptographic seal verification against the PUBLISHED DEMO
# keys (condition (5) of the umbrella par. 9.4 definition, demo scope).
# bundle_lint has no seal of its own to verify; it re-runs for coherence.
lint-demo:
	$(PY) scripts/evidence_lint.py --verify-demo samples/sample-*.json
	$(PY) scripts/discovery_lint.py --verify-demo samples/sample-BW-*.json
	$(PY) scripts/bundle_lint.py --allow-incomplete --trust-store samples/trust-store.demo.json samples/bundle.default.manifest.json samples/bundle.scoped.manifest.json samples/bundle.federated.manifest.json samples/bundle.walletsig.manifest.json

# THE conformance bar (ninth review, P3): everything the repo can check.
# CI runs these gates (the test job: make test / schema-smoke / lint / lint-demo /
# cddl-check / doc-lint with a PINNED `cddl` tool, fail-closed under CI; the reuse
# job: reuse lint). 'make lint' alone is the structural subset — see README
# # Conformance.
conformance: versions lint-catalogue rule-ownership adr-index test schema-smoke lint lint-demo cddl-check openapi-validate doc-lint reuse
	@echo "CONFORMANCE: all gates green (versions, lint-catalogue, rule-ownership, adr-index, preflight+test, schema-smoke, lint, lint-demo, cddl-check, openapi-validate, doc-lint, reuse)"

# N-04: the FULL bar requires the `cddl` tool (cddl-check above is fail-closed).
# conformance-lite is the escape hatch for contributors without a Rust toolchain:
# identical gates, but cddl-check-lite TOLERATES a missing `cddl` (prints [skip]).
# It is NOT the conformance bar — CI and releases use `make conformance`.
conformance-lite: versions lint-catalogue rule-ownership adr-index test schema-smoke lint lint-demo cddl-check-lite openapi-validate doc-lint reuse
	@echo "CONFORMANCE-LITE: gates green — but cddl-check may have SKIPPED (install cddl and run 'make conformance' for the full fail-closed bar)"

# DR-09: meta-validate every published OpenAPI contract with a PINNED
# third-party validator, offline. The bar had no such step, which is how two
# structurally invalid documents shipped green.
openapi-validate:
	@$(PY) scripts/openapi_validate.py

cddl-check-lite:
	@$(PY) scripts/cddl_check.py; s=$$?; if [ $$s -eq 3 ]; then echo "[skip] cddl absent — conformance-lite tolerates it; the full bar (make conformance) does not"; elif [ $$s -ne 0 ]; then exit $$s; fi
	$(PY) scripts/cddl_embedded.py

# R-01 version matrix: one machine-readable manifest (versions.json) is the single
# source of truth; this fails if any schema const/title, CDDL body, sample, README
# cell, OpenAPI or TS revision drifts from it. Also enforced in pytest
# (tests/test_version_matrix.py).
versions:
	$(PY) scripts/version_manifest.py
	$(PY) scripts/schema_shapes.py
	$(PY) scripts/contract_shapes.py
	$(PY) scripts/resolved_shapes.py
	$(PY) scripts/rdp_identity_inventory.py
	$(PY) scripts/response_conformance.py
	$(PY) scripts/project_counts.py

# X-20 normative lint catalogue: docs/lint-catalogue.json is the single source of
# truth for every LINT-* rule; this checks that every rule the tools emit is
# catalogued (no undocumented rule), no phantom entries, and the rendered
# docs/lint-catalogue.md is current. Also enforced in pytest
# (tests/test_lint_catalogue.py).
lint-catalogue:
	$(PY) scripts/lint_catalogue.py

# X-34 rule-ownership inventory: docs/rule-ownership.json assigns each normative
# rule family one owning document; this fails if the owner stops stating a rule,
# a non-owner document carries a bare normative restatement, or the I-D's
# deployment-defined-interface count disagrees with the bullets it lists. Also
# enforced in pytest (tests/test_rule_ownership.py).
rule-ownership:
	$(PY) scripts/rule_ownership.py

# Architecture decision records: docs/adr/SBM-ADR-NNNN.md are the records and
# docs/decisions-index.md is GENERATED from their fields, the way the lint
# catalogue is generated from its rule definitions — one authority, not two
# hand-kept copies. This fails on a malformed record or a stale index. Also
# enforced in pytest (tests/test_adr_index.py).
adr-index:
	$(PY) scripts/adr_index.py

# C3 non-divergence gate (M4/CDDL): every sample's authoritative CBOR artefact
# AND its body validate against cddl/sm-mls-erd.cddl (the projection is
# schema-validated by schema-smoke). Requires the `cddl` tool. N-04: the tool is
# MANDATORY for `make conformance` — if it is absent, cddl_check.py exits 3 (or 1
# under CI) and that non-zero propagates, so `conformance` FAILS rather than
# silently reporting green. Contributors without a Rust toolchain use
# `make conformance-lite`, which tolerates the skip.
cddl-check:
	$(PY) scripts/cddl_check.py
	$(PY) scripts/cddl_embedded.py

# Prose regression guard (wired into conformance — this comment said it was not,
# while the `conformance` target above included it; D10-05): fails if a document
# reintroduces a pre-inversion mechanism as current — JCS / RFC 8785 as the
# canonicalisation, or the removed `*_cose_b64` document fields. Guards the prose,
# not the machine-checkable layer. Allow-list in the script; the octet-authoritative
# model: docs/OCTET_AUTHORITATIVE_DESIGN.md.
doc-lint:
	$(PY) scripts/doc_lint.py

id:
	$(PY) scripts/build_id.py ietf/draft-sbm-mls-erd-00.md

# Install the developer/CI tooling (reuse, pip-licenses). The I-D render
# toolchain (kramdown-rfc, xml2rfc) is Ruby/CI-only, not installed here.
dev-tools:
	$(PY) -m pip install -r requirements-dev.txt

reuse:
	$(PY) -m reuse lint

# Informational: not a gate. Lists the licenses of the installed dependencies.
licenses-report:
	$(PY) -m piplicenses --format=markdown --with-urls --order=license 2>/dev/null || \
	  echo "pip-licenses not installed — run: pip install pip-licenses"

regen-samples:
	$(PY) scripts/regen_samples.py
