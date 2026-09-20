<!-- SPDX-FileCopyrightText: 2025-2026 Paolo De Rosa and contributors -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Third-party notices

The reference code and tooling in this repository depend on third-party open-source packages. **Those packages remain under their own licenses**; this repository does not relicense them. None is redistributed here — they are installed from their upstream package registries (PyPI, RubyGems) at build/test time. This file is informational; regenerate an up-to-date report of the installed set with `make licenses-report` (`pip install pip-licenses`).

## Runtime / test dependencies (`scripts/requirements.txt`)

| Package | License |
|---------|---------|
| `jsonschema` | MIT |
| `pytest` | MIT |
| `cbor2` | MIT |
| `pyyaml` | MIT |
| `flask` (with `Jinja2`, `Werkzeug`) | BSD-3-Clause |
| `pynacl` | Apache-2.0 |
| `cryptography` (optional) | Apache-2.0 OR BSD-3-Clause |
| `requests` (optional) | Apache-2.0 |

## Development / CI-only tooling (not required to use the artefacts)

| Tool | Purpose | License |
|------|---------|---------|
| `xml2rfc` | Internet-Draft render (`render-id` CI job) | BSD-3-Clause |
| `kramdown-rfc` (RubyGem) | Internet-Draft render | MIT |
| `reuse` | REUSE/SPDX compliance (`make reuse`, CI) | Apache-2.0 (and others) |
| `pip-licenses` | this report (`make licenses-report`) | MIT |

## Referenced standards (not code dependencies)

The Specification references external standards — IETF MLS (RFC 9420), COSE (RFC 9052), JCS (RFC 8785), RFC 3161 / ETSI EN 319 422, the ETSI EN 319 5xx series, and others — which are governed by their own IPR policies (see `IPR.md` §3). Referencing a standard does not incorporate its text into this repository.
