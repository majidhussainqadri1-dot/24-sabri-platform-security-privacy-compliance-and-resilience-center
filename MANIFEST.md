# Source Manifest

Foundation corrective candidate 0.25.1 contains only public, sanitized source and documentation.

Sensitive operational material is intentionally excluded.

- Root governance: `README.md`, `SECURITY.md`, `docs/`
- WordPress plugin: `plugin/sabri-security-center/`
- Foundation contract tests: `tests/`
- Reproducible package tooling: `tools/build-release.sh`
- Continuous integration: `.github/workflows/ci.yml`
- Generated source checksums: `CHECKSUMS.sha256`

The checksum manifest deliberately excludes itself and generated build artifacts.
