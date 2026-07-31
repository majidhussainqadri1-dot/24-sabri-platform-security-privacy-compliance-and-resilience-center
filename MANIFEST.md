# Source Manifest

Foundation corrective candidate 0.25.1 contains only public, sanitized source and documentation.

Sensitive operational material is intentionally excluded.

- Root governance: `README.md`, `SECURITY.md`, `docs/`
- WordPress plugin: `plugin/sabri-security-center/`
- Private findings triage: `plugin/sabri-security-center/src/Admin/FindingAdmin.php`
- Foundation contract tests: `tests/`
- Runtime integration guard: `tests/runtime.php`
- Reproducible package tooling: `tools/build-release.sh`
- Continuous integration: `.github/workflows/ci.yml`
- Generated source checksums: `CHECKSUMS.sha256`

The checksum manifest deliberately excludes itself and the workflow self-hash from verification, and excludes generated build artifacts.
