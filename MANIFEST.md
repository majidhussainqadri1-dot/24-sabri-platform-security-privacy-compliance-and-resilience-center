# Source Manifest

Foundation corrective candidate 0.25.2 contains only public, sanitized source and documentation.

Sensitive operational material is intentionally excluded.

- Root governance: `README.md`, `SECURITY.md`, `docs/`
- WordPress plugin: `plugin/sabri-security-center/`
- Private findings triage: `plugin/sabri-security-center/src/Admin/FindingAdmin.php`
- Scoped submenu asset loader: `plugin/sabri-security-center/src/Admin/AssetLoader.php`
- Private privacy-request operations: `plugin/sabri-security-center/src/Admin/PrivacyAdmin.php`
- Durable privacy metadata and module outcomes: `plugin/sabri-security-center/src/Storage/PrivacyRequestRepository.php`
- Privacy dispatch, callback and retry contracts: `plugin/sabri-security-center/src/Privacy/RequestDispatcher.php`
- Stale-dispatch recovery scanner: `plugin/sabri-security-center/src/Privacy/RecoveryManager.php`
- Foundation contract tests: `tests/`
- Runtime integration guard: `tests/runtime.php`
- Privacy callback, retry and stale-recovery guard: `tests/privacy.php`
- Privacy recovery scheduling guard: `tests/privacy-recovery.php`
- Scoped admin asset guard: `tests/admin-assets.php`
- Reproducible package tooling: `tools/build-release.sh`
- Continuous integration: `.github/workflows/ci.yml`
- Generated source checksums: `CHECKSUMS.sha256`

The checksum manifest deliberately excludes itself and the workflow self-hash from verification, and excludes generated build artifacts.
