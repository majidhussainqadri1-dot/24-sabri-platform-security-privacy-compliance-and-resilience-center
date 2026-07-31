# Source Manifest

Foundation corrective candidate 0.25.4 contains only public, sanitized source and documentation.

Sensitive operational material is intentionally excluded.

- Root governance: `README.md`, `SECURITY.md`, `docs/`
- WordPress plugin: `plugin/sabri-security-center/`
- Private findings triage: `plugin/sabri-security-center/src/Admin/FindingAdmin.php`
- Scoped submenu asset loader: `plugin/sabri-security-center/src/Admin/AssetLoader.php`
- Verified privacy-request operations: `plugin/sabri-security-center/src/Admin/VerifiedPrivacyAdmin.php`
- Durable privacy metadata and module outcomes: `plugin/sabri-security-center/src/Storage/PrivacyRequestRepository.php`
- Bounded privacy verification evidence: `plugin/sabri-security-center/src/Privacy/PrivacyVerificationStore.php`
- Privacy verification, dispatch, callback and retry policy: `plugin/sabri-security-center/src/Privacy/PrivacyRequestPolicy.php`, `plugin/sabri-security-center/src/Privacy/RequestDispatcher.php`
- Stale-dispatch recovery scanner: `plugin/sabri-security-center/src/Privacy/RecoveryManager.php`
- Cycle 7 review record: `docs/REVIEW-AND-CORRECTION-0.25.4-CYCLE-7.md`
- Foundation contract tests: `tests/`
- Runtime integration guard: `tests/runtime.php`
- Privacy callback, verification, retry and stale-recovery guards: `tests/privacy.php`, `tests/privacy-policy.php`
- Privacy recovery scheduling guard: `tests/privacy-recovery.php`
- Scoped admin asset guard: `tests/admin-assets.php`
- Reproducible package tooling: `tools/build-release.sh`
- Continuous integration: `.github/workflows/ci.yml`
- Generated source checksums: `CHECKSUMS.sha256`

The checksum manifest deliberately excludes itself and the workflow self-hash from verification, and excludes generated build artifacts.
