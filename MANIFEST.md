# Source Manifest

Foundation corrective candidate 0.25.6 contains only public, sanitized source and documentation.

Sensitive operational material is intentionally excluded.

- Root governance: `README.md`, `SECURITY.md`, `docs/`
- WordPress plugin: `plugin/sabri-security-center/`
- Private findings triage: `plugin/sabri-security-center/src/Admin/FindingAdmin.php`
- Verified privacy operations: `plugin/sabri-security-center/src/Admin/VerifiedPrivacyAdmin.php`
- Private assurance operations: `plugin/sabri-security-center/src/Admin/AssuranceAdmin.php`
- Compliance/vendor/backup metadata: `plugin/sabri-security-center/src/Storage/AssuranceRepository.php`
- Privacy verification and orchestration: `plugin/sabri-security-center/src/Privacy/`
- Fail-closed activation, upgrade and repair: `plugin/sabri-security-center/src/Activation.php`, `plugin/sabri-security-center/src/UpgradeManager.php`, `plugin/sabri-security-center/src/System/Repair.php`
- Collision-resistant module registry: `plugin/sabri-security-center/src/Registry/ModuleRegistry.php`
- Cycle 9 review record: `docs/REVIEW-AND-CORRECTION-0.25.6-CYCLE-9.md`
- Migration and rollback boundaries: `docs/MIGRATION.md`, `docs/ROLLBACK.md`
- Foundation and adversarial contract tests: `tests/`
- SPDX software bill of materials: `plugin/sabri-security-center/SBOM.spdx.json`
- License inventory: `plugin/sabri-security-center/LICENSES.md`
- Reproducible package tooling: `tools/build-release.sh`
- Continuous integration: `.github/workflows/ci.yml`
- Generated source checksums: `CHECKSUMS.sha256`

The checksum manifest excludes itself and the workflow self-hash from verification, and excludes generated build artifacts.
