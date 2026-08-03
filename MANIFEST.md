# Source Manifest

Foundation eight-round corrective candidate 0.25.9 contains public, sanitized source and documentation only. Sensitive operational material is intentionally excluded.

- Root governance: `README.md`, `SECURITY.md`, `docs/`
- WordPress plugin: `plugin/sabri-security-center/`
- Atomic coordination primitive: `plugin/sabri-security-center/src/Support/AtomicOptionLock.php`
- Bounded audit-gap registry: `plugin/sabri-security-center/src/Storage/AuditGapStore.php`
- Verified privacy orchestration: `plugin/sabri-security-center/src/Privacy/`
- Fail-closed activation, upgrade and repair: `plugin/sabri-security-center/src/Activation.php`, `plugin/sabri-security-center/src/UpgradeManager.php`, `plugin/sabri-security-center/src/System/Repair.php`
- Collision-resistant module registry: `plugin/sabri-security-center/src/Registry/ModuleRegistry.php`
- Cycles 22–29 review records: `docs/REVIEW-AND-CORRECTION-0.25.9-CYCLE-22.md` through `docs/REVIEW-AND-CORRECTION-0.25.9-CYCLE-29.md`
- Eight-round consolidated summary: `docs/EIGHT-ROUND-REVIEW-SUMMARY-0.25.9.md`
- Current requirements traceability: `docs/REQUIREMENTS-TRACEABILITY-0.25.9.md`
- Current external evidence gates: `docs/KNOWN-LIMITATIONS-0.25.9.md`
- Current reviewed release receipt: `docs/RELEASE-RECEIPT-0.25.9.md`
- Cycle 17 post-CI illuminative review: `docs/ILLUMINATIVE-REVIEW-AND-CORRECTION-0.25.7-CYCLE-17.md`
- Historical Cycle 18–21 evidence remains under the 0.25.8 document names.
- Migration and rollback boundaries: `docs/MIGRATION.md`, `docs/ROLLBACK.md`
- Foundation and adversarial contract tests: `tests/`
- SPDX software bill of materials: `plugin/sabri-security-center/SBOM.spdx.json`
- License inventory: `plugin/sabri-security-center/LICENSES.md`
- Reproducible package tooling: `tools/build-release.sh`
- Continuous integration: `.github/workflows/ci.yml`
- Generated source checksums: `CHECKSUMS.sha256`

The checksum manifest excludes itself from generation and excludes the workflow self-hash from verification. Generated build artifacts and `.git` metadata are not part of the source manifest.
