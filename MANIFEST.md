# Source Manifest

Foundation four-round corrective candidate 0.25.8 contains only public, sanitized source and documentation.

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
- Cycle 12 review record: `docs/REVIEW-AND-CORRECTION-0.25.7-CYCLE-12.md`
- Cycle 13 review/correction record: `docs/REVIEW-AND-CORRECTION-0.25.7-CYCLE-13.md`
- Cycle 14 extraordinary fresh review: `docs/EXTRAORDINARY-REVIEW-AND-CORRECTION-0.25.7-CYCLE-14.md`
- Cycle 15 requested Alhami/Illuminative review: `docs/ILLUMINATIVE-REVIEW-AND-CORRECTION-0.25.7-CYCLE-15.md`
- Cycle 16 final closure review: `docs/FINAL-CLOSURE-REVIEW-AND-CORRECTION-0.25.7-CYCLE-16.md`
- Cycle 17 post-CI illuminative review: `docs/ILLUMINATIVE-REVIEW-AND-CORRECTION-0.25.7-CYCLE-17.md`
- Cycle 18 retention-concurrency review: `docs/REVIEW-AND-CORRECTION-0.25.8-CYCLE-18.md`
- Cycle 19 privacy-retry safety review: `docs/REVIEW-AND-CORRECTION-0.25.8-CYCLE-19.md`
- Cycle 20 audit-gap concurrency review: `docs/REVIEW-AND-CORRECTION-0.25.8-CYCLE-20.md`
- Cycle 21 final four-round closure: `docs/REVIEW-AND-CORRECTION-0.25.8-CYCLE-21.md`
- Consolidated four-round summary: `docs/FOUR-ROUND-REVIEW-SUMMARY-0.25.8.md`
- Bounded audit-gap registry: `plugin/sabri-security-center/src/Storage/AuditGapStore.php`
- Current requirements traceability: `docs/REQUIREMENTS-TRACEABILITY-0.25.8.md`
- Historical 0.25.7 traceability: `docs/REQUIREMENTS-TRACEABILITY-0.25.7.md`
- Current known external evidence gates: `docs/KNOWN-LIMITATIONS-0.25.8.md`
- Historical 0.25.7 limitations: `docs/KNOWN-LIMITATIONS-0.25.7.md`
- Current reviewed release receipt: `docs/RELEASE-RECEIPT-0.25.8.md`
- Historical 0.25.7 receipt: `docs/RELEASE-RECEIPT-0.25.7.md`
- Migration and rollback boundaries: `docs/MIGRATION.md`, `docs/ROLLBACK.md`
- Foundation and adversarial contract tests: `tests/`
- SPDX software bill of materials: `plugin/sabri-security-center/SBOM.spdx.json`
- License inventory: `plugin/sabri-security-center/LICENSES.md`
- Reproducible package tooling: `tools/build-release.sh`
- Continuous integration: `.github/workflows/ci.yml`
- Generated source checksums: `CHECKSUMS.sha256`

The checksum manifest excludes itself and the workflow self-hash from verification, and excludes generated build artifacts.
