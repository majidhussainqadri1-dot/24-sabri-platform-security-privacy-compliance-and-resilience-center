# Migration — 0.25.9 to 0.26.0

1. Create and verify a disposable Hostinger staging backup; store only its opaque evidence reference in File 24.
2. Confirm no active upgrade, retention, governance, audit-gap, security-state or control-key owner lock is in use.
3. Install 0.26.0 over 0.25.9 on staging only.
4. Schema remains 0.25.5 because this release changes runtime integrity and evidence handling, not table shape.
5. Verify activation/runtime health, capabilities, retention and privacy-recovery schedules.
6. Exercise expired-lock refresh rejection and lock-token generation failure.
7. Exercise exact audit insert evidence, audit-gap capacity exhaustion and strict absolute timestamp rejection.
8. Exercise governance request lease loss, governance gap contention and expiry at approval commit.
9. Exercise same-status risk/finding concurrency and exact audit rollback mismatch behavior.
10. Exercise assurance audit rollback with zero-row delete and central gap registration.
11. Exercise verifier impersonation, missing privacy capability, authenticated-session self-binding and native verification confirmation.
12. Run PHP 8.0/8.3 CI, complete checksums, deterministic double build and ZIP integrity.
13. Complete real File 00/File 20 adapters, browser/accessibility, restore, penetration and operational acceptance gates before production.

No raw personal, clinical, vendor, forensic, credential or backup-location data is migrated by File 24.
