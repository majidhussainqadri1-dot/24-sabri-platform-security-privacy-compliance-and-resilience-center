# File 24 — Review and Correction Cycle 87

**Foundation target:** 0.28.0
**Defect:** F24-D121
**Method:** fresh independent adversarial review followed immediately by correction, regression testing and evidence update

## Review finding

Upgrade ownership was not refreshed around long schema operations.

## Correction applied at the end of this review

Upgrade now refreshes its atomic lease before and after schema installation.

## Verification

- Dedicated regression boundary: `tests/cycle87-upgrade-lock-lease-refresh.php`
- Complete historical and current PHP regression/adversarial suite is required after this correction.
- Source checksum, secret scan, PHP 8.0/8.3 compatibility and deterministic package gates remain mandatory.

## Cycle decision

The identified defect was corrected within Cycle 87; the cycle was not closed on discovery alone. No claim about Hostinger staging, live providers, legal applicability, penetration testing or production operation is made by this repository-level result.
