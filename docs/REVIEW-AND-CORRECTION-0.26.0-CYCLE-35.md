# Cycle 35 — Governance Request Lease Review and Correction

**Review mode:** fresh duplicate-admission lease-loss review

## Defect F24-D069

Governance request admission acquired a subject-scoped lock but did not renew or revalidate ownership around the canonical insert. If the lease expired or was reclaimed during the database operation, the original worker could continue to audit and accept a request while another worker admitted a duplicate request for the same subject.

## Correction

- The lease is renewed immediately before canonical insertion.
- It is renewed again after the insert and before audit admission.
- Loss after insert triggers an exact rollback of the worker’s own pending row.
- Rollback failure creates a governance audit gap.
- Lock-release failure now emits an explicit bounded action.
- Canonical insertion must report exactly one row.

## Verification

`tests/cycle35-governance-request-lease.php` simulates lock theft during insert and proves fail-closed rollback, absence of false success evidence, absence of false gaps after successful rollback, and normal exactly-once admission.
