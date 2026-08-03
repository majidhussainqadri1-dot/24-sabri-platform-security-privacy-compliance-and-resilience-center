# Rollback — Foundation 0.27.0

- Take a verified backup before deployment and keep the 0.26.0 artifact/hash.
- Use File 20 Safe Mode or native module restrictions during rollback where required.
- Do not delete File 24 evidence tables, audit gaps, privacy records, controls or assurance records.
- Re-run schema, capability, schedule, integration and security-state checks after code rollback.
- Treat inability of older code to interpret 0.27.0 evidence bindings as a release blocker, not approval.
- Reconcile gaps only through the authorized capability-, step-up-, evidence- and audit-gated workflow.
- Record rollback reason, operator, package hashes, affected records, smoke tests and Founder decision.
