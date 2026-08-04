# File 24 0.99.0 — Migration and Rollback Guide

- Installation and upgrades are additive and idempotent.
- Schema version remains `0.25.5`; logical registry additions use bounded namespaced options and require no destructive table migration.
- Activation snapshots schedules, capabilities and plugin-owned state; partial activation attempts compensate newly introduced schedules/capabilities.
- Upgrade locks have bounded leases and prevent downgrade/overlapping migration.
- Rollback is limited to plugin-owned code/configuration. Native companion data and WordPress core content are never deleted by File 24 rollback.
- Default uninstall is non-destructive. Purge requires a separately authorized, evidenced operation.
- Before staging upgrade: verified backup; after upgrade: schema/index verification, complete tests and module manifest reconciliation.
