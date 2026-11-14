# File 24 — V12.3 private Live Reality Freeze operator handoff

**This is an authorization and evidence-capture guide, not a live verification receipt.**

## Current access boundary (14 November 2026)

- WordPress.com/Jetpack lists `https://www.sabrihomeopathy.com` but reports `site_disconnected`; site-scoped tools are unavailable.
- WPVibe has no registered connected site; its attempt for the supplied host returned HTTP 530. This does **not** identify a root cause, prove origin/WAF failure, or establish that the user-facing website is down.
- No deployed File 24 source, WordPress database, `wp_options`, migration state, installed checksum, WAF configuration, MFA evidence, or real restore receipt was inspected.
- Never label the repository's `0.99.0` runtime and `0.25.5` schema as production versions without independent deployed evidence.

## Authorized private collection

A suitably authorized Hostinger operator can run `tools/live-reality-freeze-readonly.sh` **locally on the host**, only after checking its source and ensuring shell/WP-CLI access is approved. The tool is not run automatically by the WordPress plugin or GitHub Actions.

Example (paths are illustrative, NOT assumptions about deployed paths):

```bash
bash -n tools/live-reality-freeze-readonly.sh
bash tools/live-reality-freeze-readonly.sh --authorized-read-only \
  /absolute/path/to/wordpress \
  /absolute/path/to/wp-content/plugins/sabri-security-center
```

The command reads only core/plugin/theme metadata, a small allowlisted set of File24 version options, the **sanitized upgrade error code**, an upgrade-lock *presence flag* (never lock contents), File24-only cron hook/schedule names, DB-server/schema **metadata**, table/column/index shapes, approximate table counts, and installed source-code hashes. This process intentionally does **not** extract raw table rows, patient charts, passwords, secrets, WP configuration, private logs, cron payloads or raw serialized error options. The output directory is generated under private temp storage with owner-only permissions by `mktemp` and `umask 077`. It is not a full migration or installed-build parity audit.

**Important:** WP-CLI loads WordPress infrastructure and must be operated by a qualified administrator. `--skip-plugins --skip-themes` avoids ordinary plugin/theme execution but does not necessarily disable mu-plugins or custom host bootstrap. Review the site's exact environment before execution. The script performs no deliberate database update; it does not certify every third-party boot hook as side-effect-free.

## Required second evidence step

After collecting the private snapshot, the operator must independently verify:

1. Exact installed plugin artifact hash against the reviewed package, not just displayed `Plugin Version`.
2. Live DB schema, the relevant table/index shape, versions, `spcrc_last_upgrade_error` status after controlled redaction, migration checkpoints, and any partial-deployment state.
3. Staging artifact/schema separately; publish no private DB table content.
4. Hostinger/DNS/WAF/TLS/Cloudflare/rate-limit/MFA/provider settings as independent read-only administrative evidence.
5. Backup copies, retention, restoration tests, recovery objectives, rollback plans and latest check times.
6. Any suspected symptom with sanitized runtime logs and allowed test users — do not make live speculative patches.

## Five mandatory incident fields

| Field | At this source-only point |
|---|---|
| Repository HEAD | Verify exact GitHub `main` and PR separately |
| Deployed Version | UNVERIFIED |
| DB Version | UNVERIFIED |
| Migration State | UNVERIFIED |
| Live Verification Status | NOT RUN |

If actual installed source cannot be obtained, report verbatim:

> Exact deployed code ابھی unverified ہے؛ repository-based diagnosis provisional ہے۔

## Security restrictions

Do not put exported environment inventories, plugin lists, DB structures, keys, incident records, application passwords, screenshots containing accounts, or backup locations into public GitHub comments. The authorized owner should review and transmit **redacted necessary findings** through a private approved channel. No requester should supply WordPress credentials in this chat.

## Release decision

G1 (Live State Truth) remains **BLOCKED** until the above independent evidence is actually obtained. The presence of this tool and guide does not turn it green.
