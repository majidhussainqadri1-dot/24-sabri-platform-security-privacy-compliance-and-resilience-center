#!/usr/bin/env bash
# File 24 V12.3 / P1: read-only WordPress deployment-reality freeze.
# Private operator tool. Run ONLY with authorized Hostinger shell access.
# Does not modify WordPress, plugin files, database, options or remote services.
set -euo pipefail
umask 077

if [[ "${1:-}" != "--authorized-read-only" || $# -ne 3 ]]; then
  printf '%s\n' "Usage: $0 --authorized-read-only /absolute/wordpress/path /absolute/installed/plugin/path" >&2
  printf '%s\n' "Run only as an authorized operator; do not publish the private evidence output." >&2
  exit 64
fi

WP_PATH="$2"
PLUGIN_PATH="$3"
if [[ "$WP_PATH" != /* || "$PLUGIN_PATH" != /* || ! -f "$WP_PATH/wp-config.php" || ! -f "$PLUGIN_PATH/sabri-security-center.php" ]]; then
  printf '%s\n' "WordPress root or installed File 24 plugin path is invalid; no collection was done." >&2
  exit 65
fi
if ! command -v wp >/dev/null 2>&1; then
  printf '%s\n' "WP-CLI unavailable: do not infer installed database/schema state." >&2
  exit 69
fi

OUTPUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/file24-private-freeze.XXXXXXXX")"
UTC_NOW="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
{
  printf '%s\n' "File 24 V12.3 private, read-only environment inventory"
  printf '%s\n' "Collected UTC: $UTC_NOW"
  printf '%s\n' "Repository parity: NOT ASSESSED. Compare later to immutable approved package."
  printf '%s\n' "Real WAF/MFA/TLS/provider/restore evidence: EXTERNAL, NOT VERIFIED HERE."
  printf '%s\n' "No database row contents, user secrets, raw patient data or wp-config bytes collected."
} > "$OUTPUT_DIR/README-PRIVATE.txt"

wp_read() {
  wp --path="$WP_PATH" --skip-plugins --skip-themes "$@"
}

# Collect metadata only; keep each output private, including plugin identities.
wp_read core version > "$OUTPUT_DIR/wordpress-core-version.txt"
wp_read plugin list --format=csv --fields=name,status,version,update > "$OUTPUT_DIR/plugin-versions.csv"
wp_read theme list --format=csv --fields=name,status,version,update > "$OUTPUT_DIR/theme-versions.csv"

for option in spcrc_version spcrc_schema_version spcrc_last_upgraded_at; do
  printf '%s: ' "$option" >> "$OUTPUT_DIR/file24-version-options.txt"
  if ! wp_read option get "$option" --format=plaintext >> "$OUTPUT_DIR/file24-version-options.txt" 2>/dev/null; then
    printf '%s\n' "MISSING / UNAVAILABLE" >> "$OUTPUT_DIR/file24-version-options.txt"
  fi
done

# Read only the public-safe *shape* of an upgrade failure; never print raw
# exception text, lock tokens, serialized options, credentials or patient data.
# WP-CLI --field extracts only the governed error_code from a structured option.
upgrade_code="$(wp_read option get spcrc_last_upgrade_error --field=error_code 2>/dev/null || true)"
upgrade_code="$(printf '%s' "$upgrade_code" | LC_ALL=C tr -cd 'A-Za-z0-9_-' | cut -c1-100)"
printf 'Last upgrade error code: %s\n' "${upgrade_code:-NONE_OR_UNAVAILABLE}" > "$OUTPUT_DIR/file24-migration-error-code.txt"
if wp_read option get spcrc_upgrade_lock >/dev/null 2>&1; then
  printf '%s\n' "Upgrade lock marker: PRESENT (contents deliberately not collected)"
else
  printf '%s\n' "Upgrade lock marker: NOT PRESENT OR INACCESSIBLE"
fi > "$OUTPUT_DIR/file24-upgrade-lock-state.txt"

# Store only scheduled File24 event hook names and dates, not cron payloads.
if wp_read cron event list --format=csv --fields=hook,next_run_gmt,schedule 2>/dev/null \
  | awk -F, 'NR == 1 || $1 ~ /^spcrc_/ { print }' > "$OUTPUT_DIR/file24-cron-schedule.csv"; then
  :
else
  printf '%s\n' "UNAVAILABLE" > "$OUTPUT_DIR/file24-cron-schedule.csv"
fi

# Skip WordPress plugins/themes during metadata queries to avoid running File 24
# migration/activation hooks while checking the deployed state.
wp_read db query 'SELECT VERSION() AS db_server_version' --skip-column-names \
  > "$OUTPUT_DIR/database-server-version.txt"
wp_read db query \
  "SELECT TABLE_NAME, TABLE_ROWS AS approximate_rows FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE '%spcrc%' ORDER BY TABLE_NAME" \
  > "$OUTPUT_DIR/file24-tables-approximate-rows.txt"
wp_read db query \
  "SELECT TABLE_NAME,COLUMN_NAME,DATA_TYPE,IS_NULLABLE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE '%spcrc%' ORDER BY TABLE_NAME,ORDINAL_POSITION" \
  > "$OUTPUT_DIR/file24-columns.txt"
wp_read db query \
  "SELECT TABLE_NAME,INDEX_NAME,COLUMN_NAME,SEQ_IN_INDEX,NON_UNIQUE FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE '%spcrc%' ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX" \
  > "$OUTPUT_DIR/file24-indexes.txt"

# File hashes are installation evidence, not evidence of integrity by themselves.
# Do NOT collect .env, wp-config.php, backups, uploads, logs or sensitive records.
find "$PLUGIN_PATH" -type f \( -name '*.php' -o -name '*.js' -o -name '*.css' -o -name '*.json' -o -name '*.md' \) -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 -r sha256sum > "$OUTPUT_DIR/installed-plugin-source.sha256"
sha256sum "$PLUGIN_PATH/sabri-security-center.php" > "$OUTPUT_DIR/plugin-entry-sha256.txt"

{
  printf '%s\n' "Repository HEAD: NOT DISCOVERED BY THIS TOOL"
  printf '%s\n' "Deployed Version: see file24-version-options.txt and plugin-versions.csv"
  printf '%s\n' "DB Version: see database-server-version.txt; schema option in file24-version-options.txt"
  printf '%s\n' "Migration State: NOT FULLY VERIFIED; last_upgraded_at is metadata only"
  printf '%s\n' "Live Verification Status: NOT RUN; no live changes or end-to-end tests"
} > "$OUTPUT_DIR/required-five-fields.txt"

printf '%s\n' "Private evidence folder created: $OUTPUT_DIR"
printf '%s\n' "Do NOT upload this folder to GitHub or a public issue. Redact/review and transfer privately."
printf '%s\n' "Before staging/production conclusions: verify actual WP DB migrations, provider controls, backup/restore and package parity independently."
