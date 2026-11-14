#!/usr/bin/env bash
# V12.3 P1 test: exercise operator inventory helper with a fake read-only
# WordPress CLI and synthetic fixture. Never accesses production or network.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/file24-v123-freeze-test.XXXXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/wp" "$WORK/plugin" "$WORK/private"
printf '%s\n' '<?php // Synthetic test; not a real secret' > "$WORK/wp/wp-config.php"
printf '%s\n' '<?php // Synthetic File24 plugin entry' > "$WORK/plugin/sabri-security-center.php"
printf '%s\n' 'body{display:block}' > "$WORK/plugin/safe.css"

cat > "$WORK/bin/wp" <<'WP_STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$WP_CLI_SPY_LOG"
case " $* " in
    *" db import "*|*" db repair "*|*" option update "*|*" plugin update "*)
        printf '%s\n' "Unexpected mutation command!" >&2
        exit 91 ;;
esac
if [[ "${WP_CLI_SYNTHETIC_FAILURE:-0}" == "1" && "$*" == *" db query "* ]]; then
    exit 77
fi
case " $* " in
    *" core version "*) printf '%s\n' "7.0-test" ;;
    *" plugin list "*) printf '%s\n' 'name,status,version,update' 'sabri-security-center,active,0.99.0,none' ;;
    *" theme list "*) printf '%s\n' 'name,status,version,update' 'synthetic,active,1.0,none' ;;
    *" option get "*) printf '%s\n' '0.25.5' ;;
    *" db query "*) printf '%s\n' 'synthetic-metadata-only' ;;
    *) printf '%s\n' 'Unexpected WP-CLI read operation' >&2; exit 92 ;;
esac
WP_STUB
chmod 700 "$WORK/bin/wp"
export PATH="$WORK/bin:$PATH"
export WP_CLI_SPY_LOG="$WORK/calls.log"
touch "$WP_CLI_SPY_LOG"

if bash "$ROOT/tools/live-reality-freeze-readonly.sh" > "$WORK/unauthorized.txt" 2>&1; then
    printf '%s\n' "FAIL: helper accepted an unauthorized invocation." >&2
    exit 1
fi
if [[ -s "$WP_CLI_SPY_LOG" ]]; then
    printf '%s\n' "FAIL: unauthorized attempt triggered WP CLI." >&2
    exit 1
fi

TMPDIR="$WORK/private" bash "$ROOT/tools/live-reality-freeze-readonly.sh" \
    --authorized-read-only "$WORK/wp" "$WORK/plugin" > "$WORK/success.txt"

find "$WORK/private" -mindepth 1 -maxdepth 1 -type d -name 'file24-private-freeze.*' -print > "$WORK/folders.txt"
[[ "$(wc -l < "$WORK/folders.txt")" -eq 1 ]] || { echo "FAIL: expected one private receipt" >&2; exit 1; }
RECEIPT="$(head -n1 "$WORK/folders.txt")"
[[ "$(stat -c %a "$RECEIPT")" == "700" ]] || { echo "FAIL: receipt not private" >&2; exit 1; }

for name in README-PRIVATE.txt wordpress-core-version.txt plugin-versions.csv theme-versions.csv \
    file24-version-options.txt database-server-version.txt file24-tables-approximate-rows.txt \
    file24-columns.txt installed-plugin-source.sha256 plugin-entry-sha256.txt required-five-fields.txt; do
    [[ -f "$RECEIPT/$name" ]] || { echo "FAIL: missing receipt $name" >&2; exit 1; }
done
grep -q 'NOT RUN' "$RECEIPT/required-five-fields.txt"
grep -q 'UNVERIFIED' "$RECEIPT/required-five-fields.txt" \
    || grep -q 'NOT DISCOVERED' "$RECEIPT/required-five-fields.txt"
[[ "$(wc -l < "$WP_CLI_SPY_LOG")" -ge 6 ]] || { echo "FAIL: metadata reads missing" >&2; exit 1; }
! grep -E 'db (export|import|repair)|option update|plugin update|user list|wp-config.php' "$WP_CLI_SPY_LOG"

if [[ -s "$WORK/wp/wp-config.php" && -s "$WORK/plugin/sabri-security-center.php" ]]; then
    :
else
    echo "FAIL: helper mutated fixture files" >&2
    exit 1
fi

# Fail closed on an unavailable database, rather than claiming completed freeze.
export WP_CLI_SYNTHETIC_FAILURE=1
if TMPDIR="$WORK/private" bash "$ROOT/tools/live-reality-freeze-readonly.sh" \
    --authorized-read-only "$WORK/wp" "$WORK/plugin" > "$WORK/failure.txt" 2>&1; then
    echo "FAIL: failed database query incorrectly completed collection" >&2
    exit 1
fi

printf '%s\n' "PASS: V12.3 private read-only freeze syntax, authorization, source hashing and WP-CLI failure handling"
