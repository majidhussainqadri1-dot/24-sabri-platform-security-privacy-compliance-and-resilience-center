# Cycle 31 — Lock Token Generation Review and Correction

**Review mode:** fresh entropy-failure and malformed-provider-output review

## Defect F24-D065

The coordination lock trusted any `wp_generate_uuid4()` return value and called `random_bytes()` without exception handling. Malformed UUID output could become a weak/invalid owner token, while an entropy-provider exception could terminate a sensitive operation with an uncaught fatal error.

## Correction

Token generation now:

- accepts only a canonical RFC 4122 version-4 UUID;
- falls back to 128 bits from `random_bytes()` when WordPress output is malformed or unavailable;
- catches `Throwable`, emits a bounded diagnostic action and returns `spcrc_atomic_lock_token_unavailable` instead of fatally terminating.

## Verification

`tests/cycle31-lock-token-generation.php` proves malformed-provider fallback, token strength/ownership/release and the exception-to-error contract.
