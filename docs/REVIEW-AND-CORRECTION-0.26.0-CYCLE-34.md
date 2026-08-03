# Cycle 34 — Absolute Timestamp Review and Correction

**Review mode:** fresh temporal-input ambiguity and calendar-integrity review

## Defect F24-D068

`Sanitizer::isoTime()` delegated directly to `strtotime()`. Relative phrases such as “tomorrow” and impossible dates such as `2026-02-30` could be accepted and silently normalized. Security expiries, evidence chronology, retry windows and governance deadlines therefore depended on ambient parser behavior rather than an explicit absolute timestamp contract.

## Correction

The sanitizer now accepts only strict, round-tripped absolute forms:

- `YYYY-MM-DD`;
- UTC/MySQL `YYYY-MM-DD HH:MM:SS`;
- RFC 3339 timestamps with explicit `Z` or numeric offset, including bounded fractional seconds.

Relative text, impossible calendar values and partial/ambiguous forms fail closed. Accepted values are normalized to UTC RFC 3339.

## Verification

`tests/cycle34-strict-absolute-time.php` covers relative-text rejection, invalid calendar rejection, UTC/MySQL input, numeric offsets, Zulu time, minute precision and fractional seconds.
