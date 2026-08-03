<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Support;

final class Sanitizer
{
    public static function text(mixed $value, int $maxLength = 200): string
    {
        if (! is_scalar($value) && $value !== null) {
            return '';
        }

        $text = self::validUtf8((string) $value);
        if ($text === '') {
            return '';
        }
        $text = sanitize_text_field($text);
        return self::truncate($text, $maxLength);
    }

    public static function key(mixed $value, int $maxLength = 120): string
    {
        if (! is_scalar($value) && $value !== null) {
            return '';
        }

        return self::truncate(sanitize_key((string) $value), $maxLength);
    }

    /** @return string[] */
    public static function textList(mixed $value, int $maxItems = 50, int $maxLength = 200): array
    {
        if (! is_array($value)) {
            return [];
        }

        $result = [];
        foreach (array_slice($value, 0, max(0, $maxItems)) as $item) {
            if (! is_scalar($item) && $item !== null) {
                continue;
            }

            $clean = self::text($item, $maxLength);
            if ($clean !== '') {
                $result[] = $clean;
            }
        }

        return array_values(array_unique($result));
    }

    public static function uuid(mixed $value): string
    {
        if (! is_scalar($value) && $value !== null) {
            return '';
        }

        $uuid = strtolower(trim((string) $value));
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $uuid) === 1
            ? $uuid
            : '';
    }


    /**
     * Accept only a bounded opaque locator. File paths, URLs, e-mail addresses,
     * bearer material and free-form evidence are deliberately excluded.
     */
    public static function opaqueReference(mixed $value, int $maxLength = 255): string
    {
        if (! is_scalar($value) && $value !== null) {
            return '';
        }

        $reference = trim((string) $value);
        if ($reference === '' || strlen($reference) > $maxLength) {
            return '';
        }
        if (
            preg_match('/\s/', $reference) === 1
            || str_contains($reference, '/')
            || str_contains($reference, '\\')
            || str_contains($reference, '@')
            || preg_match('/^[a-z][a-z0-9+.-]*:\/\//i', $reference) === 1
            || preg_match('/^[A-Za-z]:/', $reference) === 1
        ) {
            return '';
        }

        return preg_match('/^[a-z][a-z0-9_-]{1,31}:[A-Za-z0-9][A-Za-z0-9._:-]{2,220}$/', $reference) === 1
            ? self::truncate($reference, $maxLength)
            : '';
    }

    public static function containsSensitiveMaterial(mixed $value): bool
    {
        if (! is_scalar($value) && $value !== null) {
            return true;
        }

        $text = trim((string) $value);
        if ($text === '') {
            return false;
        }

        return preg_match('/-----BEGIN [A-Z ]*PRIVATE KEY-----/i', $text) === 1
            || preg_match('/\b(?:api[_-]?key|secret|password|passwd|token|authorization)\s*[:=]\s*\S+/i', $text) === 1
            || preg_match('/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/i', $text) === 1
            || preg_match('/\b[a-z][a-z0-9+.-]*:\/\//i', $text) === 1
            || preg_match('/(?:^|\s)(?:[A-Za-z]:\\\\|\/(?:var|home|srv|private|etc|tmp|mnt|opt)\/|wp-content\/)/i', $text) === 1
            || preg_match('/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i', $text) === 1
            || preg_match('/\b\d{10,16}\b/', preg_replace('/[- ]/', '', $text) ?? $text) === 1
            || preg_match('/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/', $text) === 1
            || preg_match('/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b/', $text) === 1;
    }

    public static function boolean(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        $parsed = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
        return $parsed === null ? false : $parsed;
    }

    public static function isoTime(mixed $value): string
    {
        if (! is_scalar($value) && $value !== null) {
            return '';
        }

        $value = trim((string) $value);
        if ($value === '') {
            return '';
        }

        $dateTime = self::absoluteDateTime($value);
        return $dateTime instanceof \DateTimeImmutable
            ? $dateTime->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:sP')
            : '';
    }

    private static function absoluteDateTime(string $value): ?\DateTimeImmutable
    {
        $utc = new \DateTimeZone('UTC');
        $formats = [];

        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) === 1) {
            $formats[] = ['!Y-m-d', $value, $utc, 'Y-m-d'];
        } elseif (preg_match('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/', $value) === 1) {
            $formats[] = ['!Y-m-d H:i:s', $value, $utc, 'Y-m-d H:i:s'];
        } elseif (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/', $value) === 1) {
            $normalized = str_ends_with($value, 'Z') ? substr($value, 0, -1) . '+00:00' : $value;
            if (preg_match('/\.([0-9]{1,6})([+-]\d{2}:\d{2})$/', $normalized, $fraction) === 1) {
                $padded = str_pad($fraction[1], 6, '0');
                $normalized = preg_replace('/\.[0-9]{1,6}([+-]\d{2}:\d{2})$/', '.' . $padded . '$1', $normalized) ?? '';
                $formats[] = ['!Y-m-d\TH:i:s.uP', $normalized, null, 'Y-m-d\TH:i:s.uP'];
            } elseif (preg_match('/T\d{2}:\d{2}:\d{2}[+-]/', $normalized) === 1) {
                $formats[] = ['!Y-m-d\TH:i:sP', $normalized, null, 'Y-m-d\TH:i:sP'];
            } else {
                $formats[] = ['!Y-m-d\TH:iP', $normalized, null, 'Y-m-d\TH:iP'];
            }
        } else {
            return null;
        }

        foreach ($formats as [$format, $input, $timezone, $roundTripFormat]) {
            $parsed = $timezone instanceof \DateTimeZone
                ? \DateTimeImmutable::createFromFormat($format, $input, $timezone)
                : \DateTimeImmutable::createFromFormat($format, $input);
            $errors = \DateTimeImmutable::getLastErrors();
            $hasErrors = is_array($errors) && ((int) ($errors['warning_count'] ?? 0) > 0 || (int) ($errors['error_count'] ?? 0) > 0);
            if (! $parsed instanceof \DateTimeImmutable || $hasErrors || $parsed->format($roundTripFormat) !== $input) {
                continue;
            }
            return $parsed;
        }

        return null;
    }

    private static function truncate(string $value, int $maxLength): string
    {
        if ($maxLength < 1) {
            return '';
        }

        if (function_exists('mb_substr')) {
            return mb_substr($value, 0, $maxLength, 'UTF-8');
        }
        if (function_exists('iconv_substr')) {
            $truncated = iconv_substr($value, 0, $maxLength, 'UTF-8');
            return is_string($truncated) ? $truncated : '';
        }

        if (preg_match_all('/./us', $value, $characters) !== false) {
            return implode('', array_slice($characters[0], 0, $maxLength));
        }
        return '';
    }

    private static function validUtf8(string $value): string
    {
        if ($value === '') {
            return '';
        }
        if (function_exists('wp_check_invalid_utf8')) {
            return (string) wp_check_invalid_utf8($value, false);
        }
        return preg_match('//u', $value) === 1 ? $value : '';
    }
}
