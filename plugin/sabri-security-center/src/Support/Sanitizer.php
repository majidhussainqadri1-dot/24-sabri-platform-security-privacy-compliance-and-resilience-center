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

        $text = sanitize_text_field((string) $value);
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
            || preg_match('/\b\d{10,16}\b/', preg_replace('/[- ]/', '', $text) ?? $text) === 1;
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

        $timestamp = strtotime($value);
        return $timestamp === false ? '' : gmdate('c', $timestamp);
    }

    private static function truncate(string $value, int $maxLength): string
    {
        if ($maxLength < 1) {
            return '';
        }

        return function_exists('mb_substr')
            ? mb_substr($value, 0, $maxLength)
            : substr($value, 0, $maxLength);
    }
}
