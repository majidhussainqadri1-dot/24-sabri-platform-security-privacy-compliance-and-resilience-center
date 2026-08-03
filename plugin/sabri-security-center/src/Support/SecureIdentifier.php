<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Support;

if (! class_exists(Sanitizer::class, false)) {
    require_once __DIR__ . '/Sanitizer.php';
}

/**
 * Generates validated UUIDv4 identifiers without trusting a pluggable helper
 * blindly. A malformed WordPress UUID result falls back to cryptographic bytes;
 * complete entropy failure is surfaced as a hard error.
 */
final class SecureIdentifier
{
    /** @return string|\WP_Error */
    public static function uuid4(string $purpose = 'record'): string|\WP_Error
    {
        $candidate = '';
        if (function_exists('wp_generate_uuid4')) {
            try {
                $candidate = strtolower(trim((string) wp_generate_uuid4()));
            } catch (\Throwable $error) {
                if (function_exists('do_action')) {
                    do_action(
                        'spcrc/wordpress_uuid_generation_failed',
                        Sanitizer::key($purpose, 80),
                        get_class($error)
                    );
                }
                $candidate = '';
            }
        }
        if (self::validUuid4($candidate)) {
            return $candidate;
        }

        try {
            $bytes = random_bytes(16);
            $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
            $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
            $hex = bin2hex($bytes);
            $candidate = sprintf(
                '%s-%s-%s-%s-%s',
                substr($hex, 0, 8),
                substr($hex, 8, 4),
                substr($hex, 12, 4),
                substr($hex, 16, 4),
                substr($hex, 20, 12)
            );
        } catch (\Throwable $error) {
            if (function_exists('do_action')) {
                do_action('spcrc/secure_identifier_generation_failed', Sanitizer::key($purpose, 80), get_class($error));
            }
            return new \WP_Error(
                'spcrc_secure_identifier_unavailable',
                'A cryptographically strong record identifier could not be generated.'
            );
        }

        if (! self::validUuid4($candidate)) {
            return new \WP_Error(
                'spcrc_secure_identifier_invalid',
                'A valid UUIDv4 record identifier could not be generated.'
            );
        }
        return $candidate;
    }

    public static function validUuid4(string $uuid): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', strtolower(trim($uuid))) === 1;
    }
}
