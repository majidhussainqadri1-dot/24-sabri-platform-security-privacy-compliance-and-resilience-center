<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Security;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Cryptographic assurance policy. File 24 validates metadata and lifecycle
 * evidence; native owners retain encryption/decryption and key custody.
 */
final class CryptographyPolicy
{
    private const APPROVED = ['xchacha20-poly1305', 'aes-256-gcm', 'sodium-secretbox'];
    private const HASHES = ['sha-256', 'sha-384', 'sha-512', 'argon2id'];

    /** @param array<string,mixed> $metadata @return array<string,mixed>|\WP_Error */
    public function validate(array $metadata): array|\WP_Error
    {
        $algorithm = Sanitizer::key($metadata['algorithm'] ?? '', 40);
        $purpose = Sanitizer::key($metadata['purpose'] ?? '', 80);
        $keyRef = Sanitizer::opaqueReference($metadata['key_ref'] ?? '');
        $version = Sanitizer::text($metadata['key_version'] ?? '', 40);
        $rotationAt = Sanitizer::isoTime($metadata['rotation_due_at'] ?? '');
        $recoveryRef = Sanitizer::opaqueReference($metadata['recovery_evidence_ref'] ?? '');

        if (! in_array($algorithm, self::APPROVED, true) || $purpose === '' || $keyRef === '' || $version === '') {
            return new \WP_Error('spcrc_crypto_metadata_invalid', 'Approved algorithm, purpose, opaque key reference and key version are required.');
        }
        if ($rotationAt === '') {
            return new \WP_Error('spcrc_crypto_rotation_missing', 'A bounded key-rotation date is required.');
        }
        $rotationTimestamp = strtotime($rotationAt);
        if ($rotationTimestamp === false || $rotationTimestamp <= time()) {
            return new \WP_Error('spcrc_crypto_rotation_overdue', 'Approved cryptographic metadata requires a key-rotation due date that has not already expired.');
        }
        if (in_array($purpose, ['master-key', 'private-evidence', 'clinical', 'identity-document'], true) && $recoveryRef === '') {
            return new \WP_Error('spcrc_crypto_recovery_evidence_missing', 'High-impact key metadata requires opaque recovery evidence.');
        }

        return [
            'algorithm' => $algorithm,
            'purpose' => $purpose,
            'key_ref' => $keyRef,
            'key_version' => $version,
            'rotation_due_at' => $rotationAt,
            'recovery_evidence_ref' => $recoveryRef,
            'approved' => true,
        ];
    }

    public static function hashAlgorithmAllowed(string $algorithm): bool
    {
        return in_array(Sanitizer::key($algorithm, 30), self::HASHES, true);
    }

    public static function permitsEncryptionClaim(array $metadata): bool
    {
        return ! is_wp_error((new self())->validate($metadata));
    }

    public static function permitsEndToEndClaim(bool $independentAuditPassed, bool $endpointKeyControlProven): bool
    {
        return $independentAuditPassed && $endpointKeyControlProven;
    }
}
