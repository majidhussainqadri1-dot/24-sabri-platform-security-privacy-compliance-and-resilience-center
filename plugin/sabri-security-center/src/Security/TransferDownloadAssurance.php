<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Security;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * File 24 assurance contract for File 17/native owners and CF-04 when activated.
 * This class does not upload, store or deliver files and therefore preserves native ownership.
 */
final class TransferDownloadAssurance
{
    public const VERIFIED_TRANSFER_MAX_BYTES = 1073741824;
    public const MAX_EVIDENCE_AGE_DAYS = 90;

    /** @var list<string> */
    private const TRANSFER_CONTROLS = [
        'verified_sender',
        'authorized_recipient',
        'sender_recipient_binding',
        'purpose_binding',
        'relationship_recheck',
        'consent_recheck',
        'multipart_or_chunked',
        'pause_resume',
        'interruption_recovery',
        'checksum',
        'mime_magic_validation',
        'malware_scan',
        'archive_bomb_scan',
        'polyglot_scan',
        'private_storage',
        'short_lived_delivery_grant',
        'expiry',
        'revocation',
        'audit',
    ];

    /** @var list<string> */
    private const DOWNLOAD_CONTROLS = [
        'native_owner_eligibility',
        'queue',
        'progress',
        'pause_resume',
        'retry',
        'checksum',
        'range_requests',
        'weak_connection_recovery',
        'click_time_authorization',
        'history',
        'audit',
        'expiry',
        'revocation',
    ];

    /** @param array<string,mixed> $evidence @return array<string,mixed> */
    public static function evaluateTransfer(array $evidence, ?int $now = null): array
    {
        $controls = Sanitizer::textList($evidence['controls'] ?? [], 100, 100);
        $missing = array_values(array_diff(self::TRANSFER_CONTROLS, $controls));
        $parsedMaxBytes = Sanitizer::strictInteger($evidence['max_bytes_per_file'] ?? null, 1, self::VERIFIED_TRANSFER_MAX_BYTES);
        $maxBytes = $parsedMaxBytes ?? 0;
        $sizeValid = $parsedMaxBytes !== null;
        $evidenceRef = Sanitizer::opaqueReference($evidence['evidence_ref'] ?? '');
        $testedAt = Sanitizer::isoTime($evidence['tested_at'] ?? '');
        $evidenceFresh = self::evidenceFresh($testedAt, $now);
        $state = $missing === [] && $sizeValid && $evidenceRef !== '' && $evidenceFresh
            ? 'verified'
            : ($controls === [] ? 'unassessed' : 'blocked');

        return [
            'state' => $state,
            'missing_controls' => $missing,
            'max_bytes_per_file' => $maxBytes,
            'one_gib_limit_valid' => $sizeValid,
            'evidence_fresh' => $evidenceFresh,
            'evidence_ref' => $evidenceRef,
            'transfer_allowed' => $state === 'verified',
        ];
    }

    /** @param array<string,mixed> $evidence @return array<string,mixed> */
    public static function evaluateDownload(array $evidence, ?int $now = null): array
    {
        $controls = Sanitizer::textList($evidence['controls'] ?? [], 100, 100);
        $missing = array_values(array_diff(self::DOWNLOAD_CONTROLS, $controls));
        $evidenceRef = Sanitizer::opaqueReference($evidence['evidence_ref'] ?? '');
        $testedAt = Sanitizer::isoTime($evidence['tested_at'] ?? '');
        $evidenceFresh = self::evidenceFresh($testedAt, $now);
        $state = $missing === [] && $evidenceRef !== '' && $evidenceFresh
            ? 'verified'
            : ($controls === [] ? 'unassessed' : 'blocked');

        return [
            'state' => $state,
            'missing_controls' => $missing,
            'evidence_fresh' => $evidenceFresh,
            'evidence_ref' => $evidenceRef,
            'download_allowed' => $state === 'verified',
        ];
    }

    private static function evidenceFresh(string $testedAt, ?int $now): bool
    {
        $tested = $testedAt === '' ? false : strtotime($testedAt);
        $now ??= time();
        return $tested !== false
            && $tested <= $now + 300
            && $tested >= $now - (self::MAX_EVIDENCE_AGE_DAYS * DAY_IN_SECONDS);
    }
}
