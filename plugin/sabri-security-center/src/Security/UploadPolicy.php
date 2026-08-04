<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Security;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Technical upload assurance. Native modules retain content approval and file
 * ownership; File 24 provides fail-closed validation and scanner contracts.
 */
final class UploadPolicy
{
    /** @var array<string,array<string,mixed>> */
    private const PURPOSES = [
        'public-image' => ['max' => 15728640, 'mimes' => ['image/jpeg', 'image/png', 'image/webp', 'image/avif']],
        'private-document' => ['max' => 26214400, 'mimes' => ['application/pdf', 'image/jpeg', 'image/png']],
        'video-source' => ['max' => 2147483648, 'mimes' => ['video/mp4', 'video/webm', 'video/quicktime']],
        'audio-source' => ['max' => 268435456, 'mimes' => ['audio/mpeg', 'audio/mp4', 'audio/ogg', 'audio/wav']],
        'evidence-bundle' => ['max' => 52428800, 'mimes' => ['application/pdf', 'application/zip']],
    ];

    /** @param array<string,mixed> $file @return array<string,mixed>|\WP_Error */
    public function validate(array $file, string $purpose): array|\WP_Error
    {
        $purpose = Sanitizer::key($purpose, 60);
        if (! isset(self::PURPOSES[$purpose])) {
            return new \WP_Error('spcrc_upload_purpose_invalid', 'Upload purpose is not approved.');
        }
        $name = Sanitizer::text($file['name'] ?? '', 255);
        $size = absint($file['size'] ?? 0);
        $declared = strtolower(Sanitizer::text($file['declared_mime'] ?? '', 120));
        $detected = strtolower(Sanitizer::text($file['detected_mime'] ?? '', 120));
        $sha256 = strtolower(Sanitizer::text($file['sha256'] ?? '', 64));

        if ($name === '' || $size < 1 || $size > (int) self::PURPOSES[$purpose]['max']) {
            return new \WP_Error('spcrc_upload_size_invalid', 'Upload name or size is invalid for the selected purpose.');
        }
        if (preg_match('/[\x00-\x1f\x7f]/', $name) === 1 || preg_match('/\.(php\d*|phtml|phar|cgi|pl|py|sh|exe|dll|js|html?)$/i', $name) === 1) {
            return new \WP_Error('spcrc_upload_name_dangerous', 'Executable or active-content upload was rejected.');
        }
        if (preg_match('/\.(?:jpg|jpeg|png|webp|pdf|mp4|webm|mp3|wav)\.(?:php\d*|phtml|phar|js|html?)$/i', $name) === 1) {
            return new \WP_Error('spcrc_upload_double_extension', 'Double-extension upload was rejected.');
        }
        if ($declared === '' || $detected === '' || ! hash_equals($declared, $detected)) {
            return new \WP_Error('spcrc_upload_mime_mismatch', 'Declared and detected MIME types do not match.');
        }
        if (! in_array($detected, self::PURPOSES[$purpose]['mimes'], true)) {
            return new \WP_Error('spcrc_upload_mime_not_allowed', 'Detected MIME type is not allowed for this purpose.');
        }
        if (preg_match('/^[a-f0-9]{64}$/', $sha256) !== 1) {
            return new \WP_Error('spcrc_upload_hash_invalid', 'A valid SHA-256 source hash is required.');
        }

        return [
            'accepted_for_quarantine' => true,
            'purpose' => $purpose,
            'name' => $name,
            'size' => $size,
            'mime' => $detected,
            'sha256' => $sha256,
            'delivery_allowed' => false,
        ];
    }

    /** @param array<string,mixed> $scanner @return array<string,mixed>|\WP_Error */
    public function scannerResult(array $scanner): array|\WP_Error
    {
        $status = Sanitizer::key($scanner['status'] ?? '', 30);
        $evidenceRef = Sanitizer::opaqueReference($scanner['evidence_ref'] ?? '');
        $scannedAt = Sanitizer::isoTime($scanner['scanned_at'] ?? '');
        $engine = Sanitizer::key($scanner['engine'] ?? '', 80);
        if (! in_array($status, ['clean', 'infected', 'unsupported', 'error'], true) || $scannedAt === '' || $engine === '') {
            return new \WP_Error('spcrc_upload_scan_invalid', 'Scanner status, engine and timestamp are required.');
        }
        if ($evidenceRef === '') {
            return new \WP_Error('spcrc_upload_scan_evidence_missing', 'Scanner result requires an opaque evidence reference.');
        }
        return [
            'status' => $status,
            'engine' => $engine,
            'scanned_at' => $scannedAt,
            'evidence_ref' => $evidenceRef,
            'delivery_allowed' => $status === 'clean',
        ];
    }
}
