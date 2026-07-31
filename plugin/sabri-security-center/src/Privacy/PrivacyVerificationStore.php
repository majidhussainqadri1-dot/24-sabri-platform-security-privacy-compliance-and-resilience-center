<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Persists bounded identity/authority verification evidence on the canonical
 * privacy-request row. It never stores identity documents or exported data.
 */
final class PrivacyVerificationStore
{
    /** @param array<string,mixed> $evidence
     *  @return true|\WP_Error
     */
    public function persist(string $requestUuid, array $evidence): true|\WP_Error
    {
        global $wpdb;

        $requestUuid = Sanitizer::uuid($requestUuid);
        $existing = $this->get($requestUuid);
        if ($requestUuid === '' || $existing === null) {
            return new \WP_Error('spcrc_privacy_verification_request_missing', 'Privacy request could not be found for verification evidence.');
        }

        $safe = $this->sanitize($evidence);
        if ($safe === null) {
            return new \WP_Error('spcrc_privacy_verification_evidence_invalid', 'Privacy verification evidence is invalid.');
        }

        if ($this->hasEvidence($existing)) {
            foreach (array_keys($safe) as $key) {
                if ((string) ($existing[$key] ?? '') !== (string) $safe[$key]) {
                    return new \WP_Error('spcrc_privacy_verification_collision', 'Privacy request verification evidence cannot be rebound.');
                }
            }
            return true;
        }

        $lockVersion = absint($existing['lock_version'] ?? 0);
        $status = Sanitizer::key($existing['status'] ?? '', 40);
        if ($status !== 'dispatching') {
            return new \WP_Error('spcrc_privacy_verification_state_invalid', 'Privacy verification evidence may be attached only before native dispatch.');
        }

        $updated = $wpdb->update(
            $wpdb->prefix . 'spcrc_privacy_requests',
            array_merge($safe, [
                'lock_version' => $lockVersion + 1,
                'updated_at' => current_time('mysql', true),
            ]),
            ['request_uuid' => $requestUuid, 'status' => 'dispatching', 'lock_version' => $lockVersion],
            ['%s', '%s', '%s', '%d', '%s', '%d', '%s'],
            ['%s', '%s', '%d']
        );
        if ($updated === false) {
            return new \WP_Error('spcrc_privacy_verification_write_failed', 'Privacy verification evidence could not be stored.');
        }
        if ($updated !== 1) {
            return new \WP_Error('spcrc_privacy_verification_concurrent', 'Privacy request changed before verification evidence was stored.');
        }

        return true;
    }

    /** @return array<string,mixed>|null */
    public function get(string $requestUuid): ?array
    {
        global $wpdb;

        $requestUuid = Sanitizer::uuid($requestUuid);
        if ($requestUuid === '') {
            return null;
        }

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT request_uuid, status, lock_version, verification_method, authority_basis, verification_reference, verified_by_user_id, verified_at FROM {$wpdb->prefix}spcrc_privacy_requests WHERE request_uuid = %s",
                $requestUuid
            ),
            ARRAY_A
        );

        return is_array($row) ? $row : null;
    }

    /** @param array<string,mixed> $record */
    public function hasEvidence(array $record): bool
    {
        $safe = $this->sanitize($record);
        if ($safe === null) {
            return false;
        }

        $verifiedAt = strtotime((string) $safe['verified_at'] . ' UTC');
        return $verifiedAt !== false
            && $verifiedAt <= time() + 300
            && (bool) get_userdata((int) $safe['verified_by_user_id']);
    }

    /** @param array<string,mixed> $record
     *  @return array<string,mixed>
     */
    public function enrich(array $record): array
    {
        $uuid = Sanitizer::uuid($record['request_uuid'] ?? '');
        $evidence = $uuid === '' ? null : $this->get($uuid);
        return $evidence === null ? $record : array_merge($record, $evidence);
    }

    /** @param array<string,mixed> $evidence
     *  @return array<string,mixed>|null
     */
    private function sanitize(array $evidence): ?array
    {
        $method = Sanitizer::key($evidence['verification_method'] ?? '', 40);
        $basis = Sanitizer::key($evidence['authority_basis'] ?? '', 40);
        $reference = Sanitizer::text($evidence['verification_reference'] ?? '', 200);
        $verifiedBy = absint($evidence['verified_by_user_id'] ?? 0);
        $verifiedAt = Sanitizer::isoTime($evidence['verified_at'] ?? '');

        if (
            ! in_array($method, PrivacyRequestPolicy::verificationMethods(), true)
            || ! in_array($basis, PrivacyRequestPolicy::authorityBases(), true)
            || ! PrivacyRequestPolicy::verificationPairAllowed($method, $basis)
            || $reference === ''
            || $verifiedBy < 1
            || $verifiedAt === ''
        ) {
            return null;
        }

        return [
            'verification_method' => $method,
            'authority_basis' => $basis,
            'verification_reference' => $reference,
            'verified_by_user_id' => $verifiedBy,
            'verified_at' => gmdate('Y-m-d H:i:s', (int) strtotime($verifiedAt)),
        ];
    }
}
