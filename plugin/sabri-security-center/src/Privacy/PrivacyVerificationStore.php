<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Validates and persists bounded identity/authority verification evidence on
 * the canonical privacy-request row. It never stores identity documents or
 * exported personal data.
 */
final class PrivacyVerificationStore
{
    private const DAY_SECONDS = 86400;
    /** @param array<string,mixed> $evidence
     *  @param array<string,mixed> $requestContext
     *  @return array<string,mixed>|\WP_Error
     */
    public function validateEvidence(array $evidence, array $requestContext = []): array|\WP_Error
    {
        $safe = $this->sanitize($evidence);
        if ($safe === null) {
            return new \WP_Error(
                'spcrc_privacy_verification_evidence_invalid',
                'Privacy verification evidence is invalid or the reference is not an opaque case identifier.'
            );
        }

        $verifiedAt = strtotime((string) $safe['verified_at'] . ' UTC');
        if ($verifiedAt === false || $verifiedAt > time() + 300) {
            return new \WP_Error(
                'spcrc_privacy_verified_at_invalid',
                'A valid, non-future verification timestamp is required before dispatch.'
            );
        }
        $maximumAge = $this->maximumEvidenceAge((string) $safe['verification_method']);
        if ($verifiedAt < time() - $maximumAge) {
            return new \WP_Error(
                'spcrc_privacy_verification_stale',
                'Privacy verification evidence is too old for this verification method.'
            );
        }
        if (! get_userdata((int) $safe['verified_by_user_id'])) {
            return new \WP_Error(
                'spcrc_privacy_verifier_invalid',
                'A valid verifying operator is required before dispatch.'
            );
        }
        if (! $this->verifierAuthorized($requestContext, $safe)) {
            return new \WP_Error(
                'spcrc_privacy_verifier_forbidden',
                'The verifying actor is not authorized to attest this privacy verification method.'
            );
        }
        if (! $this->evidenceConfirmed($requestContext, $safe)) {
            return new \WP_Error(
                'spcrc_privacy_verification_proof_missing',
                'The selected verification method has no confirmed native or operator evidence.'
            );
        }

        return $safe;
    }

    /** @param array<string,mixed> $evidence
     *  @return bool|\WP_Error
     */
    public function persist(string $requestUuid, array $evidence): bool|\WP_Error
    {
        global $wpdb;

        $requestUuid = Sanitizer::uuid($requestUuid);
        $existing = $this->get($requestUuid);
        if ($requestUuid === '' || $existing === null) {
            return new \WP_Error(
                'spcrc_privacy_verification_request_missing',
                'Privacy request could not be found for verification evidence.'
            );
        }

        $validated = $this->validateEvidence($evidence, $existing);
        if (is_wp_error($validated)) {
            return $validated;
        }

        if ($this->hasEvidence($existing)) {
            foreach (array_keys($validated) as $key) {
                if ((string) ($existing[$key] ?? '') !== (string) $validated[$key]) {
                    return new \WP_Error(
                        'spcrc_privacy_verification_collision',
                        'Privacy request verification evidence cannot be rebound.'
                    );
                }
            }
            return true;
        }

        $lockVersion = absint($existing['lock_version'] ?? 0);
        $status = Sanitizer::key($existing['status'] ?? '', 40);
        if ($status !== 'dispatching') {
            return new \WP_Error(
                'spcrc_privacy_verification_state_invalid',
                'Privacy verification evidence may be attached only before native dispatch.'
            );
        }

        $updated = $wpdb->update(
            $wpdb->prefix . 'spcrc_privacy_requests',
            array_merge($validated, [
                'lock_version' => $lockVersion + 1,
                'updated_at' => current_time('mysql', true),
            ]),
            ['request_uuid' => $requestUuid, 'status' => 'dispatching', 'lock_version' => $lockVersion],
            ['%s', '%s', '%s', '%d', '%s', '%d', '%s'],
            ['%s', '%s', '%d']
        );
        if ($updated === false) {
            return new \WP_Error(
                'spcrc_privacy_verification_write_failed',
                'Privacy verification evidence could not be stored.'
            );
        }
        if ($updated !== 1) {
            return new \WP_Error(
                'spcrc_privacy_verification_concurrent',
                'Privacy request changed before verification evidence was stored.'
            );
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
                "SELECT request_uuid, requester_user_id, status, lock_version, verification_method, authority_basis, verification_reference, verified_by_user_id, verified_at FROM {$wpdb->prefix}spcrc_privacy_requests WHERE request_uuid = %s",
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
            && $verifiedAt >= time() - $this->maximumEvidenceAge((string) $safe['verification_method'])
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
        $reference = $this->opaqueReference($evidence['verification_reference'] ?? '');
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


    private function maximumEvidenceAge(string $method): int
    {
        $defaults = [
            'authenticated-session' => 900,
            'verified-email-link' => self::DAY_SECONDS,
            'verified-mobile-otp' => 3600,
            'guardian-verification' => self::DAY_SECONDS,
            'authorized-agent-verification' => self::DAY_SECONDS,
            'manual-document-review' => 7 * self::DAY_SECONDS,
        ];
        $age = (int) apply_filters(
            'spcrc/privacy_verification_maximum_age',
            $defaults[$method] ?? 3600,
            $method
        );
        return max(300, min(7 * self::DAY_SECONDS, $age));
    }

    private function opaqueReference(mixed $value): string
    {
        return Sanitizer::opaqueReference($value);
    }


    /** @param array<string,mixed> $request
     *  @param array<string,mixed> $evidence
     */
    private function verifierAuthorized(array $request, array $evidence): bool
    {
        $method = (string) $evidence['verification_method'];
        $basis = (string) $evidence['authority_basis'];
        $requesterUserId = absint($request['requester_user_id'] ?? 0);
        $verifiedBy = absint($evidence['verified_by_user_id'] ?? 0);
        $actor = get_current_user_id();

        if ($method === 'authenticated-session') {
            return $actor > 0 && $requesterUserId === $actor && $verifiedBy === $actor;
        }

        $operatorAuthorized = $actor > 0
            && $verifiedBy === $actor
            && current_user_can('spcrc_manage_privacy_requests');
        if ($method === 'manual-document-review') {
            return $operatorAuthorized;
        }

        if ($operatorAuthorized) {
            return true;
        }

        return Sanitizer::boolean(apply_filters(
            'spcrc/privacy_verifier_authorized',
            false,
            $actor,
            $verifiedBy,
            $method,
            $basis,
            $requesterUserId,
            (string) $evidence['verification_reference']
        ));
    }

    /** @param array<string,mixed> $request
     *  @param array<string,mixed> $evidence
     */
    private function evidenceConfirmed(array $request, array $evidence): bool
    {
        $method = (string) $evidence['verification_method'];
        $requesterUserId = absint($request['requester_user_id'] ?? 0);
        $verifiedBy = absint($evidence['verified_by_user_id'] ?? 0);

        if ($method === 'manual-document-review') {
            return true;
        }

        if ($method === 'authenticated-session') {
            return $requesterUserId > 0
                && $requesterUserId === $verifiedBy
                && $verifiedBy === get_current_user_id();
        }

        return Sanitizer::boolean(apply_filters(
            'spcrc/privacy_verification_confirmed',
            false,
            $method,
            (string) $evidence['authority_basis'],
            $requesterUserId,
            (string) $evidence['verification_reference'],
            $verifiedBy,
            (string) $evidence['verified_at']
        ));
    }
}
