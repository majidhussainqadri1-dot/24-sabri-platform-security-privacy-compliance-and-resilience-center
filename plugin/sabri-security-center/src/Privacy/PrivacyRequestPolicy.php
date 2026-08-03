<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;
use Sabri\Platform\Security\Support\Sanitizer;

if (! class_exists(AuditGapStore::class, false)) {
    require_once dirname(__DIR__) . '/Storage/AuditGapStore.php';
}

/**
 * Applies verification, destructive-operation, retry and callback policy
 * without duplicating canonical privacy-request storage ownership.
 */
final class PrivacyRequestPolicy
{
    private const VERIFICATION_METHODS = ['authenticated-session', 'email-confirmed', 'manual-document-review', 'guardian-verified', 'authorized-agent-reviewed'];
    private const AUTHORITY_BASES = ['self', 'guardian', 'authorized-agent', 'legal-representative'];
    private const RETRYABLE_REQUEST_STATUSES = ['failed', 'partial', 'recovery-required'];
    private const RETRYABLE_MODULE_STATUSES = ['not-started', 'failed', 'rejected', 'unavailable', 'recovery-required'];
    private const CALLBACK_SOURCE_STATUSES = ['dispatching', 'pending', 'queued', 'accepted', 'recovery-required'];
    private const SAFE_CODE_PREFIX = 'retry-safe-';
    private const DEFAULT_MAX_ATTEMPTS = 5;

    private PrivacyVerificationStore $verification;

    public function __construct(
        private PrivacyRequestRepository $storage,
        ?PrivacyVerificationStore $verification = null
    ) {
        if ($verification === null && ! class_exists(PrivacyVerificationStore::class, false)) {
            require_once __DIR__ . '/PrivacyVerificationStore.php';
        }
        $this->verification = $verification ?? new PrivacyVerificationStore();
    }

    /** @return string[] */
    public static function types(): array
    {
        return PrivacyRequestRepository::types();
    }

    /** @return string[] */
    public static function retryableStatuses(): array
    {
        return PrivacyRequestRepository::retryableStatuses();
    }

    /** @return string[] */
    public static function verificationMethods(): array
    {
        return self::VERIFICATION_METHODS;
    }

    /** @return string[] */
    public static function authorityBases(): array
    {
        return self::AUTHORITY_BASES;
    }

    public static function verificationPairAllowed(string $method, string $basis): bool
    {
        if ($method === 'guardian-verified') {
            return $basis === 'guardian';
        }
        if ($method === 'authorized-agent-reviewed') {
            return in_array($basis, ['authorized-agent', 'legal-representative'], true);
        }
        if (in_array($method, ['authenticated-session', 'email-confirmed'], true)) {
            return $basis === 'self';
        }

        return $method === 'manual-document-review' && in_array($basis, self::AUTHORITY_BASES, true);
    }

    /** @param array<string,mixed> $request
     *  @return array<string,mixed>|\WP_Error
     */
    public function begin(array $request): array|\WP_Error
    {
        $requesterUserId = absint($request['requester_user_id'] ?? 0);
        if ($requesterUserId < 1 || ! get_userdata($requesterUserId)) {
            return new \WP_Error('spcrc_privacy_subject_missing', 'An existing WordPress privacy subject is required before dispatch.');
        }

        $validation = $this->validateVerification($request);
        if (is_wp_error($validation)) {
            return $validation;
        }

        $rawDueAt = is_scalar($request['due_at'] ?? null) ? trim((string) ($request['due_at'] ?? '')) : '';
        if ($rawDueAt !== '' && Sanitizer::isoTime($rawDueAt) === '') {
            return new \WP_Error('spcrc_privacy_due_at_invalid', 'Privacy request due date is invalid.');
        }

        $assignedUserId = absint($request['assigned_user_id'] ?? get_current_user_id());
        if ($assignedUserId < 1 || ! get_userdata($assignedUserId)) {
            return new \WP_Error('spcrc_privacy_assignee_invalid', 'A valid assigned privacy operator is required.');
        }

        // Validate method-specific proof and opaque-reference syntax only after
        // all structural request fields pass. Invalid evidence must leave no
        // canonical row and must not trigger avoidable native proof adapters.
        $validation = $this->verification->validateEvidence(
            $validation,
            ['requester_user_id' => $requesterUserId]
        );
        if (is_wp_error($validation)) {
            return $validation;
        }

        $begin = $this->storage->begin($request);
        if (is_wp_error($begin)) {
            return $begin;
        }

        $requestUuid = Sanitizer::uuid($begin['request_uuid'] ?? '');
        $stored = $this->verification->persist($requestUuid, $validation);
        if (is_wp_error($stored)) {
            $compensated = $this->storage->finalize(
                $requestUuid,
                'recovery-required',
                'dispatching',
                'verification_evidence_storage_failed'
            );

            if (is_wp_error($compensated)) {
                AuditGapStore::record(
                    'spcrc_privacy_audit_gap',
                    'privacy_request',
                    $requestUuid,
                    'verification_compensation_failed',
                    [
                        'verification_error_code' => $stored->get_error_code(),
                        'compensation_error_code' => $compensated->get_error_code(),
                    ]
                );
                do_action('spcrc/privacy_verification_compensation_failed', $requestUuid, $stored, $compensated);
                return new \WP_Error(
                    'spcrc_privacy_verification_compensation_failed',
                    'Verification evidence and the recovery-required compensation state could not be stored. The request is blocked pending reconciliation.'
                );
            }

            AuditGapStore::record(
                'spcrc_privacy_audit_gap',
                'privacy_request',
                $requestUuid,
                'verification_evidence_storage_failed',
                ['verification_error_code' => $stored->get_error_code()]
            );
            do_action('spcrc/privacy_verification_storage_failed', $requestUuid, $stored);
            return $stored;
        }

        return array_merge($begin, $validation);
    }

    public function claimModule(string $requestUuid, string $moduleKey): bool|\WP_Error
    {
        return $this->storage->claimModule($requestUuid, $moduleKey);
    }

    /** @param array<string,mixed> $result */
    public function storeModuleResult(string $requestUuid, string $moduleKey, array $result): bool|\WP_Error
    {
        return $this->storage->storeModuleResult($requestUuid, $moduleKey, $this->encodeRetrySafety($result));
    }

    public function finalize(string $requestUuid, string $status, string $expectedStatus = 'dispatching', string $lastErrorCode = ''): bool|\WP_Error
    {
        return $this->storage->finalize($requestUuid, $status, $expectedStatus, $lastErrorCode);
    }

    /** @param array<string,mixed> $authorization
     *  @return array<string,mixed>|\WP_Error
     */
    public function claimRetry(string $requestUuid, int $assignedUserId, array $authorization = []): array|\WP_Error
    {
        $record = $this->get($requestUuid);
        if ($record === null) {
            return new \WP_Error('spcrc_privacy_request_missing', 'Privacy request could not be found.');
        }

        $destructiveAuthorized = $this->deletionRetryAuthorized($record, $authorization);
        $eligibility = $this->retryEligibility($record, $destructiveAuthorized);
        if (! $eligibility['eligible']) {
            $messages = [
                'status-not-retryable' => 'Privacy request status does not permit retry.',
                'verification-missing' => 'Verified identity-and-authority evidence is missing. Legacy request requires manual reconciliation.',
                'attempt-limit' => 'Privacy request reached the bounded retry-attempt limit.',
                'retry-time-invalid' => 'Privacy request retry timing is missing or invalid.',
                'not-due' => 'Privacy request retry is not due yet.',
                'deletion-reauthorization-required' => 'Deletion retry requires a fresh exact destructive confirmation.',
                'manual-reconciliation' => 'No safely retryable module result is available. Manual reconciliation is required.',
            ];
            $codes = [
                'status-not-retryable' => 'spcrc_privacy_retry_forbidden',
                'verification-missing' => 'spcrc_privacy_retry_verification_missing',
                'attempt-limit' => 'spcrc_privacy_retry_attempt_limit',
                'retry-time-invalid' => 'spcrc_privacy_retry_time_invalid',
                'not-due' => 'spcrc_privacy_retry_not_due',
                'deletion-reauthorization-required' => 'spcrc_privacy_deletion_retry_confirmation_required',
                'manual-reconciliation' => 'spcrc_privacy_retry_modules_missing',
            ];
            return new \WP_Error(
                $codes[$eligibility['code']] ?? 'spcrc_privacy_retry_forbidden',
                $messages[$eligibility['code']] ?? 'Privacy request cannot be retried safely.'
            );
        }

        if ($assignedUserId < 1 || ! get_userdata($assignedUserId)) {
            return new \WP_Error('spcrc_privacy_retry_assignee_invalid', 'A valid assigned privacy operator is required for retry.');
        }

        $claimed = $this->storage->claimRetry($requestUuid, $assignedUserId);
        return is_wp_error($claimed) ? $claimed : $this->verification->enrich($claimed);
    }

    /** @param array<string,mixed> $result
     *  @return array<string,mixed>|\WP_Error
     */
    public function completeModule(string $requestUuid, string $moduleKey, array $result): array|\WP_Error
    {
        $moduleKey = Sanitizer::key($moduleKey, 120);
        $record = $this->storage->get($requestUuid);
        $moduleResults = $this->storage->moduleResults($requestUuid);
        if ($record === null || $moduleKey === '' || ! isset($moduleResults[$moduleKey])) {
            return new \WP_Error('spcrc_privacy_callback_invalid', 'Privacy completion callback is invalid.');
        }

        $callbackReference = Sanitizer::opaqueReference($result['callback_reference'] ?? '');
        $actor = get_current_user_id();
        $callbackAuthorized = $callbackReference !== '' && Sanitizer::boolean(apply_filters(
            'spcrc/authorize_privacy_module_callback',
            false,
            $actor,
            $requestUuid,
            $moduleKey,
            $callbackReference,
            $result
        ));
        if (! $callbackAuthorized) {
            return new \WP_Error(
                'spcrc_privacy_callback_forbidden',
                'Native privacy completion requires an authenticated, module-bound callback authority reference.'
            );
        }
        unset($result['callback_reference']);

        $requestStatus = Sanitizer::key($record['status'] ?? '', 40);
        if (! in_array($requestStatus, ['dispatching', 'pending', 'partial', 'recovery-required'], true)) {
            return new \WP_Error('spcrc_privacy_callback_closed', 'Privacy request is not open for module completion.');
        }

        $sourceStatus = Sanitizer::key($moduleResults[$moduleKey]['status'] ?? '', 40);
        if (! in_array($sourceStatus, self::CALLBACK_SOURCE_STATUSES, true)) {
            return new \WP_Error(
                'spcrc_privacy_callback_module_unclaimed',
                'Native completion evidence cannot be recorded before the module operation has been claimed.'
            );
        }

        $status = Sanitizer::key($result['status'] ?? '', 40);
        $retrySafe = Sanitizer::boolean($result['retry_safe'] ?? false);
        if ($status === 'failed' && ! $retrySafe) {
            $result = [
                'ok' => false,
                'status' => 'failed',
                'code' => 'manual-reconciliation-required',
                'reference' => $result['reference'] ?? '',
                'message' => 'Native failure was stored, but retry safety was not confirmed. Manual reconciliation is required.',
                'retry_safe' => false,
            ];
        }

        return $this->storage->completeModule($requestUuid, $moduleKey, $this->encodeRetrySafety($result));
    }

    public function markStaleDispatching(int $ageSeconds = 900, int $limit = 100): int|\WP_Error
    {
        return $this->storage->markStaleDispatching($ageSeconds, $limit);
    }

    /** @return array<string,array<string,mixed>> */
    public function moduleResults(string $requestUuid): array
    {
        return $this->storage->moduleResults($requestUuid);
    }

    /** @return array<string,mixed>|null */
    public function get(string $requestUuid): ?array
    {
        $record = $this->storage->get($requestUuid);
        return $record === null ? null : $this->verification->enrich($record);
    }

    public function activeCount(): int
    {
        return $this->storage->activeCount();
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(int $limit = 50): array
    {
        return array_map(
            fn (array $row): array => $this->verification->enrich($row),
            $this->storage->recent($limit)
        );
    }

    /** @param array<string,array<string,mixed>> $results
     *  @return array{ok:bool,status:string}
     */
    public static function aggregateResults(array $results): array
    {
        return PrivacyRequestRepository::aggregateResults($results);
    }

    /** @param array<string,mixed> $record
     *  @return array{eligible:bool,code:string,retry_at:string,retry_modules:int}
     */
    public function retryEligibility(array $record, bool $destructiveAuthorized = false): array
    {
        $status = Sanitizer::key($record['status'] ?? '', 40);
        if (! in_array($status, self::RETRYABLE_REQUEST_STATUSES, true)) {
            return ['eligible' => false, 'code' => 'status-not-retryable', 'retry_at' => '', 'retry_modules' => 0];
        }

        $record = $this->verification->enrich($record);
        if (! $this->verification->hasEvidence($record)) {
            return ['eligible' => false, 'code' => 'verification-missing', 'retry_at' => '', 'retry_modules' => 0];
        }

        if (absint($record['dispatch_attempts'] ?? 0) >= $this->maxAttempts()) {
            return ['eligible' => false, 'code' => 'attempt-limit', 'retry_at' => '', 'retry_modules' => 0];
        }

        $retryAt = trim((string) ($record['next_retry_at'] ?? ''));
        $retryTimestamp = $retryAt === '' ? false : strtotime($retryAt . ' UTC');
        if ($retryTimestamp === false) {
            return ['eligible' => false, 'code' => 'retry-time-invalid', 'retry_at' => '', 'retry_modules' => 0];
        }
        if ($retryTimestamp > time()) {
            return ['eligible' => false, 'code' => 'not-due', 'retry_at' => $retryAt, 'retry_modules' => 0];
        }

        if (Sanitizer::key($record['request_type'] ?? '', 40) === 'deletion' && ! $destructiveAuthorized) {
            return ['eligible' => false, 'code' => 'deletion-reauthorization-required', 'retry_at' => '', 'retry_modules' => 0];
        }

        $results = $this->storage->moduleResults((string) ($record['request_uuid'] ?? ''));
        $safe = 0;
        $unsafe = 0;
        foreach ($results as $result) {
            $moduleStatus = Sanitizer::key($result['status'] ?? '', 40);
            if (! in_array($moduleStatus, self::RETRYABLE_MODULE_STATUSES, true)) {
                continue;
            }
            if ($moduleStatus === 'not-started' || str_starts_with(Sanitizer::key($result['code'] ?? '', 120), self::SAFE_CODE_PREFIX)) {
                ++$safe;
            } else {
                ++$unsafe;
            }
        }

        if ($safe === 0 || $unsafe > 0) {
            return ['eligible' => false, 'code' => 'manual-reconciliation', 'retry_at' => '', 'retry_modules' => 0];
        }

        return ['eligible' => true, 'code' => 'ready', 'retry_at' => $retryAt, 'retry_modules' => $safe];
    }

    /** @param array<string,mixed> $request
     *  @return array<string,mixed>|\WP_Error
     */
    private function validateVerification(array $request): array|\WP_Error
    {
        if (! Sanitizer::boolean($request['verification_attested'] ?? false)) {
            return new \WP_Error('spcrc_privacy_verification_attestation_required', 'Explicit identity-and-authority verification attestation is required before dispatch.');
        }

        $method = Sanitizer::key($request['verification_method'] ?? '', 40);
        $basis = Sanitizer::key($request['authority_basis'] ?? '', 40);
        $reference = Sanitizer::text($request['verification_reference'] ?? '', 200);
        $verifiedBy = absint($request['verified_by_user_id'] ?? 0);
        $verifiedAt = Sanitizer::isoTime($request['verified_at'] ?? '');
        $verifiedTimestamp = $verifiedAt === '' ? false : strtotime($verifiedAt);

        if (! in_array($method, self::VERIFICATION_METHODS, true)) {
            return new \WP_Error('spcrc_privacy_verification_method_invalid', 'Privacy verification method is invalid.');
        }
        if (! in_array($basis, self::AUTHORITY_BASES, true)) {
            return new \WP_Error('spcrc_privacy_authority_basis_invalid', 'Privacy request authority basis is invalid.');
        }
        if (! self::verificationPairAllowed($method, $basis)) {
            return new \WP_Error('spcrc_privacy_verification_authority_mismatch', 'Verification method does not support the selected authority basis.');
        }
        if ($reference === '') {
            return new \WP_Error('spcrc_privacy_verification_reference_required', 'A bounded opaque verification reference is required. Raw identity documents must not be stored here.');
        }
        if ($verifiedBy < 1 || ! get_userdata($verifiedBy)) {
            return new \WP_Error('spcrc_privacy_verifier_invalid', 'A valid verifying operator is required before dispatch.');
        }
        if ($verifiedTimestamp === false || $verifiedTimestamp > time() + 300) {
            return new \WP_Error('spcrc_privacy_verified_at_invalid', 'A valid, non-future verification timestamp is required before dispatch.');
        }

        return [
            'verification_method' => $method,
            'authority_basis' => $basis,
            'verification_reference' => $reference,
            'verified_by_user_id' => $verifiedBy,
            'verified_at' => gmdate('c', $verifiedTimestamp),
        ];
    }

    /** @param array<string,mixed> $record
     *  @param array<string,mixed> $authorization
     */
    private function deletionRetryAuthorized(array $record, array $authorization): bool
    {
        if (Sanitizer::key($record['request_type'] ?? '', 40) !== 'deletion') {
            return true;
        }

        $uuid = Sanitizer::uuid($record['request_uuid'] ?? '');
        $confirmation = is_scalar($authorization['deletion_confirmation'] ?? null)
            ? trim((string) $authorization['deletion_confirmation'])
            : '';
        $stepUpReference = Sanitizer::opaqueReference($authorization['step_up_reference'] ?? '');
        $actor = get_current_user_id();
        $stepUpOk = $uuid !== ''
            && $actor > 0
            && $stepUpReference !== ''
            && Sanitizer::boolean(apply_filters(
                'spcrc/verify_step_up_assurance',
                false,
                $actor,
                'privacy:deletion-retry',
                $stepUpReference
            ));
        return $stepUpOk && hash_equals('RETRY DELETION ' . $uuid, $confirmation);
    }

    /** @param array<string,mixed> $result
     *  @return array<string,mixed>
     */
    private function encodeRetrySafety(array $result): array
    {
        $status = Sanitizer::key($result['status'] ?? '', 40);
        $retrySafe = Sanitizer::boolean($result['retry_safe'] ?? false)
            && in_array($status, ['failed', 'rejected', 'unavailable', 'recovery-required'], true);
        $code = Sanitizer::key($result['code'] ?? '', 120);
        if ($retrySafe && ! str_starts_with($code, self::SAFE_CODE_PREFIX)) {
            $code = self::SAFE_CODE_PREFIX . ($code !== '' ? $code : 'native-failure');
        }
        $result['code'] = $code;
        unset($result['retry_safe']);
        return $result;
    }

    private function maxAttempts(): int
    {
        return max(1, min(20, (int) apply_filters('spcrc/privacy_max_dispatch_attempts', self::DEFAULT_MAX_ATTEMPTS)));
    }
}
