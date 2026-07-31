<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Storage\PrivacyRequestRepository;
use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Applies retry and callback policy without duplicating File 24 storage ownership.
 * Storage remains canonical in PrivacyRequestRepository.
 */
final class PrivacyRequestPolicy
{
    private const RETRYABLE_REQUEST_STATUSES = ['failed', 'partial', 'recovery-required'];
    private const RETRYABLE_MODULE_STATUSES = ['not-started', 'failed', 'rejected', 'unavailable', 'recovery-required'];
    private const CALLBACK_SOURCE_STATUSES = ['dispatching', 'pending', 'queued', 'accepted', 'recovery-required'];
    private const SAFE_CODE_PREFIX = 'retry-safe-';
    private const DEFAULT_MAX_ATTEMPTS = 5;

    public function __construct(private PrivacyRequestRepository $storage)
    {
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

    /** @param array<string,mixed> $request
     *  @return array<string,mixed>|\WP_Error
     */
    public function begin(array $request): array|\WP_Error
    {
        return $this->storage->begin($request);
    }

    public function claimModule(string $requestUuid, string $moduleKey): true|\WP_Error
    {
        return $this->storage->claimModule($requestUuid, $moduleKey);
    }

    /** @param array<string,mixed> $result */
    public function storeModuleResult(string $requestUuid, string $moduleKey, array $result): true|\WP_Error
    {
        return $this->storage->storeModuleResult($requestUuid, $moduleKey, $this->encodeRetrySafety($result));
    }

    public function finalize(string $requestUuid, string $status, string $expectedStatus = 'dispatching', string $lastErrorCode = ''): true|\WP_Error
    {
        return $this->storage->finalize($requestUuid, $status, $expectedStatus, $lastErrorCode);
    }

    /** @return array<string,mixed>|\WP_Error */
    public function claimRetry(string $requestUuid, int $assignedUserId): array|\WP_Error
    {
        $record = $this->storage->get($requestUuid);
        if ($record === null) {
            return new \WP_Error('spcrc_privacy_request_missing', 'Privacy request could not be found.');
        }

        $eligibility = $this->retryEligibility($record);
        if (! $eligibility['eligible']) {
            $messages = [
                'status-not-retryable' => 'Privacy request status does not permit retry.',
                'attempt-limit' => 'Privacy request reached the bounded retry-attempt limit.',
                'not-due' => 'Privacy request retry is not due yet.',
                'manual-reconciliation' => 'No safely retryable module result is available. Manual reconciliation is required.',
            ];
            $codes = [
                'status-not-retryable' => 'spcrc_privacy_retry_forbidden',
                'attempt-limit' => 'spcrc_privacy_retry_attempt_limit',
                'not-due' => 'spcrc_privacy_retry_not_due',
                'manual-reconciliation' => 'spcrc_privacy_retry_modules_missing',
            ];
            return new \WP_Error(
                $codes[$eligibility['code']] ?? 'spcrc_privacy_retry_forbidden',
                $messages[$eligibility['code']] ?? 'Privacy request cannot be retried safely.'
            );
        }

        return $this->storage->claimRetry($requestUuid, $assignedUserId);
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
        return $this->storage->get($requestUuid);
    }

    public function activeCount(): int
    {
        return $this->storage->activeCount();
    }

    /** @return array<int,array<string,mixed>> */
    public function recent(int $limit = 50): array
    {
        return $this->storage->recent($limit);
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
    public function retryEligibility(array $record): array
    {
        $status = Sanitizer::key($record['status'] ?? '', 40);
        if (! in_array($status, self::RETRYABLE_REQUEST_STATUSES, true)) {
            return ['eligible' => false, 'code' => 'status-not-retryable', 'retry_at' => '', 'retry_modules' => 0];
        }

        if (absint($record['dispatch_attempts'] ?? 0) >= $this->maxAttempts()) {
            return ['eligible' => false, 'code' => 'attempt-limit', 'retry_at' => '', 'retry_modules' => 0];
        }

        $retryAt = (string) ($record['next_retry_at'] ?? '');
        $retryTimestamp = $retryAt === '' ? false : strtotime($retryAt . ' UTC');
        if ($retryTimestamp !== false && $retryTimestamp > time()) {
            return ['eligible' => false, 'code' => 'not-due', 'retry_at' => $retryAt, 'retry_modules' => 0];
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
