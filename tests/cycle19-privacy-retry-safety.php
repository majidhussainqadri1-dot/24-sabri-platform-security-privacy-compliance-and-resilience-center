<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/PrivacyRequestRepository.php';

use Sabri\Platform\Security\Storage\PrivacyRequestRepository;

$assertions = 0;
function expectCycle19(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

/** @param array<string,array<string,mixed>> $results */
function seedPrivacyRetry(string $uuid, array $results, string $status = 'partial'): void
{
    global $wpdb;
    $wpdb->privacy[$uuid] = [
        'request_uuid' => $uuid,
        'requester_user_id' => 11,
        'request_type' => 'deletion',
        'status' => $status,
        'assigned_user_id' => 7,
        'jurisdiction' => 'PK',
        'due_at' => null,
        'module_results_json' => wp_json_encode($results, JSON_UNESCAPED_SLASHES),
        'dispatch_attempts' => 1,
        'lock_version' => 3,
        'next_retry_at' => current_time('mysql', true),
        'last_error_code' => 'module_failed',
        'completed_at' => null,
        'created_at' => current_time('mysql', true),
        'updated_at' => current_time('mysql', true),
    ];
}

$repository = new PrivacyRequestRepository();
$uuid = '00000000-0000-4000-8000-000000000019';
seedPrivacyRetry($uuid, [
    'file-safe' => [
        'ok' => false,
        'status' => 'failed',
        'code' => 'retry-safe-provider-timeout',
        'reference' => 'opaque-safe-ref',
        'message' => 'Provider timed out before a destructive side effect.',
    ],
    'file-unsafe' => [
        'ok' => false,
        'status' => 'failed',
        'code' => 'manual-reconciliation-required',
        'reference' => 'opaque-unsafe-ref',
        'message' => 'Outcome is uncertain and must not be replayed.',
    ],
    'file-not-started' => [
        'ok' => false,
        'status' => 'not-started',
        'code' => '',
        'reference' => '',
        'message' => '',
    ],
    'file-complete' => [
        'ok' => true,
        'status' => 'completed',
        'code' => 'completed',
        'reference' => 'opaque-complete-ref',
        'message' => 'Completed.',
    ],
]);

$claimed = $repository->claimRetry($uuid, 23);
expectCycle19(! is_wp_error($claimed), 'A request with explicitly safe modules must be claimable.');
expectCycle19(($claimed['status'] ?? '') === 'dispatching', 'A successful retry claim must move the request to dispatching.');
expectCycle19(($claimed['assigned_user_id'] ?? 0) === 23, 'A successful retry claim must bind the validated operator.');
expectCycle19(($claimed['retry_modules'] ?? []) === ['file-safe', 'file-not-started'], 'Only not-started and explicitly retry-safe modules may be replayed.');
expectCycle19(($claimed['module_results']['file-safe']['status'] ?? '') === 'not-started', 'The explicitly safe failed module must reset to not-started.');
expectCycle19(($claimed['module_results']['file-safe']['code'] ?? 'x') === '', 'Reset retry-safe modules must clear the prior retry code.');
expectCycle19(($claimed['module_results']['file-unsafe']['status'] ?? '') === 'failed', 'An uncertain failed module must remain failed and must not be replayed.');
expectCycle19(($claimed['module_results']['file-unsafe']['code'] ?? '') === 'manual-reconciliation-required', 'Unsafe failure evidence must remain intact.');
expectCycle19(($claimed['module_results']['file-complete']['status'] ?? '') === 'completed', 'Completed module evidence must remain immutable.');
expectCycle19((int) ($wpdb->privacy[$uuid]['dispatch_attempts'] ?? 0) === 2, 'A successful retry claim must increment the dispatch attempt once.');

$unsafeUuid = '00000000-0000-4000-8000-000000000119';
seedPrivacyRetry($unsafeUuid, [
    'file-unsafe' => [
        'ok' => false,
        'status' => 'recovery-required',
        'code' => 'manual-reconciliation-required',
        'reference' => 'opaque-uncertain-ref',
        'message' => 'Unknown outcome.',
    ],
]);
$unsafe = $repository->claimRetry($unsafeUuid, 23);
expectCycle19(is_wp_error($unsafe), 'A request with no provably safe module must fail closed.');
expectCycle19($unsafe->get_error_code() === 'spcrc_privacy_retry_modules_missing', 'Unsafe-only retry rejection must use the canonical error code.');
expectCycle19(($wpdb->privacy[$unsafeUuid]['status'] ?? '') === 'partial', 'Unsafe-only rejection must not mutate canonical request state.');

$invalidAssigneeUuid = '00000000-0000-4000-8000-000000000219';
seedPrivacyRetry($invalidAssigneeUuid, [
    'file-safe' => [
        'ok' => false,
        'status' => 'failed',
        'code' => 'retry-safe-provider-timeout',
        'reference' => 'opaque-safe-ref',
        'message' => 'Safe to retry.',
    ],
]);
$invalidAssignee = $repository->claimRetry($invalidAssigneeUuid, 0);
expectCycle19(is_wp_error($invalidAssignee), 'Storage-layer retry claims must reject an invalid operator.');
expectCycle19($invalidAssignee->get_error_code() === 'spcrc_privacy_retry_assignee_invalid', 'Invalid operator rejection must use the canonical error code.');
expectCycle19(($wpdb->privacy[$invalidAssigneeUuid]['status'] ?? '') === 'partial', 'Invalid operator rejection must not mutate request state.');

$source = (string) file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/PrivacyRequestRepository.php');
expectCycle19(str_contains($source, "private const SAFE_CODE_PREFIX = 'retry-safe-';"), 'The storage boundary must define the canonical retry-safe code prefix.');
expectCycle19(str_contains($source, 'str_starts_with($code, self::SAFE_CODE_PREFIX)'), 'The storage boundary must enforce the retry-safe prefix, not merely the dispatcher policy.');
expectCycle19(str_contains($source, '! get_userdata($assignedUserId)'), 'The storage boundary must validate the retry operator independently.');

echo "PASS: {$assertions} Cycle 19 privacy-retry safety assertions\n";
