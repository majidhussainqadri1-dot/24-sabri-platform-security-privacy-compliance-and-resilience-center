<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
$base = __DIR__ . '/../plugin/sabri-security-center/src/';
require_once $base . 'Support/Sanitizer.php';
require_once $base . 'Support/AtomicOptionLock.php';
require_once $base . 'Storage/AuditGapStore.php';
require_once $base . 'Storage/PrivacyRequestRepository.php';
require_once $base . 'Privacy/PrivacyVerificationStore.php';
require_once $base . 'Privacy/PrivacyRequestPolicy.php';

use Sabri\Platform\Security\Privacy\PrivacyRequestPolicy;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;

$assertions = 0;
$assert = static function (bool $condition, string $message) use (&$assertions): void {
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
    ++$assertions;
};

$request = static function (string $uuid): array {
    return [
        'request_uuid' => $uuid,
        'request_type' => 'access',
        'requester_user_id' => 7,
        'assigned_user_id' => 7,
        'module_keys' => ['file-24-security-center'],
        'verification_method' => 'manual-document-review',
        'authority_basis' => 'self',
        'verification_reference' => 'case:cycle29-verification',
        'verified_by_user_id' => 7,
        'verified_at' => gmdate('c'),
        'verification_attested' => true,
    ];
};

$source = file_get_contents($base . 'Privacy/PrivacyRequestPolicy.php');
$assert(str_contains($source, '$compensated = $this->storage->finalize('), 'Verification persistence failure must capture its compensation result.');
$assert(str_contains($source, "'verification_compensation_failed'"), 'Failed compensation must create a dedicated bounded gap reason.');
$assert(str_contains($source, "'spcrc_privacy_verification_compensation_failed'"), 'Failed compensation must return a dedicated canonical error.');
$assert(substr_count($source, 'AuditGapStore::record(') >= 2, 'Both successful and failed compensation paths must create reconciliation evidence.');

$GLOBALS['wpdb'] = new FakeWpdb();
$GLOBALS['wp_options'] = [];
$GLOBALS['wpdb']->failPrivacyVerificationUpdate = true;
$repository = new PrivacyRequestRepository();
$policy = new PrivacyRequestPolicy($repository);
$uuid = '90000000-0000-4000-8000-000000000001';
$result = $policy->begin($request($uuid));
$assert(is_wp_error($result) && $result->get_error_code() === 'spcrc_privacy_verification_write_failed', 'Successful compensation must preserve the original verification-storage error.');
$row = $repository->get($uuid);
$assert(($row['status'] ?? '') === 'recovery-required', 'Verification storage failure must durably move the request out of dispatching state.');
$assert(($row['last_error_code'] ?? '') === 'verification_evidence_storage_failed', 'Recovery state must preserve the bounded verification failure code.');
$gaps = AuditGapStore::all('spcrc_privacy_audit_gap');
$assert(count($gaps) === 1, 'Verification storage failure must create exactly one bounded privacy gap.');
$gap = reset($gaps);
$assert(($gap['reason'] ?? '') === 'verification_evidence_storage_failed', 'Successful compensation gap must identify the original evidence-storage failure.');

$GLOBALS['wpdb'] = new FakeWpdb();
$GLOBALS['wp_options'] = [];
$GLOBALS['wpdb']->failPrivacyVerificationUpdate = true;
$GLOBALS['wpdb']->failPrivacyFinalizeUpdate = true;
$repository = new PrivacyRequestRepository();
$policy = new PrivacyRequestPolicy($repository);
$uuid = '90000000-0000-4000-8000-000000000002';
$result = $policy->begin($request($uuid));
$assert(is_wp_error($result) && $result->get_error_code() === 'spcrc_privacy_verification_compensation_failed', 'Failed compensation must return the dedicated release-blocking error.');
$row = $repository->get($uuid);
$assert(($row['status'] ?? '') === 'dispatching', 'A failed compensation must not falsely claim recovery-required persistence.');
$assert(empty($row['verification_reference']), 'Failed verification persistence must not leave partial evidence fields.');
$gaps = AuditGapStore::all('spcrc_privacy_audit_gap');
$assert(count($gaps) === 1, 'Failed compensation must create exactly one bounded privacy audit gap.');
$gap = reset($gaps);
$assert(($gap['reason'] ?? '') === 'verification_compensation_failed', 'Gap reason must distinguish compensation failure from ordinary evidence failure.');
$assert(($gap['context']['verification_error_code'] ?? '') === 'spcrc_privacy_verification_write_failed', 'Gap context must preserve the bounded verification error code.');
$assert(($gap['context']['compensation_error_code'] ?? '') === 'spcrc_privacy_finalize_failed', 'Gap context must preserve the bounded compensation error code.');
$assert(array_filter($GLOBALS['wp_actions'], static fn(array $entry): bool => ($entry[0] ?? '') === 'spcrc/privacy_verification_compensation_failed') !== [], 'Failed compensation must emit an operational escalation action.');

fwrite(STDOUT, "PASS: {$assertions} Cycle 29 privacy-verification compensation assertions\n");
