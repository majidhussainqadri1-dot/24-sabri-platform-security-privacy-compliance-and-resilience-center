<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Support/AtomicOptionLock.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Storage/AuditGapStore.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once __DIR__ . '/../plugin/sabri-security-center/src/Storage/GovernanceRepository.php';

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\GovernanceRepository;

$assertions = 0;
$assert = static function (bool $condition, string $message) use (&$assertions): void {
    if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    ++$assertions;
};

$request = [
    'decision_type' => 'policy-exception',
    'subject_key' => 'file-22-composer',
    'module_key' => 'file-24-security-center',
    'evidence_ref' => 'vault:governance:exception-1',
    'rationale' => 'A bounded staging exception is requested for verified testing.',
    'expires_at' => gmdate('c', time() + 3600),
];
$lockName = 'spcrc_governance_request_lock_' . substr(hash('sha256', 'policy-exception|file-22-composer'), 0, 32);
$repo = new GovernanceRepository(new AuditLogger());

$GLOBALS['wp_options'][$lockName] = ['token' => 'active-owner', 'expires_at' => time() + 60];
$blocked = $repo->request($request);
$assert(is_wp_error($blocked) && $blocked->get_error_code() === 'spcrc_governance_request_locked', 'Active subject lock must fail closed.');
$assert($GLOBALS['wpdb']->governance === [], 'Contended request must not create a governance row.');
$assert(($GLOBALS['wp_options'][$lockName]['token'] ?? '') === 'active-owner', 'Contended request must not delete another owner lock.');

$GLOBALS['wp_options'][$lockName] = ['token' => 'expired-owner', 'expires_at' => time() - 1];
$created = $repo->request($request);
$assert(is_string($created) && $created !== '', 'Expired subject lock must be reclaimed atomically.');
$assert(count($GLOBALS['wpdb']->governance) === 1, 'Exactly one governance row must be created.');
$assert(! array_key_exists($lockName, $GLOBALS['wp_options']), 'Owner lock must be released by exact token after completion.');

$duplicate = $repo->request($request);
$assert(is_wp_error($duplicate) && $duplicate->get_error_code() === 'spcrc_governance_duplicate_pending', 'Second pending request must be rejected under the same subject lock.');
$assert(count($GLOBALS['wpdb']->governance) === 1, 'Duplicate rejection must preserve one canonical pending request.');

$GLOBALS['wp_options'][$lockName] = 'corrupt-lock';
$malformed = $repo->request(array_merge($request, ['subject_key' => 'file-22-composer']));
$assert(is_wp_error($malformed) && $malformed->get_error_code() === 'spcrc_governance_request_locked', 'Malformed lock must fail closed rather than be overwritten.');
$assert($GLOBALS['wp_options'][$lockName] === 'corrupt-lock', 'Malformed lock evidence must remain available for repair.');

echo "PASS: {$assertions} Cycle 23 governance request-lock assertions\n";
