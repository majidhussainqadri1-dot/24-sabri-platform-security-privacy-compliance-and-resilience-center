<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
$base = __DIR__ . '/../plugin/sabri-security-center/src/';
require_once $base . 'Support/Sanitizer.php';
require_once $base . 'Support/AtomicOptionLock.php';
require_once $base . 'Storage/AuditGapStore.php';
require_once $base . 'Storage/AuditLogger.php';
require_once $base . 'Storage/ControlRepository.php';

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\ControlRepository;

$assertions = 0;
$assert = static function (bool $condition, string $message) use (&$assertions): void {
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
    ++$assertions;
};

$source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Storage/ControlRepository.php');
$assert(str_contains($source, 'AtomicOptionLock::acquire'), 'Control upserts must acquire an atomic subject lock.');
$assert(substr_count($source, 'AtomicOptionLock::refresh') >= 3, 'Control ownership must be refreshed before write, audit and rollback.');
$assert(str_contains($source, 'control_lock_lost_after_write'), 'Post-write ownership loss must create a bounded audit gap.');
$assert(str_contains($source, "['control_key' => \$key, 'updated_at' => \$now]"), 'Audit rollback must be compare-bound to the row written by this request.');

$GLOBALS['wpdb'] = new FakeWpdb();
$repo = new ControlRepository(new AuditLogger());
$key = 'access-control-review';
$lockOption = 'spcrc_control_lock_' . substr(hash('sha256', $key), 0, 32);
$GLOBALS['wp_options'][$lockOption] = ['token' => 'other-owner', 'expires_at' => time() + 60];
$locked = $repo->upsert([
    'control_key' => $key,
    'title' => 'Access control review',
    'framework' => 'NIST',
    'status' => 'implemented',
]);
$assert(is_wp_error($locked) && $locked->get_error_code() === 'spcrc_control_locked', 'An active subject lock must block a concurrent control upsert.');
$assert($GLOBALS['wpdb']->controls === [], 'A contended control upsert must not write a row.');

$GLOBALS['wp_options'][$lockOption] = ['token' => 'expired-owner', 'expires_at' => time() - 1];
$created = $repo->upsert([
    'control_key' => $key,
    'title' => 'Access control review',
    'framework' => 'NIST',
    'status' => 'implemented',
]);
$assert($created === $key, 'An expired control lock must be reclaimed atomically.');
$assert(! isset($GLOBALS['wp_options'][$lockOption]), 'The control lock must be released by its owner after success.');

$GLOBALS['wpdb']->stealControlLockOnWrite = true;
$lost = $repo->upsert([
    'control_key' => $key,
    'title' => 'Access control review updated',
    'framework' => 'NIST',
    'status' => 'implemented',
]);
$assert(is_wp_error($lost) && $lost->get_error_code() === 'spcrc_control_lock_lost_after_write', 'A stolen post-write lock must fail closed before audit completion.');
$gaps = get_option('spcrc_control_audit_gap', []);
$assert(is_array($gaps) && count($gaps) === 1, 'Post-write ownership loss must be recorded as one bounded control audit gap.');

$GLOBALS['wp_options'] = [];
$GLOBALS['wpdb'] = new FakeWpdb();
$repo = new ControlRepository(new AuditLogger());
$repo->upsert([
    'control_key' => $key,
    'title' => 'Original title',
    'framework' => 'NIST',
    'status' => 'implemented',
]);
$GLOBALS['wpdb']->failAuditInsert = true;
$failed = $repo->upsert([
    'control_key' => $key,
    'title' => 'Un-audited replacement',
    'framework' => 'NIST',
    'status' => 'implemented',
]);
$assert(is_wp_error($failed) && $failed->get_error_code() === 'spcrc_control_audit_failed', 'Audit failure must return the canonical control audit error.');
$assert(($GLOBALS['wpdb']->controls[$key]['title'] ?? '') === 'Original title', 'Audit failure must restore the exact pre-write control state while ownership is held.');
$assert(! isset($GLOBALS['wp_options'][$lockOption]), 'The control lock must be released after rollback.');

fwrite(STDOUT, "PASS: {$assertions} Cycle 28 control-upsert concurrency assertions\n");
