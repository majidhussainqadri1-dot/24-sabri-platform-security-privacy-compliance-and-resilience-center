<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditGapStore.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/GovernanceRepository.php';

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\GovernanceRepository;

$assertions = 0;
function expectCycle35(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$repo = new GovernanceRepository(new AuditLogger());
$data = [
    'decision_type' => 'policy-exception',
    'subject_key' => 'cycle35-subject',
    'module_key' => 'file-24-security-center',
    'evidence_ref' => 'case:cycle35-evidence',
    'rationale' => 'A bounded test rationale for lock-lease verification.',
    'expires_at' => gmdate('c', time() + 3600),
];

$GLOBALS['wpdb']->stealGovernanceLockOnInsert = true;
$result = $repo->request($data);
expectCycle35(is_wp_error($result), 'Lease loss after insert must fail the governance request.');
expectCycle35($result->get_error_code() === 'spcrc_governance_request_lock_lost_after_write', 'Lease loss must have a dedicated failure code.');
expectCycle35($GLOBALS['wpdb']->governance === [], 'The unaudited request must be rolled back after lease loss.');
expectCycle35($GLOBALS['wpdb']->events === [], 'Lease-lost request must not emit a canonical success audit event.');
expectCycle35(get_option('spcrc_governance_audit_gap', []) === [], 'Successful rollback must not create a false audit gap.');

unset($GLOBALS['wp_options']['spcrc_governance_request_lock_' . substr(hash('sha256', 'policy-exception|cycle35-subject'), 0, 32)]);
$ok = $repo->request($data);
expectCycle35(is_string($ok), 'A request with a continuously owned lease must succeed.');
expectCycle35(count($GLOBALS['wpdb']->governance) === 1, 'Successful request must create exactly one governance row.');
expectCycle35(count($GLOBALS['wpdb']->events) === 1, 'Successful request must create exactly one audit event.');

printf("PASS: %d Cycle 35 governance-request lease assertions\n", $assertions);
