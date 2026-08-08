<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Privacy\DataGovernanceRegistry;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;

function c175(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$data = new DataGovernanceRegistry($registry);
$base = [
    'ledger_key' => 'cycle175-ledger',
    'module_key' => 'file-17-network',
    'subject_ref' => 'subject:cycle175',
    'request_ref' => 'privacy:cycle175',
    'deletion_scope' => ['messages'],
    'expected_version' => 0,
];

$negative = $data->recordDeletionObligation($base + ['attempts' => -3]);
c175(is_wp_error($negative) && $negative->get_error_code() === 'spcrc_deletion_attempts_invalid', 'Negative deletion attempt counters must fail closed rather than resetting silently to zero.');

$fractional = $data->recordDeletionObligation($base + ['attempts' => '2.5']);
c175(is_wp_error($fractional) && $fractional->get_error_code() === 'spcrc_deletion_attempts_invalid', 'Fractional deletion attempt counters must fail closed.');

$badTime = $data->recordDeletionObligation($base + ['attempts' => 2, 'next_retry_at' => 'tomorrow noon']);
c175(is_wp_error($badTime) && $badTime->get_error_code() === 'spcrc_deletion_retry_time_invalid', 'Malformed relative retry timestamps must not silently become an immediate retry.');

$valid = $data->recordDeletionObligation($base + ['attempts' => 2, 'next_retry_at' => gmdate('c', time() + 600)]);
c175(is_string($valid), 'Valid bounded deletion replay state must remain storable.');
$record = $registry->get('deletion-ledger', 'cycle175-ledger');
c175(is_array($record) && (int) ($record['payload']['attempts'] ?? -1) === 2 && ($record['payload']['next_retry_at'] ?? '') !== '', 'Valid replay attempts and absolute retry time must round-trip unchanged.');

$source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Privacy/DataGovernanceRegistry.php');
c175(is_string($source) && str_contains($source, 'spcrc_deletion_attempts_invalid') && str_contains($source, 'spcrc_deletion_retry_time_invalid'), 'Strict deletion-ledger input guards must remain in source.');

echo "PASS: cycle175 deletion-ledger attempt/retry input-integrity defects fixed and retested\n";
