<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Privacy\DataGovernanceRegistry;
use Sabri\Platform\Security\Privacy\DeletionReplayManager;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;

function c138(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$audit = new AuditLogger();
$artifacts = new GovernedArtifactRegistry($audit);
$data = new DataGovernanceRegistry($artifacts);
$saved = $data->recordDeletionObligation([
    'ledger_key' => 'cycle138-failed',
    'module_key' => 'file-17-communication',
    'subject_ref' => 'subject:cycle138',
    'request_ref' => 'privacy:cycle138',
    'status' => 'failed',
    'evidence_ref' => 'deletion:cycle138-failure',
    'attempts' => 3,
    'next_retry_at' => gmdate('c', time() + HOUR_IN_SECONDS),
]);
c138(is_string($saved), 'Failed deletion obligation with a future retry window must persist.');

$calls = 0;
add_filter('spcrc/privacy_deletion_replay_module', static function (array $result) use (&$calls): array {
    ++$calls;
    return ['status' => 'reconciled', 'evidence_ref' => 'deletion:unexpected-early-retry', 'error_code' => ''];
}, 10, 2);

$counts = (new DeletionReplayManager($artifacts, $audit))->run();
c138($calls === 0, 'Future next_retry_at must suppress premature module replay.');
c138(($counts['processed'] ?? -1) === 0, 'Deferred retry must not be counted as a processed replay.');
$record = $artifacts->get('deletion-ledger', 'cycle138-failed');
c138(is_array($record) && ($record['status'] ?? '') === 'failed', 'Deferred failed record must remain unchanged until its retry window.');

echo "PASS: cycle138 deletion-replay backoff defect fixed and retested\n";
