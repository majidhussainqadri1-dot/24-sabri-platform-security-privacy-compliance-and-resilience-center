<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\System\Repair;

function c150(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$repair = new Repair();
$preview = $repair->preview();
c150(preg_match('/^[a-f0-9]{64}$/', (string) ($preview['preview_hash'] ?? '')) === 1, 'Repair must expose a deterministic dry-run preview binding.');
c150(($preview['owned_scope_only'] ?? false) === true && ($preview['destructive'] ?? true) === false, 'Repair preview must explicitly remain File 24-owned and non-destructive.');
c150((int) ($preview['potential_table_count'] ?? 0) > 0 && (int) ($preview['potential_capability_count'] ?? 0) > 0, 'Dry-run must disclose bounded potential affected counts.');

$missing = $repair->run();
c150(is_wp_error($missing) && $missing->get_error_code() === 'spcrc_repair_confirmation_required', 'Direct repair without typed authorization context must fail closed.');

add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
$base = [
    'preview_hash' => $preview['preview_hash'],
    'reason' => 'Cycle 150 verified repair rehearsal',
    'backup_checkpoint_ref' => 'backup:cycle150-checkpoint',
    'rollback_ref' => 'rollback:cycle150-plan',
    'step_up_reference' => 'assertion:cycle150-stepup',
    'typed_confirmation' => 'REPAIR FILE 24',
];
$stale = $base; $stale['preview_hash'] = str_repeat('a', 64);
$staleResult = $repair->run($stale);
c150(is_wp_error($staleResult) && $staleResult->get_error_code() === 'spcrc_repair_preview_stale', 'Repair must reject an unbound/stale dry-run preview.');

$noBackup = $base; $noBackup['backup_checkpoint_ref'] = '';
$noBackupResult = $repair->run($noBackup);
c150(is_wp_error($noBackupResult) && $noBackupResult->get_error_code() === 'spcrc_repair_recovery_evidence_required', 'Repair must require backup checkpoint and rollback evidence.');

$result = $repair->run($base);
c150(is_array($result) && ! empty($result['retention_schedule_verified']) && ! empty($result['resilience_schedule_verified']), 'Verified repair context must complete and re-verify recurring operations.');
c150(($result['backup_checkpoint_ref'] ?? '') === 'backup:cycle150-checkpoint' && ($result['rollback_ref'] ?? '') === 'rollback:cycle150-plan', 'Repair result must retain bounded recovery evidence references for audit.');

$dashboard = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Admin/Dashboard.php');
c150(is_string($dashboard) && str_contains($dashboard, 'preview_hash') && str_contains($dashboard, 'backup_checkpoint_ref') && str_contains($dashboard, 'rollback_ref') && str_contains($dashboard, 'step_up_reference') && str_contains($dashboard, 'typed_confirmation'), 'The wp-admin repair surface must collect dry-run, backup, rollback, step-up and typed-confirmation evidence.');

echo "PASS: cycle150 non-destructive repair evidence-gate defect fixed and retested\n";
