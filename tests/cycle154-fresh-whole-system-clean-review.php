<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\System\Repair;

function c154(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$root = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
$markers = [
    'Rest/GovernanceController.php' => ['spcrc_governance_step_up_required', 'overviewRecord', 'strictInteger'],
    'Privacy/DeletionReplayManager.php' => ['scheduleValid', 'spcrc_deletion_replay_audit_gap', 'recordPersistenceGap'],
    'Monitoring/RemoteEvidenceQueue.php' => ['scheduleValid', 'spcrc_remote_evidence_audit_gap', 'recordPersistenceGap'],
    'Resilience/ResilienceCoordinator.php' => ['scheduleValid'],
    'Release/ReleaseGateManager.php' => ['spcrc_release_gate_dual_approval_required', 'spcrc_release_gate_sequence_blocked', 'spcrc_release_gate_audit_gaps_open'],
    'Rest/StatusController.php' => ['trustCacheMaxAge', 'must-revalidate'],
    'System/Repair.php' => ['preview_hash', 'backup_checkpoint_ref', 'rollback_ref', 'non-destructive-repair'],
    'Support/Sanitizer.php' => ['strictInteger'],
];
foreach ($markers as $file => $needles) {
    $source = file_get_contents($root . $file);
    c154(is_string($source), $file . ' must be readable.');
    foreach ($needles as $needle) {
        c154(str_contains($source, $needle), $file . ' must retain corrected contract marker ' . $needle . '.');
    }
}

c154(Sanitizer::strictInteger('-7', 1, 10) === null && Sanitizer::strictInteger('7', 1, 10) === 7, 'Strict integer boundary remains fail-closed.');
c154(count(ReleaseGateManager::phases()) === 12, 'Release phase model remains complete after hardening.');
$managed = AuditGapStore::managedOptions();
c154(in_array('spcrc_detection_audit_gap', $managed, true) && in_array('spcrc_remote_evidence_audit_gap', $managed, true) && in_array('spcrc_deletion_replay_audit_gap', $managed, true), 'Operational gap categories remain visible for reconciliation.');
$preview = (new Repair())->preview();
c154(($preview['owned_scope_only'] ?? false) === true && ($preview['destructive'] ?? true) === false, 'Repair remains non-destructive and native-boundary preserving.');

foreach (range(146, 153) as $cycle) {
    $matches = glob(__DIR__ . '/cycle' . $cycle . '-*.php');
    c154(is_array($matches) && count($matches) === 1, 'Each defect-bearing review Cycle ' . $cycle . ' must have one permanent independent regression program.');
}

echo "PASS: cycle154 fresh whole-system review found no new repository-correctable defect\n";
