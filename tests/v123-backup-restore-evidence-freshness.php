<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\System\SystemCheck;

function v123BackupFreshAssert(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$old = [
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() - 400 * 86400),
    'restore_tested_at' => gmdate('c', time() - 399 * 86400),
    'evidence_ref' => 'vault:v123-very-old-paired-evidence',
];
$repo = new AssuranceRepository();
$normalized = $repo->backupEvidence($old);
v123BackupFreshAssert(
    ($normalized['status'] ?? '') !== 'verified',
    'Year-old backup/restore receipts must not remain verified forever.'
);

add_filter('spcrc/backup_evidence', static fn (): array => $old, 10, 1);
$checker = new SystemCheck(new ModuleRegistry());
$checks = array_column($checker->run(), null, 'key');
v123BackupFreshAssert(
    ($checks['backup_evidence']['status'] ?? '') === 'warning',
    'System Check must reject stale paired backup/restore even when both dates exist.'
);

$GLOBALS['wp_filters']['spcrc/backup_evidence'] = [];
$recent = [
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() - 7200),
    'restore_tested_at' => gmdate('c', time() - 3600),
    'evidence_ref' => 'vault:v123-current-paired-evidence',
];
v123BackupFreshAssert(
    ($repo->backupEvidence($recent)['status'] ?? '') === 'verified',
    'Fresh paired backup/restore with opaque reference remains verified by the shape contract.'
);
add_filter('spcrc/backup_evidence', static fn (): array => $recent, 10, 1);
$checks = array_column($checker->run(), null, 'key');
v123BackupFreshAssert(
    ($checks['backup_evidence']['status'] ?? '') === 'pass',
    'Recent, chronological and referenced paired evidence remains an eligible check.'
);

$GLOBALS['wp_filters']['spcrc/backup_evidence'] = [];
$staleBackup = [
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() - 5 * 86400),
    'restore_tested_at' => gmdate('c', time() - 4 * 86400),
    'evidence_ref' => 'vault:v123-five-days-old',
];
v123BackupFreshAssert(
    ($repo->backupEvidence($staleBackup)['status'] ?? '') !== 'verified',
    'A backup older than the bounded grace period must not be current.'
);
add_filter('spcrc/backup_evidence', static fn (): array => $staleBackup, 10, 1);
$checks = array_column($checker->run(), null, 'key');
v123BackupFreshAssert(
    ($checks['backup_evidence']['status'] ?? '') === 'warning',
    'Stale five-day backup cannot yield a green operational System Check.'
);

echo "PASS: V12.3 stale backup/restore receipts fail closed in both repository and system posture\n";
