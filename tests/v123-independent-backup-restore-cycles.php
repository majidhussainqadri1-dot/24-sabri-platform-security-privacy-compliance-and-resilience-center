<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\System\SystemCheck;

function v123DrAssert(bool $ok, string $message): void
{
    if (! $ok) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}
$repo = new AssuranceRepository();
$system = new SystemCheck(new ModuleRegistry());
$daily = [
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() - 3600),
    'restore_tested_at' => gmdate('c', time() - 30 * DAY_IN_SECONDS),
    'evidence_ref' => 'vault:latest-daily-backup',
    'evidence_model' => 'independent-cycles',
    'restore_source_backup_at' => gmdate('c', time() - 31 * DAY_IN_SECONDS),
    'restore_evidence_ref' => 'vault:independent-restore-drill',
];
$current = $repo->backupEvidence($daily);
v123DrAssert(($current['status'] ?? '') === 'verified', 'Current daily backup and separate monthly restore need a valid documented model.');
v123DrAssert(($current['evidence_model'] ?? '') === 'independent-cycles', 'Independent evidence model must survive normalization.');
v123DrAssert(($current['restore_evidence_ref'] ?? '') === 'vault:independent-restore-drill', 'Opaque restore proof must be preserved to SystemCheck.');

add_filter('spcrc/backup_evidence', static fn (): array => $daily, 10, 1);
$checks = array_column($system->run(), null, 'key');
v123DrAssert(($checks['backup_evidence']['status'] ?? '') === 'pass', 'Separate recent restore proof must not fail due to newer daily backup.');
$GLOBALS['wp_filters']['spcrc/backup_evidence'] = [];

$noSource = $daily;
unset($noSource['restore_source_backup_at']);
v123DrAssert(($repo->backupEvidence($noSource)['status'] ?? '') !== 'verified', 'Independent model without restored snapshot source must reject.');
add_filter('spcrc/backup_evidence', static fn (): array => $noSource, 10, 1);
v123DrAssert((array_column($system->run(), null, 'key')['backup_evidence']['status'] ?? '') !== 'pass', 'SystemCheck also blocks a missing restored snapshot source.');
$GLOBALS['wp_filters']['spcrc/backup_evidence'] = [];

$sameEvidence = $daily;
$sameEvidence['restore_evidence_ref'] = $sameEvidence['evidence_ref'];
v123DrAssert(($repo->backupEvidence($sameEvidence)['status'] ?? '') !== 'verified', 'Separate operations require distinct opaque evidence receipts.');

$badChronology = $daily;
$badChronology['restore_source_backup_at'] = gmdate('c', time() - 29 * DAY_IN_SECONDS);
v123DrAssert(($repo->backupEvidence($badChronology)['status'] ?? '') !== 'verified', 'Restore cannot predate its actual restored snapshot evidence source.');

$stale = $daily;
$stale['restore_tested_at'] = gmdate('c', time() - 120 * DAY_IN_SECONDS);
v123DrAssert(($repo->backupEvidence($stale)['status'] ?? '') !== 'verified', 'Independent restore drill must satisfy the quarterly freshness bound.');

$legacy = [
    'status' => 'verified',
    'last_success_at' => gmdate('c', time() - 7200),
    'restore_tested_at' => gmdate('c', time() - 3600),
    'evidence_ref' => 'vault:legacy-same-snapshot',
];
v123DrAssert(($repo->backupEvidence($legacy)['status'] ?? '') === 'verified', 'Legacy later-restored paired backup remains valid.');
v123DrAssert(
    array_keys($repo->backupEvidence($legacy)) === ['status','last_success_at','restore_tested_at','evidence_ref'],
    'Existing four-field paired backup contract must remain stable.'
);

echo "PASS: V12.3 daily backup and independent restored snapshot receipts are truthful and fail closed\n";
