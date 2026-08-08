<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Resilience\ResilienceCoordinator;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\FindingRepository;
use Sabri\Platform\Security\Storage\GovernanceRepository;

function c137(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$audit = new AuditLogger();
$artifacts = new GovernedArtifactRegistry($audit);
$findings = new FindingRepository($audit, new GovernanceRepository($audit));
$resilience = new ResilienceCoordinator($artifacts, new AssuranceRepository($audit), $findings);

$negative = $resilience->saveRecoveryObjective([
    'service_key' => 'cycle137-negative', 'title' => 'Negative recovery objective',
    'tier' => 'tier-a', 'rpo_seconds' => -60, 'rto_seconds' => 300,
]);
c137(is_wp_error($negative) && $negative->get_error_code() === 'spcrc_resilience_measurement_invalid', 'Negative RPO must be rejected rather than converted by absint.');

$nonNumeric = $resilience->recordDrill([
    'drill_key' => 'cycle137-nonnumeric', 'title' => 'Tampered measurement drill',
    'status' => 'passed', 'scenario' => 'restore', 'evidence_ref' => 'drill:cycle137',
    'measured_rpo_seconds' => 'INF', 'measured_rto_seconds' => 900,
]);
c137(is_wp_error($nonNumeric) && $nonNumeric->get_error_code() === 'spcrc_resilience_measurement_invalid', 'INF/non-numeric measured values must fail closed.');

$valid = $resilience->saveRecoveryObjective([
    'service_key' => 'cycle137-valid', 'title' => 'Valid recovery objective',
    'tier' => 'tier-a', 'rpo_seconds' => '900', 'rto_seconds' => '7200',
]);
c137(is_string($valid), 'Finite non-negative integer-string RPO/RTO values remain valid.');

echo "PASS: cycle137 resilience numeric-integrity defect fixed and retested\n";
