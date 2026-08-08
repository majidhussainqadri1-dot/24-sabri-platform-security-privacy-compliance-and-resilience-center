<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

function c144(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$required = [
    'cycle136-critical-incident-dual-control-review.php',
    'cycle137-resilience-numeric-integrity-review.php',
    'cycle138-deletion-replay-backoff-review.php',
    'cycle139-transfer-classification-location-review.php',
    'cycle140-governed-review-freshness-review.php',
    'cycle141-cryptography-rotation-freshness-review.php',
    'cycle142-detection-alert-durability-review.php',
    'cycle143-security-state-and-audit-key-review.php',
];
foreach ($required as $test) {
    c144(is_file(__DIR__ . '/' . $test), "Fresh review requires permanent regression {$test}.");
}
$production = [
    '../plugin/sabri-security-center/src/Incident/IncidentCoordinator.php' => 'spcrc_critical_incident_dual_approval_required',
    '../plugin/sabri-security-center/src/Privacy/DeletionReplayManager.php' => 'nextRetryTimestamp',
    '../plugin/sabri-security-center/src/Privacy/DataGovernanceRegistry.php' => 'spcrc_transfer_restricted_location_unknown',
    '../plugin/sabri-security-center/src/Registry/GovernedArtifactRegistry.php' => 'spcrc_artifact_review_freshness_invalid',
    '../plugin/sabri-security-center/src/Security/CryptographyPolicy.php' => 'spcrc_crypto_rotation_overdue',
    '../plugin/sabri-security-center/src/Monitoring/DetectionEngine.php' => 'spcrc_detection_audit_gap',
];
foreach ($production as $relative => $needle) {
    $source = file_get_contents(__DIR__ . '/' . $relative);
    c144(is_string($source) && str_contains($source, $needle), "Fresh whole-system review lost corrected contract {$needle}.");
}
echo "PASS: cycle144 fresh whole-system adversarial review found no new repository-correctable defect\n";
