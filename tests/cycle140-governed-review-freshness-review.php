<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;

function c140(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$artifacts = new GovernedArtifactRegistry(new AuditLogger());
$stale = $artifacts->save([
    'artifact_type' => 'policy', 'artifact_key' => 'cycle140-stale', 'title' => 'Stale approved policy',
    'status' => 'approved', 'classification' => 'C1', 'evidence_ref' => 'review:cycle140-stale',
    'reviewed_at' => '2020-01-01T00:00:00Z', 'next_review_at' => '2021-01-01T00:00:00Z',
]);
c140(is_wp_error($stale) && $stale->get_error_code() === 'spcrc_artifact_review_freshness_invalid', 'Expired governance review windows must not remain approved.');

$futureReviewed = $artifacts->save([
    'artifact_type' => 'policy', 'artifact_key' => 'cycle140-future', 'title' => 'Future-reviewed policy',
    'status' => 'approved', 'classification' => 'C1', 'evidence_ref' => 'review:cycle140-future',
    'reviewed_at' => gmdate('c', time() + HOUR_IN_SECONDS), 'next_review_at' => gmdate('c', time() + DAY_IN_SECONDS),
]);
c140(is_wp_error($futureReviewed) && $futureReviewed->get_error_code() === 'spcrc_artifact_review_freshness_invalid', 'Materially future review evidence must fail closed.');

$fresh = $artifacts->save([
    'artifact_type' => 'policy', 'artifact_key' => 'cycle140-fresh', 'title' => 'Fresh approved policy',
    'status' => 'approved', 'classification' => 'C1', 'evidence_ref' => 'review:cycle140-fresh',
    'reviewed_at' => gmdate('c', time() - 60), 'next_review_at' => gmdate('c', time() + DAY_IN_SECONDS),
]);
c140(is_string($fresh), 'Current review evidence with an unexpired next-review date must pass.');

echo "PASS: cycle140 general governed-review freshness defect fixed and retested\n";
