<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\AuditLogger;

function c193(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$repo = new AssuranceRepository(new AuditLogger());

$negativeOwner = $repo->upsert([
    'record_type' => 'vendor',
    'record_key' => 'cycle193-owner',
    'title' => 'Negative owner integrity',
    'status' => 'unassessed',
    'owner_user_id' => -7,
]);
c193(is_wp_error($negativeOwner) && $negativeOwner->get_error_code() === 'spcrc_assurance_owner_invalid', 'Negative assurance owner must not be absint-coerced into user 7.');

$staleReview = $repo->upsert([
    'record_type' => 'compliance',
    'record_key' => 'cycle193-stale-review',
    'title' => 'Stale compliance determination',
    'status' => 'applicable',
    'owner_user_id' => 7,
    'evidence_ref' => 'evidence:cycle193-compliance',
    'reviewed_at' => gmdate('c', time() - (3 * DAY_IN_SECONDS)),
    'next_review_at' => gmdate('c', time() - (2 * DAY_IN_SECONDS)),
]);
c193(is_wp_error($staleReview) && $staleReview->get_error_code() === 'spcrc_assurance_next_review_expired', 'A time-bounded compliance determination with an already expired next-review date must not remain current.');

$classes = [];
for ($i = 0; $i < 21; ++$i) $classes[] = 'C1-domain-' . $i;
$overflow = $repo->upsert([
    'record_type' => 'vendor',
    'record_key' => 'cycle193-classes',
    'title' => 'Assurance scope completeness',
    'status' => 'unassessed',
    'owner_user_id' => 7,
    'data_classes' => $classes,
]);
c193(is_wp_error($overflow) && $overflow->get_error_code() === 'spcrc_assurance_data_classes_invalid', 'Over-limit assurance data-class scope must be rejected rather than silently truncated.');

$valid = $repo->upsert([
    'record_type' => 'compliance',
    'record_key' => 'cycle193-valid',
    'title' => 'Current compliance determination',
    'status' => 'applicable',
    'owner_user_id' => 7,
    'evidence_ref' => 'evidence:cycle193-valid',
    'reviewed_at' => gmdate('c', time() - 60),
    'next_review_at' => gmdate('c', time() + DAY_IN_SECONDS),
    'data_classes' => ['C1', 'C2'],
]);
c193(is_string($valid), 'Current time-bounded assurance with a bounded data-class list must remain valid.');

echo "PASS: cycle193 assurance owner coercion, stale determination and scope-truncation defects fixed and retested\n";
