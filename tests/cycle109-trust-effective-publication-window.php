<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Trust\TrustCenterService;

$registry = new GovernedArtifactRegistry(new AuditLogger());
$trust = new TrustCenterService($registry);

$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps'] = ['spcrc_manage_trust_center' => true];
foreach ([
    'future-effective' => 'A future effective public statement.',
    'current-effective' => 'A currently effective public statement.',
] as $key => $summary) {
    $draft = $trust->saveClaim([
        'claim_type' => 'accessibility-commitment',
        'claim_key' => $key,
        'title' => 'Accessibility commitment',
        'summary' => $summary,
        'status' => 'draft',
    ]);
    cycleReviewAssert(! is_wp_error($draft), 'Each publication-window claim must begin as a draft: ' . $key);
}

$GLOBALS['current_user_id'] = 8;
$GLOBALS['current_user_caps'] = ['spcrc_approve_governance_decision' => true];
$future = $trust->saveClaim([
    'claim_type' => 'accessibility-commitment',
    'claim_key' => 'future-effective',
    'status' => 'verified',
    'expected_version' => 1,
    'evidence_ref' => 'evidence:future-effective-001',
    'reviewed_at' => gmdate('c', time() - 60),
    'effective_at' => gmdate('c', time() + 3600),
    'expires_at' => gmdate('c', time() + 7200),
]);
cycleReviewAssert(! is_wp_error($future), 'A future-effective claim may be approved and scheduled.');
cycleReviewAssert(count($trust->publicClaims()) === 0, 'A verified claim must not publish before its effective time.');

$current = $trust->saveClaim([
    'claim_type' => 'accessibility-commitment',
    'claim_key' => 'current-effective',
    'status' => 'verified',
    'expected_version' => 1,
    'evidence_ref' => 'evidence:current-effective-001',
    'reviewed_at' => gmdate('c', time() - 120),
    'effective_at' => gmdate('c', time() - 60),
    'expires_at' => gmdate('c', time() + 7200),
]);
cycleReviewAssert(! is_wp_error($current), 'A currently effective evidence-backed claim must be approved.');
$published = $trust->publicClaims();
cycleReviewAssert(count($published) === 1 && ($published[0]['key'] ?? '') === 'current-effective', 'Only the currently effective claim may be publicly projected.');
cycleReviewAssert(($published[0]['effective_at'] ?? '') !== '', 'The public projection must disclose the effective timestamp.');

$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps'] = ['spcrc_manage_trust_center' => true];
$invalidDraft = $trust->saveClaim([
    'claim_type' => 'accessibility-commitment',
    'claim_key' => 'invalid-effective',
    'title' => 'Invalid effective time',
    'summary' => 'This draft must fail.',
    'status' => 'draft',
    'effective_at' => 'not-a-time',
]);
cycleReviewAssert(is_wp_error($invalidDraft) && $invalidDraft->get_error_code() === 'spcrc_trust_claim_effective_time_invalid', 'An explicitly malformed effective time must fail closed instead of becoming silently immediate.');

cycleReviewPass(109, 'trust-effective-publication-window');
