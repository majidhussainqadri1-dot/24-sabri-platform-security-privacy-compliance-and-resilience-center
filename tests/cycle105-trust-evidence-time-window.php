<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Trust\TrustCenterService;

$registry = new GovernedArtifactRegistry(new AuditLogger());
$trust = new TrustCenterService($registry);

$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps']['spcrc_manage_trust_center'] = true;
unset($GLOBALS['current_user_caps']['spcrc_approve_governance_decision']);
$draft = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'time-window-security-overview',
    'title' => 'Time-window security overview',
    'summary' => 'A reviewed and expiring public-safe claim.',
    'status' => 'draft',
]);
cycleReviewAssert(! is_wp_error($draft), 'An attributable draft must be created before chronology tests.');

$GLOBALS['current_user_id'] = 8;
unset($GLOBALS['current_user_caps']['spcrc_manage_trust_center']);
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;

$futureReview = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'time-window-security-overview',
    'status' => 'verified',
    'expected_version' => 1,
    'evidence_ref' => 'evidence:time-window-001',
    'reviewed_at' => gmdate('c', time() + 3600),
    'expires_at' => gmdate('c', time() + 7200),
]);
cycleReviewAssert(is_wp_error($futureReview) && $futureReview->get_error_code() === 'spcrc_trust_claim_time_window_invalid', 'A future-dated review must fail closed.');

$expired = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'time-window-security-overview',
    'status' => 'verified',
    'expected_version' => 1,
    'evidence_ref' => 'evidence:time-window-001',
    'reviewed_at' => gmdate('c', time() - 7200),
    'expires_at' => gmdate('c', time() - 3600),
]);
cycleReviewAssert(is_wp_error($expired) && $expired->get_error_code() === 'spcrc_trust_claim_time_window_invalid', 'An already expired public claim must not enter verified state.');

$reversed = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'time-window-security-overview',
    'status' => 'verified',
    'expected_version' => 1,
    'evidence_ref' => 'evidence:time-window-001',
    'reviewed_at' => gmdate('c', time() - 60),
    'expires_at' => gmdate('c', time() - 120),
]);
cycleReviewAssert(is_wp_error($reversed) && $reversed->get_error_code() === 'spcrc_trust_claim_time_window_invalid', 'Expiry at or before review must fail closed.');

$valid = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'time-window-security-overview',
    'status' => 'verified',
    'expected_version' => 1,
    'evidence_ref' => 'evidence:time-window-001',
    'reviewed_at' => gmdate('c', time() - 60),
    'expires_at' => gmdate('c', time() + 3600),
]);
cycleReviewAssert(! is_wp_error($valid), 'A completed recent review with future expiry must be accepted.');
cycleReviewAssert(count($trust->publicClaims()) === 1, 'Only the valid current claim may be publicly projected.');

cycleReviewPass(105, 'trust-evidence-time-window');
