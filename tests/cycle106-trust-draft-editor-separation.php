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
    'claim_type' => 'privacy-notice',
    'claim_key' => 'editor-separation-privacy-notice',
    'title' => 'Privacy notice statement',
    'summary' => 'Initial reviewed wording.',
    'status' => 'draft',
]);
cycleReviewAssert(! is_wp_error($draft), 'The original author must be able to create a draft.');
cycleReviewAssert(($registry->get('trust-claim', 'editor-separation-privacy-notice')['owner_user_id'] ?? 0) === 7, 'The original draft must identify its author.');

$GLOBALS['current_user_id'] = 8;
$GLOBALS['current_user_caps']['spcrc_manage_trust_center'] = true;
unset($GLOBALS['current_user_caps']['spcrc_approve_governance_decision']);
$edited = $trust->saveClaim([
    'claim_type' => 'privacy-notice',
    'claim_key' => 'editor-separation-privacy-notice',
    'title' => 'Privacy notice statement',
    'summary' => 'Materially revised wording by a second editor.',
    'status' => 'draft',
    'expected_version' => 1,
]);
cycleReviewAssert(! is_wp_error($edited), 'An authorized second editor must be able to revise the draft with exact concurrency control.');
$editedRecord = $registry->get('trust-claim', 'editor-separation-privacy-notice');
cycleReviewAssert(($editedRecord['owner_user_id'] ?? 0) === 8, 'The latest material editor must become the approval-separation owner.');
cycleReviewAssert(($editedRecord['version'] ?? 0) === 2, 'The edit must advance the governed artifact version exactly once.');

$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$selfApproval = $trust->saveClaim([
    'claim_type' => 'privacy-notice',
    'claim_key' => 'editor-separation-privacy-notice',
    'status' => 'verified',
    'expected_version' => 2,
    'evidence_ref' => 'evidence:editor-separation-001',
    'reviewed_at' => gmdate('c', time() - 30),
    'expires_at' => gmdate('c', time() + 3600),
]);
cycleReviewAssert(is_wp_error($selfApproval) && $selfApproval->get_error_code() === 'spcrc_trust_claim_self_approval_forbidden', 'The latest material editor must not approve their own wording.');

$GLOBALS['current_user_id'] = 9;
unset($GLOBALS['current_user_caps']['spcrc_manage_trust_center']);
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$approved = $trust->saveClaim([
    'claim_type' => 'privacy-notice',
    'claim_key' => 'editor-separation-privacy-notice',
    'status' => 'verified',
    'expected_version' => 2,
    'evidence_ref' => 'evidence:editor-separation-001',
    'reviewed_at' => gmdate('c', time() - 30),
    'expires_at' => gmdate('c', time() + 3600),
]);
cycleReviewAssert(! is_wp_error($approved), 'A third independently authorized actor must be able to approve the unchanged revised draft.');
$published = $trust->publicClaims();
cycleReviewAssert(count($published) === 1, 'The independently approved revised claim must publish exactly once.');
cycleReviewAssert(($published[0]['summary'] ?? '') === 'Materially revised wording by a second editor.', 'The approved public claim must preserve the exact latest draft wording.');

cycleReviewPass(106, 'trust-draft-editor-separation');
