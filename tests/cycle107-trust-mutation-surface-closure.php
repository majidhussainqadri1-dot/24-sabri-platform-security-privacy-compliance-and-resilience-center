<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
require_once $base . 'Registry/GovernedArtifactRegistry.php';
require_once $base . 'Trust/TrustCenterService.php';
require_once $base . 'Rest/GovernanceController.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Rest\GovernanceController;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Trust\TrustCenterService;

$registry = new GovernedArtifactRegistry(new AuditLogger());
$trust = new TrustCenterService($registry);
$controller = new GovernanceController($registry, $trust);

$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps'] = [
    'spcrc_view_overview' => true,
    'spcrc_manage_trust_center' => true,
];
$draftRequest = [
    'artifact_type' => 'trust-claim',
    'claim_type' => 'responsible-disclosure',
    'artifact_key' => 'rest-responsible-disclosure',
    'title' => 'Responsible disclosure statement',
    'summary' => 'A bounded public statement awaiting independent review.',
    'status' => 'draft',
    'expected_version' => 0,
];
cycleReviewAssert($controller->canSave($draftRequest), 'A Trust Center manager must be authorized to draft through REST.');
$draftResponse = $controller->saveArtifact($draftRequest);
cycleReviewAssert($draftResponse instanceof WP_REST_Response, 'The REST mutation surface must route a valid draft through the Trust Center service.');
$draftRecord = $registry->get('trust-claim', 'rest-responsible-disclosure');
cycleReviewAssert(($draftRecord['owner_user_id'] ?? 0) === 7 && ($draftRecord['version'] ?? 0) === 1, 'The REST-created draft must retain attributable author and version evidence.');

$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$selfApprovalRequest = [
    'artifact_type' => 'trust-claim',
    'claim_type' => 'responsible-disclosure',
    'artifact_key' => 'rest-responsible-disclosure',
    'status' => 'verified',
    'expected_version' => 1,
    'evidence_ref' => 'evidence:rest-trust-001',
    'reviewed_at' => gmdate('c', time() - 30),
    'expires_at' => gmdate('c', time() + 3600),
];
$selfApproval = $controller->saveArtifact($selfApprovalRequest);
cycleReviewAssert(is_wp_error($selfApproval) && $selfApproval->get_error_code() === 'spcrc_trust_claim_self_approval_forbidden', 'REST must not bypass self-approval prevention.');

$GLOBALS['current_user_id'] = 8;
$GLOBALS['current_user_caps'] = [
    'spcrc_view_overview' => true,
    'spcrc_approve_governance_decision' => true,
];
cycleReviewAssert($controller->canSave($selfApprovalRequest), 'A distinct governance approver may submit the verified transition without draft-management authority.');
$approvedResponse = $controller->saveArtifact($selfApprovalRequest);
cycleReviewAssert($approvedResponse instanceof WP_REST_Response, 'The distinct approver must verify the unchanged REST draft through the Trust service.');
cycleReviewAssert(count($trust->publicClaims()) === 1, 'The approved REST claim must publish exactly once.');

$GLOBALS['current_user_id'] = 9;
$GLOBALS['current_user_caps'] = ['spcrc_view_overview' => true];
cycleReviewAssert(! $controller->canList(['artifact_type' => 'trust-claim']), 'Overview authority alone must not expose trust authorship or evidence records.');
$GLOBALS['current_user_caps']['spcrc_manage_trust_center'] = true;
cycleReviewAssert($controller->canList(['artifact_type' => 'trust-claim']), 'Trust management authority may read its restricted records.');

$controllerWithoutTrust = new GovernanceController($registry);
cycleReviewAssert(! $controllerWithoutTrust->canSave($draftRequest), 'Trust mutations must fail closed when the approval service is not injected.');

$adminSource = file_get_contents($base . 'Admin/RegistryAdmin.php');
cycleReviewAssert(is_string($adminSource) && str_contains($adminSource, '$this->trustCenter->saveClaim($data)'), 'The wp-admin fallback must route trust claims through the same approval service.');
cycleReviewAssert(is_string($adminSource) && str_contains($adminSource, 'RESTRICTED_READ_TYPES') && str_contains($adminSource, "'trust-claim'"), 'The wp-admin fallback must restrict trust evidence reads by duty.');
$pluginSource = file_get_contents($base . 'Plugin.php');
cycleReviewAssert(is_string($pluginSource) && str_contains($pluginSource, 'new RegistryAdmin($artifacts, $trust)') && str_contains($pluginSource, 'new GovernanceController($artifacts, $trust)'), 'Plugin boot must inject the approval service into both mutation surfaces.');

cycleReviewPass(107, 'trust-mutation-surface-closure');
