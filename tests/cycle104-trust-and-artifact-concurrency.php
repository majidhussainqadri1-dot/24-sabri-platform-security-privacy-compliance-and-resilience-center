<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Rest\StatusController;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\System\SystemCheck;
use Sabri\Platform\Security\Trust\TrustCenterService;

$registry = new GovernedArtifactRegistry(new AuditLogger());

$created = $registry->save([
    'artifact_type' => 'policy',
    'artifact_key' => 'concurrency-policy',
    'title' => 'Concurrency policy',
    'status' => 'draft',
    'classification' => 'C1',
    'payload' => ['purpose' => 'test'],
]);
cycleReviewAssert(! is_wp_error($created), 'A new artifact with expected version zero must be created.');

$unversioned = $registry->save([
    'artifact_type' => 'policy',
    'artifact_key' => 'concurrency-policy',
    'title' => 'Concurrency policy update',
    'status' => 'under-review',
    'classification' => 'C1',
    'payload' => ['purpose' => 'unsafe update'],
]);
cycleReviewAssert(is_wp_error($unversioned) && $unversioned->get_error_code() === 'spcrc_artifact_expected_version_required', 'An existing artifact must not be overwritten without an expected version.');

$stale = $registry->save([
    'artifact_type' => 'policy',
    'artifact_key' => 'concurrency-policy',
    'title' => 'Concurrency policy stale update',
    'status' => 'under-review',
    'classification' => 'C1',
    'payload' => ['purpose' => 'stale update'],
], 99);
cycleReviewAssert(is_wp_error($stale) && $stale->get_error_code() === 'spcrc_artifact_concurrent_update', 'A stale expected version must fail closed.');

$updated = $registry->save([
    'artifact_type' => 'policy',
    'artifact_key' => 'concurrency-policy',
    'title' => 'Concurrency policy reviewed',
    'status' => 'under-review',
    'classification' => 'C1',
    'payload' => ['purpose' => 'safe update'],
], 1);
cycleReviewAssert(! is_wp_error($updated), 'The exact expected version must permit the update.');
cycleReviewAssert(($registry->get('policy', 'concurrency-policy')['version'] ?? 0) === 2, 'A successful guarded update must increment the version exactly once.');

$unexpectedVersion = $registry->save([
    'artifact_type' => 'policy',
    'artifact_key' => 'new-policy-with-version',
    'title' => 'Invalid pre-versioned creation',
    'status' => 'draft',
    'classification' => 'C1',
    'payload' => [],
], 1);
cycleReviewAssert(is_wp_error($unexpectedVersion) && $unexpectedVersion->get_error_code() === 'spcrc_artifact_unexpected_version', 'A new artifact must not claim a pre-existing version.');

$trust = new TrustCenterService($registry);
unset($GLOBALS['current_user_caps']['spcrc_manage_trust_center'], $GLOBALS['current_user_caps']['spcrc_approve_governance_decision']);
$forbidden = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'security-overview',
    'title' => 'Security overview',
    'status' => 'draft',
]);
cycleReviewAssert(is_wp_error($forbidden) && $forbidden->get_error_code() === 'spcrc_trust_claim_forbidden', 'Trust claim drafting requires explicit management authority.');

$GLOBALS['current_user_caps']['spcrc_manage_trust_center'] = true;
$draft = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'security-overview',
    'title' => 'Security overview',
    'summary' => 'Evidence-gated public security information.',
    'status' => 'draft',
]);
cycleReviewAssert(! is_wp_error($draft), 'An authorized manager must be able to create a draft public claim.');
cycleReviewAssert(($registry->get('trust-claim', 'security-overview')['owner_user_id'] ?? 0) === 7, 'The draft author must be durably attributed.');

$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$selfApproval = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'security-overview',
    'title' => 'Security overview',
    'summary' => 'Evidence-gated public security information.',
    'status' => 'verified',
    'expected_version' => 1,
    'evidence_ref' => 'evidence:trust-001',
    'reviewed_at' => gmdate('c'),
    'expires_at' => gmdate('c', time() + DAY_IN_SECONDS),
]);
cycleReviewAssert(is_wp_error($selfApproval) && $selfApproval->get_error_code() === 'spcrc_trust_claim_self_approval_forbidden', 'The draft author must not approve the same public claim.');

$GLOBALS['current_user_id'] = 8;
unset($GLOBALS['current_user_caps']['spcrc_manage_trust_center'], $GLOBALS['current_user_caps']['spcrc_approve_governance_decision']);
$unapproved = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'security-overview',
    'title' => 'Security overview',
    'summary' => 'Evidence-gated public security information.',
    'status' => 'verified',
    'expected_version' => 1,
    'evidence_ref' => 'evidence:trust-001',
    'reviewed_at' => gmdate('c'),
    'expires_at' => gmdate('c', time() + DAY_IN_SECONDS),
]);
cycleReviewAssert(is_wp_error($unapproved) && $unapproved->get_error_code() === 'spcrc_trust_claim_approval_forbidden', 'A second actor still requires explicit approval authority.');

$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$approved = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'security-overview',
    'title' => 'Security overview',
    'summary' => 'Evidence-gated public security information.',
    'status' => 'verified',
    'expected_version' => 1,
    'evidence_ref' => 'evidence:trust-001',
    'reviewed_at' => gmdate('c'),
    'expires_at' => gmdate('c', time() + DAY_IN_SECONDS),
]);
cycleReviewAssert(! is_wp_error($approved), 'A distinct authorized approver must be able to verify the evidence-backed claim.');
cycleReviewAssert(count($trust->publicClaims()) === 1, 'Exactly one approved unexpired claim must be publicly projected.');

add_filter('spcrc/public_trust_payload', static function (array $payload): array {
    $payload['claims'][] = [
        'key' => 'forged-claim',
        'type' => 'certification',
        'title' => 'Forged certification',
        'summary' => 'Injected after evidence review.',
        'verified_at' => gmdate('c'),
        'expires_at' => gmdate('c', time() + DAY_IN_SECONDS),
    ];
    return $payload;
});

$modules = new ModuleRegistry();
$states = new SecurityStateRegistry($modules, new AuditLogger());
$controller = new StatusController($modules, $states, new SystemCheck($modules), trustCenter: $trust);
$public = $controller->trust()->get_data();
cycleReviewAssert(count($public['claims'] ?? []) === 1, 'A general WordPress filter must not inject a public trust claim.');
cycleReviewAssert(($public['claims'][0]['key'] ?? '') === 'security-overview', 'Only the evidence-gated claim may be published.');
cycleReviewAssert(($public['responsible_disclosure_available'] ?? true) === false, 'Disclosure availability must not be asserted without a verified disclosure claim.');
cycleReviewAssert(($public['privacy_request_available'] ?? true) === false, 'Privacy-request availability must not be asserted without a verified rights-request claim.');

cycleReviewPass(104, 'trust-and-artifact-concurrency');
