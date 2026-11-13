<?php

declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Trust\TrustCenterService;

function tewAssert(bool $passed, string $message): void
{
    if (! $passed) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$registry = new GovernedArtifactRegistry(new AuditLogger());
$trust = new TrustCenterService($registry);
$future = gmdate('c', time() + 3600);
$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps'] = ['spcrc_manage_trust_center' => true];
$draft = $trust->saveClaim([
    'claim_type' => 'accessibility-commitment', 'claim_key' => 'fixed-schedule',
    'title' => 'Scheduled evidence statement', 'summary' => 'Scheduled future approval',
    'status' => 'draft', 'effective_at' => $future,
]);
tewAssert(is_string($draft), 'Scheduled claim draft is stored.');

$GLOBALS['current_user_id'] = 8;
$GLOBALS['current_user_caps'] = ['spcrc_approve_governance_decision' => true];
$approval = [
    'claim_type' => 'accessibility-commitment', 'claim_key' => 'fixed-schedule',
    'status' => 'verified', 'expected_version' => 1,
    'evidence_ref' => 'evidence:future-provenance',
    'reviewed_at' => gmdate('c', time() - 60),
    'expires_at' => gmdate('c', time() + 7200),
];
$missing = $trust->saveClaim($approval);
tewAssert(is_wp_error($missing) && $missing->get_error_code() === 'spcrc_trust_claim_effective_window_changed', 'Omitting a future draft effective time must fail closed.');
$early = $trust->saveClaim($approval + ['effective_at' => gmdate('c', time() - 10)]);
tewAssert(is_wp_error($early) && $early->get_error_code() === 'spcrc_trust_claim_effective_window_changed', 'Approval cannot advance a future effective window.');
tewAssert(count($trust->publicClaims()) === 0, 'Rejected approval must not publish a claim.');
$valid = $trust->saveClaim($approval + ['effective_at' => $future]);
tewAssert(is_string($valid), 'Matching future-effective approval may pass.');
tewAssert(count($trust->publicClaims()) === 0, 'Future-effective claim is still not public after approval.');
echo "PASS: trust-center independently drafted effective windows survive approval\n";
