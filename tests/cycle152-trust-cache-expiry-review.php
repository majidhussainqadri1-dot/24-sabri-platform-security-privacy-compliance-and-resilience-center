<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Rest\StatusController;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\System\SystemCheck;
use Sabri\Platform\Security\Trust\TrustCenterService;

function c152(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$trust = new TrustCenterService($registry);
$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps'] = ['spcrc_manage_trust_center' => true];
$draft = $trust->saveClaim([
    'claim_type' => 'security-overview', 'claim_key' => 'short-lived-claim',
    'title' => 'Short-lived verified statement', 'summary' => 'Evidence expires shortly.', 'status' => 'draft',
]);
c152(! is_wp_error($draft), 'Trust draft must be created.');
$GLOBALS['current_user_id'] = 8;
$GLOBALS['current_user_caps'] = ['spcrc_approve_governance_decision' => true];
$approved = $trust->saveClaim([
    'claim_type' => 'security-overview', 'claim_key' => 'short-lived-claim', 'status' => 'verified',
    'expected_version' => 1, 'evidence_ref' => 'evidence:short-trust',
    'reviewed_at' => gmdate('c', time() - 30), 'expires_at' => gmdate('c', time() + 60),
]);
c152(! is_wp_error($approved), 'Short-lived trust claim must verify for cache-boundary testing.');

$modules = new ModuleRegistry();
$states = new SecurityStateRegistry($modules, new AuditLogger());
$controller = new StatusController($modules, $states, new SystemCheck($modules), trustCenter: $trust);
$response = $controller->trust();
$cache = (string) ($response->get_headers()['Cache-Control'] ?? '');
c152(preg_match('/max-age=(\d+)/', $cache, $match) === 1, 'Public trust response must publish an explicit cache lifetime.');
$maxAge = (int) ($match[1] ?? 999);
c152($maxAge >= 0 && $maxAge <= 60, 'Trust cache lifetime must never outlive the earliest verified claim expiry.');

$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps'] = [];
$emptyController = new StatusController(new ModuleRegistry(), new SecurityStateRegistry(new ModuleRegistry(), new AuditLogger()), new SystemCheck(new ModuleRegistry()));
$emptyCache = (string) ($emptyController->trust()->get_headers()['Cache-Control'] ?? '');
c152(str_contains($emptyCache, 'max-age=300'), 'An empty safe Trust Center may retain the bounded five-minute public cache.');

echo "PASS: cycle152 Trust Center cache/claim-expiry defect fixed and retested\n";
