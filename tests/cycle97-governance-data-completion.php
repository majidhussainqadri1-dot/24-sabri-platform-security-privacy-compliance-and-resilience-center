<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\GovernancePolicyService;
use Sabri\Platform\Security\Privacy\DataGovernanceRegistry;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Registry\RequirementCatalog;
use Sabri\Platform\Security\Storage\AuditLogger;

$count = 0;
function c97(bool $condition, string $message): void { global $count; ++$count; if (! $condition) { fwrite(STDERR, "FAIL: $message\n"); exit(1); } }

$artifacts = new GovernedArtifactRegistry(new AuditLogger());
$policies = new GovernancePolicyService($artifacts);
$data = new DataGovernanceRegistry($artifacts);

c97(RequirementCatalog::count() === 100, 'F24-R001 through F24-R100 must be catalogued.');
c97(RequirementCatalog::repositoryCodingComplete(), 'All requirements must have repository implementations.');
c97(count(GovernedArtifactRegistry::types()) === 28, 'All governed logical domains must exist.');
c97(count(PlatformIntegrationMatrix::all()) === 26, 'Files 00 through 25 must have a formal integration row.');

$master = $policies->savePolicy([
    'policy_key' => 'master-plan-v3', 'title' => 'Definitive Master Plan',
    'hierarchy_level' => 'master-plan', 'policy_version' => '3.0', 'status' => 'approved',
    'evidence_ref' => 'decision:founder-v3', 'reviewed_at' => gmdate('c', time() - 60),
    'next_review_at' => gmdate('c', time() + DAY_IN_SECONDS),
]);
c97(is_string($master), 'Approved master policy must persist with review evidence.');
$child = $policies->savePolicy([
    'policy_key' => 'security-charter-v1', 'title' => 'Security Governance Charter',
    'hierarchy_level' => 'security-charter', 'policy_version' => '1.0', 'status' => 'draft',
    'parent_policy_key' => 'master-plan-v3',
]);
c97(is_string($child), 'Lower policy may bind to a higher policy.');
$badParent = $policies->savePolicy([
    'policy_key' => 'bad-parent', 'title' => 'Invalid policy hierarchy',
    'hierarchy_level' => 'master-plan', 'policy_version' => '1.0', 'status' => 'draft',
    'parent_policy_key' => 'security-charter-v1',
]);
c97(is_wp_error($badParent) && $badParent->get_error_code() === 'spcrc_policy_parent_hierarchy_invalid', 'Policy hierarchy must fail closed.');
$noEvidence = $policies->savePolicy([
    'policy_key' => 'missing-evidence', 'title' => 'Missing evidence policy',
    'hierarchy_level' => 'procedure', 'policy_version' => '1.0', 'status' => 'approved',
]);
c97(is_wp_error($noEvidence) && $noEvidence->get_error_code() === 'spcrc_policy_approval_evidence_missing', 'Approved policy must require evidence and review dates.');

$asset = $data->registerDataAsset([
    'asset_key' => 'privacy-requests', 'title' => 'Privacy request registry', 'status' => 'active',
    'classification' => 'C4', 'native_owner' => 'file-24-security-center',
    'retention_rule' => 'privacy-request-rule', 'fields' => ['request UUID', 'status', 'opaque evidence reference'],
]);
c97(is_string($asset), 'Data inventory asset must persist.');
$activity = $data->registerProcessingActivity([
    'activity_key' => 'privacy-dispatch', 'title' => 'Privacy request dispatch', 'status' => 'draft',
    'classification' => 'C4', 'native_owner' => 'file-24-security-center',
    'purpose' => 'privacy-rights-orchestration', 'lawful_basis' => 'applicability-review',
    'fields' => ['opaque request reference'], 'destinations' => ['native owner modules'],
]);
c97(is_string($activity), 'Processing activity must persist without copying native data.');
$hold = $data->recordLegalHold([
    'hold_key' => 'hold-case-01', 'title' => 'Category-specific legal hold', 'status' => 'active',
    'scope' => ['incident evidence metadata'], 'authority_basis' => 'documented-request',
    'evidence_ref' => 'vault:hold-01', 'reviewed_at' => gmdate('c', time() - 60),
    'next_review_at' => gmdate('c', time() + DAY_IN_SECONDS),
]);
c97(is_string($hold) && $data->activeLegalHold('hold-case-01'), 'Active legal hold must be discoverable.');
$deletion = $data->recordDeletionObligation([
    'ledger_key' => 'delete-01', 'module_key' => 'file-17-communication',
    'subject_ref' => 'subject:anon-01', 'request_ref' => 'privacy:req-01',
    'deletion_scope' => ['messages owned by File 17'], 'legal_hold_ref' => 'hold:case-01',
]);
c97(is_string($deletion), 'Cross-file deletion obligation must be tracked by opaque references.');

$sensitive = $artifacts->save([
    'artifact_type' => 'asset', 'artifact_key' => 'leak', 'title' => 'Unsafe asset',
    'status' => 'active', 'classification' => 'C5',
    'payload' => ['password' => 'password=supersecret'],
]);
c97(is_wp_error($sensitive) && $sensitive->get_error_code() === 'spcrc_artifact_payload_sensitive', 'Sensitive payload material must be rejected.');

$record = $artifacts->get('data-inventory', 'privacy-requests');
c97(is_array($record) && ($record['version'] ?? 0) === 1, 'Artifact must expose an optimistic version.');
$stale = $artifacts->transition('data-inventory', 'privacy-requests', 'blocked', 99);
c97(is_wp_error($stale) && $stale->get_error_code() === 'spcrc_artifact_concurrent_update', 'Stale artifact mutation must fail closed.');

c97(count($GLOBALS['wpdb']->events) >= 6, 'Governed changes must produce durable audit events.');
echo "PASS: $count Cycle 97 governance/data completion assertions\n";
