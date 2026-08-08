<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Rest\GovernanceController;
use Sabri\Platform\Security\Storage\AuditLogger;

function c146(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$controller = new GovernanceController($registry);

$low = $registry->save([
    'artifact_type' => 'asset', 'artifact_key' => 'overview-safe', 'title' => 'Low sensitivity asset',
    'status' => 'active', 'classification' => 'C1', 'evidence_ref' => 'evidence:asset-safe',
    'payload' => ['internal_note' => 'bounded detail'],
]);
c146(! is_wp_error($low), 'Baseline C1 asset must save.');
$high = $registry->save([
    'artifact_type' => 'asset', 'artifact_key' => 'restricted-asset', 'title' => 'Restricted asset metadata',
    'status' => 'restricted', 'classification' => 'C5', 'evidence_ref' => 'evidence:asset-restricted',
    'payload' => ['custody' => 'restricted'],
]);
c146(! is_wp_error($high), 'Baseline C5 asset must save for read-boundary review.');

$GLOBALS['current_user_caps'] = ['spcrc_view_overview' => true];
$response = $controller->listArtifacts(['artifact_type' => 'asset', 'limit' => 20]);
c146($response instanceof WP_REST_Response, 'Overview authority must retain the bounded overview projection.');
$rows = $response->get_data()['artifacts'] ?? [];
c146(count($rows) === 1 && ($rows[0]['artifact_key'] ?? '') === 'overview-safe', 'Overview reads must exclude C3-C5 artifacts even within an otherwise readable type.');
c146(! array_key_exists('payload', $rows[0]) && ! array_key_exists('evidence_ref', $rows[0]) && ! array_key_exists('owner_user_id', $rows[0]), 'Overview projection must not expose payload, evidence reference or actor metadata.');

$GLOBALS['current_user_caps'] = ['spcrc_view_overview' => true, 'spcrc_manage_assets' => true];
$full = $controller->listArtifacts(['artifact_type' => 'asset', 'limit' => 20]);
$fullRows = $full instanceof WP_REST_Response ? ($full->get_data()['artifacts'] ?? []) : [];
c146(count($fullRows) === 2 && array_key_exists('payload', $fullRows[0]), 'Native artifact managers must retain full private records.');

$GLOBALS['current_user_caps'] = ['spcrc_manage_key_metadata' => true];
$request = [
    'artifact_type' => 'key-metadata', 'artifact_key' => 'master-key-meta', 'title' => 'Master key metadata',
    'status' => 'planned', 'classification' => 'C5', 'expected_version' => 0,
];
$blocked = $controller->saveArtifact($request);
c146(is_wp_error($blocked) && $blocked->get_error_code() === 'spcrc_governance_step_up_required', 'Sensitive REST governance mutation must fail without fresh step-up assurance.');
add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
$request['step_up_reference'] = 'assertion:cycle146-stepup';
$saved = $controller->saveArtifact($request);
c146($saved instanceof WP_REST_Response, 'Sensitive REST governance mutation may proceed after delegated capability and fresh step-up.');

$invalidVersion = $request;
$invalidVersion['artifact_key'] = 'second-key-meta';
$invalidVersion['title'] = 'Second key metadata';
$invalidVersion['expected_version'] = '-1';
$rejected = $controller->saveArtifact($invalidVersion);
c146(is_wp_error($rejected) && $rejected->get_error_code() === 'spcrc_governance_expected_version_invalid', 'Negative expected versions must not be coerced into a valid optimistic-lock value.');

echo "PASS: cycle146 governance REST least-privilege and step-up defects fixed and retested\n";
