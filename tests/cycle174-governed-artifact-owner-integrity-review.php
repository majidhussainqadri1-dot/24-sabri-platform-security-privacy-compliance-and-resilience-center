<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;

function c174(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$invalid = $registry->save([
    'artifact_type' => 'asset',
    'artifact_key' => 'cycle174-negative-owner',
    'title' => 'Negative owner coercion review',
    'status' => 'active',
    'classification' => 'C1',
    'owner_user_id' => -7,
    'payload' => [],
]);
c174(is_wp_error($invalid) && $invalid->get_error_code() === 'spcrc_artifact_owner_invalid', 'Negative owner IDs must fail closed rather than being absint-coerced into another real user.');

$system = $registry->save([
    'artifact_type' => 'asset',
    'artifact_key' => 'cycle174-system-owner',
    'title' => 'System-owned governed asset',
    'status' => 'active',
    'classification' => 'C1',
    'owner_user_id' => 0,
    'payload' => [],
]);
c174(is_string($system), 'Explicit system owner 0 must remain supported for seeded/platform artifacts.');
$record = $registry->get('asset', 'cycle174-system-owner');
c174(is_array($record) && ($record['owner_user_id'] ?? null) === 0, 'System owner 0 must round-trip without coercion.');

$source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Registry/GovernedArtifactRegistry.php');
c174(is_string($source) && str_contains($source, 'spcrc_artifact_owner_invalid') && ! str_contains($source, '$ownerUserId = absint('), 'Strict owner identity validation must remain encoded in save path.');

echo "PASS: cycle174 governed-artifact owner-identity coercion defect fixed and retested\n";
