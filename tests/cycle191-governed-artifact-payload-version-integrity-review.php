<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;

function c191(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$registry = new GovernedArtifactRegistry(new AuditLogger());
$list = [];
for ($i = 0; $i < 51; ++$i) $list[] = 'item-' . $i;
$overflow = $registry->save([
    'artifact_type' => 'asset',
    'artifact_key' => 'cycle191-list-overflow',
    'title' => 'Payload list overflow review',
    'status' => 'active',
    'classification' => 'C1',
    'owner_user_id' => 7,
    'payload' => ['declared_controls' => $list],
]);
c191(is_wp_error($overflow) && $overflow->get_error_code() === 'spcrc_artifact_payload_list_exceeded', 'A 51st payload-list item must reject the artifact rather than be silently omitted.');

$created = $registry->save([
    'artifact_type' => 'asset',
    'artifact_key' => 'cycle191-version',
    'title' => 'Stored version integrity review',
    'status' => 'active',
    'classification' => 'C1',
    'owner_user_id' => 7,
    'payload' => [],
]);
c191(is_string($created), 'Artifact fixture must create at version one.');
$option = 'spcrc_artifact_' . substr(hash('sha256', 'asset|cycle191-version'), 0, 40);
$GLOBALS['wp_options'][$option]['version'] = -1;
$corrupt = $registry->get('asset', 'cycle191-version');
c191(is_array($corrupt) && ($corrupt['version'] ?? null) === 0, 'Malformed negative persisted version must surface as invalid rather than normalize to a valid positive version.');
$update = $registry->save(array_merge($corrupt ?? [], ['title' => 'Must not overwrite']), 1);
c191(is_wp_error($update) && $update->get_error_code() === 'spcrc_artifact_concurrent_update', 'Corrupted persisted version must block optimistic update instead of being absint-coerced into the expected version.');

$source = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Registry/GovernedArtifactRegistry.php');
c191(str_contains($source, 'spcrc_artifact_payload_list_exceeded') && ! str_contains($source, "'version' => max(1, absint("), 'Payload overflow and stored-version strictness must remain encoded.');

echo "PASS: cycle191 governed-artifact silent payload truncation and stored-version coercion defects fixed and retested\n";
