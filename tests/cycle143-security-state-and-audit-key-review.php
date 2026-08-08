<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;

function c143(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$modules = new ModuleRegistry();
c143($modules->register([
    'module_key' => 'cycle143-module',
    'name' => 'Cycle 143 Module',
    'version' => '1.0.0',
    'owner' => 'File 24',
    'data_classes' => ['C1'],
    'public_routes' => [],
    'private_routes' => [],
]), 'Test module manifest must register.');
$moduleKey = 'cycle143-module';
$states = new SecurityStateRegistry($modules, new AuditLogger());

$long = $states->merge([
    '11111111-1111-4111-8111-111111111143' => [
        'request_id' => '11111111-1111-4111-8111-111111111143',
        'module_key' => $moduleKey, 'state' => 'restricted-writes', 'reason' => 'Long external restriction',
        'requested_by' => 7, 'requested_at' => gmdate('c'), 'expires_at' => gmdate('c', time() + 2 * DAY_IN_SECONDS),
    ],
]);
c143(! isset($long['11111111-1111-4111-8111-111111111143']), 'External merged restrictions must obey the same maximum TTL as native requests.');

$future = $states->merge([
    '22222222-2222-4222-8222-222222222143' => [
        'request_id' => '22222222-2222-4222-8222-222222222143',
        'module_key' => $moduleKey, 'state' => 'restricted-writes', 'reason' => 'Future external restriction',
        'requested_by' => 7, 'requested_at' => gmdate('c', time() + HOUR_IN_SECONDS), 'expires_at' => gmdate('c', time() + 2 * HOUR_IN_SECONDS),
    ],
]);
c143(! isset($future['22222222-2222-4222-8222-222222222143']), 'Materially future-dated external state requests must fail closed.');

$valid = $states->merge([
    '33333333-3333-4333-8333-333333333143' => [
        'request_id' => '33333333-3333-4333-8333-333333333143',
        'module_key' => $moduleKey, 'state' => 'restricted-writes', 'reason' => 'Current external restriction',
        'requested_by' => 7, 'requested_at' => gmdate('c', time() - 30), 'expires_at' => gmdate('c', time() + HOUR_IN_SECONDS),
    ],
]);
c143(isset($valid['33333333-3333-4333-8333-333333333143']), 'Bounded, current external state evidence must remain consumable.');

$auditSource = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Storage/AuditLogger.php');
c143(is_string($auditSource) && ! str_contains($auditSource, "hash('sha256', __FILE__)"), 'Audit pseudonymization must not fall back to a deterministic source-path key.');
c143(str_contains((string) $auditSource, "spcrc/audit_pseudonymization_key") && str_contains((string) $auditSource, "return '[REDACTED]'"), 'Audit pseudonymization must use a private configured key or fail closed to redaction.');

echo "PASS: cycle143 external security-state time bounds and audit-pseudonym key defects fixed and retested\n";
