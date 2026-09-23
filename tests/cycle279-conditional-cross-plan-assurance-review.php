<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ConditionalIntegrationCatalog;

function c279(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

c279(ConditionalIntegrationCatalog::repositoryCodingComplete(), 'Conditional integration catalogue must be structurally complete.');
c279(count(ConditionalIntegrationCatalog::all()) === 3, 'Exactly three approved conditional cross-plan assurance contracts are required.');

foreach (ConditionalIntegrationCatalog::all() as $key => $record) {
    $evidence = [
        'controls' => $record['required_controls'],
        'contract_version' => $record['contract_version'],
        'evidence_ref' => 'evidence:' . $key,
        'reviewed_at' => gmdate('c'),
        'native_owner_preserved' => true,
        'activation_requested' => false,
    ];
    $ready = ConditionalIntegrationCatalog::evaluate($key, $evidence);
    c279(($ready['state'] ?? '') === 'ready-for-activation-review', $key . ' complete evidence must be ready but not auto-activated.');
    c279(empty($ready['write_allowed']) && empty($ready['activation_allowed']), $key . ' must remain non-writable until activation is explicitly requested.');

    $evidence['activation_requested'] = true;
    $verified = ConditionalIntegrationCatalog::evaluate($key, $evidence);
    c279(($verified['state'] ?? '') === 'verified', $key . ' complete requested activation evidence must verify.');
    c279(! empty($verified['write_allowed']) && ! empty($verified['activation_allowed']), $key . ' verified activation evidence must permit the bounded governed action.');

    $broken = $evidence;
    array_pop($broken['controls']);
    $blocked = ConditionalIntegrationCatalog::evaluate($key, $broken);
    c279(($blocked['state'] ?? '') === 'blocked' && empty($blocked['write_allowed']), $key . ' must fail closed when a required control is missing.');
}

$malformedVersion = ConditionalIntegrationCatalog::evaluate('traffic-analytics', [
    'controls' => ConditionalIntegrationCatalog::get('traffic-analytics')['required_controls'] ?? [],
    'contract_version' => 'not-a-version',
    'evidence_ref' => 'evidence:bad-version',
    'reviewed_at' => gmdate('c'),
    'native_owner_preserved' => true,
    'activation_requested' => true,
]);
c279(($malformedVersion['state'] ?? '') === 'blocked' && empty($malformedVersion['contract_compatible']), 'Malformed contract versions must fail closed.');

$unknown = ConditionalIntegrationCatalog::evaluate('unknown-plan', [
    'controls' => [],
    'activation_requested' => true,
]);
c279(($unknown['state'] ?? '') === 'unknown' && empty($unknown['write_allowed']), 'Unknown conditional plans must fail closed.');

echo "PASS: Cycle 279 conditional cross-plan assurance corrections passed\n";
