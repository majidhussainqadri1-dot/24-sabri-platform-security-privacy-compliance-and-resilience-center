<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\System\SystemCheck;

function assertV123ReservedCheck(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$checker = new SystemCheck(new ModuleRegistry());
$baseline = $checker->run();
assertV123ReservedCheck(count($baseline) === 13, 'Original native check inventory remains present.');

// The name used to alert that core checks were manipulated must never be
// claimable by a general-purpose WordPress extension with fabricated PASS.
add_filter('spcrc/system_checks', static function (array $items): array {
    $items[] = [
        'key' => 'system_checks_integrity',
        'label' => 'Externally forged integrity certification',
        'status' => 'pass',
        'detail' => 'Everything is verified',
    ];
    $items[] = [
        'key' => 'module_truth',
        'label' => 'Module evidence',
        'status' => 'unknown',
        'detail' => 'No external verification',
    ];
    return $items;
}, 10, 1);

$result = $checker->run();
$integrityRows = array_values(array_filter($result, static fn (array $row): bool => ($row['key'] ?? '') === 'system_checks_integrity'));
assertV123ReservedCheck(count($integrityRows) === 1, 'Reserved system-check key must be unique.');
assertV123ReservedCheck(
    ($integrityRows[0]['status'] ?? '') === 'critical',
    'Forged PASS under reserved integrity key must fail closed.'
);
assertV123ReservedCheck(
    ($integrityRows[0]['label'] ?? '') !== 'Externally forged integrity certification',
    'The native control must own the integrity finding label.'
);

$byKey = array_column($result, null, 'key');
assertV123ReservedCheck(
    ($byKey['module_truth']['status'] ?? '') === 'unknown',
    'Well-formed independent unknown evidence remains available without false success.'
);
assertV123ReservedCheck(
    ($byKey['schema'] ?? null) === (array_column($baseline, null, 'key')['schema'] ?? null),
    'Native schema evidence remains canonical.'
);

echo "PASS: File24 V12.3 externally forged reserved integrity results rejected\n";
