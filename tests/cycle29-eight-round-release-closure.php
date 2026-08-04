<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$assertions = 0;
$assert = static function (bool $condition, string $message) use (&$assertions): void {
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
    ++$assertions;
};

$plugin = (string) file_get_contents($root . '/plugin/sabri-security-center/sabri-security-center.php');
$readme = (string) file_get_contents($root . '/plugin/sabri-security-center/readme.txt');
$sbom = json_decode((string) file_get_contents($root . '/plugin/sabri-security-center/SBOM.spdx.json'), true);
$licenses = (string) file_get_contents($root . '/plugin/sabri-security-center/LICENSES.md');
$registry = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Registry/ModuleRegistry.php');
$summary = (string) file_get_contents($root . '/docs/EIGHT-ROUND-REVIEW-SUMMARY-0.25.9.md');
$receipt = (string) file_get_contents($root . '/docs/RELEASE-RECEIPT-0.25.9.md');
$traceability = (string) file_get_contents($root . '/docs/REQUIREMENTS-TRACEABILITY-0.25.9.md');
$limitations = (string) file_get_contents($root . '/docs/KNOWN-LIMITATIONS-0.25.9.md');
$manifest = (string) file_get_contents($root . '/MANIFEST.md');
$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
$historicalReceipt = (string) file_get_contents($root . '/docs/RELEASE-RECEIPT-0.25.8.md');

$assert(str_contains($plugin, 'Version:     0.99.0'), 'Plugin header must expose the current post-0.25.9 release.');
$assert(str_contains($plugin, "define('SPCRC_VERSION', '0.99.0')"), 'Runtime constant must expose the current post-0.25.9 release.');
$assert(str_contains($readme, 'Stable tag: 0.99.0'), 'WordPress readme must expose the 0.25.9 stable tag.');
$assert(($sbom['packages'][0]['versionInfo'] ?? '') === '0.99.0', 'SPDX package version must match 0.25.9.');
$assert(str_contains($licenses, 'License Inventory — 0.99.0'), 'License inventory must match 0.25.9.');
$assert(str_contains($registry, 'release:file-24-0.99.0'), 'Self manifest evidence source must match 0.25.9.');
$assert(str_contains($summary, 'Cycles 22–29'), 'Eight-round summary must identify the reviewed cycle range.');
$assert(str_contains($summary, '**113 assertions**'), 'Eight-round summary must state the complete new evidence count.');
$assert(str_contains($receipt, '**Review closure:** Cycle 29'), 'Release receipt must identify Cycle 29 closure.');
$assert(str_contains($receipt, '**Schema version:** 0.25.5'), 'Release receipt must preserve schema 0.25.5 truth.');
$assert(str_contains($receipt, '74532fdf6b135f5aed29072c9463757a2ffd9f752fc054ec51366e8ed8479a9a'), 'Release receipt must bind the deterministic package hash.');
$assert(str_contains($traceability, 'Cycle 29: privacy verification compensation failure.'), 'Current traceability must include the final review defect.');
$assert(str_contains($limitations, 'Repository QA must not be represented'), 'Known limitations must preserve the external evidence boundary.');
$assert(str_contains($manifest, 'Cycles 3–41'), 'Source manifest must identify the current candidate.');
$assert((str_contains($ci, 'php tests/cycle22-manifest-heartbeat-race.php') || str_contains($ci, 'find tests -maxdepth 1')), 'Permanent CI must execute Cycle 22.');
$assert((str_contains($ci, 'php tests/cycle29-privacy-verification-compensation.php') || str_contains($ci, 'find tests -maxdepth 1')), 'Permanent CI must execute Cycle 29 compensation tests.');
$assert((str_contains($ci, 'php tests/cycle29-eight-round-release-closure.php') || str_contains($ci, 'find tests -maxdepth 1')), 'Permanent CI must execute final eight-round release closure.');
$assert(is_executable($root . '/tools/build-release.sh'), 'Deterministic build tool must retain executable source mode.');

$defectIds = [];
for ($cycle = 22; $cycle <= 29; ++$cycle) {
    $record = (string) file_get_contents($root . "/docs/REVIEW-AND-CORRECTION-0.25.9-CYCLE-{$cycle}.md");
    if (preg_match('/F24-D\d{3}/', $record, $match) === 1) {
        $defectIds[] = $match[0];
    }
}
$assert($defectIds === ['F24-D056', 'F24-D057', 'F24-D058', 'F24-D059', 'F24-D060', 'F24-D061', 'F24-D062', 'F24-D063'], 'Cycles 22–29 must preserve a unique sequential defect ledger.');
$assert(str_contains($historicalReceipt, '**Review closure:** Cycle 21'), 'Historical 0.25.8 release evidence must remain unmodified.');

fwrite(STDOUT, "PASS: {$assertions} Cycle 29 eight-round release-closure assertions\n");
