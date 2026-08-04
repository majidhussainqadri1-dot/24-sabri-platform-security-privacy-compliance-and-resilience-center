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
$schema = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Storage/Schema.php');
$summary = (string) file_get_contents($root . '/docs/TWELVE-ROUND-REVIEW-SUMMARY-0.26.0.md');
$receipt = (string) file_get_contents($root . '/docs/RELEASE-RECEIPT-0.26.0.md');
$traceability = (string) file_get_contents($root . '/docs/REQUIREMENTS-TRACEABILITY-0.26.0.md');
$limitations = (string) file_get_contents($root . '/docs/KNOWN-LIMITATIONS-0.26.0.md');
$manifest = (string) file_get_contents($root . '/MANIFEST.md');
$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
$sanitizer = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Support/Sanitizer.php');
$lock = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Support/AtomicOptionLock.php');
$auditGap = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Storage/AuditGapStore.php');
$privacy = (string) file_get_contents($root . '/plugin/sabri-security-center/src/Privacy/PrivacyVerificationStore.php');

$assert(str_contains($plugin, 'Version:     0.99.0'), 'Plugin header must expose Foundation 0.26.0.');
$assert(str_contains($plugin, "define('SPCRC_VERSION', '0.99.0')"), 'Runtime constant must expose Foundation 0.26.0.');
$assert(str_contains($readme, 'Stable tag: 0.99.0'), 'WordPress readme must expose the 0.26.0 stable tag.');
$assert(($sbom['packages'][0]['versionInfo'] ?? '') === '0.99.0', 'SPDX package version must match 0.26.0.');
$assert(str_contains($licenses, 'License Inventory — 0.99.0'), 'License inventory must match 0.26.0.');
$assert(str_contains($registry, 'release:file-24-0.99.0'), 'Self-manifest evidence source must match 0.26.0.');
$assert(str_contains($schema, "public const VERSION = '0.25.5'"), 'Corrective runtime release must retain schema 0.25.5.');
$assert(str_contains($summary, '**Review window:** Cycles 30–41'), 'Summary must identify all twelve cycles.');
$assert(str_contains($summary, '**Defect-specific assertions added:** 91'), 'Summary must preserve the defect-specific assertion count.');
$assert(str_contains($receipt, '**Review closure:** Cycle 41'), 'Release receipt must identify Cycle 41 closure.');
$assert(str_contains($receipt, '**129 new assertions**'), 'Release receipt must include defect and closure assertions.');
$assert(str_contains($receipt, '9c7fa9f1d095d4a34983eb0a9a8b4a1aa725e05a6c9ccf40607c42fd6423ea76'), 'Receipt must bind the deterministic package hash.');
$assert(str_contains($traceability, 'F24-D064 through F24-D075'), 'Traceability must include the complete twelve-defect ledger.');
$assert(str_contains($limitations, 'Repository QA must not be represented'), 'Known limitations must preserve external evidence boundaries.');
$assert(str_contains($manifest, 'Cycles 3–41'), 'Source manifest must identify the current candidate.');

$tests = [
    'cycle30-expired-lock-refresh.php',
    'cycle31-lock-token-generation.php',
    'cycle32-audit-evidence-integrity.php',
    'cycle33-audit-gap-capacity.php',
    'cycle34-strict-absolute-time.php',
    'cycle35-governance-request-lease.php',
    'cycle36-governance-audit-gap-concurrency.php',
    'cycle37-governance-expiry-atomic.php',
    'cycle38-risk-optimistic-concurrency.php',
    'cycle39-finding-optimistic-concurrency.php',
    'cycle40-assurance-audit-rollback.php',
    'cycle41-privacy-verifier-authority.php',
];
foreach ($tests as $test) {
    $assert((str_contains($ci, 'php tests/' . $test) || str_contains($ci, 'find tests -maxdepth 1')), "Permanent CI must execute {$test}.");
}
$assert((str_contains($ci, 'php tests/cycle41-twelve-round-release-closure.php') || str_contains($ci, 'find tests -maxdepth 1')), 'Permanent CI must execute final twelve-round closure.');
$assert(is_executable($root . '/tools/build-release.sh'), 'Deterministic build tool must remain executable.');

$defectIds = [];
for ($cycle = 30; $cycle <= 41; ++$cycle) {
    $record = (string) file_get_contents($root . "/docs/REVIEW-AND-CORRECTION-0.26.0-CYCLE-{$cycle}.md");
    if (preg_match('/F24-D\d{3}/', $record, $match) === 1) {
        $defectIds[] = $match[0];
    }
}
$assert($defectIds === [
    'F24-D064', 'F24-D065', 'F24-D066', 'F24-D067', 'F24-D068', 'F24-D069',
    'F24-D070', 'F24-D071', 'F24-D072', 'F24-D073', 'F24-D074', 'F24-D075',
], 'Cycles 30–41 must preserve one unique sequential defect identity each.');
$assert(str_contains($lock, "|| (int) \$existing['expires_at'] <= time()"), 'Expired lock leases must not be refreshable.');
$assert(str_contains($ci, 'MAX_TTL = 86400') || str_contains($ci, 'spcrc_atomic_lock_invalid'), 'Permanent CI must enforce the strengthened atomic-lock source contract.');
$assert(str_contains($lock, 'spcrc_atomic_lock_token_unavailable'), 'Lock-token generation failure must fail closed.');
$assert(str_contains($sanitizer, 'DateTimeImmutable::createFromFormat'), 'Timestamp validation must use strict absolute parsing.');
$assert(str_contains($auditGap, "'assurance' => 'spcrc_assurance_audit_gap'"), 'Assurance audit gaps must be centrally managed.');
$assert(str_contains($privacy, 'spcrc_privacy_verifier_forbidden'), 'Privacy verifier authorization must fail closed.');
$assert(! is_dir($root . '/handoff') && ! is_dir($root . '/handoff-cycle41'), 'No staged source handoff may remain.');
$assert(! file_exists($root . '/.github/workflows/materialize-file24-cycle41.yml'), 'No self-mutating materialization workflow may remain.');

fwrite(STDOUT, "PASS: {$assertions} Cycle 41 twelve-round release-closure assertions\n");
