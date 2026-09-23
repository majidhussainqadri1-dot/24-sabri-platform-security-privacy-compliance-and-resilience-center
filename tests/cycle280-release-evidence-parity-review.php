<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\ConditionalIntegrationCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Release\ReleaseStatus;

function c280(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$root = dirname(__DIR__);
$source = json_decode((string) file_get_contents($root . '/docs/SOURCE-MANIFEST-0.99.0.json'), true, 512, JSON_THROW_ON_ERROR);
$packagedSource = json_decode((string) file_get_contents($root . '/plugin/sabri-security-center/docs/SOURCE-MANIFEST.json'), true, 512, JSON_THROW_ON_ERROR);

foreach ([$source, $packagedSource] as $manifest) {
    c280(($manifest['integration_files']['first'] ?? -1) === 0, 'Source manifest integration numbering must start at 00.');
    c280(($manifest['integration_files']['last'] ?? -1) === 26, 'Source manifest integration numbering must end at 26.');
    c280(($manifest['integration_files']['count'] ?? 0) === 27, 'Source manifest must record 27 permanent integration rows.');
    c280(($manifest['conditional_integration_contracts']['count'] ?? 0) === 3, 'Source manifest must record three conditional integration contracts.');
    c280(($manifest['verification']['php_files_minimum'] ?? 0) >= 294, 'Source manifest must carry the corrected PHP verification floor.');
    c280(($manifest['verification']['test_programs_minimum'] ?? 0) >= 206, 'Source manifest must carry the corrected test-program floor.');
    c280(($manifest['verification']['latest_review_cycle'] ?? 0) >= 280, 'Source manifest review lineage must retain Cycle 280 or advance beyond it.');
    c280(str_contains((string) ($manifest['source_checksum_artifact'] ?? ''), 'file24-source-checksums.sha256'), 'Source checksum evidence must refer to the exact-head CI artifact.');
    c280(! array_key_exists('checksum_ledger', $manifest), 'Source manifest must not claim a non-existent repository checksum ledger.');
}

$receipt = (string) file_get_contents($root . '/docs/RELEASE-RECEIPT-0.99.0.md');
c280(str_contains($receipt, 'Files 00–26 integration rows: `27`'), 'Release receipt must record Files 00–26 / 27 rows.');
c280(str_contains($receipt, 'Conditional cross-plan assurance contracts: `3/3`'), 'Release receipt must record 3/3 conditional integrations.');
c280(str_contains($receipt, 'Cycles `198–277`') && preg_match('/`278–([0-9]+)`/', $receipt, $receiptRange) === 1 && (int) ($receiptRange[1] ?? 0) >= 280, 'Release receipt must preserve Cycle 280 while allowing later corrective reviews.');

$register = (string) file_get_contents($root . '/docs/EIGHTY-ROUND-REVIEW-AND-CORRECTION-CYCLES-198-277.md');
c280(str_contains($register, 'Defect-bearing requested rounds | **9**'), 'Eighty-round register must use the corrected nine-defect count.');
c280(str_contains($register, '198, 199, 200, 201, 202, 203, 204, 205, 206'), 'Eighty-round register must include Cycle 206 as defect-bearing.');

$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
c280(preg_match('/test "\\$count" -ge ([0-9]+)/', $ci, $lintFloor) === 1 && (int) ($lintFloor[1] ?? 0) >= 294, 'CI must retain or advance the corrected PHP source/test floor.');
c280(preg_match_all('/test "\\$count" -ge ([0-9]+)/', $ci, $floors) >= 2 && min(array_map('intval', $floors[1] ?? [])) >= 206, 'CI must retain or advance the corrected independent test-program floor.');
c280(str_contains($ci, 'seq 116 197'), 'CI must retain explicit historical regression existence through Cycle 197.');
c280(str_contains($ci, 'cycle277-eighty-round-review-closure.php'), 'CI must explicitly bind Cycle 277 closure.');
c280(str_contains($ci, 'cycle278-manifest-integration-completeness-review.php'), 'CI must explicitly bind Cycle 278.');
c280(str_contains($ci, 'cycle279-conditional-cross-plan-assurance-review.php'), 'CI must explicitly bind Cycle 279.');
c280(str_contains($ci, 'cycle280-release-evidence-parity-review.php'), 'CI must explicitly bind Cycle 280.');
c280(str_contains($ci, 'file24-source-snapshot-exact-head.zip'), 'CI source snapshot naming must no longer claim Cycle 184.');

c280(PlatformIntegrationMatrix::complete(), 'Permanent integration matrix must remain structurally complete.');
c280(ConditionalIntegrationCatalog::repositoryCodingComplete(), 'Conditional integration catalogue must remain complete.');
c280(ReleaseStatus::repositoryCodingComplete(), 'ReleaseStatus must include the corrected current repository scope.');

echo "PASS: Cycle 280 release-evidence and exact-head parity corrections passed\n";
