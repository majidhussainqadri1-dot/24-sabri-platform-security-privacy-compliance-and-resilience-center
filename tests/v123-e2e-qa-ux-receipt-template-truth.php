<?php

declare(strict_types=1);

function v123E2eAssert(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$json = file_get_contents(__DIR__ . '/../docs/V123-QA15-24-AND-UX01-14-E2E-RECEIPT-TEMPLATES.json');
$book = is_string($json) ? json_decode($json, true) : null;
v123E2eAssert(is_array($book), 'E2E evidence contract must be parseable.');
v123E2eAssert(($book['schema'] ?? null) === 'sabri-file24/v12.3-e2e-qa-evidence/1.0', 'E2E evidence template schema exact.');
v123E2eAssert(($book['truth_state'] ?? null) === 'all_not_run', 'Source-only fixtures cannot be labelled operational.');
$cases = $book['cases'] ?? null;
v123E2eAssert(is_array($cases) && count($cases) === 24, '14 UX and 10 QA cases must exist once.');
$ids = [];
foreach ($cases as $case) {
    v123E2eAssert(is_array($case), 'Case payload must be an array.');
    $id = (string) ($case['id'] ?? '');
    $ids[] = $id;
    v123E2eAssert(
        is_string($case['owner'] ?? null) && trim($case['owner']) !== ''
            && is_string($case['positive_acceptance_scenario'] ?? null)
            && is_string($case['mandatory_negative_case'] ?? null),
        "Each case must define owner and positive/negative test: {$id}"
    );
    v123E2eAssert(($case['status'] ?? null) === 'not_run', "No invented acceptance: {$id}");
    foreach (['execution_environment','repository_head','installed_package_checksum',
              'installed_plugin_version','db_schema_version','migration_state',
              'wordpress_core','php_runtime','browser_os_device','actor_role','locale',
              'synthetic_data_reference','observed_result','reviewer_identity_proof',
              'execution_started_at_utc','execution_finished_at_utc','retest_result',
              'independent_approval_ref'] as $field) {
        v123E2eAssert(
            array_key_exists($field, $case) && $case[$field] === null,
            "Nonexecuted receipt {$id} must explicitly mark {$field} as unknown."
        );
    }
    foreach (['redacted_evidence_refs','linked_defect_ids'] as $field) {
        v123E2eAssert(
            is_array($case[$field] ?? null) && $case[$field] === [],
            "No invented proof/defect IDs in {$id}."
        );
    }
}
$expected = [];
for ($i = 15; $i <= 24; ++$i) $expected[] = 'QA-' . $i;
for ($i = 1; $i <= 14; ++$i) $expected[] = 'UX-' . str_pad((string) $i, 2, '0', STR_PAD_LEFT);
sort($ids);
sort($expected);
v123E2eAssert($ids === $expected, 'Exact 24 QA and UX names without duplicates required.');
v123E2eAssert(
    ($book['counts']['actual_executed'] ?? null) === 0
        && ($book['counts']['staging_accepted'] ?? null) === 0
        && ($book['counts']['live_accepted'] ?? null) === 0,
    'All real acceptance counts remain zero until external receipts.'
);
echo "PASS: V12.3 twenty-four staging E2E receipt templates without invented operational evidence\n";
