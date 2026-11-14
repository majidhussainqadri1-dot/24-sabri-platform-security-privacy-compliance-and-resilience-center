<?php

declare(strict_types=1);

/**
 * V12.3 D01/G0 machine-readable acceptance inventory.
 * Records a requirement's mapping without falsely certifying deployment.
 */
function v123LedgerAssert(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$path = __DIR__ . '/../docs/V123-ACCEPTANCE-EVIDENCE-LEDGER.json';
$json = file_get_contents($path);
$ledger = is_string($json) ? json_decode($json, true) : null;
v123LedgerAssert(is_array($ledger), 'Acceptance ledger must parse as JSON.');
v123LedgerAssert(
    ($ledger['schema'] ?? null) === 'sabri-file24/v12.3-acceptance-ledger/1.0',
    'Acceptance ledger must declare the exact schema.'
);
v123LedgerAssert(
    ($ledger['release_candidate_status'] ?? '') !== 'operational',
    'Pending source branch is not an operational release.'
);

$expected = [
    'outcome_metrics' => ['M', 1, 12],
    'acceptance_qa' => ['QA-', 15, 24],
    'storage_lifecycle' => ['STO-', 1, 10],
    'v123_changes' => ['V12.3-', 1, 10],
];
$checks = is_array($ledger['checks'] ?? null) ? $ledger['checks'] : [];
foreach ($expected as $family => [$prefix, $start, $end]) {
    $rows = $checks[$family] ?? null;
    v123LedgerAssert(is_array($rows), "Missing mapped family {$family}.");
    $ids = [];
    foreach ($rows as $row) {
        v123LedgerAssert(is_array($row), "{$family} has invalid row.");
        v123LedgerAssert(
            is_string($row['owner'] ?? null) && trim($row['owner']) !== '',
            "{$family} requires an actual named domain owner."
        );
        v123LedgerAssert(
            in_array($row['source_mapping_status'] ?? '', ['mapped', 'not_mapped'], true),
            "{$family} source mapping must be explicit."
        );
        foreach (['staging_status', 'live_status'] as $field) {
            $state = $row[$field] ?? '';
            v123LedgerAssert(
                in_array($state, ['not_run', 'blocked', 'failed', 'accepted'], true),
                "{$family} environment state is invalid."
            );
            if ($state === 'accepted') {
                v123LedgerAssert(
                    is_string($row['evidence_ref'] ?? null) && trim($row['evidence_ref']) !== '',
                    "{$family} accepted state requires actual evidence reference."
                );
            }
        }
        $ids[] = (string) ($row['id'] ?? '');
    }
    $wanted = [];
    for ($i = $start; $i <= $end; ++$i) {
        $wanted[] = $prefix . str_pad((string) $i, 2, '0', STR_PAD_LEFT);
    }
    sort($ids);
    sort($wanted);
    v123LedgerAssert($ids === $wanted, "{$family} must have exact nonduplicated V12.3 IDs.");
}

$gates = is_array($ledger['gates'] ?? null) ? $ledger['gates'] : [];
v123LedgerAssert(count($gates) === 10, 'Ten governance gates G0..G9 required.');
foreach ($gates as $index => $gate) {
    v123LedgerAssert(
        is_array($gate) && ($gate['id'] ?? '') === 'G' . $index,
        'Gate order and identity must be stable.'
    );
    v123LedgerAssert(
        in_array($gate['status'] ?? '', ['mapped', 'source_corrected', 'blocked', 'pending', 'accepted'], true),
        'Gate status must be in controlled vocabulary.'
    );
    if (($gate['status'] ?? '') === 'accepted') {
        v123LedgerAssert(
            is_string($gate['evidence_ref'] ?? null) && $gate['evidence_ref'] !== '',
            'Accepted gate must have nonblank independent evidence.'
        );
    }
}

$incident = $ledger['mandatory_incident_fields'] ?? [];
foreach (['repository_head', 'deployed_version', 'db_version', 'migration_state', 'live_verification_status'] as $key) {
    v123LedgerAssert(
        is_string($incident[$key] ?? null) && $incident[$key] !== '',
        "Production incident field {$key} must never be silently omitted."
    );
}
v123LedgerAssert(($ledger['counts']['live_verified_corrections'] ?? null) === 0, 'No live source fixes can be claimed without live evidence.');
v123LedgerAssert(($ledger['counts']['independent_human_pr_approvals'] ?? null) === 0, 'Do not invent independent human approvals.');
v123LedgerAssert(($ledger['counts']['total_source_findings'] ?? null) === 22, 'Bounded source finding ledger count must be exact.');
echo "PASS: V12.3 acceptance ledger has all 52 mapped/blocked entries and no invented live assurance\n";
