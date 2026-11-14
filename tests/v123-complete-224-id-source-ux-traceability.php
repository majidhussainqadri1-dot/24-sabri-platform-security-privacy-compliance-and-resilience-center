<?php

declare(strict_types=1);

/**
 * Source traceability completeness is NOT feature acceptance or live assurance.
 * Verify IDs, immutable legacy-source hashes, owner fields and blocked states.
 */
function v123FullTraceAssert(bool $ok, string $reason): void
{
    if (! $ok) {
        fwrite(STDERR, "FAIL: {$reason}\n");
        exit(1);
    }
}

$root = dirname(__DIR__);
$json = file_get_contents($root . '/docs/V123-LEGACY-168-AND-UX14-SOURCE-TRACEABILITY.json');
$rtm = is_string($json) ? json_decode($json, true) : null;
v123FullTraceAssert(is_array($rtm), 'V12.3 source-to-UX RTM must be parseable JSON.');
v123FullTraceAssert(
    ($rtm['schema'] ?? '') === 'sabri-file24/v12.3-source-and-ux-rtm/1.0',
    'Source and UX RTM requires an exact schema.'
);
$items = $rtm['entries'] ?? [];
v123FullTraceAssert(is_array($items) && count($items) === 182, 'Exactly 168 legacy + 14 UX entries required.');

$expected = [];
for ($n = 1; $n <= 100; ++$n) $expected[] = 'F24-R' . str_pad((string) $n, 3, '0', STR_PAD_LEFT);
for ($n = 262; $n <= 285; ++$n) $expected[] = 'CV-' . $n;
$expected[] = 'F24-CEN-01';
for ($n = 1; $n <= 25; ++$n) $expected[] = 'F24-FUT-' . str_pad((string) $n, 3, '0', STR_PAD_LEFT);
for ($n = 1; $n <= 14; ++$n) $expected[] = 'UX-' . str_pad((string) $n, 2, '0', STR_PAD_LEFT);
$docs = [];
$chat = 0;
foreach ($items as $id => $item) {
    v123FullTraceAssert(is_array($item) && ($item['id'] ?? '') === $id, "Mapped ID mismatch: {$id}");
    v123FullTraceAssert(
        is_string($item['title'] ?? null) && trim($item['title']) !== '',
        "Missing primary-source requirement title: {$id}"
    );
    v123FullTraceAssert(
        ($item['source_independent_review'] ?? 'missing') !== 'accepted',
        "Cannot fabricate independent review for {$id}"
    );
    v123FullTraceAssert(
        ($item['staging_acceptance'] ?? '') === 'not_run'
        && ($item['live_acceptance'] ?? '') === 'not_run',
        "Actual deployed acceptance must not be inferred: {$id}"
    );
    v123FullTraceAssert(
        ($item['actual_evidence_ref'] ?? 'MISSING') === null,
        "Unverified acceptance must not contain invented evidence: {$id}"
    );

    if (str_starts_with($id, 'CHAT-')) {
        ++$chat;
    } elseif (! in_array($id, $expected, true)) {
        v123FullTraceAssert(false, "Unexpected source/UX ID: {$id}");
    }

    if (str_starts_with($id, 'UX-')) {
        v123FullTraceAssert(
            is_string($item['native_owner'] ?? null) && $item['native_owner'] !== '',
            "UX acceptance needs a native owner: {$id}"
        );
        continue;
    }
    $source = $item['legacy_source'] ?? '';
    $sha = $item['legacy_source_blob_sha'] ?? '';
    v123FullTraceAssert(
        is_string($source) && str_starts_with($source, 'docs/') && preg_match('/^[0-9a-f]{40}$/', (string) $sha) === 1,
        "Missing exact source document locator/hash: {$id}"
    );
    if (! isset($docs[$source])) {
        $bytes = file_get_contents($root . '/' . $source);
        v123FullTraceAssert(is_string($bytes), "Missing original source file: {$source}");
        $docs[$source] = [
            'text' => $bytes,
            'blob' => sha1('blob ' . strlen($bytes) . "\0" . $bytes),
        ];
    }
    v123FullTraceAssert(
        hash_equals((string) $docs[$source]['blob'], (string) $sha),
        "Legacy file changed without updating the exact source receipt: {$source}"
    );
    v123FullTraceAssert(
        preg_match('/^\\|\\s*' . preg_quote($id, '/') . '\\s*\\|/m', $docs[$source]['text']) === 1,
        "Original legacy source missing the mapped exact ID: {$id}"
    );
}
v123FullTraceAssert($chat === 18, 'Exactly 18 original CHAT directives required.');
$found = array_keys($items);
sort($found);
sort($expected);
$nonChat = array_values(array_filter($found, static fn (string $id): bool => ! str_starts_with($id, 'CHAT-')));
v123FullTraceAssert($nonChat === $expected, 'Every non-CHAT baseline and UX ID must occur once.');
v123FullTraceAssert(count($docs) === 4, 'Exactly four original legacy source documents required.');

$ledgerBytes = file_get_contents($root . '/docs/V123-ACCEPTANCE-EVIDENCE-LEDGER.json');
$ledger = is_string($ledgerBytes) ? json_decode($ledgerBytes, true) : null;
v123FullTraceAssert(is_array($ledger), 'The 42 independent V12.3 new IDs must remain in their separate acceptance ledger.');
$additional = [];
foreach (($ledger['checks'] ?? []) as $family) {
    foreach ($family as $row) {
        $additional[] = (string) ($row['id'] ?? '');
    }
}
v123FullTraceAssert(count($additional) === 42, 'Exactly 42 new QA/metric/storage/delta IDs required.');
v123FullTraceAssert(
    count(array_unique(array_merge(array_keys($items), $additional))) === 224,
    'Total 224 legacy/UX/V12.3 mapped IDs must remain unique without status conflation.'
);

echo "PASS: V12.3 exact 168 legacy + 14 UX + 42 new IDs, four source hashes, 224/224 mapped without invented acceptance\n";
