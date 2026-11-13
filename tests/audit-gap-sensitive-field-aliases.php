<?php

declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Storage\AuditGapStore;

function gaeAssert(bool $passed, string $message): void
{
    if (! $passed) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

$option = 'spcrc_test_alias_audit_gap';
$created = AuditGapStore::record($option, 'risk', 'test-object', 'write_failed', [
    'patientName' => 'PRIVATE PATIENT NAME',
    'medicalHistory' => 'PRIVATE HEALTH HISTORY',
    'guardianContact' => 'PRIVATE GUARDIAN CONTACT',
    'chiefComplaint' => 'PRIVATE CHIEF COMPLAINT',
    'ordinary' => 'bounded-safe',
]);
gaeAssert($created, 'Auditable write must persist.');
$raw = get_option($option, []);
$row = is_array($raw) ? current($raw) : null;
$context = is_array($row) ? ($row['context'] ?? []) : [];
foreach (['patientname','medicalhistory','guardiancontact','chiefcomplaint'] as $key) {
    gaeAssert(($context[$key] ?? '') === '[REDACTED]', 'Sensitive alias must be redacted before storage: ' . $key);
}
gaeAssert(($context['ordinary'] ?? '') === 'bounded-safe', 'Unrelated non-sensitive evidence remains useful.');

// A legacy/malformed source could already contain the plaintext: its read
// projection must not expose the value even though underlying repair is separate.
$rawKey = (string) array_key_first($raw);
$raw[$rawKey]['context'] = ['patientName' => 'EXISTING PRIVATE CLINICAL RECORD', 'ordinary' => 'bounded-safe'];
update_option($option, $raw, false);
$read = AuditGapStore::all($option);
$displayed = current($read);
gaeAssert(($displayed['context']['patientname'] ?? '') === '[REDACTED]', 'Read projection redacts legacy patientName payload.');
gaeAssert(($displayed['context']['ordinary'] ?? '') === 'bounded-safe', 'Read projection preserves safe evidence.');

echo "PASS: AuditGapStore sensitive field aliases are redacted on write and read\n";
