<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Storage\AuditLogger;

function assertAuditAlias(bool $condition, string $reason): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$reason}\n");
        exit(1);
    }
}

$before = count($GLOBALS['wpdb']->events);
$event = (new AuditLogger())->record(
    'audit_alias_privacy_check',
    'file-24-security-center',
    'recorded',
    'high',
    [
        'patientName' => 'PRIVATE PATIENT FULL NAME',
        'medicalHistory' => 'PRIVATE MEDICAL NARRATIVE',
        'chiefComplaint' => 'PRIVATE SYMPTOM NARRATIVE',
        'guardianName' => 'PRIVATE GUARDIAN NAME',
        'phoneNumber' => '+92 300 111 2233',
        'EmailAddress' => 'private.contact@example.test',
        'ipAddress' => '203.0.113.77',
        'userAgent' => 'PRIVATE UNIQUE DEVICE',
        'ordinary_event' => 'review-completed',
        'nested' => [
            'caseHistory' => 'PRIVATE NESTED CLINICAL RECORD',
            'postalAddress' => 'PRIVATE STREET LOCATION',
        ],
    ]
);

assertAuditAlias(is_string($event), 'Security event must be recorded.');
assertAuditAlias(count($GLOBALS['wpdb']->events) === $before + 1, 'Exactly one event is written.');
$stored = $GLOBALS['wpdb']->events[$before]['context_json'] ?? '';
$decoded = is_string($stored) ? json_decode($stored, true) : null;
assertAuditAlias(is_array($decoded), 'Audit JSON must remain valid.');

foreach ([
    'patientname', 'medicalhistory', 'chiefcomplaint', 'guardianname',
] as $field) {
    assertAuditAlias(($decoded[$field] ?? null) === '[REDACTED]', "{$field} must not retain sensitive narrative.");
}
assertAuditAlias(($decoded['nested']['casehistory'] ?? $decoded['nested']['caseHistory'] ?? null) === '[REDACTED]', 'Nested clinical narrative must be redacted.');

foreach (['phonenumber', 'emailaddress', 'ipaddress', 'useragent'] as $name) {
    assertAuditAlias(str_starts_with((string) ($decoded[$name] ?? ''), 'sha256:'), "{$name} must be pseudonymized.");
}
assertAuditAlias(str_starts_with((string) ($decoded['nested']['postaladdress'] ?? ''), 'sha256:'), 'Nested postal address must be pseudonymized.');
assertAuditAlias(($decoded['ordinary_event'] ?? null) === 'review-completed', 'Non-sensitive evidence remains usable.');

foreach (['PRIVATE PATIENT', 'PRIVATE MEDICAL', 'PRIVATE SYMPTOM', 'PRIVATE GUARDIAN',
          'PRIVATE NESTED', 'PRIVATE STREET', 'PRIVATE UNIQUE', 'private.contact@example.test'] as $private) {
    assertAuditAlias(! str_contains((string) $stored, $private), 'Sensitive material leaked into audit JSON.');
}
echo "PASS: audit sensitive field aliases and nested clinical privacy\n";
