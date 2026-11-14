<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Storage\AuditLogger;

function assertV123MultilingualAudit(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$before = count($GLOBALS['wpdb']->events);
$context = [
    'مریض_نام' => 'PRIVATE URDU PATIENT NAME',
    'التاريخ_المرضي' => 'PRIVATE ARABIC MEDICAL HISTORY',
    'طبی_معلومات' => 'PRIVATE URDU MEDICAL CASE DETAILS',
    'nested' => [
        'رپورٹ_مریض' => 'PRIVATE NESTED CLINICAL REPORT',
        'اسم_المريض' => 'PRIVATE NESTED ARABIC PATIENT NAME',
        'ordinary_status' => 'correctly-bounded',
    ],
    'patientName_مریض' => 'PRIVATE MIXED LANGUAGE CLINICAL IDENTITY',
    'ordinary_event' => 'review-complete',
];
$id = (new AuditLogger())->record(
    'multilingual_audit_privacy_check',
    'file-24-security-center',
    'recorded',
    'high',
    $context
);
assertV123MultilingualAudit(is_string($id), 'Security audit event must be saved.');
assertV123MultilingualAudit(count($GLOBALS['wpdb']->events) === $before + 1, 'Exactly one event is stored.');
$json = $GLOBALS['wpdb']->events[$before]['context_json'] ?? '';
$decoded = is_string($json) ? json_decode($json, true) : null;
assertV123MultilingualAudit(is_array($decoded), 'Stored audit context must be valid JSON.');
assertV123MultilingualAudit(
    ($decoded['ordinary_event'] ?? null) === 'review-complete'
    && ($decoded['nested']['ordinary_status'] ?? null) === 'correctly-bounded',
    'Safe ASCII diagnostic metadata must remain available.'
);

foreach ([
    'PRIVATE URDU PATIENT NAME',
    'PRIVATE ARABIC MEDICAL HISTORY',
    'PRIVATE URDU MEDICAL CASE DETAILS',
    'PRIVATE NESTED CLINICAL REPORT',
    'PRIVATE NESTED ARABIC PATIENT NAME',
    'PRIVATE MIXED LANGUAGE CLINICAL IDENTITY',
] as $sensitive) {
    assertV123MultilingualAudit(! str_contains($json, $sensitive), 'Sensitive multilingual context leaked to persistent audit JSON.');
}

$redacted = 0;
foreach ($decoded as $name => $value) {
    if (str_starts_with((string) $name, 'field_')) {
        assertV123MultilingualAudit($value === '[REDACTED]', 'Unknown non-ASCII field must fail closed.');
        ++$redacted;
    }
}
assertV123MultilingualAudit($redacted >= 3, 'Hashed private Unicode field keys remain pseudonymous and redacted.');
assertV123MultilingualAudit(
    ($decoded['nested']['field_' . substr(hash('sha256', 'رپورٹ_مریض'), 0, 16)] ?? null) === '[REDACTED]',
    'Nested Urdu narrative field must not leak.'
);
assertV123MultilingualAudit(
    ($decoded['patientname_'] ?? $decoded['patientname'] ?? null) === '[REDACTED]',
    'Mixed ASCII/Urdu sensitive label must fail closed.'
);
echo "PASS: File 24 V12.3 multilingual Urdu/Arabic audit context cannot leak patient data\n";
