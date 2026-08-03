<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Storage\AuditGapStore;
AuditGapStore::record('spcrc_cycle68_audit_gap', 'privacy', 'case-68', 'audit_failed', [
    'email' => 'person@example.test',
    'ordinary' => 'bounded evidence',
]);
$gap = end($GLOBALS['wp_options']['spcrc_cycle68_audit_gap']);
cycleReviewAssert(($gap['context']['email'] ?? '') === '[REDACTED]', 'Sensitive context keys must be redacted regardless of value parser.');
cycleReviewAssert(($gap['context']['ordinary'] ?? '') === 'bounded evidence', 'Non-sensitive bounded evidence must survive.');

cycleReviewPass(68, 'audit-gap-context-redaction');
