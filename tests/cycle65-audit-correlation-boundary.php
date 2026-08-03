<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Storage\AuditLogger;
$_SERVER['HTTP_X_CORRELATION_ID'] = 'external-correlation-12345';
$audit = new AuditLogger();
$id = $audit->record('cycle65_event', 'file-24-security-center');
cycleReviewAssert(is_string($id), 'Audit event must persist.');
$row = end($GLOBALS['wpdb']->events);
cycleReviewAssert(($row['correlation_id'] ?? '') !== 'external-correlation-12345', 'Untrusted incoming correlation must never become canonical identity.');
$context = json_decode((string) ($row['context_json'] ?? '{}'), true);
cycleReviewAssert(str_starts_with((string) ($context['_incoming_correlation_hash'] ?? ''), 'sha256:'), 'Incoming correlation may be retained only as a pseudonymous hash.');
unset($_SERVER['HTTP_X_CORRELATION_ID']);

cycleReviewPass(65, 'audit-correlation-boundary');
