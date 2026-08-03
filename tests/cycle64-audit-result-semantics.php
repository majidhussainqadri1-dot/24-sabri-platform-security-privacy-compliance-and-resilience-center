<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Storage\AuditLogger;
$audit = new AuditLogger();
$bad = $audit->record('cycle64_event', 'file-24-security-center', 'totally-unreviewed-state', 'low');
cycleReviewAssert(is_wp_error($bad), 'Unapproved audit result semantics must be rejected.');
cycleReviewAssert($bad->get_error_code() === 'spcrc_invalid_audit_event', 'Invalid audit result must have explicit error identity.');
cycleReviewAssert($GLOBALS['wpdb']->events === [], 'Invalid audit result must not reach storage.');

cycleReviewPass(64, 'audit-result-semantics');
