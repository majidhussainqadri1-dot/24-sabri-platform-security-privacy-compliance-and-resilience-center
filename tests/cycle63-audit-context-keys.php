<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Storage\AuditLogger;
$audit = new AuditLogger();
$id = $audit->record('cycle63_event', 'file-24-security-center', 'recorded', 'low', [
    'Unsafe Key!' => 'first',
    'unsafe-key' => 'second',
    str_repeat('a', 200) => 'bounded',
]);
cycleReviewAssert(is_string($id), 'Bounded audit context must persist.');
$context = json_decode((string) end($GLOBALS['wpdb']->events)['context_json'], true);
cycleReviewAssert(is_array($context) && count($context) === 3, 'Sanitized key collisions must not overwrite evidence.');
cycleReviewAssert(max(array_map('strlen', array_keys($context))) <= 89, 'Audit context keys must remain bounded including collision suffix.');

cycleReviewPass(63, 'audit-context-keys');
