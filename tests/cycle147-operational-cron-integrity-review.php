<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Monitoring\RemoteEvidenceQueue;
use Sabri\Platform\Security\Privacy\DeletionReplayManager;
use Sabri\Platform\Security\Resilience\ResilienceCoordinator;

function c147(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$cases = [
    [DeletionReplayManager::EVENT, [DeletionReplayManager::class, 'ensureScheduled'], 'hourly', 300],
    [RemoteEvidenceQueue::EVENT, [RemoteEvidenceQueue::class, 'ensureScheduled'], 'hourly', 120],
    [ResilienceCoordinator::DRILL_EVENT, [ResilienceCoordinator::class, 'ensureScheduled'], 'daily', DAY_IN_SECONDS],
];

foreach ($cases as [$hook, $ensure, $recurrence, $delay]) {
    $GLOBALS['wp_scheduled'] = [$hook => time() + $delay];
    $GLOBALS['wp_schedule_recurrences'] = [$hook => 'weekly'];
    c147($ensure() === false, $hook . ' must reject a pre-existing wrong recurrence rather than treating mere presence as healthy.');

    $GLOBALS['wp_scheduled'] = [$hook => time() - 10];
    $GLOBALS['wp_schedule_recurrences'] = [$hook => $recurrence];
    c147($ensure() === false, $hook . ' must reject stale/past schedule evidence.');

    $GLOBALS['wp_scheduled'] = [];
    $GLOBALS['wp_schedule_recurrences'] = [];
    c147($ensure() === true, $hook . ' must create and verify its expected recurring event when missing.');
    c147(($GLOBALS['wp_schedule_recurrences'][$hook] ?? '') === $recurrence, $hook . ' must verify the exact intended recurrence.');
}

echo "PASS: cycle147 deletion/remote/resilience cron-integrity defects fixed and retested\n";
