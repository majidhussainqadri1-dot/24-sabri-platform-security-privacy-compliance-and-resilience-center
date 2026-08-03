<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Retention\RetentionManager;
$GLOBALS['wp_scheduled'][RetentionManager::CRON_HOOK]=time()+3600;
$GLOBALS['wp_schedule_recurrences'][RetentionManager::CRON_HOOK]='hourly';
cycleReviewAssert(!RetentionManager::ensureScheduled(),'Wrong retention recurrence must fail verification.');
$GLOBALS['wp_schedule_recurrences'][RetentionManager::CRON_HOOK]='daily';
cycleReviewAssert(RetentionManager::ensureScheduled(),'Correct daily recurrence must verify.');

cycleReviewPass(91, 'retention-schedule-integrity');
