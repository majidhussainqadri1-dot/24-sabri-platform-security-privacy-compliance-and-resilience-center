<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Privacy\RecoveryManager;
$GLOBALS['wp_scheduled'][RecoveryManager::EVENT]=time()+300;
$GLOBALS['wp_schedule_recurrences'][RecoveryManager::EVENT]='daily';
cycleReviewAssert(!RecoveryManager::ensureScheduled(),'Wrong recovery recurrence must fail verification.');
$GLOBALS['wp_schedule_recurrences'][RecoveryManager::EVENT]='hourly';
cycleReviewAssert(RecoveryManager::ensureScheduled(),'Correct hourly recovery recurrence must verify.');

cycleReviewPass(95, 'privacy-recovery-schedule');
