<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


$source=file_get_contents(dirname(__DIR__).'/plugin/sabri-security-center/src/UpgradeManager.php');
cycleReviewAssert(is_string($source)&&str_contains($source,'cleanupNewSchedules'),'Upgrade failures must remove only schedules created by the failed attempt.');
cycleReviewAssert(is_string($source)&&str_contains($source,'$retentionExisted')&&str_contains($source,'$recoveryExisted'),'Schedule ownership must be snapshotted before repair.');

cycleReviewPass(88, 'upgrade-partial-schedule-cleanup');
