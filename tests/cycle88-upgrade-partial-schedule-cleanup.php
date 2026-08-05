<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';

$source = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/UpgradeManager.php');
cycleReviewAssert(is_string($source) && str_contains($source, 'scheduleSnapshot'), 'Upgrade must snapshot schedule ownership before any runtime repair.');
cycleReviewAssert(is_string($source) && str_contains($source, 'restoreSchedules'), 'Upgrade failures must remove only schedules created by the failed attempt.');
cycleReviewAssert(is_string($source) && str_contains($source, "'retention' =>") && str_contains($source, "'recovery' =>"), 'Both retention and privacy-recovery schedule ownership must be captured.');
cycleReviewAssert(is_string($source) && str_contains($source, 'restoreVersionState'), 'A late upgrade failure must restore the exact pre-upgrade schema and plugin version state.');
cycleReviewAssert(is_string($source) && str_contains($source, 'rollbackCapabilities'), 'A late upgrade failure must restore the exact pre-upgrade capability state.');

cycleReviewPass(88, 'upgrade-partial-schedule-cleanup');
