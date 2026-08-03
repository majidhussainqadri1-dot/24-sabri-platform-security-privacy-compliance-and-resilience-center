<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


$source=file_get_contents(dirname(__DIR__).'/plugin/sabri-security-center/src/Activation.php');
cycleReviewAssert(is_string($source)&&str_contains($source,'stateSnapshot'),'Activation must capture pre-existing version state.');
cycleReviewAssert(is_string($source)&&substr_count($source,'restoreState($stateSnapshot)')>=4,'Every post-schema activation failure must restore version-state claims.');
cycleReviewAssert(is_string($source)&&str_contains($source,'scheduleSnapshot')&&str_contains($source,'cleanupSchedules($scheduleSnapshot)'), 'Activation rollback must preserve schedules that existed before the failed attempt.');

cycleReviewPass(85, 'activation-state-rollback');
