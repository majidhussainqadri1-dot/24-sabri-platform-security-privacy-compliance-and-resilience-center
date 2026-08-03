<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


$source=file_get_contents(dirname(__DIR__).'/plugin/sabri-security-center/src/UpgradeManager.php');
cycleReviewAssert(is_string($source)&&str_contains($source,'upgrade_failure_evidence_unavailable'),'Failure-evidence persistence failure must emit an operational signal.');
cycleReviewAssert(is_string($source)&&str_contains($source,"get_option('spcrc_last_upgrade_error', null) !== \$failure"),'Upgrade failure evidence must be reread exactly.');

cycleReviewPass(89, 'upgrade-failure-evidence');
