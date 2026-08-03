<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


$source=file_get_contents(dirname(__DIR__).'/plugin/sabri-security-center/src/UpgradeManager.php');
cycleReviewAssert(is_string($source)&&substr_count($source,'refreshLock($lockToken)')>=2,'Upgrade must refresh ownership before and after long schema work.');
cycleReviewAssert(is_string($source)&&str_contains($source,'spcrc_upgrade_lock_lost'),'Lost upgrade ownership must fail closed explicitly.');

cycleReviewPass(87, 'upgrade-lock-lease-refresh');
