<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\UpgradeManager;
$GLOBALS['wp_options']['spcrc_version']='not-a-version';
$GLOBALS['wp_options']['spcrc_schema_version']='0.25.5';
$result=UpgradeManager::maybeUpgrade();
cycleReviewAssert(is_wp_error($result)&&$result->get_error_code()==='spcrc_installed_version_invalid','Malformed installed version state must fail closed.');
cycleReviewAssert(isset($GLOBALS['wp_options']['spcrc_last_upgrade_error']),'Malformed version failure must be durably recorded.');

cycleReviewPass(86, 'upgrade-version-state-validation');
