<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


$source=file_get_contents(dirname(__DIR__).'/plugin/sabri-security-center/src/Activation.php');
cycleReviewAssert(is_string($source)&&str_contains($source,'spcrc_activation_installed_at_failed'),'Activation must verify installation timestamp persistence.');
cycleReviewAssert(is_string($source)&&str_contains($source,"get_option('spcrc_installed_at', '') !== \$installedAt"),'Installed-at evidence must be reread exactly.');

cycleReviewPass(84, 'activation-installed-at-evidence');
