<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
$registry = new ModuleRegistry();
$base = ['module_key'=>'cycle72','name'=>'Cycle 72','owner'=>'File 72','data_classes'=>[],'public_routes'=>[],'private_routes'=>[]];
$bad = $registry->validate($base + ['version'=>'latest']);
cycleReviewAssert(is_wp_error($bad) && $bad->get_error_code() === 'spcrc_manifest_version_invalid', 'Arbitrary release labels must be rejected.');
$badContract = $registry->validate($base + ['version'=>'1.0.0','contract_version'=>'latest']);
cycleReviewAssert(is_wp_error($badContract) && $badContract->get_error_code() === 'spcrc_manifest_contract_version_invalid', 'Arbitrary contract labels must be rejected.');

cycleReviewPass(72, 'manifest-version-contract');
