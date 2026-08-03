<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
$registry = new ModuleRegistry();
$base = ['module_key'=>'cycle76','name'=>'Cycle 76','version'=>'1.0.0','owner'=>'File 76','public_routes'=>[],'private_routes'=>[],'contract_version'=>'1.0.0'];
$bad = $registry->validate($base + ['data_classes'=>['C1 Internal','person@example.test']]);
cycleReviewAssert(is_wp_error($bad) && $bad->get_error_code() === 'spcrc_manifest_list_sensitive', 'Sensitive list values must reject the manifest.');
$badShape = $registry->validate($base + ['data_classes'=>'C1 Internal']);
cycleReviewAssert(is_wp_error($badShape) && $badShape->get_error_code() === 'spcrc_manifest_list_invalid', 'Manifest lists must retain bounded array shape.');

cycleReviewPass(76, 'manifest-list-safety');
