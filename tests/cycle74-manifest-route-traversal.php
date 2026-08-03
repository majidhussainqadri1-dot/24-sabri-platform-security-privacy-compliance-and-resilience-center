<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
$registry = new ModuleRegistry();
$base = ['module_key'=>'cycle74','name'=>'Cycle 74','version'=>'1.0.0','owner'=>'File 74','data_classes'=>[],'private_routes'=>[]];
foreach (['/admin/../secret','/%2e%2e/secret','/admin/%2fsecret'] as $route) {
    $bad = $registry->validate($base + ['public_routes'=>[$route]]);
    cycleReviewAssert(is_wp_error($bad) && $bad->get_error_code() === 'spcrc_manifest_route_invalid', 'Traversal route must be rejected: ' . $route);
}

cycleReviewPass(74, 'manifest-route-traversal');
