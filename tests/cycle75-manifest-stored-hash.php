<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
$registry = new ModuleRegistry();
$manifest = ['module_key'=>'cycle75','name'=>'Cycle 75','version'=>'1.0.0','owner'=>'File 75','data_classes'=>[],'public_routes'=>[],'private_routes'=>[],'contract_version'=>'1.0.0'];
$json = wp_json_encode($registry->validate($manifest), JSON_UNESCAPED_SLASHES);
$GLOBALS['wpdb']->manifests['cycle75'] = ['module_version'=>'1.0.0','manifest_hash'=>str_repeat('0',64),'manifest_json'=>$json,'last_seen_at'=>gmdate('Y-m-d H:i:s')];
cycleReviewAssert(! $registry->register($manifest), 'Stored manifest hash mismatch must block registration.');
cycleReviewAssert(! isset($registry->all()['cycle75']), 'Tampered stored manifest must not enter runtime memory.');

cycleReviewPass(75, 'manifest-stored-hash');
