<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
$registry = new ModuleRegistry();
$base = ['module_key'=>'cycle73','name'=>'Cycle 73','version'=>'1.0.0','owner'=>'File 73','data_classes'=>[],'public_routes'=>[],'private_routes'=>[],'contract_version'=>'1.0.0'];
$bad = $registry->validate($base + ['canonical_data_owner'=>'person@example.test']);
cycleReviewAssert(is_wp_error($bad) && $bad->get_error_code() === 'spcrc_manifest_canonical_owner_invalid', 'Canonical ownership must not contain contact data.');
$discarded = $registry->validate($base + ['evidence_source'=>'https://private.example/evidence']);
cycleReviewAssert(is_array($discarded) && ($discarded['evidence_source'] ?? 'x') === '', 'Raw evidence locations must be discarded.');

cycleReviewPass(73, 'manifest-ownership-evidence');
