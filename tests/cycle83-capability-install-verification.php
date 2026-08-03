<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Capabilities;
cycleReviewAssert(Capabilities::install(), 'Administrator capability installation must be verifiable.');
foreach(Capabilities::autoGranted() as $cap){cycleReviewAssert(!empty($GLOBALS['administrator_role']->caps[$cap]),'Auto-granted capability must exist: '.$cap);}
cycleReviewAssert(empty($GLOBALS['administrator_role']->caps['spcrc_accept_critical_risk']), 'Critical-risk acceptance must remain explicitly delegated.');

$role = $GLOBALS['administrator_role'];
$auto = Capabilities::autoGranted();
$role->caps = [$auto[0] => true];
$role->failAdd = $auto[2];
cycleReviewAssert(! Capabilities::install(), 'Capability persistence failure must fail closed.');
cycleReviewAssert(! empty($role->caps[$auto[0]]), 'A capability present before installation must survive rollback.');
cycleReviewAssert(empty($role->caps[$auto[1]]), 'A newly added capability must be removed when a later grant fails.');
$role->failAdd = null;
cycleReviewAssert(Capabilities::install(), 'Capability installation must recover after the persistence fault is removed.');

cycleReviewPass(83, 'capability-install-verification');
