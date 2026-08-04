<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';

use Sabri\Platform\Security\Capabilities;

cycleReviewAssert(Capabilities::install(), 'Administrator capability installation must be verifiable.');
$auto = Capabilities::autoGranted();
cycleReviewAssert(count($auto) === 2, 'Generic administrators must receive only the two bounded read capabilities.');
foreach ($auto as $cap) {
    cycleReviewAssert(! empty($GLOBALS['administrator_role']->caps[$cap]), 'Auto-granted capability must exist: ' . $cap);
}
foreach (array_diff(Capabilities::all(), $auto) as $cap) {
    cycleReviewAssert(empty($GLOBALS['administrator_role']->caps[$cap]), 'Operational capability must not be inherited by the generic administrator role: ' . $cap);
}
cycleReviewAssert(empty($GLOBALS['administrator_role']->caps['spcrc_accept_critical_risk']), 'Critical-risk acceptance must remain explicitly delegated.');
cycleReviewAssert(isset(Capabilities::dutyBundles()['privacy_officer']), 'Separate privacy-officer duty bundle must be declared.');
cycleReviewAssert(isset(Capabilities::dutyBundles()['incident_commander']), 'Separate incident-commander duty bundle must be declared.');
cycleReviewAssert(isset(Capabilities::dutyBundles()['auditor']), 'Separate read-only auditor duty bundle must be declared.');

$role = $GLOBALS['administrator_role'];
$legacyOperational = 'spcrc_manage_incidents';
$role->caps = [
    $auto[0] => true,
    $legacyOperational => true,
];
$role->failAdd = $auto[1];
cycleReviewAssert(! Capabilities::install(), 'Capability persistence failure must fail closed.');
cycleReviewAssert(! empty($role->caps[$auto[0]]), 'A read capability present before installation must survive rollback.');
cycleReviewAssert(empty($role->caps[$auto[1]]), 'A failed newly added capability must remain absent after rollback.');
cycleReviewAssert(! empty($role->caps[$legacyOperational]), 'A legacy operational capability must be restored when the migration itself fails.');

$role->failAdd = null;
cycleReviewAssert(Capabilities::install(), 'Capability installation must recover after the persistence fault is removed.');
cycleReviewAssert(! empty($role->caps[$auto[0]]) && ! empty($role->caps[$auto[1]]), 'Both bounded read capabilities must be present after recovery.');
cycleReviewAssert(empty($role->caps[$legacyOperational]), 'Successful least-privilege migration must remove generic administrator operational authority.');

cycleReviewPass(83, 'capability-install-verification');
