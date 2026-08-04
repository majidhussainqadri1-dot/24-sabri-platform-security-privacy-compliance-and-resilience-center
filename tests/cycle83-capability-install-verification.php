<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';

use Sabri\Platform\Security\Capabilities;

cycleReviewAssert(Capabilities::install(), 'Administrator capability installation must be verifiable.');
$auto = Capabilities::autoGranted();
cycleReviewAssert(count($auto) >= 10, 'The bootstrap Security Administrator must retain a bounded operational capability bundle.');
foreach ($auto as $cap) {
    cycleReviewAssert(! empty($GLOBALS['administrator_role']->caps[$cap]), 'Bootstrap Security Administrator capability must exist: ' . $cap);
}
foreach (array_diff(Capabilities::all(), $auto) as $cap) {
    cycleReviewAssert(empty($GLOBALS['administrator_role']->caps[$cap]), 'Separated or high-risk capability must not be inherited by the generic administrator role: ' . $cap);
}
foreach ([
    'spcrc_accept_critical_risk',
    'spcrc_approve_governance_decision',
    'spcrc_manage_incidents',
    'spcrc_manage_privacy_requests',
    'spcrc_manage_assurance',
    'spcrc_manage_resilience',
    'spcrc_view_forensic_metadata',
    'spcrc_manage_key_metadata',
    'spcrc_run_restore_operations',
    'spcrc_close_critical_incidents',
] as $separated) {
    cycleReviewAssert(empty($GLOBALS['administrator_role']->caps[$separated]), 'Separated authority must require explicit delegation: ' . $separated);
}
cycleReviewAssert(! empty($GLOBALS['administrator_role']->caps['spcrc_request_governance_decision']), 'The Security Administrator must be able to request, but not approve, governance decisions.');
cycleReviewAssert(isset(Capabilities::dutyBundles()['privacy_officer']), 'Separate privacy-officer duty bundle must be declared.');
cycleReviewAssert(isset(Capabilities::dutyBundles()['incident_commander']), 'Separate incident-commander duty bundle must be declared.');
cycleReviewAssert(isset(Capabilities::dutyBundles()['backup_operator']), 'Separate backup-operator duty bundle must be declared.');
cycleReviewAssert(isset(Capabilities::dutyBundles()['auditor']), 'Separate read-only auditor duty bundle must be declared.');
cycleReviewAssert(isset(Capabilities::dutyBundles()['governance_approver']), 'Separate governance-approver duty bundle must be declared.');
cycleReviewAssert(isset(Capabilities::dutyBundles()['key_custodian']), 'Separate key-custodian duty bundle must be declared.');

$role = $GLOBALS['administrator_role'];
$legacySeparated = 'spcrc_manage_incidents';
$role->caps = [
    $auto[0] => true,
    $legacySeparated => true,
];
$role->failAdd = $auto[1];
cycleReviewAssert(! Capabilities::install(), 'Capability persistence failure must fail closed.');
cycleReviewAssert(! empty($role->caps[$auto[0]]), 'A capability present before installation must survive rollback.');
cycleReviewAssert(empty($role->caps[$auto[1]]), 'A failed newly added capability must remain absent after rollback.');
cycleReviewAssert(! empty($role->caps[$legacySeparated]), 'A legacy separated capability must be restored when the migration itself fails.');

$role->failAdd = null;
cycleReviewAssert(Capabilities::install(), 'Capability installation must recover after the persistence fault is removed.');
foreach ($auto as $cap) {
    cycleReviewAssert(! empty($role->caps[$cap]), 'Every bounded Security Administrator capability must be present after recovery: ' . $cap);
}
cycleReviewAssert(empty($role->caps[$legacySeparated]), 'Successful migration must remove a separated incident-command capability from the generic administrator role.');

cycleReviewPass(83, 'capability-install-verification');
