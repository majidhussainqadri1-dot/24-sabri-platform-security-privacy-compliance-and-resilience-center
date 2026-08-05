<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';

use Sabri\Platform\Security\Capabilities;

$bundles = Capabilities::dutyBundles();
foreach ([
    'privacy_officer',
    'incident_commander',
    'backup_operator',
    'auditor',
    'governance_approver',
    'critical_risk_acceptor',
    'key_custodian',
    'critical_incident_closer',
] as $duty) {
    cycleReviewAssert(isset($bundles[$duty]), 'The separated duty bundle must exist: ' . $duty);
    cycleReviewAssert(in_array('spcrc_view_overview', $bundles[$duty], true), 'A separated duty must be able to reach the File 24 parent workspace: ' . $duty);
}

cycleReviewAssert(in_array('spcrc_view_module_posture', $bundles['privacy_officer'], true), 'Privacy Officer must be able to inspect module posture before rights and compliance decisions.');
cycleReviewAssert(in_array('spcrc_view_module_posture', $bundles['incident_commander'], true), 'Incident Commander must be able to inspect affected module posture.');
cycleReviewAssert(in_array('spcrc_view_module_posture', $bundles['backup_operator'], true), 'Backup Operator must be able to inspect module and recovery posture.');
cycleReviewAssert(in_array('spcrc_view_security_events', $bundles['critical_incident_closer'], true), 'Critical incident closure must include bounded event visibility.');

foreach ([
    'privacy_officer' => ['spcrc_approve_governance_decision', 'spcrc_accept_critical_risk', 'spcrc_run_restore_operations'],
    'governance_approver' => ['spcrc_manage_trust_center', 'spcrc_accept_critical_risk', 'spcrc_manage_incidents'],
    'key_custodian' => ['spcrc_manage_privacy_requests', 'spcrc_manage_incidents', 'spcrc_run_restore_operations'],
    'critical_risk_acceptor' => ['spcrc_manage_risks', 'spcrc_approve_governance_decision', 'spcrc_manage_incidents'],
] as $duty => $forbiddenCapabilities) {
    foreach ($forbiddenCapabilities as $capability) {
        cycleReviewAssert(! in_array($capability, $bundles[$duty], true), 'Workspace access must not collapse separation of duties: ' . $duty . ' must not inherit ' . $capability);
    }
}

cycleReviewPass(108, 'separated-duty-operability');
