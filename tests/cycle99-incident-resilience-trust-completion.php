<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Incident\IncidentCoordinator;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Resilience\ResilienceCoordinator;
use Sabri\Platform\Security\Security\VulnerabilityManager;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\FindingRepository;
use Sabri\Platform\Security\Storage\GovernanceRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Trust\TrustCenterService;

$count = 0;
function c99(bool $condition, string $message): void { global $count; ++$count; if (! $condition) { fwrite(STDERR, "FAIL: $message\n"); exit(1); } }

$audit = new AuditLogger();
$artifacts = new GovernedArtifactRegistry($audit);
$governance = new GovernanceRepository($audit);
$findings = new FindingRepository($audit, $governance);
$vulnerabilities = new VulnerabilityManager($artifacts, $findings);

$vulnerability = $vulnerabilities->report([
    'vulnerability_key' => 'idor-01', 'title' => 'Object authorization weakness',
    'severity' => 'high', 'module_key' => 'file-17-communication',
    'evidence_ref' => 'pentest:finding-01', 'discovered_at' => gmdate('c', time() - 60),
]);
c99(is_string($vulnerability), 'Vulnerability report must create registry and finding evidence.');
$record = $artifacts->get('vulnerability', 'idor-01');
c99(is_array($record) && ($record['payload']['containment_required'] ?? false) === true, 'High vulnerability must require containment.');
$validated = $vulnerabilities->transition('idor-01', 'validated', 1, 'validation:idor-01');
c99(is_string($validated), 'Vulnerability must enter validated state with evidence.');
$contained = $vulnerabilities->transition('idor-01', 'contained', 2, 'containment:idor-01');
c99(is_string($contained), 'High vulnerability must record containment before remediation.');
$remediated = $vulnerabilities->transition('idor-01', 'remediated', 3, 'remediation:idor-fix-01');
c99(is_string($remediated), 'Remediation transition must follow validation/containment and accept evidence.');
$closedWithoutRetest = $vulnerabilities->transition('idor-01', 'closed', 4, 'closure:premature');
c99(is_wp_error($closedWithoutRetest) && $closedWithoutRetest->get_error_code() === 'spcrc_vulnerability_transition_invalid', 'Vulnerability closure before retest verification must fail.');
$verifiedVulnerability = $vulnerabilities->transition('idor-01', 'verified', 4, 'retest:idor-fix-01');
c99(is_string($verifiedVulnerability), 'Vulnerability remediation must be retested before closure.');
$closedVulnerability = $vulnerabilities->transition('idor-01', 'closed', 5, 'closure:idor-01');
c99(is_string($closedVulnerability), 'Verified vulnerability may close with evidence.');
$GLOBALS['wpdb']->zeroFindingInsert = true;
$partialVulnerability = $vulnerabilities->report([
    'vulnerability_key' => 'idor-partial', 'title' => 'Partial vulnerability transaction',
    'severity' => 'medium', 'module_key' => 'file-24-security-center',
    'evidence_ref' => 'pentest:finding-partial', 'discovered_at' => gmdate('c', time() - 30),
]);
c99(is_wp_error($partialVulnerability) && $partialVulnerability->get_error_code() === 'spcrc_vulnerability_finding_failed', 'Vulnerability report must expose partial linked-finding failure.');
c99(AuditGapStore::count('spcrc_finding_audit_gap') >= 1, 'Partial vulnerability transaction must create a durable audit gap.');

$incidentRepo = new IncidentRepository($audit);
$incidentCoordinator = new IncidentCoordinator($incidentRepo, $artifacts);
$incident = $incidentCoordinator->declare([
    'title' => 'Provider availability incident', 'severity' => 'sev2',
    'summary' => 'External provider is unavailable.', 'playbook' => 'vendor-breach',
    'evidence_ref' => 'incident:provider-01', 'commander_user_id' => 7,
    'out_of_band_channel_ref' => 'channel:incident-01',
]);
c99(is_string($incident), 'Incident declaration must create and declare a valid incident.');
$incidentRecord = $incidentRepo->get($incident);
c99(is_array($incidentRecord) && ($incidentRecord['status'] ?? '') === 'declared', 'Incident coordinator must finish declaration state.');
$contained = $incidentCoordinator->advance($incident, 'contained', 'Provider integration disabled and queue isolated.', 'incident:containment-01');
c99($contained === true, 'Incident containment must require evidence and follow transition law.');
$action = $incidentCoordinator->recordAction($incident, 'notify-owner', 'Notify native owner', 'completed', 'incident:notification-01', ['channel' => 'out-of-band']);
c99(is_string($action), 'Incident action ledger must persist bounded action evidence.');
c99(!(IncidentCoordinator::readiness()['ready'] ?? true), 'Out-of-band readiness must remain false without real external evidence.');

$assurance = new AssuranceRepository($audit);
$resilience = new ResilienceCoordinator($artifacts, $assurance, $findings);
$bia = $resilience->saveBia(['service_key' => 'identity', 'title' => 'Identity BIA', 'tier' => 'tier-a', 'status' => 'draft']);
c99(is_string($bia), 'BIA must persist.');
$objective = $resilience->saveRecoveryObjective(['service_key' => 'identity', 'title' => 'Identity recovery objective', 'tier' => 'tier-a', 'status' => 'provisional']);
c99(is_string($objective), 'Provisional RPO/RTO must persist without false contractual claim.');
$approvedWithoutEvidence = $resilience->saveRecoveryObjective(['service_key' => 'identity-approved', 'title' => 'Approved objective', 'tier' => 'tier-a', 'status' => 'approved']);
c99(is_wp_error($approvedWithoutEvidence), 'Approved recovery objective must require drill evidence.');
$plan = $resilience->saveContinuityPlan(['plan_key' => 'public-read-only', 'title' => 'Public read-only continuity', 'mode' => 'public-read-only', 'status' => 'draft', 'available_services' => ['public knowledge'], 'blocked_actions' => ['publishing']]);
c99(is_string($plan), 'Continuity plan must persist.');
$beforeFindings = count($GLOBALS['wpdb']->findings);
$drill = $resilience->recordDrill(['drill_key' => 'restore-01', 'title' => 'Restore exercise', 'status' => 'failed', 'scenario' => 'database-restore', 'evidence_ref' => 'drill:restore-01', 'corrective_actions' => ['repair restore procedure']]);
c99(is_string($drill) && count($GLOBALS['wpdb']->findings) === $beforeFindings + 1, 'Failed resilience drill must open a finding.');
$GLOBALS['wpdb']->zeroFindingInsert = true;
$partialDrill = $resilience->recordDrill(['drill_key' => 'restore-partial', 'title' => 'Partial restore exercise', 'status' => 'failed', 'scenario' => 'database-restore', 'evidence_ref' => 'drill:restore-partial', 'corrective_actions' => ['repair restore procedure']]);
c99(is_wp_error($partialDrill) && $partialDrill->get_error_code() === 'spcrc_drill_finding_failed', 'Failed drill must expose mandatory finding persistence failure.');
c99(AuditGapStore::count('spcrc_finding_audit_gap') >= 2, 'Partial drill transaction must preserve a second durable audit gap.');

$trust = new TrustCenterService($artifacts);
$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps']['spcrc_manage_trust_center'] = true;
$certificationDraft = $trust->saveClaim([
    'claim_type' => 'certification',
    'claim_key' => 'iso',
    'title' => 'ISO certification claim',
    'summary' => 'Independent certification evidence has not yet been established.',
    'status' => 'draft',
    'independent' => false,
]);
c99(is_string($certificationDraft), 'A certification assertion must begin as an attributable draft.');

$GLOBALS['current_user_id'] = 8;
unset($GLOBALS['current_user_caps']['spcrc_manage_trust_center']);
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$claimMissing = $trust->saveClaim([
    'claim_type' => 'certification',
    'claim_key' => 'iso',
    'status' => 'verified',
    'expected_version' => 1,
    'expires_at' => gmdate('c', time() + DAY_IN_SECONDS),
    'reviewed_at' => gmdate('c'),
    'evidence_ref' => 'cert:iso-01',
]);
c99(is_wp_error($claimMissing) && $claimMissing->get_error_code() === 'spcrc_trust_certification_independence_missing', 'Certification approval must require independent evidence declared in the reviewed draft.');

$GLOBALS['current_user_id'] = 7;
unset($GLOBALS['current_user_caps']['spcrc_approve_governance_decision']);
$GLOBALS['current_user_caps']['spcrc_manage_trust_center'] = true;
$claimDraft = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'security-overview',
    'title' => 'Security program overview',
    'summary' => 'Repository controls are documented; staging assurance is pending.',
    'status' => 'draft',
]);
c99(is_string($claimDraft), 'A public-safe trust claim must begin as an attributable draft.');

$GLOBALS['current_user_id'] = 8;
unset($GLOBALS['current_user_caps']['spcrc_manage_trust_center']);
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$claim = $trust->saveClaim([
    'claim_type' => 'security-overview',
    'claim_key' => 'security-overview',
    'status' => 'verified',
    'expected_version' => 1,
    'expires_at' => gmdate('c', time() + DAY_IN_SECONDS),
    'reviewed_at' => gmdate('c'),
    'next_review_at' => gmdate('c', time() + 2 * DAY_IN_SECONDS),
    'evidence_ref' => 'review:security-overview-01',
]);
c99(is_string($claim), 'A distinct authorized approver must verify the unchanged evidence-gated claim.');
$claims = $trust->publicClaims();
c99(count($claims) === 1 && ($claims[0]['type'] ?? '') === 'security-overview', 'Only unexpired independently approved public-safe claims may publish.');
$payload = $trust->payload();
c99(($payload['program_status'] ?? '') === 'Repository code-complete candidate; staging and production assurance pending', 'Trust payload must preserve truthful status boundary.');

echo "PASS: $count Cycle 99 incident/resilience/trust completion assertions\n";
