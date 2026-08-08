<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\AgenticAiSecurity;
use Sabri\Platform\Security\Future\ArtifactProvenanceVerifier;
use Sabri\Platform\Security\Future\AttackPathEngine;
use Sabri\Platform\Security\Future\AutomatedRemediationPolicy;
use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Future\PolicyAsCodeEngine;
use Sabri\Platform\Security\Future\PrivacyAnalyticsGuard;
use Sabri\Platform\Security\Future\PrivacyEgressGuard;
use Sabri\Platform\Security\Future\SecurityKnowledgeGraph;

function expectFuture(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

expectFuture(FutureSecurityCapabilityCatalog::count() === 25, 'Future catalogue must contain 25 approved capabilities.');
expectFuture(FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future catalogue invariants must be complete.');
expectFuture(count(FutureSecurityAssurance::supportedIds()) === 25, 'Assurance must support every future capability.');
foreach (FutureSecurityCapabilityCatalog::all() as $id => $item) {
    expectFuture(($item['native_enforcement_preserved'] ?? false) === true, "{$id} must preserve native enforcement.");
    expectFuture(($item['security_single_point_of_failure_forbidden'] ?? false) === true, "{$id} must forbid File-24 security SPoF.");
}

$graphEngine = new SecurityKnowledgeGraph();
$graph = $graphEngine->build([
    ['id'=>'stolen-session','type'=>'risk','label'=>'Stolen session'],
    ['id'=>'file17-api','type'=>'endpoint','label'=>'File 17 API'],
    ['id'=>'c5-data','type'=>'data_class','label'=>'C5 restricted data'],
], [
    ['from'=>'stolen-session','to'=>'file17-api','relation'=>'can_reach'],
    ['from'=>'file17-api','to'=>'c5-data','relation'=>'protects'],
]);
expectFuture($graph['node_count'] === 3 && $graph['edge_count'] === 2, 'Graph must preserve bounded safe nodes and edges.');
$reach = $graphEngine->reachable($graph, 'stolen-session', 'c5-data');
expectFuture($reach['reachable'] && $reach['depth'] === 2, 'Knowledge graph must expose attack reachability.');
$paths = (new AttackPathEngine($graphEngine))->analyze($graph, ['stolen-session'], ['c5-data'], ['c5-data'=>['likelihood'=>80,'data_sensitivity'=>100,'user_harm'=>90,'blast_radius'=>70]]);
expectFuture(count($paths) === 1 && $paths[0]['score'] >= 70, 'Attack-path engine must prioritize material reachable paths.');

$policy = (new PolicyAsCodeEngine())->evaluate(['version'=>'1.0','effect'=>'deny','rules'=>[['field'=>'data_class','operator'=>'equals','value'=>'C5']]], ['data_class'=>'C5']);
expectFuture($policy['matched'] && $policy['decision'] === 'deny', 'Policy-as-code must enforce declarative deny.');

$egress = (new PrivacyEgressGuard())->evaluate(['data_classes'=>['C4'],'detected_categories'=>['clinical'],'destination_class'=>'approved-clean-room','purpose'=>'research','consent_or_lawful_basis'=>true,'native_authorized'=>true,'minimum_necessary'=>true]);
expectFuture($egress['decision'] === 'allow' && $egress['native_enforcement_required'], 'DLP egress guard must permit only approved native-authorized flow.');

$analytics = (new PrivacyAnalyticsGuard())->evaluate(['epsilon'=>0.5,'remaining_budget'=>2.0,'cohort_size'=>100,'minimum_cohort'=>30,'no_raw_rows'=>true,'clipping_applied'=>true,'clean_room'=>true]);
expectFuture($analytics['decision'] === 'allow_aggregate' && abs($analytics['remaining_budget_after'] - 1.5) < 0.0001, 'Privacy analytics must consume bounded differential-privacy budget.');

$prov = (new ArtifactProvenanceVerifier())->verify(['source_commit'=>str_repeat('a',40),'artifact_sha256'=>str_repeat('b',64),'builder_identity'=>'builder:github-actions','provenance_version'=>'slsa-v1.2','signed_attestation'=>true,'sbom_present'=>true,'vex_status'=>'not_affected']);
expectFuture($prov['state'] === 'verified', 'Signed provenance fixture must verify.');

$ai = (new AgenticAiSecurity())->evaluate(['agent_id'=>'study-agent','tool_allowlist'=>['search','retrieve'],'data_classes'=>['C2'],'network_allowlist'=>['approved-ai-provider'],'max_tool_calls'=>12,'cost_budget'=>20,'high_risk_or_destructive'=>false,'human_approval'=>true,'aibom_registered'=>true,'source_citations_required'=>true]);
expectFuture($ai['decision'] === 'allow_bounded' && $ai['native_action_authorization_required'], 'Agentic AI must be bounded and native-authorized.');

$remediation = (new AutomatedRemediationPolicy())->decide(['action_type'=>'quarantine_suspicious_upload','risk_level'=>'low','reversible'=>true,'previewed'=>true,'rollback_reference'=>'rollback:upload-42','human_approvals'=>0,'step_up_verified'=>false]);
expectFuture($remediation['decision'] === 'auto_recommend' && $remediation['execute_by'] === 'native_owner', 'Low-risk autopilot must recommend, not take over native execution.');

echo "PASS: cycle114 future-security superset positive closure\n";
