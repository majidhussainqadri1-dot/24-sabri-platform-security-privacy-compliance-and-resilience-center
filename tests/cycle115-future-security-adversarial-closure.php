<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\AgenticAiSecurity;
use Sabri\Platform\Security\Future\ArtifactProvenanceVerifier;
use Sabri\Platform\Security\Future\AutomatedRemediationPolicy;
use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\PolicyAsCodeEngine;
use Sabri\Platform\Security\Future\PrivacyAnalyticsGuard;
use Sabri\Platform\Security\Future\PrivacyEgressGuard;
use Sabri\Platform\Security\Future\SecurityKnowledgeGraph;

function expectFutureAdv(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$unknown = FutureSecurityAssurance::evaluate('F24-FUT-999', []);
expectFutureAdv($unknown['state'] === 'unknown' && ! $unknown['write_allowed'], 'Unknown future capability must fail closed.');

$unsafe = FutureSecurityAssurance::evaluate('F24-FUT-001', ['crypto_inventory'=>'yes','pqc_risk_classification'=>'yes','migration_plan'=>'yes','provider_readiness'=>'yes','evidence_ref'=>'../../secrets','reviewed_at'=>gmdate('c')]);
expectFutureAdv($unsafe['state'] === 'incomplete' && in_array('evidence_ref', $unsafe['missing_controls'], true), 'Path-like evidence references must be rejected.');

$graph = (new SecurityKnowledgeGraph())->build([
    ['id'=>'secret','type'=>'secret_ref','label'=>'api_key=supersecret'],
    ['id'=>'ok','type'=>'module','label'=>'File 24'],
], [['from'=>'secret','to'=>'ok','relation'=>'uses']]);
expectFutureAdv($graph['node_count'] === 1 && $graph['edge_count'] === 0, 'Sensitive graph labels and dependent edges must be rejected.');

$unknownOp = (new PolicyAsCodeEngine())->evaluate(['version'=>'1','effect'=>'allow','rules'=>[['field'=>'role','operator'=>'eval','value'=>'admin']]], ['role'=>'admin']);
expectFutureAdv($unknownOp['decision'] === 'deny', 'Unknown policy operator must fail closed without eval.');

$egress = (new PrivacyEgressGuard())->evaluate(['data_classes'=>['C5'],'detected_categories'=>['identity'],'destination_class'=>'internet','purpose'=>'export','consent_or_lawful_basis'=>true,'native_authorized'=>true]);
expectFutureAdv($egress['decision'] === 'block', 'C5 data to unapproved internet destination must be blocked.');

$analytics = (new PrivacyAnalyticsGuard())->evaluate(['epsilon'=>5,'remaining_budget'=>1,'cohort_size'=>3,'minimum_cohort'=>30,'no_raw_rows'=>false,'clipping_applied'=>false,'clean_room'=>false]);
expectFutureAdv($analytics['decision'] === 'block' && count($analytics['reasons']) >= 4, 'Privacy analytics must block budget/cohort/raw-row violations.');

$prov = (new ArtifactProvenanceVerifier())->verify(['source_commit'=>'main','artifact_sha256'=>'bad','builder_identity'=>'https://attacker.example','provenance_version'=>'','signed_attestation'=>false,'sbom_present'=>false,'vex_status'=>'unknown']);
expectFutureAdv($prov['state'] === 'blocked' && count($prov['missing']) >= 6, 'Untrusted provenance must be blocked.');

$ai = (new AgenticAiSecurity())->evaluate(['agent_id'=>'danger','tool_allowlist'=>['delete'],'data_classes'=>['C5'],'network_allowlist'=>[],'max_tool_calls'=>999,'cost_budget'=>0,'high_risk_or_destructive'=>true,'human_approval'=>false,'aibom_registered'=>false,'source_citations_required'=>false]);
expectFutureAdv($ai['decision'] === 'block' && count($ai['reasons']) >= 6, 'Unbounded agentic AI must be blocked.');

$high = (new AutomatedRemediationPolicy())->decide(['action_type'=>'disable_account','risk_level'=>'critical','reversible'=>true,'previewed'=>true,'rollback_reference'=>'rollback:acct-1','human_approvals'=>1,'human_approval_refs'=>['approval:user-1'],'step_up_verified'=>true]);
expectFutureAdv($high['decision'] === 'block', 'Critical remediation requires dual approval.');
$dual = (new AutomatedRemediationPolicy())->decide(['action_type'=>'disable_account','risk_level'=>'critical','reversible'=>true,'previewed'=>true,'rollback_reference'=>'rollback:acct-1','human_approvals'=>2,'human_approval_refs'=>['approval:user-1','approval:user-2'],'step_up_verified'=>true]);
expectFutureAdv($dual['decision'] === 'dual_approved_recommendation' && $dual['execute_by'] === 'native_owner', 'Dual-approved critical remediation remains native-owner execution.');

echo "PASS: cycle115 future-security adversarial closure\n";
