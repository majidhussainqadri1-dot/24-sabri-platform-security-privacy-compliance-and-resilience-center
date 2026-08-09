<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\AgenticAiSecurity;
use Sabri\Platform\Security\Future\ArtifactProvenanceVerifier;
use Sabri\Platform\Security\Future\AutomatedRemediationPolicy;
use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;
use Sabri\Platform\Security\Future\PolicyAsCodeEngine;
use Sabri\Platform\Security\Future\PrivacyEgressGuard;
use Sabri\Platform\Security\Future\SecurityKnowledgeGraph;

function c277(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

c277(FutureSecurityCapabilityCatalog::count() === 25, 'Future catalogue must remain 25/25.');
c277(FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Future catalogue invariants must remain complete.');

$catalogSource = (string) file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Future/FutureSecurityCapabilityCatalog.php');
c277(str_contains($catalogSource, "public_safe_evidence_only'] ?? null) === true"), 'Repository-complete gate must enforce public-safe evidence invariant.');
c277(str_contains($catalogSource, "is_bool(\$item['external_evidence'] ?? null)"), 'External-evidence metadata must retain strict boolean type integrity.');
c277(preg_match('/(?:^|[^A-Za-z0-9_])true\s*\|/m', $catalogSource) !== 1, 'Catalogue invariant syntax must remain compatible with declared PHP 8.0 support.');

$evidence = [
    'algorithm_registry' => ['password' => 'redacted'],
    'dependency_mapping' => 'mapping-record',
    'rotation_contract' => 'rotation-record',
    'rollback_plan' => 'rollback-record',
    'evidence_ref' => 'evidence:cycle277',
    'reviewed_at' => gmdate('c'),
];
$future = FutureSecurityAssurance::evaluate('F24-FUT-002', $evidence);
c277(($future['write_allowed'] ?? true) === false, 'Sensitive nested evidence keys must fail closed.');

$agent = new AgenticAiSecurity();
$tools = [];
for ($i = 0; $i < 51; ++$i) $tools[] = 'tool-' . $i;
$agentDecision = $agent->evaluate([
    'agent_id' => 'agent-1',
    'tool_allowlist' => $tools,
    'data_classes' => ['C1'],
    'network_allowlist' => ['internal-api'],
    'max_tool_calls' => 10,
    'cost_budget' => 100,
    'human_approval' => true,
    'aibom_registered' => true,
    'source_citations_required' => true,
]);
c277(($agentDecision['decision'] ?? '') === 'block', 'Agent tool scope overflow must block rather than truncate.');
c277(in_array('tool_allowlist_invalid', $agentDecision['reasons'] ?? [], true), 'Agent overflow reason must be explicit.');

$policy = new PolicyAsCodeEngine();
$rules = [];
for ($i = 0; $i < 100; ++$i) $rules[] = ['field' => 'ok', 'operator' => 'equals', 'value' => true];
$rules[] = ['field' => 'blocked', 'operator' => 'equals', 'value' => false];
$policyDecision = $policy->evaluate(['version' => '1.0', 'effect' => 'allow', 'rules' => $rules], ['ok' => true, 'blocked' => true]);
c277(($policyDecision['decision'] ?? '') === 'deny', 'Policy rule overflow must fail closed rather than omit the 101st rule.');

$egress = new PrivacyEgressGuard();
$categories = [];
for ($i = 0; $i < 20; ++$i) $categories[] = 'category-' . $i;
$categories[] = 'secret';
$egressDecision = $egress->evaluate([
    'data_classes' => ['C1'],
    'detected_categories' => $categories,
    'destination_class' => 'approved-processor',
    'purpose' => 'research',
    'consent_or_lawful_basis' => true,
    'native_authorized' => true,
    'minimum_necessary' => false,
]);
c277(($egressDecision['decision'] ?? '') === 'block', 'DLP category overflow must block rather than hide sensitive classification.');
c277(in_array('detected_categories_invalid', $egressDecision['reasons'] ?? [], true), 'DLP overflow reason must be explicit.');

$remediation = new AutomatedRemediationPolicy();
$approvalRefs = [];
for ($i = 0; $i < 11; ++$i) $approvalRefs[] = 'approval:human-' . $i;
$remediationDecision = $remediation->decide([
    'action_type' => 'rotate-key',
    'risk_level' => 'high',
    'reversible' => true,
    'previewed' => true,
    'rollback_reference' => 'rollback:cycle277',
    'human_approvals' => 10,
    'human_approval_refs' => $approvalRefs,
    'step_up_verified' => true,
]);
c277(($remediationDecision['decision'] ?? '') === 'block', 'Approval evidence overflow must block rather than truncate.');
c277(in_array('approval_evidence_invalid', $remediationDecision['reasons'] ?? [], true), 'Malformed approval evidence must be explicitly rejected.');

$provenance = new ArtifactProvenanceVerifier();
$object = new stdClass();
$provenanceDecision = $provenance->verify([
    'source_commit' => $object,
    'artifact_sha256' => str_repeat('a', 64),
    'builder_identity' => 'builder:cycle277',
    'provenance_version' => 'slsa-v1',
    'signed_attestation' => true,
    'sbom_present' => true,
    'vex_status' => 'fixed',
]);
c277(($provenanceDecision['state'] ?? '') === 'blocked', 'Non-scalar provenance identifiers must block without unsafe string coercion.');

$graph = new SecurityKnowledgeGraph();
$nodes = [];
for ($i = 0; $i < 2001; ++$i) $nodes[] = ['id' => 'node-' . $i, 'type' => 'module', 'label' => 'Node ' . $i];
$graphResult = $graph->build($nodes, []);
c277(($graphResult['input_complete'] ?? true) === false, 'Security graph overflow must be explicit and fail closed.');
c277(in_array('graph_scope_overflow', $graphResult['errors'] ?? [], true), 'Graph overflow must expose a bounded machine-readable error.');

$register = (string) file_get_contents(dirname(__DIR__) . '/docs/EIGHTY-ROUND-REVIEW-AND-CORRECTION-CYCLES-198-277.md');
c277(str_contains($register, 'Requested review rounds | **80**'), 'Review register must record all 80 requested rounds.');
c277(str_contains($register, '198, 199, 200, 201, 202, 203, 204, 205'), 'Review register must identify defect-bearing requested rounds.');
c277(str_contains($register, 'Known unresolved repository-correctable defects after fixes/retests | **0**'), 'Closure register must retain zero known unresolved repository-correctable defects.');

preg_match_all('/^\| (?:19[8-9]|2[0-7][0-9]) \|/m', $register, $matches);
c277(count($matches[0]) === 80, 'Register must contain exactly 80 individual requested review rows (198-277).');

echo "PASS: Cycle 277 eighty-round review closure regressions passed\n";
