<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\AgenticAiSecurity;
use Sabri\Platform\Security\Future\AutomatedRemediationPolicy;
use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\PrivacyAnalyticsGuard;

function c189(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$agent = (new AgenticAiSecurity())->evaluate([
    'agent_id' => 'cycle189-agent',
    'tool_allowlist' => ['search'],
    'data_classes' => ['C1'],
    'network_allowlist' => ['internal-api'],
    'max_tool_calls' => '10calls',
    'cost_budget' => 5,
    'aibom_registered' => true,
    'source_citations_required' => true,
]);
c189(($agent['decision'] ?? '') === 'block' && in_array('tool_call_budget_invalid', $agent['reasons'] ?? [], true), 'Agentic tool-call budget must reject malformed numeric strings instead of coercing a numeric prefix.');

$analytics = (new PrivacyAnalyticsGuard())->evaluate([
    'epsilon' => 0.5,
    'remaining_budget' => 1.0,
    'cohort_size' => '50people',
    'minimum_cohort' => 30,
    'no_raw_rows' => true,
    'clipping_applied' => true,
    'clean_room' => true,
]);
c189(($analytics['decision'] ?? '') === 'block' && in_array('cohort_size_invalid', $analytics['reasons'] ?? [], true), 'Differential-privacy cohort size must reject malformed integer strings.');

$remediation = (new AutomatedRemediationPolicy())->decide([
    'action_type' => 'disable_account',
    'risk_level' => 'critical',
    'reversible' => true,
    'previewed' => true,
    'rollback_reference' => 'rollback:cycle189',
    'human_approvals' => '2people',
    'human_approval_refs' => ['approval:cycle189-a', 'approval:cycle189-b'],
    'step_up_verified' => true,
]);
c189(($remediation['decision'] ?? '') === 'block' && in_array('approval_count_invalid', $remediation['reasons'] ?? [], true), 'Critical remediation must not satisfy dual approval through a coercible malformed count.');

$assurance = FutureSecurityAssurance::evaluate('F24-FUT-007', [
    'control_id' => 'control:cycle189',
    'coverage' => 'complete',
    'evidence_freshness' => 'current',
    'owner' => 'security-team',
    'failure_state' => 'blocked',
    'evidence_ref' => 'evidence:cycle189-assurance',
    'reviewed_at' => gmdate('c', time() - 60),
    'max_age_days' => '365days',
]);
c189(($assurance['write_allowed'] ?? true) === false && in_array('reviewed_at', $assurance['missing_controls'] ?? [], true), 'Malformed assurance freshness window must fail closed rather than being cast to an integer.');

echo "PASS: cycle189 Future Security numeric-coercion contracts hardened and retested\n";
