<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

use Sabri\Platform\Security\Support\Sanitizer;

final class AgenticAiSecurity
{
    /** @param array<string,mixed> $plan
     *  @return array<string,mixed>
     */
    public function evaluate(array $plan): array
    {
        $agent = Sanitizer::key($plan['agent_id'] ?? '', 120);
        $tools = Sanitizer::textList($plan['tool_allowlist'] ?? [], 50, 80);
        $dataClasses = array_map('strtoupper', Sanitizer::textList($plan['data_classes'] ?? [], 10, 10));
        $network = Sanitizer::textList($plan['network_allowlist'] ?? [], 50, 180);
        $maxCalls = max(0, (int) ($plan['max_tool_calls'] ?? 0));
        $costBudget = (float) ($plan['cost_budget'] ?? 0);
        $highRisk = Sanitizer::boolean($plan['high_risk_or_destructive'] ?? false);
        $humanApproval = Sanitizer::boolean($plan['human_approval'] ?? false);
        $registered = Sanitizer::boolean($plan['aibom_registered'] ?? false);
        $citations = Sanitizer::boolean($plan['source_citations_required'] ?? false);
        $reasons = [];
        if ($agent === '') $reasons[] = 'agent_identity_missing';
        if ($tools === []) $reasons[] = 'tool_allowlist_missing';
        if ($maxCalls < 1 || $maxCalls > 100) $reasons[] = 'tool_call_budget_invalid';
        if ($costBudget <= 0 || $costBudget > 10000) $reasons[] = 'cost_budget_invalid';
        if ($network === []) $reasons[] = 'network_allowlist_missing';
        if (array_intersect($dataClasses, ['C4','C5']) !== [] && ! $humanApproval) $reasons[] = 'sensitive_data_human_approval_required';
        if ($highRisk && ! $humanApproval) $reasons[] = 'high_risk_human_approval_required';
        if (! $registered) $reasons[] = 'aibom_registration_required';
        if (! $citations) $reasons[] = 'source_citation_policy_required';
        return ['decision' => $reasons === [] ? 'allow_bounded' : 'block', 'reasons' => $reasons, 'agent_id' => $agent, 'native_action_authorization_required' => true];
    }
}
