<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

use Sabri\Platform\Security\Support\Sanitizer;

final class AgenticAiSecurity
{
    private const DATA_CLASSES = ['C0','C1','C2','C3','C4','C5'];

    /** @param array<string,mixed> $plan
     *  @return array<string,mixed>
     */
    public function evaluate(array $plan): array
    {
        $agent = Sanitizer::key($plan['agent_id'] ?? '', 120);
        [$tools, $toolsValid] = $this->strictTextList($plan['tool_allowlist'] ?? [], 50, 80);
        [$dataClassValues, $dataClassesValid] = $this->strictTextList($plan['data_classes'] ?? [], 10, 10);
        $dataClasses = array_values(array_unique(array_map('strtoupper', $dataClassValues)));
        [$network, $networkValid] = $this->strictTextList($plan['network_allowlist'] ?? [], 50, 180);
        $maxCalls = Sanitizer::strictInteger($plan['max_tool_calls'] ?? null, 1, 100);
        $costBudget = $this->finiteFloat($plan['cost_budget'] ?? null);
        $highRisk = Sanitizer::boolean($plan['high_risk_or_destructive'] ?? false);
        $humanApproval = Sanitizer::boolean($plan['human_approval'] ?? false);
        $registered = Sanitizer::boolean($plan['aibom_registered'] ?? false);
        $citations = Sanitizer::boolean($plan['source_citations_required'] ?? false);
        $unknownClasses = array_values(array_diff($dataClasses, self::DATA_CLASSES));
        $reasons = [];

        if ($agent === '') $reasons[] = 'agent_identity_missing';
        if (! $toolsValid) $reasons[] = 'tool_allowlist_invalid';
        if ($tools === []) $reasons[] = 'tool_allowlist_missing';
        if (! $dataClassesValid) $reasons[] = 'data_scope_invalid';
        if ($dataClasses === []) $reasons[] = 'data_scope_missing';
        if ($unknownClasses !== []) $reasons[] = 'unknown_data_class';
        if ($maxCalls === null) $reasons[] = 'tool_call_budget_invalid';
        if ($costBudget === null || $costBudget <= 0 || $costBudget > 10000) $reasons[] = 'cost_budget_invalid';
        if (! $networkValid) $reasons[] = 'network_allowlist_invalid';
        if ($network === []) $reasons[] = 'network_allowlist_missing';
        if (array_intersect($dataClasses, ['C4','C5']) !== [] && ! $humanApproval) $reasons[] = 'sensitive_data_human_approval_required';
        if ($highRisk && ! $humanApproval) $reasons[] = 'high_risk_human_approval_required';
        if (! $registered) $reasons[] = 'aibom_registration_required';
        if (! $citations) $reasons[] = 'source_citation_policy_required';

        return [
            'decision' => $reasons === [] ? 'allow_bounded' : 'block',
            'reasons' => array_values(array_unique($reasons)),
            'agent_id' => $agent,
            'unknown_data_classes' => $unknownClasses,
            'native_action_authorization_required' => true,
        ];
    }

    /** @return array{0:string[],1:bool} */
    private function strictTextList(mixed $value, int $maxItems, int $maxLength): array
    {
        if (! is_array($value) || $value === [] || count($value) > $maxItems || array_keys($value) !== range(0, count($value) - 1)) {
            return [[], false];
        }
        $clean = Sanitizer::textList($value, $maxItems, $maxLength);
        if (count($clean) !== count($value)) {
            return [$clean, false];
        }
        return [$clean, true];
    }

    private function finiteFloat(mixed $value): ?float
    {
        if ((! is_int($value) && ! is_float($value) && ! is_string($value)) || ! is_numeric($value)) {
            return null;
        }
        $number = (float) $value;
        return is_finite($number) ? $number : null;
    }
}
