<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

use Sabri\Platform\Security\Support\Sanitizer;

final class PolicyAsCodeEngine
{
    /** @param array<string,mixed> $policy
     *  @param array<string,mixed> $context
     *  @return array<string,mixed>
     */
    public function evaluate(array $policy, array $context): array
    {
        $version = Sanitizer::text($policy['version'] ?? '', 40);
        $effect = Sanitizer::key($policy['effect'] ?? 'deny', 30);
        $rules = is_array($policy['rules'] ?? null) ? array_slice($policy['rules'], 0, 100) : [];
        if ($version === '' || ! in_array($effect, ['allow', 'deny', 'require_approval'], true) || $rules === []) {
            return ['matched' => false, 'decision' => 'deny', 'reason' => 'invalid_policy', 'version' => $version];
        }

        foreach ($rules as $rule) {
            if (! is_array($rule) || ! $this->ruleMatches($rule, $context)) {
                return ['matched' => false, 'decision' => 'deny', 'reason' => 'rule_not_satisfied', 'version' => $version];
            }
        }
        return ['matched' => true, 'decision' => $effect, 'reason' => 'policy_matched', 'version' => $version];
    }

    /** @param array<string,mixed> $rule
     *  @param array<string,mixed> $context
     */
    private function ruleMatches(array $rule, array $context): bool
    {
        $field = Sanitizer::key($rule['field'] ?? '', 80);
        $operator = Sanitizer::key($rule['operator'] ?? '', 30);
        if ($field === '' || ! array_key_exists($field, $context)) return false;
        $actual = $context[$field];
        $expected = $rule['value'] ?? null;
        return match ($operator) {
            'equals' => is_scalar($actual) && is_scalar($expected) && (string) $actual === (string) $expected,
            'present' => $actual !== null && $actual !== '' && $actual !== [],
            'in' => is_array($expected) && in_array($actual, $expected, true),
            'gte' => is_numeric($actual) && is_numeric($expected) && (float) $actual >= (float) $expected,
            'lte' => is_numeric($actual) && is_numeric($expected) && (float) $actual <= (float) $expected,
            default => false,
        };
    }
}
