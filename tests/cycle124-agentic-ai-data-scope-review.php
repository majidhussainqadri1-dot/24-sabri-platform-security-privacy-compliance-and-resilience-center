<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\AgenticAiSecurity;

function expectCycle124(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$guard = new AgenticAiSecurity();
$base = [
    'agent_id' => 'study-agent',
    'tool_allowlist' => ['search', 'retrieve'],
    'network_allowlist' => ['approved-ai-provider'],
    'max_tool_calls' => 12,
    'cost_budget' => 20,
    'high_risk_or_destructive' => false,
    'human_approval' => false,
    'aibom_registered' => true,
    'source_citations_required' => true,
];

$missingScope = $guard->evaluate($base + ['data_classes' => []]);
expectCycle124($missingScope['decision'] === 'block' && in_array('data_scope_missing', $missingScope['reasons'], true), 'Agent plans must declare a bounded data scope.');

$unknownScope = $guard->evaluate($base + ['data_classes' => ['C9']]);
expectCycle124($unknownScope['decision'] === 'block' && in_array('unknown_data_class', $unknownScope['reasons'], true), 'Unknown AI data classes must fail closed.');

$nonFiniteBudget = $guard->evaluate(array_merge($base, ['data_classes' => ['C2'], 'cost_budget' => INF]));
expectCycle124($nonFiniteBudget['decision'] === 'block' && in_array('cost_budget_invalid', $nonFiniteBudget['reasons'], true), 'Infinite AI cost budgets must fail closed.');

$valid = $guard->evaluate($base + ['data_classes' => ['C2']]);
expectCycle124($valid['decision'] === 'allow_bounded' && $valid['native_action_authorization_required'], 'Bounded C2 study agent plan must remain allowable subject to native authorization.');

echo "PASS: cycle124 agentic-AI data-scope defects fixed and retested\n";
