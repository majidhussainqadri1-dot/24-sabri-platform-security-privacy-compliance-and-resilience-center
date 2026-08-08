<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\AttackPathEngine;
use Sabri\Platform\Security\Future\SecurityKnowledgeGraph;

function expectCycle119(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$graphEngine = new SecurityKnowledgeGraph();
$graph = $graphEngine->build([
    ['id' => 'risk-a', 'type' => 'risk', 'label' => 'Risk A'],
    ['id' => 'data-c5', 'type' => 'data_class', 'label' => 'C5 data'],
], [
    ['from' => 'risk-a', 'to' => 'data-c5', 'relation' => 'can_reach'],
]);
$engine = new AttackPathEngine($graphEngine);
expectCycle119($engine->score(['likelihood' => INF, 'reachability' => 0, 'data_sensitivity' => 0, 'user_harm' => 0, 'blast_radius' => 0]) === 0, 'Non-finite risk dimensions must not inflate the score.');
expectCycle119($engine->score(['likelihood' => NAN, 'reachability' => 0, 'data_sensitivity' => 0, 'user_harm' => 0, 'blast_radius' => 0]) === 0, 'NaN risk dimensions must fail closed to zero contribution.');

$paths = $engine->analyze($graph, ['risk-a', 'risk-a'], ['data-c5', 'data-c5'], ['data-c5' => ['likelihood' => 80, 'data_sensitivity' => 100, 'user_harm' => 90, 'blast_radius' => 70]]);
expectCycle119(count($paths) === 1, 'Duplicate source/target inputs must not create duplicate attack paths.');
expectCycle119($paths[0]['score'] >= 70 && $paths[0]['score'] <= 100, 'Material finite path risk must remain bounded and prioritized.');

echo "PASS: cycle119 attack-path numeric/deterministic defects fixed and retested\n";
