<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\SecurityKnowledgeGraph;

function expectCycle118(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$engine = new SecurityKnowledgeGraph();
$graph = $engine->build([
    ['id' => 'module-a', 'type' => 'module', 'label' => 'File 17'],
    ['id' => 'module-a', 'type' => 'endpoint', 'label' => 'Conflicting identity'],
    ['id' => 'data-c5', 'type' => 'data_class', 'label' => 'C5 data'],
], [
    ['from' => 'module-a', 'to' => 'data-c5', 'relation' => 'can_reach'],
]);
expectCycle118($graph['ambiguous_node_count'] === 1, 'Conflicting duplicate node IDs must be identified as ambiguous.');
expectCycle118($graph['node_count'] === 1 && $graph['edge_count'] === 0, 'Ambiguous nodes and their edges must be removed, not silently overwritten.');

$valid = $engine->build([
    ['id' => 'source', 'type' => 'risk', 'label' => 'Source'],
    ['id' => 'source', 'type' => 'risk', 'label' => 'Source'],
    ['id' => 'target', 'type' => 'data_class', 'label' => 'Target'],
], [
    ['from' => 'source', 'to' => 'target', 'relation' => 'can_reach'],
]);
expectCycle118($valid['node_count'] === 2 && $valid['ambiguous_node_count'] === 0, 'Exact duplicate nodes may deduplicate without becoming ambiguous.');
expectCycle118($engine->reachable($valid, 'source', 'target')['reachable'] === true, 'Valid registered-node path must remain reachable.');

$tampered = $valid;
$tampered['edges'][] = ['from' => 'target', 'to' => 'phantom', 'relation' => 'can_reach'];
expectCycle118($engine->reachable($tampered, 'source', 'phantom')['reachable'] === false, 'Reachability must not traverse phantom nodes absent from the node registry.');

echo "PASS: cycle118 graph integrity defects fixed and retested\n";
