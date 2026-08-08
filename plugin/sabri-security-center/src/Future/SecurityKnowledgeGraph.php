<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

use Sabri\Platform\Security\Support\Sanitizer;

final class SecurityKnowledgeGraph
{
    private const NODE_TYPES = [
        'user','role','capability','module','endpoint','data_class','secret_ref','vendor','region',
        'vulnerability','control','evidence','risk','workload','ai_asset','release','backup','policy',
    ];

    /** @param array<int,array<string,mixed>> $nodes
     *  @param array<int,array<string,mixed>> $edges
     *  @return array<string,mixed>
     */
    public function build(array $nodes, array $edges): array
    {
        $safeNodes = [];
        foreach (array_slice($nodes, 0, 2000) as $node) {
            $id = Sanitizer::key($node['id'] ?? '', 120);
            $type = Sanitizer::key($node['type'] ?? '', 40);
            $label = Sanitizer::text($node['label'] ?? '', 160);
            if ($id === '' || ! in_array($type, self::NODE_TYPES, true) || $label === '' || Sanitizer::containsSensitiveMaterial($label)) {
                continue;
            }
            $safeNodes[$id] = ['id' => $id, 'type' => $type, 'label' => $label];
        }

        $safeEdges = [];
        $seen = [];
        foreach (array_slice($edges, 0, 10000) as $edge) {
            $from = Sanitizer::key($edge['from'] ?? '', 120);
            $to = Sanitizer::key($edge['to'] ?? '', 120);
            $relation = Sanitizer::key($edge['relation'] ?? '', 60);
            if ($from === '' || $to === '' || $relation === '' || ! isset($safeNodes[$from], $safeNodes[$to]) || $from === $to) {
                continue;
            }
            $key = $from . '>' . $relation . '>' . $to;
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $safeEdges[] = ['from' => $from, 'to' => $to, 'relation' => $relation];
        }

        return ['nodes' => array_values($safeNodes), 'edges' => $safeEdges, 'node_count' => count($safeNodes), 'edge_count' => count($safeEdges)];
    }

    /** @param array<string,mixed> $graph
     *  @return array{reachable:bool,path:string[],depth:int}
     */
    public function reachable(array $graph, string $from, string $to, int $maxDepth = 8): array
    {
        $from = Sanitizer::key($from, 120);
        $to = Sanitizer::key($to, 120);
        $maxDepth = max(1, min(12, $maxDepth));
        if ($from === '' || $to === '') {
            return ['reachable' => false, 'path' => [], 'depth' => 0];
        }

        $adj = [];
        foreach (($graph['edges'] ?? []) as $edge) {
            if (! is_array($edge)) continue;
            $a = Sanitizer::key($edge['from'] ?? '', 120);
            $b = Sanitizer::key($edge['to'] ?? '', 120);
            if ($a !== '' && $b !== '') $adj[$a][] = $b;
        }

        $queue = [[$from, [$from], 0]];
        $visited = [$from => true];
        while ($queue !== []) {
            [$node, $path, $depth] = array_shift($queue);
            if ($node === $to) return ['reachable' => true, 'path' => $path, 'depth' => $depth];
            if ($depth >= $maxDepth) continue;
            foreach (array_values(array_unique($adj[$node] ?? [])) as $next) {
                if (isset($visited[$next])) continue;
                $visited[$next] = true;
                $queue[] = [$next, [...$path, $next], $depth + 1];
            }
        }
        return ['reachable' => false, 'path' => [], 'depth' => 0];
    }
}
