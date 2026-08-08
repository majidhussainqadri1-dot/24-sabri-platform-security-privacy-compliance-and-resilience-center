<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

use Sabri\Platform\Security\Support\Sanitizer;

final class AttackPathEngine
{
    public function __construct(private ?SecurityKnowledgeGraph $graph = null)
    {
        $this->graph ??= new SecurityKnowledgeGraph();
    }

    /** @param array<string,mixed> $graph
     *  @param string[] $sources
     *  @param string[] $targets
     *  @param array<string,array<string,mixed>> $riskByTarget
     *  @return array<int,array<string,mixed>>
     */
    public function analyze(array $graph, array $sources, array $targets, array $riskByTarget = []): array
    {
        $paths = [];
        foreach (array_slice($sources, 0, 50) as $source) {
            foreach (array_slice($targets, 0, 50) as $target) {
                $source = Sanitizer::key($source, 120);
                $target = Sanitizer::key($target, 120);
                if ($source === '' || $target === '') continue;
                $reach = $this->graph->reachable($graph, $source, $target, 10);
                if (! $reach['reachable']) continue;
                $risk = $riskByTarget[$target] ?? [];
                $score = $this->score([
                    'likelihood' => $risk['likelihood'] ?? 50,
                    'reachability' => max(10, 100 - ($reach['depth'] * 8)),
                    'data_sensitivity' => $risk['data_sensitivity'] ?? 50,
                    'user_harm' => $risk['user_harm'] ?? 50,
                    'blast_radius' => $risk['blast_radius'] ?? 50,
                ]);
                $paths[] = ['source' => $source, 'target' => $target, 'path' => $reach['path'], 'depth' => $reach['depth'], 'score' => $score];
            }
        }
        usort($paths, static fn(array $a, array $b): int => $b['score'] <=> $a['score']);
        return array_slice($paths, 0, 100);
    }

    /** @param array<string,mixed> $dimensions */
    public function score(array $dimensions): int
    {
        $weights = ['likelihood' => 20, 'reachability' => 25, 'data_sensitivity' => 20, 'user_harm' => 20, 'blast_radius' => 15];
        $total = 0.0;
        foreach ($weights as $key => $weight) {
            $value = max(0, min(100, (float) ($dimensions[$key] ?? 0)));
            $total += $value * ($weight / 100);
        }
        return (int) round(max(0, min(100, $total)));
    }
}
