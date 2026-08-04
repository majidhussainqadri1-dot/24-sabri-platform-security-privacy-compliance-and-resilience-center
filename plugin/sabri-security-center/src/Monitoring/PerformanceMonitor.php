<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Monitoring;

use Sabri\Platform\Security\Support\Sanitizer;

final class PerformanceMonitor
{
    private const OPTION = 'spcrc_performance_samples_v1';
    private const MAX_SAMPLES_PER_METRIC = 500;

    public function record(string $metric, float $value, string $unit = 'ms'): void
    {
        $metric = Sanitizer::key($metric, 80);
        $unit = Sanitizer::key($unit, 20);
        if ($metric === '' || ! is_finite($value) || $value < 0) {
            return;
        }
        $all = get_option(self::OPTION, []);
        $all = is_array($all) ? $all : [];
        $samples = is_array($all[$metric] ?? null) ? $all[$metric] : [];
        $samples[] = ['value' => round($value, 4), 'unit' => $unit, 'at' => gmdate('c')];
        if (count($samples) > self::MAX_SAMPLES_PER_METRIC) {
            $samples = array_slice($samples, -self::MAX_SAMPLES_PER_METRIC);
        }
        $all[$metric] = $samples;
        update_option(self::OPTION, $all, false);
    }

    /** @return array<string,mixed> */
    public function summary(string $metric): array
    {
        $metric = Sanitizer::key($metric, 80);
        $all = get_option(self::OPTION, []);
        $samples = is_array($all) && is_array($all[$metric] ?? null) ? $all[$metric] : [];
        $values = [];
        foreach ($samples as $sample) {
            if (is_array($sample) && is_numeric($sample['value'] ?? null)) {
                $values[] = (float) $sample['value'];
            }
        }
        sort($values, SORT_NUMERIC);
        if ($values === []) {
            return ['metric' => $metric, 'count' => 0, 'p50' => null, 'p95' => null, 'max' => null, 'status' => 'unknown'];
        }
        return [
            'metric' => $metric,
            'count' => count($values),
            'p50' => $this->percentile($values, 0.50),
            'p95' => $this->percentile($values, 0.95),
            'max' => max($values),
            'status' => 'measured',
        ];
    }

    /** @param float[] $values */
    private function percentile(array $values, float $ratio): float
    {
        $index = (int) ceil(count($values) * $ratio) - 1;
        return $values[max(0, min(count($values) - 1, $index))];
    }
}
