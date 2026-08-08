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
        if ($metric === '' || $unit === '' || ! is_finite($value) || $value < 0) {
            return;
        }
        $all = get_option(self::OPTION, []);
        $all = is_array($all) ? $all : [];
        $samples = is_array($all[$metric] ?? null) ? $all[$metric] : [];
        $canonicalUnit = $this->canonicalUnit($samples);
        if ($canonicalUnit !== '' && ! hash_equals($canonicalUnit, $unit)) {
            return;
        }
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
        $unit = $this->canonicalUnit($samples);
        $values = [];
        $discarded = 0;
        foreach ($samples as $sample) {
            if (! is_array($sample)) {
                ++$discarded;
                continue;
            }
            $sampleUnit = Sanitizer::key($sample['unit'] ?? '', 20);
            $raw = $sample['value'] ?? null;
            if ($unit === '' || $sampleUnit !== $unit || ! is_numeric($raw)) {
                ++$discarded;
                continue;
            }
            $value = (float) $raw;
            if (! is_finite($value) || $value < 0) {
                ++$discarded;
                continue;
            }
            $values[] = $value;
        }
        sort($values, SORT_NUMERIC);
        if ($values === []) {
            return ['metric' => $metric, 'unit' => $unit, 'count' => 0, 'discarded_samples' => $discarded, 'p50' => null, 'p95' => null, 'max' => null, 'status' => 'unknown'];
        }
        return [
            'metric' => $metric,
            'unit' => $unit,
            'count' => count($values),
            'discarded_samples' => $discarded,
            'p50' => $this->percentile($values, 0.50),
            'p95' => $this->percentile($values, 0.95),
            'max' => max($values),
            'status' => 'measured',
        ];
    }

    /** @param array<int,mixed> $samples */
    private function canonicalUnit(array $samples): string
    {
        $counts = [];
        foreach ($samples as $sample) {
            if (! is_array($sample) || ! is_numeric($sample['value'] ?? null)) {
                continue;
            }
            $value = (float) $sample['value'];
            $unit = Sanitizer::key($sample['unit'] ?? '', 20);
            if ($unit === '' || ! is_finite($value) || $value < 0) {
                continue;
            }
            $counts[$unit] = ($counts[$unit] ?? 0) + 1;
        }
        if ($counts === []) {
            return '';
        }
        ksort($counts, SORT_STRING);
        arsort($counts, SORT_NUMERIC);
        return (string) array_key_first($counts);
    }

    /** @param float[] $values */
    private function percentile(array $values, float $ratio): float
    {
        $index = (int) ceil(count($values) * $ratio) - 1;
        return $values[max(0, min(count($values) - 1, $index))];
    }
}
