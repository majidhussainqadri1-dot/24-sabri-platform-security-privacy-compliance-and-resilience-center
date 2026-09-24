<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Monitoring;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Executable File 24 measurable-performance contract (F24-R092).
 *
 * Repository code defines the metric vocabulary and validation rules; actual
 * thresholds and measurements remain environment/staging evidence.
 */
final class PerformanceObjectiveContract
{
    /** @var array<string,array{unit:string,direction:string}> */
    private const METRICS = [
        'event_ingestion_rate' => ['unit' => 'events_per_second', 'direction' => 'minimum'],
        'burst_rate' => ['unit' => 'events_per_second', 'direction' => 'minimum'],
        'dashboard_p95_latency' => ['unit' => 'ms', 'direction' => 'maximum'],
        'maximum_backlog' => ['unit' => 'items', 'direction' => 'maximum'],
        'retry_failure_recovery_time' => ['unit' => 'seconds', 'direction' => 'maximum'],
        'data_loss_tolerance' => ['unit' => 'events', 'direction' => 'maximum'],
        'export_time' => ['unit' => 'seconds', 'direction' => 'maximum'],
        'storage_growth' => ['unit' => 'bytes_per_day', 'direction' => 'maximum'],
    ];

    /** @return array<string,array{unit:string,direction:string}> */
    public static function definitions(): array
    {
        return self::METRICS;
    }

    /** @return string[] */
    public static function metricKeys(): array
    {
        return array_keys(self::METRICS);
    }

    public static function repositoryCodingComplete(): bool
    {
        if (count(self::METRICS) !== 8) {
            return false;
        }
        foreach (self::METRICS as $key => $definition) {
            if ($key === '' || ! in_array($definition['direction'], ['minimum', 'maximum'], true) || $definition['unit'] === '') {
                return false;
            }
        }
        return true;
    }

    /** @param array<string,mixed> $payload @return true|\WP_Error */
    public static function validateArtifact(array $payload): true|\WP_Error
    {
        $metric = Sanitizer::key($payload['metric'] ?? '', 80);
        if (! isset(self::METRICS[$metric])) {
            return new \WP_Error('spcrc_performance_metric_invalid', 'Performance objective must use a governed File 24 metric.');
        }
        $definition = self::METRICS[$metric];
        $unit = Sanitizer::key($payload['unit'] ?? '', 40);
        $direction = Sanitizer::key($payload['direction'] ?? '', 20);
        if ($unit !== $definition['unit'] || $direction !== $definition['direction']) {
            return new \WP_Error('spcrc_performance_metric_contract_mismatch', 'Performance objective unit/direction does not match the governed metric contract.');
        }
        $threshold = $payload['threshold'] ?? null;
        if (! is_numeric($threshold) || ! is_finite((float) $threshold) || (float) $threshold < 0) {
            return new \WP_Error('spcrc_performance_threshold_invalid', 'Performance objective requires a finite non-negative threshold.');
        }
        $environment = Sanitizer::key($payload['environment'] ?? '', 20);
        if (! in_array($environment, ['staging', 'production'], true)) {
            return new \WP_Error('spcrc_performance_environment_invalid', 'Performance objective must be bound to staging or production.');
        }
        $effectiveVersion = Sanitizer::text($payload['effective_version'] ?? '', 60);
        if (preg_match('/^\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?$/', $effectiveVersion) !== 1) {
            return new \WP_Error('spcrc_performance_version_invalid', 'Performance objective requires a bounded effective software version.');
        }
        $window = Sanitizer::strictInteger($payload['measurement_window_seconds'] ?? null, 1, 2678400);
        if ($window === null) {
            return new \WP_Error('spcrc_performance_window_invalid', 'Performance objective requires a measurement window between one second and 31 days.');
        }
        return true;
    }

    /**
     * @param array<string,array<string,mixed>> $objectives
     * @param array<string,mixed> $measurements
     * @return array<string,mixed>
     */
    public static function evaluate(array $objectives, array $measurements = []): array
    {
        $missing = [];
        $invalid = [];
        $breaches = [];
        $measured = 0;

        foreach (self::METRICS as $metric => $definition) {
            $objective = $objectives[$metric] ?? null;
            if (! is_array($objective)) {
                $missing[] = $metric;
                continue;
            }
            $payload = array_merge($objective, ['metric' => $metric]);
            $validation = self::validateArtifact($payload);
            $evidenceRef = Sanitizer::opaqueReference($objective['evidence_ref'] ?? '');
            if (is_wp_error($validation) || $evidenceRef === '') {
                $invalid[] = $metric;
                continue;
            }

            if (! array_key_exists($metric, $measurements)) {
                continue;
            }
            $raw = $measurements[$metric];
            if (! is_numeric($raw) || ! is_finite((float) $raw) || (float) $raw < 0) {
                $invalid[] = $metric;
                continue;
            }
            ++$measured;
            $value = (float) $raw;
            $threshold = (float) $objective['threshold'];
            if (($definition['direction'] === 'maximum' && $value > $threshold)
                || ($definition['direction'] === 'minimum' && $value < $threshold)
            ) {
                $breaches[] = $metric;
            }
        }

        $state = 'configured';
        if ($missing !== [] || $invalid !== []) {
            $state = 'incomplete';
        } elseif ($measurements !== [] && $measured < count(self::METRICS)) {
            $state = 'measuring';
        } elseif ($measured === count(self::METRICS)) {
            $state = $breaches === [] ? 'measured' : 'breached';
        }

        return [
            'state' => $state,
            'required_metric_count' => count(self::METRICS),
            'measured_metric_count' => $measured,
            'missing_metrics' => $missing,
            'invalid_metrics' => array_values(array_unique($invalid)),
            'breaches' => $breaches,
            'release_ready' => $state === 'measured',
        ];
    }
}
