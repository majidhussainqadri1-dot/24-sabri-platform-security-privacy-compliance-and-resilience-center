<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
use Sabri\Platform\Security\Monitoring\PerformanceMonitor;
function c131(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }
$GLOBALS['wp_options']['spcrc_performance_samples_v1'] = ['api_latency' => [
    ['value'=>10.0,'unit'=>'ms','at'=>gmdate('c')],
    ['value'=>20.0,'unit'=>'ms','at'=>gmdate('c')],
    ['value'=>INF,'unit'=>'ms','at'=>gmdate('c')],
    ['value'=>1.0,'unit'=>'s','at'=>gmdate('c')],
]];
$monitor = new PerformanceMonitor();
$summary = $monitor->summary('api_latency');
c131(($summary['unit'] ?? '') === 'ms', 'Performance summary must establish one canonical unit.');
c131(($summary['count'] ?? 0) === 2 && ($summary['discarded_samples'] ?? 0) === 2, 'Non-finite and mixed-unit samples must be excluded from measurement.');
c131(is_finite((float) ($summary['p95'] ?? INF)) && ($summary['max'] ?? null) === 20.0, 'Tampered Infinity must not produce a measured infinite p95/max.');
$monitor->record('api_latency', 1.0, 's');
$afterMismatch = $monitor->summary('api_latency');
c131(($afterMismatch['count'] ?? 0) === 2, 'A record using a conflicting unit must not contaminate an existing metric.');
$monitor->record('api_latency', 30.0, 'ms');
$afterValid = $monitor->summary('api_latency');
c131(($afterValid['count'] ?? 0) === 3 && ($afterValid['max'] ?? null) === 30.0, 'Same-unit finite samples must remain recordable.');
echo "PASS: cycle131 performance numeric/unit integrity defects fixed and retested\n";
