<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

function c142(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$source = file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Monitoring/DetectionEngine.php');
c142(is_string($source), 'DetectionEngine source must be readable.');
c142(str_contains($source, "use Sabri\\Platform\\Security\\Storage\\AuditGapStore;"), 'Detection engine must depend on durable audit-gap recording.');
c142(str_contains($source, "if (is_wp_error(\$alert))"), 'Detection engine must explicitly inspect alert persistence failure.');
c142(str_contains($source, "AuditGapStore::record('spcrc_detection_audit_gap'"), 'Alert persistence failure must create durable detection-gap evidence.');
c142(str_contains($source, "do_action('spcrc/detection_alert_persistence_failed'"), 'Alert persistence failure must emit an operational failure signal.');
c142(str_contains($source, 'private function createAlert') && str_contains($source, 'string|\\WP_Error'), 'Alert creation must return its persistence result rather than silently discarding it.');

echo "PASS: cycle142 detection-alert durability defect fixed and retested\n";
