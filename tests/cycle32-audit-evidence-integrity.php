<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php';

use Sabri\Platform\Security\Storage\AuditLogger;

$assertions = 0;
function expectCycle32(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$logger = new AuditLogger();
$before = count($GLOBALS['wpdb']->events);
$GLOBALS['wp_json_encode_fail'] = true;
$encoded = $logger->record('cycle32_encode', 'file-24-security-center', 'blocked', 'high', ['control' => 'critical']);
unset($GLOBALS['wp_json_encode_fail']);
expectCycle32(is_wp_error($encoded), 'Context encoding failure must return a bounded error.');
expectCycle32($encoded->get_error_code() === 'spcrc_audit_context_encode_failed', 'Encoding failure must use the dedicated evidence-integrity code.');
expectCycle32(count($GLOBALS['wpdb']->events) === $before, 'A context encoding failure must not store an evidence-empty audit event.');

$GLOBALS['wpdb']->zeroAuditInsert = true;
$zero = $logger->record('cycle32_zero', 'file-24-security-center', 'blocked', 'high', []);
expectCycle32(is_wp_error($zero), 'A zero-row audit insert must be treated as failure.');
expectCycle32($zero->get_error_code() === 'spcrc_audit_write_failed', 'Zero-row insert must use the canonical audit write error.');
expectCycle32(count($GLOBALS['wpdb']->events) === $before, 'A zero-row insert must not appear in canonical event history.');

$ok = $logger->record('cycle32_ok', 'file-24-security-center', 'recorded', 'low', ['bounded' => 'yes']);
expectCycle32(is_string($ok), 'A valid exactly-once audit insert must still succeed.');
expectCycle32(count($GLOBALS['wpdb']->events) === $before + 1, 'Successful insert must append exactly one event.');

printf("PASS: %d Cycle 32 audit-evidence integrity assertions\n", $assertions);
