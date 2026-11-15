<?php
/**
 * File24 real-WordPress activation regression (2026-11-15).
 *
 * An isolated MySQL 8 / WP7.0.1+7.1.4 activation failed because
 * REQUIRED_INDEXES demanded governance.status_expires and subject_status,
 * whereas Schema::install() actually creates status_expiry and type_subject.
 * Validate all names declared in SQL against the exact required schema names
 * before treating a self-reported schema manifest as deployable.
 */
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
$rc = new ReflectionClass(\Sabri\Platform\Security\Storage\Schema::class);
$constant = $rc->getReflectionConstant('REQUIRED_INDEXES');
if (! $constant) { fwrite(STDERR, "FAIL: index manifest not inspectable\n"); exit(1); }
$required = $constant->getValue();
$source = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/Schema.php');
if (!is_array($required) || !is_string($source)) { exit(1); }
$checks = 0;
foreach ($required as $logicalTable => $names) {
    $start = strpos($source, 'dbDelta("CREATE TABLE {$tables[\'' . $logicalTable . '\']} (');
    if ($start === false) {
        fwrite(STDERR, "FAIL: missing actual SQL table for {$logicalTable}\n"); exit(1);
    }
    $end = strpos($source, ') {$charset};");', $start);
    if ($end === false) {
        fwrite(STDERR, "FAIL: missing actual SQL close for {$logicalTable}\n"); exit(1);
    }
    $sql = substr($source, $start, $end - $start);
    preg_match_all('/^\s*(?:UNIQUE\s+)?KEY\s+([a-z0-9_]+)\s*\(/mi', $sql, $found);
    $declared = array_merge(['PRIMARY'], $found[1]);
    foreach ($names as $name) {
        if (!in_array($name, $declared, true)) {
            fwrite(STDERR, "FAIL: {$logicalTable}.{$name} required but absent from real dbDelta SQL\n");
            exit(1);
        }
        $checks++;
    }
}
echo "File24 all-table required-index-to-dbDelta SQL parity: {$checks} checks PASSED\n";
