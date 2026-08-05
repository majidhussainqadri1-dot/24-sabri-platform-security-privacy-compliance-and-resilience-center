<?php

declare(strict_types=1);

$tests = glob(__DIR__ . '/*.php') ?: [];
sort($tests, SORT_STRING);
foreach ($tests as $test) {
    if (basename($test) === basename(__FILE__) || basename($test) === 'bootstrap.php') {
        continue;
    }
    $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($test) . ' 2>&1';
    $lines = [];
    $exitCode = 0;
    exec($command, $lines, $exitCode);
    if ($exitCode !== 0) {
        $message = implode(' | ', $lines);
        $message = str_replace(['%', "\r", "\n", ':'], ['%25', '%0D', '%0A', '%3A'], $message);
        echo '::error file=' . str_replace(dirname(__DIR__) . '/', '', $test) . '::' . $message . "\n";
        exit(1);
    }
}

echo "PASS: diagnostic runner found no failing PHP test program\n";
