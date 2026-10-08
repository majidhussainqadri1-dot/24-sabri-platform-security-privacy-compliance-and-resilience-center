<?php

declare(strict_types=1);

// Regression: packaged and repository source manifests must agree, and their
// minimum source/test counts must not exceed the exact checked-out tree.
$root = dirname(__DIR__);
$repositoryPath = $root . '/docs/SOURCE-MANIFEST-0.99.0.json';
$packagePath = $root . '/plugin/sabri-security-center/docs/SOURCE-MANIFEST.json';

function c281Assert(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$repositoryRaw = file_get_contents($repositoryPath);
$packageRaw = file_get_contents($packagePath);
c281Assert(is_string($repositoryRaw) && is_string($packageRaw), 'Both source manifests must be readable.');
$repository = json_decode($repositoryRaw, true, 512, JSON_THROW_ON_ERROR);
$package = json_decode($packageRaw, true, 512, JSON_THROW_ON_ERROR);
c281Assert(is_array($repository) && is_array($package), 'Both source manifests must be JSON objects.');
c281Assert($repository === $package, 'Packaged source manifest must exactly match the repository source manifest.');

$verification = $repository['verification'] ?? [];
c281Assert(is_array($verification), 'Verification requirements must exist.');
$phpMinimum = $verification['php_files_minimum'] ?? null;
$testMinimum = $verification['test_programs_minimum'] ?? null;
c281Assert(is_int($phpMinimum) && $phpMinimum > 0, 'PHP file minimum must be a positive integer.');
c281Assert(is_int($testMinimum) && $testMinimum > 0, 'Test program minimum must be a positive integer.');

$phpCount = 0;
foreach (['plugin', 'tests'] as $directory) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root . '/' . $directory, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $entry) {
        if ($entry->isFile() && $entry->getExtension() === 'php') {
            ++$phpCount;
        }
    }
}
$testCount = 0;
foreach (new DirectoryIterator($root . '/tests') as $entry) {
    if ($entry->isFile() && $entry->getExtension() === 'php' && $entry->getFilename() !== 'bootstrap.php') {
        ++$testCount;
    }
}
c281Assert($phpCount >= $phpMinimum, "PHP file count {$phpCount} is below {$phpMinimum}.");
c281Assert($testCount >= $testMinimum, "Test program count {$testCount} is below {$testMinimum}.");

echo "PASS: Cycle 281 source manifest parity; {$phpCount} PHP files and {$testCount} test programs\n";
