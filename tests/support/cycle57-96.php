<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/bootstrap.php';

$base = dirname(__DIR__, 2) . '/plugin/sabri-security-center/src/';
foreach ([
    'Support/Sanitizer.php',
    'Support/SecureIdentifier.php',
    'Support/AtomicOptionLock.php',
    'Capabilities.php',
    'Storage/AuditLogger.php',
    'Storage/AuditGapStore.php',
    'Storage/Schema.php',
    'Storage/PrivacyRequestRepository.php',
    'Registry/ModuleRegistry.php',
    'Registry/SecurityStateRegistry.php',
    'Privacy/PrivacyRequestPolicy.php',
    'Privacy/PrivacyVerificationStore.php',
    'Privacy/RecoveryManager.php',
    'Retention/RetentionManager.php',
    'UpgradeManager.php',
] as $file) {
    require_once $base . $file;
}

$GLOBALS['cycle_review_assertions'] = 0;
function cycleReviewAssert(bool $condition, string $message): void
{
    ++$GLOBALS['cycle_review_assertions'];
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

function cycleReviewPass(int $cycle, string $label): void
{
    echo sprintf("PASS: %d Cycle %d %s assertions\n", $GLOBALS['cycle_review_assertions'], $cycle, $label);
}
