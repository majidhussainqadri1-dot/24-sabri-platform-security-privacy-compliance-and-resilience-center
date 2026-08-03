<?php

declare(strict_types=1);

$source = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Retention/RetentionManager.php');
if (! is_string($source)) {
    fwrite(STDERR, "FAIL: RetentionManager source unavailable.\n");
    exit(1);
}

$assertions = [
    "private const LOCK_OPTION = 'spcrc_retention_lock'" => 'Retention lock must have one canonical option key.',
    'private function acquireLock(): string|\\WP_Error' => 'Retention must expose a typed atomic lock acquisition path.',
    'add_option(' => 'Retention lock must use WordPress atomic option insertion.',
    "'expires_at' => \$now + self::LOCK_SECONDS" => 'Retention lock must carry a bounded expiry.',
    "new \\WP_Error('spcrc_retention_locked'" => 'Lock contention must be distinguishable from storage failure.',
    "new \\WP_Error('spcrc_retention_lock_unavailable'" => 'Lock storage failure must fail closed.',
    'private function releaseLock(string $token): void' => 'Retention must release only through a token-aware path.',
    "hash_equals((string) (\$existing['token'] ?? ''), \$token)" => 'Retention lock release must verify ownership.',
    'delete_option(self::LOCK_OPTION)' => 'Atomic option lock must be removed on release or unschedule.',
    '$this->releaseLock($lock);' => 'Every run path must reach owner-aware lock release.',
];

$count = 0;
foreach ($assertions as $needle => $message) {
    if (! str_contains($source, $needle)) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
    ++$count;
}

if (str_contains($source, 'if (get_transient(self::LOCK_KEY)')) {
    fwrite(STDERR, "FAIL: Legacy check-then-set transient lock must not remain.\n");
    exit(1);
}
++$count;

echo "PASS: {$count} Cycle 18 retention-concurrency assertions\n";
