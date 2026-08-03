<?php

declare(strict_types=1);

$source = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Retention/RetentionManager.php');
if (! is_string($source)) {
    fwrite(STDERR, "FAIL: RetentionManager source unavailable.\n");
    exit(1);
}

$assertions = [
    "private const LOCK_OPTION = 'spcrc_retention_lock'" => 'Retention lock must have one canonical option key.',
    'private function acquireLock(): string|\WP_Error' => 'Retention must expose a typed atomic lock acquisition path.',
    'AtomicOptionLock::acquire(self::LOCK_OPTION, self::LOCK_SECONDS)' => 'Retention lock must use exact-value atomic acquisition.',
    'AtomicOptionLock::refresh(self::LOCK_OPTION, $token, self::LOCK_SECONDS)' => 'Retention must renew ownership before destructive phases.',
    "'spcrc_retention_locked'" => 'Lock contention must be distinguishable from storage failure.',
    "'spcrc_retention_lock_unavailable'" => 'Lock storage failure must fail closed.',
    'private function releaseLock(string $token): void' => 'Retention must release only through a token-aware path.',
    'AtomicOptionLock::release(self::LOCK_OPTION, $token)' => 'Retention lock release must verify exact ownership.',
    "'retention_lock_lost'" => 'Lost ownership must stop further destructive retention work.',
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
