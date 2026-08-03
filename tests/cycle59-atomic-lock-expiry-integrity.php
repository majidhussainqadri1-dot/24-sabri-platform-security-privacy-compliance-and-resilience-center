<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Support\AtomicOptionLock;
$GLOBALS['wp_options']['spcrc_cycle59_lock'] = ['token' => str_repeat('a', 32), 'expires_at' => time() + 90000];
$result = AtomicOptionLock::acquire('spcrc_cycle59_lock', 30);
cycleReviewAssert(is_wp_error($result), 'Unbounded future lock expiry must fail closed.');
cycleReviewAssert($result->get_error_code() === 'spcrc_atomic_lock_malformed', 'Unbounded future lock must be classified as malformed.');

cycleReviewPass(59, 'atomic-lock-expiry-integrity');
