<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Support\AtomicOptionLock;
$GLOBALS['wp_options']['spcrc_cycle58_lock'] = ['token' => 'bad', 'expires_at' => time() + 30];
$result = AtomicOptionLock::acquire('spcrc_cycle58_lock', 30);
cycleReviewAssert(is_wp_error($result), 'Malformed persisted owner token must fail closed.');
cycleReviewAssert($result->get_error_code() === 'spcrc_atomic_lock_malformed', 'Malformed lock must be identified explicitly.');
cycleReviewAssert(isset($GLOBALS['wp_options']['spcrc_cycle58_lock']), 'Malformed lock must not be silently deleted.');

cycleReviewPass(58, 'atomic-lock-token-integrity');
