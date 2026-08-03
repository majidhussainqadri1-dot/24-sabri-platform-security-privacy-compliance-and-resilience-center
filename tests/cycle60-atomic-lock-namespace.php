<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Support\AtomicOptionLock;
$result = AtomicOptionLock::acquire('foreign_lock', 30);
cycleReviewAssert(is_wp_error($result), 'Locks outside the File 24 namespace must be rejected.');
cycleReviewAssert($result->get_error_code() === 'spcrc_atomic_lock_invalid', 'Invalid lock namespace must be explicit.');
cycleReviewAssert(! isset($GLOBALS['wp_options']['foreign_lock']), 'Foreign option must not be mutated.');

cycleReviewPass(60, 'atomic-lock-namespace');
