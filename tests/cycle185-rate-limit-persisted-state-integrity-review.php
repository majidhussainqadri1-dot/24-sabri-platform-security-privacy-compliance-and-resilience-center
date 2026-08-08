<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Security\RateLimiter;

function c185(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$limiter = new RateLimiter();
$salt = wp_salt('auth');
$optionFor = static function (string $scope, string $identifier) use ($salt): string {
    $bucket = substr(hash_hmac('sha256', $scope . '|' . $identifier, $salt), 0, 40);
    return 'spcrc_rate_' . $bucket;
};

$now = time();
$negative = $optionFor('cycle185-negative', 'subject');
$GLOBALS['wp_options'][$negative] = ['window_started' => $now - 1, 'count' => -4, 'expires_at' => $now + 60, 'violations' => 0];
$result = $limiter->check('cycle185-negative', 'subject', 10, 60);
c185(is_wp_error($result) && $result->get_error_code() === 'spcrc_rate_limit_state_invalid', 'Negative persisted count must fail closed instead of lowering effective request usage.');

$malformed = $optionFor('cycle185-malformed', 'subject');
$GLOBALS['wp_options'][$malformed] = ['window_started' => $now - 1, 'count' => '3requests', 'expires_at' => $now + 60, 'violations' => 0];
$result = $limiter->check('cycle185-malformed', 'subject', 10, 60);
c185(is_wp_error($result) && $result->get_error_code() === 'spcrc_rate_limit_state_invalid', 'Malformed persisted counters must not be integer-coerced.');

$violation = $optionFor('cycle185-violation', 'subject');
$GLOBALS['wp_options'][$violation] = ['window_started' => $now - 1, 'count' => 2, 'expires_at' => $now + 60, 'violations' => -9];
$result = $limiter->check('cycle185-violation', 'subject', 10, 60);
c185(is_wp_error($result) && $result->get_error_code() === 'spcrc_rate_limit_state_invalid', 'Negative persisted violation count must not weaken progressive challenge state.');

$chronology = $optionFor('cycle185-chronology', 'subject');
$GLOBALS['wp_options'][$chronology] = ['window_started' => $now - 1, 'count' => 2, 'expires_at' => $now + 90000, 'violations' => 0];
$result = $limiter->check('cycle185-chronology', 'subject', 10, 60);
c185(is_wp_error($result) && $result->get_error_code() === 'spcrc_rate_limit_state_invalid', 'Persisted windows beyond the global maximum must fail closed.');

$expired = $optionFor('cycle185-expired', 'subject');
$GLOBALS['wp_options'][$expired] = ['window_started' => $now - 120, 'count' => 10, 'expires_at' => $now - 60, 'violations' => 4];
$result = $limiter->check('cycle185-expired', 'subject', 10, 60);
c185(! is_wp_error($result) && ($result['allowed'] ?? false) === true && ($result['remaining'] ?? -1) === 9, 'A structurally valid expired window must reinitialize rather than become a permanent denial.');

$source = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Security/RateLimiter.php');
c185(str_contains($source, 'Sanitizer::strictInteger') && str_contains($source, 'spcrc_rate_limit_state_invalid'), 'Strict persisted-state validation must remain encoded in the limiter.');

echo "PASS: cycle185 rate-limit persisted-state coercion and integrity defect fixed and retested\n";
