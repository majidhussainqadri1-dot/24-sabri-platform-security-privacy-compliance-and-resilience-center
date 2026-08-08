<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Security\CryptographyPolicy;

function c141(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$policy = new CryptographyPolicy();
$past = $policy->validate([
    'algorithm' => 'xchacha20-poly1305', 'purpose' => 'master-key',
    'key_ref' => 'key:cycle141', 'key_version' => '7',
    'rotation_due_at' => gmdate('c', time() - 60),
    'recovery_evidence_ref' => 'recovery:cycle141',
]);
c141(is_wp_error($past) && $past->get_error_code() === 'spcrc_crypto_rotation_overdue', 'Already-expired key rotation metadata must not remain approved.');

$future = $policy->validate([
    'algorithm' => 'xchacha20-poly1305', 'purpose' => 'master-key',
    'key_ref' => 'key:cycle141', 'key_version' => '8',
    'rotation_due_at' => gmdate('c', time() + DAY_IN_SECONDS),
    'recovery_evidence_ref' => 'recovery:cycle141',
]);
c141(is_array($future) && ! empty($future['approved']), 'Current cryptographic metadata with future rotation and recovery evidence must pass.');

echo "PASS: cycle141 cryptographic rotation-freshness defect fixed and retested\n";
