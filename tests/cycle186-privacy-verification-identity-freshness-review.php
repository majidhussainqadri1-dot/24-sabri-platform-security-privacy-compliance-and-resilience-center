<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Privacy\PrivacyVerificationStore;

function c186(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$store = new PrivacyVerificationStore();

$negativeVerifier = $store->validateEvidence([
    'verification_method' => 'manual-document-review',
    'authority_basis' => 'self',
    'verification_reference' => 'case:cycle186-negative-verifier',
    'verified_by_user_id' => -7,
    'verified_at' => gmdate('c'),
], ['requester_user_id' => 21]);
c186(is_wp_error($negativeVerifier) && $negativeVerifier->get_error_code() === 'spcrc_privacy_verification_evidence_invalid', 'Negative verifier ID must fail structural validation rather than become user 7.');

$negativeRequester = $store->validateEvidence([
    'verification_method' => 'authenticated-session',
    'authority_basis' => 'self',
    'verification_reference' => 'session:cycle186-requester',
    'verified_by_user_id' => 7,
    'verified_at' => gmdate('c'),
], ['requester_user_id' => -7]);
c186(is_wp_error($negativeRequester) && $negativeRequester->get_error_code() === 'spcrc_privacy_verifier_forbidden', 'Negative requester ID must not be absint-coerced into the current authenticated user.');

add_filter('spcrc/privacy_verification_confirmed', static fn (): bool => true, 10, 7);
$emailEvidence = $store->validateEvidence([
    'verification_method' => 'email-confirmed',
    'authority_basis' => 'self',
    'verification_reference' => 'email:cycle186-confirmed',
    'verified_by_user_id' => 7,
    'verified_at' => gmdate('c', time() - 7200),
], ['requester_user_id' => 21]);
c186(is_array($emailEvidence), 'Two-hour-old confirmed-email evidence must use the intended one-day freshness window, not the stale obsolete method-name fallback.');

add_filter('spcrc/privacy_verification_maximum_age', static fn (): string => '86400seconds', 99, 2);
$freshSession = $store->validateEvidence([
    'verification_method' => 'authenticated-session',
    'authority_basis' => 'self',
    'verification_reference' => 'session:cycle186-filter',
    'verified_by_user_id' => 7,
    'verified_at' => gmdate('c', time() - 1200),
], ['requester_user_id' => 7]);
c186(is_wp_error($freshSession) && $freshSession->get_error_code() === 'spcrc_privacy_verification_stale', 'Malformed freshness-policy filter output must not be integer-coerced into a looser verification window.');

$storeSource = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Privacy/PrivacyVerificationStore.php');
$policySource = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Privacy/PrivacyRequestPolicy.php');
c186(str_contains($storeSource, "'email-confirmed' => self::DAY_SECONDS") && str_contains($storeSource, 'Sanitizer::strictInteger'), 'Current verification method names and strict verifier parsing must remain encoded.');
c186(! str_contains($policySource, "absint(\$request['requester_user_id']") && ! str_contains($policySource, "absint(\$request['verified_by_user_id']"), 'Privacy request policy must not coercively reinterpret requester or verifier identities.');

echo "PASS: cycle186 privacy verifier identity-coercion and stale method-freshness mapping defects fixed and retested\n";
