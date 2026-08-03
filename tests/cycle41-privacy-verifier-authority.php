<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Privacy/PrivacyRequestPolicy.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Privacy/PrivacyVerificationStore.php';

use Sabri\Platform\Security\Privacy\PrivacyVerificationStore;

$assertions = 0;
function expectCycle41(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$store = new PrivacyVerificationStore();
$request = ['requester_user_id' => 21];
$evidence = static fn (string $method, int $verifiedBy, string $basis = 'self'): array => [
    'verification_method' => $method,
    'authority_basis' => $basis,
    'verification_reference' => 'case:cycle41-authority',
    'verified_by_user_id' => $verifiedBy,
    'verified_at' => gmdate('c'),
];

$GLOBALS['current_user_id'] = 7;
$result = $store->validateEvidence($evidence('manual-document-review', 99), $request);
expectCycle41(is_wp_error($result), 'A valid but different user must not be accepted as the manual verifier.');
expectCycle41($result->get_error_code() === 'spcrc_privacy_verifier_forbidden', 'Verifier impersonation must return the dedicated authorization error.');

$result = $store->validateEvidence($evidence('manual-document-review', 7), $request);
expectCycle41(is_array($result), 'The current capable privacy operator may attest manual review.');
expectCycle41(($result['verified_by_user_id'] ?? 0) === 7, 'Stored verifier identity must equal the authenticated actor.');

unset($GLOBALS['current_user_caps']['spcrc_manage_privacy_requests']);
$result = $store->validateEvidence($evidence('manual-document-review', 7), $request);
expectCycle41(is_wp_error($result) && $result->get_error_code() === 'spcrc_privacy_verifier_forbidden', 'Manual review without the privacy-management capability must fail closed.');

$request = ['requester_user_id' => 7];
$result = $store->validateEvidence($evidence('authenticated-session', 7), $request);
expectCycle41(is_array($result), 'Authenticated-session self-verification remains bound to the current requester without operator privilege.');

$GLOBALS['current_user_caps']['spcrc_manage_privacy_requests'] = true;
add_filter('spcrc/privacy_verification_confirmed', static fn (): bool => true, 10, 7);
$result = $store->validateEvidence($evidence('email-confirmed', 7), ['requester_user_id' => 21]);
expectCycle41(is_array($result), 'A capable current operator plus native confirmation may attest a non-manual method.');

$GLOBALS['current_user_id'] = 8;
$result = $store->validateEvidence($evidence('email-confirmed', 7), ['requester_user_id' => 21]);
expectCycle41(is_wp_error($result) && $result->get_error_code() === 'spcrc_privacy_verifier_forbidden', 'Confirmed evidence must still reject verifier identity mismatch.');

printf("PASS: %d Cycle 41 privacy-verifier authority assertions\n", $assertions);
