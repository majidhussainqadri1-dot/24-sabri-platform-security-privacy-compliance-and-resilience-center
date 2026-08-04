<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Privacy\PrivacyVerificationStore;
$store=new PrivacyVerificationStore();
$evidence=['verification_method'=>'authenticated-session','authority_basis'=>'self','verification_reference'=>'session:cycle96','verified_by_user_id'=>7,'verified_at'=>gmdate('c',time()-3600)];
$result=$store->validateEvidence($evidence,['requester_user_id'=>7]);
cycleReviewAssert(is_wp_error($result)&&$result->get_error_code()==='spcrc_privacy_verification_stale','Stale authenticated-session evidence must fail closed.');
$evidence['verified_at']=gmdate('c',time()-60);
cycleReviewAssert(is_array($store->validateEvidence($evidence,['requester_user_id'=>7])),'Fresh authenticated-session evidence must remain valid.');


$root = dirname(__DIR__);
$plugin = (string) file_get_contents($root . '/plugin/sabri-security-center/sabri-security-center.php');
$readme = (string) file_get_contents($root . '/plugin/sabri-security-center/readme.txt');
$ci = (string) file_get_contents($root . '/.github/workflows/ci.yml');
cycleReviewAssert(str_contains($plugin, 'Version:     0.99.0') && str_contains($plugin, "define('SPCRC_VERSION', '0.99.0')"), 'Final runtime identity must be 0.99.0.');
cycleReviewAssert(str_contains($readme, 'Stable tag: 0.99.0'), 'WordPress stable tag must match 0.99.0.');
cycleReviewAssert(is_file($root . '/docs/FORTY-ROUND-REVIEW-SUMMARY-0.99.0.md'), 'Forty-round summary must exist.');
cycleReviewAssert(is_file($root . '/docs/RELEASE-RECEIPT-0.99.0.md'), 'Release receipt must exist.');
cycleReviewAssert(is_file($root . '/docs/KNOWN-LIMITATIONS-0.99.0.md'), 'Truthful limitations must exist.');
cycleReviewAssert(is_file($root . '/docs/REQUIREMENTS-TRACEABILITY-0.99.0.md'), 'Requirements traceability must exist.');
cycleReviewAssert(str_contains($ci, 'cycle96-privacy-verification-freshness.php') || str_contains($ci, "find tests -maxdepth 1"), 'Permanent CI must execute the final review boundary.');

cycleReviewPass(96, 'privacy-verification-freshness');
