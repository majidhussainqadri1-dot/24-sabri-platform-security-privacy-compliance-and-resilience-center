<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
use Sabri\Platform\Security\Security\UploadPolicy;
function c133(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }
$now = strtotime('2026-08-08T10:00:00Z');
$policy = new UploadPolicy();
$hashA = str_repeat('a', 64);
$hashB = str_repeat('b', 64);
$mismatch = $policy->scannerResult(['status'=>'clean','engine'=>'scanner-v1','sha256'=>$hashB,'scanned_at'=>gmdate('c',$now),'evidence_ref'=>'scan:mismatch'], $hashA, $now);
c133(is_wp_error($mismatch) && $mismatch->get_error_code() === 'spcrc_upload_scan_hash_mismatch', 'Clean scan evidence for another file hash must not be reusable.');
$stale = $policy->scannerResult(['status'=>'clean','engine'=>'scanner-v1','sha256'=>$hashA,'scanned_at'=>gmdate('c',$now-(2*DAY_IN_SECONDS)),'evidence_ref'=>'scan:stale'], $hashA, $now);
c133(is_wp_error($stale) && $stale->get_error_code() === 'spcrc_upload_scan_stale', 'Stale scanner evidence must not release quarantine.');
$future = $policy->scannerResult(['status'=>'clean','engine'=>'scanner-v1','sha256'=>$hashA,'scanned_at'=>gmdate('c',$now+3600),'evidence_ref'=>'scan:future'], $hashA, $now);
c133(is_wp_error($future) && $future->get_error_code() === 'spcrc_upload_scan_stale', 'Materially future scanner timestamps must fail closed.');
$valid = $policy->scannerResult(['status'=>'clean','engine'=>'scanner-v1','sha256'=>$hashA,'scanned_at'=>gmdate('c',$now-60),'evidence_ref'=>'scan:valid'], $hashA, $now);
c133(is_array($valid) && ! empty($valid['delivery_allowed']) && ($valid['sha256'] ?? '') === $hashA, 'Fresh clean scan bound to the exact source hash may permit delivery.');
echo "PASS: cycle133 upload scan hash/freshness binding defects fixed and retested\n";
