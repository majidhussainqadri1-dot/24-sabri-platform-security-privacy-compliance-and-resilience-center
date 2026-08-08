<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\AIHomeopathyTeacherAssurance;
use Sabri\Platform\Security\Security\TransferDownloadAssurance;
use Sabri\Platform\Security\Security\UploadPolicy;
use Sabri\Platform\Security\Storage\RiskRepository;
use Sabri\Platform\Security\Support\Sanitizer;

function c149(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

c149(Sanitizer::strictInteger('-5', 1, 5) === null, 'Strict integer parsing must reject a negative score instead of absolute-value coercion.');
c149(Sanitizer::strictInteger('2.5', 1, 5) === null && Sanitizer::strictInteger(2.0, 1, 5) === null, 'Strict integer parsing must reject decimal and float evidence.');
c149(Sanitizer::strictInteger('5', 1, 5) === 5, 'Canonical bounded integer strings must remain valid.');

$risk = (new RiskRepository())->create(['title' => 'Tampered score', 'module_key' => 'file-24-security-center', 'likelihood' => '-5', 'impact' => 4]);
c149(is_wp_error($risk) && $risk->get_error_code() === 'spcrc_risk_score_invalid', 'Risk scoring must not coerce negative likelihood into a high valid score.');

$transferControls = ['verified_sender','authorized_recipient','sender_recipient_binding','purpose_binding','relationship_recheck','consent_recheck','multipart_or_chunked','pause_resume','interruption_recovery','checksum','mime_magic_validation','malware_scan','archive_bomb_scan','polyglot_scan','private_storage','short_lived_delivery_grant','expiry','revocation','audit'];
$transfer = TransferDownloadAssurance::evaluateTransfer([
    'controls' => $transferControls,
    'max_bytes_per_file' => '-1073741824',
    'evidence_ref' => 'evidence:cycle149-transfer',
    'tested_at' => gmdate('c'),
]);
c149(empty($transfer['transfer_allowed']) && empty($transfer['one_gib_limit_valid']), 'Negative transfer-size evidence must not become a valid 1 GiB limit.');

$upload = (new UploadPolicy())->validate([
    'name' => 'image.jpg', 'size' => '-1024', 'declared_mime' => 'image/jpeg',
    'detected_mime' => 'image/jpeg', 'sha256' => str_repeat('a', 64),
], 'private-document');
c149(is_wp_error($upload) && $upload->get_error_code() === 'spcrc_upload_size_invalid', 'Negative upload size must fail rather than being converted to a positive size.');

$aiControls = ['institutional_ai_identity','visible_ai_disclosure','corpus_allowlist','retrieval_acl','source_citations','prompt_injection_defense','medical_review','shariah_review','budget_cap','provider_failure_fallback','deletion_propagation','file26_classification_contract'];
$now = time();
$futureLaunch = AIHomeopathyTeacherAssurance::evaluate([
    'controls' => $aiControls, 'identity_type' => 'institutional-ai', 'human_review_enabled' => true,
    'daily_post_cap' => 4, 'evidence_ref' => 'evidence:cycle149-ai', 'tested_at' => gmdate('c', $now),
    'launch_at' => gmdate('c', $now + 120),
], $now);
c149(empty($futureLaunch['launch_valid']) && empty($futureLaunch['publication_allowed']), 'A launch scheduled minutes in the future must not authorize publication before its launch time.');
$negativeCap = AIHomeopathyTeacherAssurance::evaluate([
    'controls' => $aiControls, 'identity_type' => 'institutional-ai', 'human_review_enabled' => true,
    'daily_post_cap' => '-4', 'evidence_ref' => 'evidence:cycle149-ai-cap', 'tested_at' => gmdate('c', $now),
    'launch_at' => gmdate('c', $now - 60),
], $now);
c149(empty($negativeCap['daily_post_cap_valid']) && empty($negativeCap['publication_allowed']), 'Negative AI cadence must not become a valid posting cap.');

echo "PASS: cycle149 strict numeric and launch-time integrity defects fixed and retested\n";
