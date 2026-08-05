<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\AIHomeopathyTeacherAssurance;
use Sabri\Platform\Security\Policy\AntiSurveillancePolicy;
use Sabri\Platform\Security\Policy\BoundaryPolicyCatalog;
use Sabri\Platform\Security\Policy\RankingFairnessPolicy;
use Sabri\Platform\Security\Registry\ChatDirectiveCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Security\TransferDownloadAssurance;

$count = 0;
function c111(bool $condition, string $message): void { global $count; ++$count; if (! $condition) { fwrite(STDERR, "FAIL: $message\n"); exit(1); } }

c111(ChatDirectiveCatalog::get('CHAT-UNKNOWN-999') === null, 'Unknown chat directive must not receive a permissive fallback.');
c111(count(array_unique(ChatDirectiveCatalog::ids())) === ChatDirectiveCatalog::count(), 'Directive IDs must remain unique.');
foreach (ChatDirectiveCatalog::ids() as $id) c111(preg_match('/^CHAT-[A-Z]+-[0-9]{3}$/', $id) === 1, 'Directive ID format invalid: ' . $id);

$evaluated = PlatformIntegrationMatrix::evaluate();
c111(($evaluated[13]['write_allowed'] ?? true) === false, 'Legacy File 13 welcome writes must remain gated until compatibility evidence exists.');
c111(($evaluated[26]['write_allowed'] ?? true) === false, 'Unassessed File 26 ranking/recommendation writes must fail closed.');
c111(($evaluated[24]['write_allowed'] ?? false) === true, 'File 24 native assurance must remain available without becoming a security single point of failure.');

$staleRanking = RankingFairnessPolicy::evaluate([
    'controls' => ['file26_owner_contract', 'versioned_policy', 'explainability', 'audit_log', 'appeal_path', 'manipulation_resistance', 'verified_review_weighting', 'monthly_recomputation', 'donation_independence', 'payment_independence', 'founder_non_favoritism'],
    'influences' => ['qualifications'],
    'policy_version' => '1.0.0',
    'evidence_ref' => 'vault:stale-ranking',
    'tested_at' => '2026-08-05T09:00:00Z',
    'recomputed_at' => '2026-06-01T00:00:00Z',
], strtotime('2026-08-05T10:00:00Z'));
c111(($staleRanking['write_allowed'] ?? true) === false && empty($staleRanking['recomputation_fresh']), 'Stale doctor ranking must fail closed.');

$aiImpersonation = AIHomeopathyTeacherAssurance::evaluate([
    'controls' => ['institutional_ai_identity'],
    'identity_type' => 'verified-doctor',
    'launch_at' => '2026-08-01T00:00:00Z',
    'human_review_enabled' => false,
    'daily_post_cap' => 5,
    'evidence_ref' => 'vault:ai-bad',
    'tested_at' => '2026-08-05T09:00:00Z',
], strtotime('2026-08-05T10:00:00Z'));
c111(($aiImpersonation['publication_allowed'] ?? true) === false, 'AI human/doctor impersonation, excessive cadence and absent launch review must block publication.');
c111(empty($aiImpersonation['identity_valid']) && empty($aiImpersonation['daily_post_cap_valid']) && empty($aiImpersonation['human_review_valid']), 'AI assurance must identify each independent launch defect.');

$oversizeTransfer = TransferDownloadAssurance::evaluateTransfer([
    'controls' => ['verified_sender'],
    'max_bytes_per_file' => TransferDownloadAssurance::VERIFIED_TRANSFER_MAX_BYTES + 1,
    'evidence_ref' => 'vault:oversize',
    'tested_at' => '2026-08-05T09:00:00Z',
]);
c111(($oversizeTransfer['transfer_allowed'] ?? true) === false && empty($oversizeTransfer['one_gib_limit_valid']), 'A transfer larger than one GiB must be blocked.');

$weakDownload = TransferDownloadAssurance::evaluateDownload([
    'controls' => ['queue', 'progress'],
    'evidence_ref' => 'vault:weak-download',
    'tested_at' => '2026-08-05T09:00:00Z',
]);
c111(($weakDownload['download_allowed'] ?? true) === false, 'Download without authorization, checksum, recovery and revocation must fail closed.');
c111(in_array('click_time_authorization', $weakDownload['missing_controls'] ?? [], true), 'Download failure must identify click-time authorization as missing.');

$surveillance = AntiSurveillancePolicy::evaluate([
    'uses' => ['sale_of_personal_data', 'security_log_monetization'],
    'controls' => ['declared_purpose', 'user_notice'],
    'evidence_ref' => 'vault:surveillance-bad',
    'reviewed_at' => '2026-01-01T00:00:00Z',
    'next_review_at' => '2026-12-31T00:00:00Z',
]);
c111(count($surveillance['prohibited_uses_detected'] ?? []) === 2, 'Personal-data sale and security-log monetization must both be detected.');
c111(($surveillance['processing_allowed'] ?? true) === false, 'Prohibited surveillance processing must remain blocked despite partial controls.');

$rankingDomain = BoundaryPolicyCatalog::get('ranking') ?? [];
c111(in_array('donation_boost', $rankingDomain['forbidden_in_general_context'] ?? [], true), 'Ranking boundary must prohibit donation boosts.');
$transferDomain = BoundaryPolicyCatalog::get('file-transfer') ?? [];
c111(in_array('one_gib_per_file_limit', $transferDomain['required_controls'] ?? [], true), 'Transfer boundary must require the one-GiB limit.');
$privacyDomain = BoundaryPolicyCatalog::get('privacy-anti-surveillance') ?? [];
c111(in_array('security_log_monetization', $privacyDomain['forbidden_in_general_context'] ?? [], true), 'Privacy boundary must prohibit security-log monetization.');

$root = dirname(__DIR__);
foreach (['THREE-PLAN-HARMONIZATION-0.99.0.md', 'CHAT-DIRECTIVES-TRACEABILITY-0.99.0.md', 'FILES-00-26-INTEGRATION-MATRIX-0.99.0.md', 'REVIEW-AND-CORRECTION-ALL-CHATS-ROUND-1.md', 'REVIEW-AND-CORRECTION-ALL-CHATS-ROUND-2.md'] as $doc) {
    c111(is_file($root . '/docs/' . $doc), 'Three-plan evidence document missing: ' . $doc);
}

c111(str_contains((string) file_get_contents($root . '/docs/CHAT-DIRECTIVES-TRACEABILITY-0.99.0.md'), 'CHAT-QA-001'), 'Traceability evidence must include the fresh review rule.');
c111(str_contains((string) file_get_contents($root . '/docs/FILES-00-26-INTEGRATION-MATRIX-0.99.0.md'), 'File 26'), 'Integration evidence must include File 26.');

echo "PASS: $count Cycle 111 adversarial three-plan closure assertions\n";
