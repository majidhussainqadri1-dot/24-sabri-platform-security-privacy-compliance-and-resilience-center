<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\AIHomeopathyTeacherAssurance;
use Sabri\Platform\Security\Policy\AntiSurveillancePolicy;
use Sabri\Platform\Security\Policy\BoundaryPolicyCatalog;
use Sabri\Platform\Security\Policy\GovernancePolicyService;
use Sabri\Platform\Security\Policy\IslamicGovernanceCharter;
use Sabri\Platform\Security\Policy\RankingFairnessPolicy;
use Sabri\Platform\Security\Registry\ChatDirectiveCatalog;
use Sabri\Platform\Security\Registry\PlatformIntegrationMatrix;
use Sabri\Platform\Security\Release\ReleaseStatus;
use Sabri\Platform\Security\Security\TransferDownloadAssurance;

$count = 0;
function c110(bool $condition, string $message): void { global $count; ++$count; if (! $condition) { fwrite(STDERR, "FAIL: $message\n"); exit(1); } }

c110(ChatDirectiveCatalog::count() === 18, 'All-Chats File 24 directive catalogue must contain the frozen 18-directive subset.');
c110(ChatDirectiveCatalog::repositoryCodingComplete(), 'Every directive must have source, owner, assurance implementation and repository status.');
c110(ChatDirectiveCatalog::get('CHAT-INT-026') !== null, 'File 26 integration directive must be traceable.');
c110(ChatDirectiveCatalog::get('CHAT-XFER-001') !== null, 'Verified one-GiB transfer directive must be traceable.');

c110(PlatformIntegrationMatrix::complete(), 'Files 00–26 matrix must be contiguous and complete.');
c110(count(PlatformIntegrationMatrix::all()) === 27, 'File matrix must include 27 permanent numbered files.');
$file13 = PlatformIntegrationMatrix::get(13) ?? [];
$file20 = PlatformIntegrationMatrix::get(20) ?? [];
$file25 = PlatformIntegrationMatrix::get(25) ?? [];
$file26 = PlatformIntegrationMatrix::get(26) ?? [];
c110(str_contains((string) ($file13['native_owner'] ?? ''), 'legacy compatibility only'), 'File 13 must no longer own the welcome experience.');
c110(str_contains((string) ($file20['native_owner'] ?? ''), 'welcome invocation/frequency'), 'File 20 must own welcome invocation and frequency.');
c110(str_contains((string) ($file25['native_owner'] ?? ''), 'welcome visual/RTL/accessibility'), 'File 25 must own welcome visual, RTL and accessibility.');
c110(($file26['criticality'] ?? '') === 'high-risk' && ($file26['contract_filter'] ?? '') === 'spcrc/file26_contract_state', 'File 26 must be a high-risk versioned integration.');

$now = strtotime('2026-08-05T10:00:00Z');
$hierarchy = GovernancePolicyService::hierarchy();
c110(($hierarchy['islamic-supremacy-charter'] ?? 99) === 0, 'Islamic Supremacy Charter must be the highest policy level.');
c110(($hierarchy['master-plan'] ?? 0) > ($hierarchy['islamic-supremacy-charter'] ?? 99), 'Master Plan must remain subordinate to the Islamic charter.');
c110(IslamicGovernanceCharter::annualReviewValid('2026-01-01T00:00:00Z', '2026-12-31T00:00:00Z', $now), 'Charter review within twelve months must be valid.');
c110(! IslamicGovernanceCharter::annualReviewValid('2026-01-01T00:00:00Z', '2027-02-01T00:00:00Z', $now), 'Charter review beyond twelve months must fail.');

$privacy = AntiSurveillancePolicy::evaluate([
    'uses' => ['security_and_abuse_prevention'],
    'controls' => ['declared_purpose', 'data_minimization', 'bounded_retention', 'access_control', 'user_notice', 'user_choice_or_valid_basis', 'deletion_reconciliation', 'vendor_purpose_binding'],
    'evidence_ref' => 'vault:privacy-policy-2026',
    'reviewed_at' => '2026-01-01T00:00:00Z',
    'next_review_at' => '2026-12-31T00:00:00Z',
], $now);
c110(($privacy['state'] ?? '') === 'verified', 'Purpose-bound minimized processing must pass anti-surveillance assurance.');
$privacyBlocked = AntiSurveillancePolicy::evaluate([
    'uses' => ['hidden_profiling'],
    'controls' => ['declared_purpose'],
    'evidence_ref' => 'vault:bad-purpose',
    'reviewed_at' => '2026-01-01T00:00:00Z',
    'next_review_at' => '2026-12-31T00:00:00Z',
], $now);
c110(($privacyBlocked['processing_allowed'] ?? true) === false, 'Hidden profiling must be blocked.');

$ranking = RankingFairnessPolicy::evaluate([
    'controls' => ['file26_owner_contract', 'versioned_policy', 'explainability', 'audit_log', 'appeal_path', 'manipulation_resistance', 'verified_review_weighting', 'monthly_recomputation', 'donation_independence', 'payment_independence', 'founder_non_favoritism'],
    'influences' => ['qualifications', 'experience', 'verified_reviews', 'knowledge_contribution'],
    'policy_version' => '1.0.0',
    'evidence_ref' => 'vault:ranking-evaluation-1',
    'tested_at' => '2026-08-05T09:00:00Z',
    'recomputed_at' => '2026-08-01T00:00:00Z',
], $now);
c110(($ranking['state'] ?? '') === 'verified', 'Versioned and recent money-independent ranking evidence must pass.');
$rankingPaid = RankingFairnessPolicy::evaluate([
    'controls' => ['file26_owner_contract'],
    'influences' => ['donation'],
    'policy_version' => '1.0.0',
    'evidence_ref' => 'vault:ranking-bad',
    'tested_at' => '2026-08-05T09:00:00Z',
    'recomputed_at' => '2026-08-01T00:00:00Z',
], $now);
c110(in_array('donation', $rankingPaid['forbidden_influences'] ?? [], true), 'Donation influence must be detected and blocked.');

$ai = AIHomeopathyTeacherAssurance::evaluate([
    'controls' => ['institutional_ai_identity', 'visible_ai_disclosure', 'corpus_allowlist', 'retrieval_acl', 'source_citations', 'prompt_injection_defense', 'medical_review', 'shariah_review', 'budget_cap', 'provider_failure_fallback', 'deletion_propagation', 'file26_classification_contract'],
    'identity_type' => 'institutional-ai',
    'launch_at' => '2026-08-01T00:00:00Z',
    'human_review_enabled' => true,
    'daily_post_cap' => 4,
    'evidence_ref' => 'vault:ai-teacher-launch-1',
    'tested_at' => '2026-08-05T09:00:00Z',
], $now);
c110(($ai['state'] ?? '') === 'verified', 'AI Teacher with disclosure, four-post cap and initial human review must pass.');

$transferControls = ['verified_sender', 'authorized_recipient', 'sender_recipient_binding', 'purpose_binding', 'relationship_recheck', 'consent_recheck', 'multipart_or_chunked', 'pause_resume', 'interruption_recovery', 'checksum', 'mime_magic_validation', 'malware_scan', 'archive_bomb_scan', 'polyglot_scan', 'private_storage', 'short_lived_delivery_grant', 'expiry', 'revocation', 'audit'];
$transfer = TransferDownloadAssurance::evaluateTransfer([
    'controls' => $transferControls,
    'max_bytes_per_file' => TransferDownloadAssurance::VERIFIED_TRANSFER_MAX_BYTES,
    'evidence_ref' => 'vault:transfer-assurance-1',
    'tested_at' => '2026-08-05T09:00:00Z',
], $now);
c110(($transfer['state'] ?? '') === 'verified', 'Verified-user one-GiB resumable transfer assurance must pass complete evidence.');

$downloadControls = ['native_owner_eligibility', 'queue', 'progress', 'pause_resume', 'retry', 'checksum', 'range_requests', 'weak_connection_recovery', 'click_time_authorization', 'history', 'audit', 'expiry', 'revocation'];
$download = TransferDownloadAssurance::evaluateDownload([
    'controls' => $downloadControls,
    'evidence_ref' => 'vault:download-assurance-1',
    'tested_at' => '2026-08-05T09:00:00Z',
], $now);
c110(($download['state'] ?? '') === 'verified', 'Universal eligible download assurance must pass complete evidence.');

c110(count(BoundaryPolicyCatalog::all()) === 11, 'Boundary catalogue must include five new All-Chats domains.');
foreach (['privacy-anti-surveillance', 'ranking', 'ai-teacher', 'file-transfer', 'download'] as $domain) {
    c110(BoundaryPolicyCatalog::get($domain) !== null, 'Missing All-Chats boundary domain: ' . $domain);
}
c110(ReleaseStatus::repositoryCodingComplete(), 'Three-plan repository coding status must include the new directive, matrix and boundary gates.');
c110(! ReleaseStatus::productionReady(), 'Repository harmonization must not falsely assert staging or production readiness.');

echo "PASS: $count Cycle 110 three-plan harmonization assertions\n";
