<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\AntiSurveillancePolicy;
use Sabri\Platform\Security\Policy\IslamicGovernanceCharter;

function c129(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$now = strtotime('2026-08-08T10:00:00Z');
c129(! IslamicGovernanceCharter::annualReviewValid('2020-01-01T00:00:00Z', '2020-12-31T00:00:00Z', $now), 'Expired annual-review window must not remain valid forever.');
c129(! IslamicGovernanceCharter::annualReviewValid('2026-09-01T00:00:00Z', '2027-08-31T00:00:00Z', $now), 'Future review date must not verify current governance.');
c129(IslamicGovernanceCharter::annualReviewValid('2026-01-01T00:00:00Z', '2026-12-31T00:00:00Z', $now), 'Current annual review window must remain valid.');
$stale = AntiSurveillancePolicy::evaluate([
    'uses' => ['security_and_abuse_prevention'],
    'controls' => ['declared_purpose','data_minimization','bounded_retention','access_control','user_notice','user_choice_or_valid_basis','deletion_reconciliation','vendor_purpose_binding'],
    'evidence_ref' => 'evidence:privacy-old',
    'reviewed_at' => '2020-01-01T00:00:00Z',
    'next_review_at' => '2020-12-31T00:00:00Z',
], $now);
c129(empty($stale['processing_allowed']) && empty($stale['annual_review_valid']), 'Anti-surveillance processing must block after governance review expiry.');

echo "PASS: cycle129 annual governance-review expiry defect fixed and retested\n";
