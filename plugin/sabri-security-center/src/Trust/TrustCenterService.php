<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Trust;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Support\Sanitizer;

/** Supplies evidence-gated, public-safe facts; File 25 owns presentation. */
final class TrustCenterService
{
    private const ALLOWED_CLAIMS = [
        'privacy-notice', 'security-overview', 'responsible-disclosure',
        'rights-request', 'cookie-information', 'approved-subprocessor',
        'accessibility-commitment', 'certification',
    ];
    private const CLOCK_SKEW_SECONDS = 300;

    public function __construct(private GovernedArtifactRegistry $artifacts)
    {
    }

    /** @return string|\WP_Error */
    public function saveClaim(array $data): string|\WP_Error
    {
        $claimType = Sanitizer::key($data['claim_type'] ?? '', 80);
        if (! in_array($claimType, self::ALLOWED_CLAIMS, true)) {
            return new \WP_Error('spcrc_trust_claim_type_invalid', 'Trust claim type is not approved for public presentation.');
        }

        $claimKey = Sanitizer::key($data['claim_key'] ?? $claimType, 120);
        $status = Sanitizer::key($data['status'] ?? 'draft', 30);
        $expectedVersion = absint($data['expected_version'] ?? 0);
        $existing = $claimKey !== '' ? $this->artifacts->get('trust-claim', $claimKey) : null;
        $existingPayload = is_array($existing['payload'] ?? null) ? $existing['payload'] : [];
        $actor = get_current_user_id();
        if ($actor < 1) {
            return new \WP_Error('spcrc_trust_claim_actor_invalid', 'Trust Center changes require an authenticated attributable actor.');
        }

        $evidenceRef = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        $expiresAt = Sanitizer::isoTime($data['expires_at'] ?? '');
        $reviewedAt = Sanitizer::isoTime($data['reviewed_at'] ?? '');

        if ($status === 'verified') {
            if (! current_user_can('spcrc_approve_governance_decision')) {
                return new \WP_Error('spcrc_trust_claim_approval_forbidden', 'Verified public claims require independent governance approval authority.');
            }
            if (! is_array($existing) || ! in_array(($existing['status'] ?? ''), ['draft', 'expired'], true)) {
                return new \WP_Error('spcrc_trust_claim_workflow_invalid', 'A verified public claim must approve an existing draft or expired claim.');
            }
            $owner = absint($existing['owner_user_id'] ?? 0);
            if ($owner < 1) {
                return new \WP_Error('spcrc_trust_claim_author_invalid', 'A verified public claim requires an attributable draft author or latest material editor.');
            }
            if ($owner === $actor) {
                return new \WP_Error('spcrc_trust_claim_self_approval_forbidden', 'The claim author or latest material editor cannot approve the same public claim.');
            }
            if ($expectedVersion < 1) {
                return new \WP_Error('spcrc_trust_claim_expected_version_required', 'Trust claim approval requires the exact current draft version.');
            }
            if (Sanitizer::key($existingPayload['claim_type'] ?? '', 80) !== $claimType) {
                return new \WP_Error('spcrc_trust_claim_identity_changed', 'Claim type cannot be changed during approval.');
            }
            $submittedTitle = Sanitizer::text($data['title'] ?? '', 200);
            $submittedSummary = Sanitizer::text($data['summary'] ?? '', 500);
            if (($submittedTitle !== '' && $submittedTitle !== Sanitizer::text($existing['title'] ?? '', 200))
                || ($submittedSummary !== '' && $submittedSummary !== Sanitizer::text($existingPayload['summary'] ?? '', 500))
            ) {
                return new \WP_Error('spcrc_trust_claim_content_changed', 'Claim content cannot be rewritten during independent approval.');
            }
            if ($evidenceRef === '' || $expiresAt === '' || $reviewedAt === '') {
                return new \WP_Error('spcrc_trust_claim_evidence_missing', 'Verified public claims require evidence, a completed review and an expiry.');
            }
            $now = time();
            $reviewedTimestamp = strtotime($reviewedAt);
            $expiresTimestamp = strtotime($expiresAt);
            if ($reviewedTimestamp === false || $expiresTimestamp === false
                || $reviewedTimestamp > $now + self::CLOCK_SKEW_SECONDS
                || $expiresTimestamp <= $now
                || $expiresTimestamp <= $reviewedTimestamp
            ) {
                return new \WP_Error('spcrc_trust_claim_time_window_invalid', 'Verified public claims require a completed non-future review and a future expiry after that review.');
            }
        } elseif (! current_user_can('spcrc_manage_trust_center')) {
            return new \WP_Error('spcrc_trust_claim_forbidden', 'Trust Center claims require explicit management authority.');
        }

        $independent = $status === 'verified'
            ? Sanitizer::boolean($existingPayload['independent'] ?? false)
            : Sanitizer::boolean($data['independent'] ?? false);
        if ($claimType === 'certification' && $status === 'verified' && ! $independent) {
            return new \WP_Error('spcrc_trust_certification_independence_missing', 'Certification claims require independent evidence declared in the reviewed draft.');
        }

        // A draft's owner is its latest material author/editor. Otherwise an
        // editor could rewrite another person's draft, preserve the old owner,
        // and then approve their own new wording under a false two-person trail.
        $ownerUserId = $status === 'verified'
            ? absint($existing['owner_user_id'] ?? 0)
            : $actor;
        $payload = $status === 'verified'
            ? [
                'claim_type' => Sanitizer::key($existingPayload['claim_type'] ?? '', 80),
                'summary' => Sanitizer::text($existingPayload['summary'] ?? '', 500),
                'public_url' => '',
                'independent' => $independent,
                'approved_by_user_id' => $actor,
            ]
            : [
                'claim_type' => $claimType,
                'summary' => Sanitizer::text($data['summary'] ?? '', 500),
                'public_url' => '',
                'independent' => $independent,
            ];

        return $this->artifacts->save([
            'artifact_type' => 'trust-claim',
            'artifact_key' => $claimKey,
            'title' => $status === 'verified' ? ($existing['title'] ?? '') : ($data['title'] ?? ''),
            'status' => $status,
            'classification' => 'C0',
            'owner_user_id' => $ownerUserId,
            'evidence_ref' => $evidenceRef,
            'effective_at' => $data['effective_at'] ?? '',
            'expires_at' => $expiresAt,
            'reviewed_at' => $reviewedAt,
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => $payload,
        ], $expectedVersion);
    }

    /** @return array<int,array<string,mixed>> */
    public function publicClaims(): array
    {
        $claims = [];
        $now = time();
        foreach ($this->artifacts->recent('trust-claim', 100) as $record) {
            if (($record['status'] ?? '') !== 'verified' || ($record['classification'] ?? '') !== 'C0') {
                continue;
            }
            $payload = is_array($record['payload'] ?? null) ? $record['payload'] : [];
            $claimType = Sanitizer::key($payload['claim_type'] ?? '', 80);
            if (! in_array($claimType, self::ALLOWED_CLAIMS, true)) {
                continue;
            }
            $reviewed = Sanitizer::isoTime($record['reviewed_at'] ?? '');
            $expires = Sanitizer::isoTime($record['expires_at'] ?? '');
            $evidenceRef = Sanitizer::opaqueReference($record['evidence_ref'] ?? '');
            $reviewedTimestamp = $reviewed === '' ? false : strtotime($reviewed);
            $expiresTimestamp = $expires === '' ? false : strtotime($expires);
            if ($evidenceRef === '' || $reviewedTimestamp === false || $expiresTimestamp === false
                || $reviewedTimestamp > $now + self::CLOCK_SKEW_SECONDS
                || $expiresTimestamp <= $now
                || $expiresTimestamp <= $reviewedTimestamp
            ) {
                continue;
            }
            $owner = absint($record['owner_user_id'] ?? 0);
            $approver = absint($payload['approved_by_user_id'] ?? 0);
            if ($owner < 1 || $approver < 1 || $approver === $owner) {
                continue;
            }
            if ($claimType === 'certification' && ! Sanitizer::boolean($payload['independent'] ?? false)) {
                continue;
            }
            $claims[] = [
                'key' => Sanitizer::key($record['artifact_key'] ?? '', 120),
                'type' => $claimType,
                'title' => Sanitizer::text($record['title'] ?? '', 200),
                'summary' => Sanitizer::text($payload['summary'] ?? '', 500),
                'verified_at' => $reviewed,
                'expires_at' => $expires,
            ];
        }
        return $claims;
    }

    /** @return array<string,mixed> */
    public function payload(): array
    {
        return [
            'platform' => 'Sabri Social Homeopathy Platform',
            'program_status' => 'Repository code-complete candidate; staging and production assurance pending',
            'claims' => $this->publicClaims(),
            'unsupported_claims' => [
                'No claim of unhackable security',
                'No claim of certification without independent evidence',
                'No claim of end-to-end encryption without audited implementation',
            ],
            'generated_at' => gmdate('c'),
        ];
    }
}
