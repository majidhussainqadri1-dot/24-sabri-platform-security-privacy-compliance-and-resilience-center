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

    public function __construct(private GovernedArtifactRegistry $artifacts)
    {
    }

    /** @return string|\WP_Error */
    public function saveClaim(array $data): string|\WP_Error
    {
        if (! current_user_can('spcrc_manage_trust_center')) {
            return new \WP_Error('spcrc_trust_claim_forbidden', 'Trust Center claims require explicit management authority.');
        }

        $claimType = Sanitizer::key($data['claim_type'] ?? '', 80);
        if (! in_array($claimType, self::ALLOWED_CLAIMS, true)) {
            return new \WP_Error('spcrc_trust_claim_type_invalid', 'Trust claim type is not approved for public presentation.');
        }
        $status = Sanitizer::key($data['status'] ?? 'draft', 30);
        $evidenceRef = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        $expiresAt = Sanitizer::isoTime($data['expires_at'] ?? '');
        $reviewedAt = Sanitizer::isoTime($data['reviewed_at'] ?? '');

        if ($status === 'verified') {
            if (! current_user_can('spcrc_approve_governance_decision')) {
                return new \WP_Error('spcrc_trust_claim_approval_forbidden', 'Verified public claims require independent governance approval authority.');
            }
            if ($evidenceRef === '' || $expiresAt === '' || $reviewedAt === '') {
                return new \WP_Error('spcrc_trust_claim_evidence_missing', 'Verified public claims require evidence, a completed review and an expiry.');
            }
        }
        if ($claimType === 'certification' && $status === 'verified' && ! Sanitizer::boolean($data['independent'] ?? false)) {
            return new \WP_Error('spcrc_trust_certification_independence_missing', 'Certification claims require independent evidence.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'trust-claim',
            'artifact_key' => $data['claim_key'] ?? $claimType,
            'title' => $data['title'] ?? '',
            'status' => $status,
            'classification' => 'C0',
            'owner_user_id' => get_current_user_id(),
            'evidence_ref' => $evidenceRef,
            'effective_at' => $data['effective_at'] ?? '',
            'expires_at' => $expiresAt,
            'reviewed_at' => $reviewedAt,
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'claim_type' => $claimType,
                'summary' => Sanitizer::text($data['summary'] ?? '', 500),
                'public_url' => '',
                'independent' => Sanitizer::boolean($data['independent'] ?? false),
            ],
        ], absint($data['expected_version'] ?? 0));
    }

    /** @return array<int,array<string,mixed>> */
    public function publicClaims(): array
    {
        $claims = [];
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
            if ($reviewed === '' || $expires === '' || strtotime($expires) <= time()) {
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
