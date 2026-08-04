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
        $claimType = Sanitizer::key($data['claim_type'] ?? '', 80);
        if (! in_array($claimType, self::ALLOWED_CLAIMS, true)) {
            return new \WP_Error('spcrc_trust_claim_type_invalid', 'Trust claim type is not approved for public presentation.');
        }
        $status = Sanitizer::key($data['status'] ?? 'draft', 30);
        $evidenceRef = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        if ($status === 'verified' && ($evidenceRef === '' || Sanitizer::isoTime($data['expires_at'] ?? '') === '')) {
            return new \WP_Error('spcrc_trust_claim_evidence_missing', 'Verified public claims require evidence and an expiry.');
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
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $evidenceRef,
            'effective_at' => $data['effective_at'] ?? '',
            'expires_at' => $data['expires_at'] ?? '',
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'claim_type' => $claimType,
                'summary' => Sanitizer::text($data['summary'] ?? '', 500),
                'public_url' => '',
                'independent' => Sanitizer::boolean($data['independent'] ?? false),
            ],
        ]);
    }

    /** @return array<int,array<string,mixed>> */
    public function publicClaims(): array
    {
        $claims = [];
        foreach ($this->artifacts->recent('trust-claim', 100) as $record) {
            if (($record['status'] ?? '') !== 'verified' || ($record['classification'] ?? '') !== 'C0') {
                continue;
            }
            $expires = Sanitizer::isoTime($record['expires_at'] ?? '');
            if ($expires === '' || strtotime($expires) <= time()) {
                continue;
            }
            $payload = is_array($record['payload'] ?? null) ? $record['payload'] : [];
            $claims[] = [
                'key' => Sanitizer::key($record['artifact_key'] ?? '', 120),
                'type' => Sanitizer::key($payload['claim_type'] ?? '', 80),
                'title' => Sanitizer::text($record['title'] ?? '', 200),
                'summary' => Sanitizer::text($payload['summary'] ?? '', 500),
                'verified_at' => Sanitizer::isoTime($record['reviewed_at'] ?? ''),
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
