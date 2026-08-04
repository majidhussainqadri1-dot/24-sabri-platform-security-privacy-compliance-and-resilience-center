<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Policy;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Support\Sanitizer;

/** Versioned policy hierarchy and exception registry. */
final class GovernancePolicyService
{
    private const LEVELS = [
        'master-plan' => 10,
        'security-charter' => 20,
        'privacy-data-governance' => 30,
        'compliance-applicability' => 40,
        'control-catalog' => 50,
        'module-contract' => 60,
        'procedure' => 70,
        'configuration' => 80,
        'evidence' => 90,
    ];

    public function __construct(private GovernedArtifactRegistry $artifacts)
    {
    }

    /** @return string|\WP_Error */
    public function savePolicy(array $data): string|\WP_Error
    {
        $level = Sanitizer::key($data['hierarchy_level'] ?? '', 80);
        if (! isset(self::LEVELS[$level])) {
            return new \WP_Error('spcrc_policy_hierarchy_invalid', 'A supported policy hierarchy level is required.');
        }
        $version = Sanitizer::text($data['policy_version'] ?? '', 40);
        if ($version === '' || preg_match('/^[0-9]+(?:\.[0-9]+){0,3}(?:-[a-z0-9.-]+)?$/i', $version) !== 1) {
            return new \WP_Error('spcrc_policy_version_invalid', 'A bounded semantic policy version is required.');
        }
        $status = Sanitizer::key($data['status'] ?? 'draft', 30);
        $evidenceRef = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        if ($status === 'approved' && ($evidenceRef === '' || Sanitizer::isoTime($data['reviewed_at'] ?? '') === '' || Sanitizer::isoTime($data['next_review_at'] ?? '') === '')) {
            return new \WP_Error('spcrc_policy_approval_evidence_missing', 'Approved policy requires review, next-review and evidence references.');
        }
        $parentKey = Sanitizer::key($data['parent_policy_key'] ?? '', 120);
        if ($parentKey !== '') {
            $parent = $this->artifacts->get('policy', $parentKey);
            if (! is_array($parent)) {
                return new \WP_Error('spcrc_policy_parent_missing', 'Parent policy is not registered.');
            }
            $parentPayload = is_array($parent['payload'] ?? null) ? $parent['payload'] : [];
            $parentLevel = Sanitizer::key($parentPayload['hierarchy_level'] ?? '', 80);
            if (! isset(self::LEVELS[$parentLevel]) || self::LEVELS[$parentLevel] >= self::LEVELS[$level]) {
                return new \WP_Error('spcrc_policy_parent_hierarchy_invalid', 'Parent policy must be higher in the approved hierarchy.');
            }
        }
        return $this->artifacts->save([
            'artifact_type' => 'policy',
            'artifact_key' => $data['policy_key'] ?? '',
            'title' => $data['title'] ?? '',
            'status' => $status,
            'classification' => $data['classification'] ?? 'C1',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $evidenceRef,
            'effective_at' => $data['effective_at'] ?? '',
            'expires_at' => $data['expires_at'] ?? '',
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'hierarchy_level' => $level,
                'hierarchy_rank' => self::LEVELS[$level],
                'policy_version' => $version,
                'parent_policy_key' => $parentKey,
                'standards' => Sanitizer::textList($data['standards'] ?? [], 30, 100),
                'owner_role' => Sanitizer::key($data['owner_role'] ?? '', 80),
                'change_record_ref' => Sanitizer::opaqueReference($data['change_record_ref'] ?? ''),
            ],
        ]);
    }

    /** @return string|\WP_Error */
    public function saveException(array $data): string|\WP_Error
    {
        $status = Sanitizer::key($data['status'] ?? 'requested', 30);
        $expiresAt = Sanitizer::isoTime($data['expires_at'] ?? '');
        $evidenceRef = Sanitizer::opaqueReference($data['evidence_ref'] ?? '');
        if ($status === 'approved' && ($expiresAt === '' || $evidenceRef === '')) {
            return new \WP_Error('spcrc_exception_approval_invalid', 'Approved exception requires expiry and private evidence reference.');
        }
        if ($expiresAt !== '' && strtotime($expiresAt) <= time()) {
            return new \WP_Error('spcrc_exception_expiry_invalid', 'Exception expiry must be in the future.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'exception',
            'artifact_key' => $data['exception_key'] ?? '',
            'title' => $data['title'] ?? '',
            'status' => $status,
            'classification' => 'C4',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $evidenceRef,
            'expires_at' => $expiresAt,
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'policy_key' => Sanitizer::key($data['policy_key'] ?? '', 120),
                'scope' => Sanitizer::text($data['scope'] ?? '', 300),
                'compensating_controls' => Sanitizer::textList($data['compensating_controls'] ?? [], 30, 120),
                'requester_user_id' => absint($data['requester_user_id'] ?? get_current_user_id()),
                'approver_user_id' => absint($data['approver_user_id'] ?? 0),
            ],
        ]);
    }

    /** @return array<string,int> */
    public static function hierarchy(): array
    {
        return self::LEVELS;
    }
}
