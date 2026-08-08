<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Privacy;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Data inventory, processing, consent, transfer, legal-hold and deletion-ledger
 * orchestration. Native modules retain the underlying data.
 */
final class DataGovernanceRegistry
{
    public function __construct(private GovernedArtifactRegistry $artifacts)
    {
    }

    /** @param array<string,mixed> $data @return string|\WP_Error */
    public function registerDataAsset(array $data): string|\WP_Error
    {
        $classification = strtoupper(Sanitizer::text($data['classification'] ?? '', 2));
        $owner = Sanitizer::key($data['native_owner'] ?? '', 120);
        $retention = Sanitizer::key($data['retention_rule'] ?? '', 120);
        if (! in_array($classification, ['C0', 'C1', 'C2', 'C3', 'C4', 'C5'], true) || $owner === '' || $retention === '') {
            return new \WP_Error('spcrc_data_asset_invalid', 'Classification, native owner and retention rule are required.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'data-inventory',
            'artifact_key' => $data['asset_key'] ?? '',
            'title' => $data['title'] ?? '',
            'status' => $data['status'] ?? 'draft',
            'classification' => $classification,
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'module_key' => $owner,
            'evidence_ref' => $data['evidence_ref'] ?? '',
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'native_owner' => $owner,
                'data_subjects' => Sanitizer::textList($data['data_subjects'] ?? [], 20, 80),
                'fields' => Sanitizer::textList($data['fields'] ?? [], 100, 100),
                'storage' => Sanitizer::textList($data['storage'] ?? [], 20, 120),
                'access_roles' => Sanitizer::textList($data['access_roles'] ?? [], 30, 100),
                'retention_rule' => $retention,
                'backup_rule' => Sanitizer::key($data['backup_rule'] ?? '', 120),
                'deletion_method' => Sanitizer::key($data['deletion_method'] ?? '', 120),
            ],
        ], absint($data['expected_version'] ?? 0));
    }

    /** @param array<string,mixed> $data @return string|\WP_Error */
    public function registerProcessingActivity(array $data): string|\WP_Error
    {
        $purpose = Sanitizer::text($data['purpose'] ?? '', 500);
        $nativeOwner = Sanitizer::key($data['native_owner'] ?? '', 120);
        $lawfulBasis = Sanitizer::key($data['lawful_basis'] ?? '', 80);
        if ($purpose === '' || $nativeOwner === '' || $lawfulBasis === '') {
            return new \WP_Error('spcrc_processing_activity_invalid', 'Purpose, native owner and lawful basis are required.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'processing-activity',
            'artifact_key' => $data['activity_key'] ?? '',
            'title' => $data['title'] ?? '',
            'status' => $data['status'] ?? 'draft',
            'classification' => $data['classification'] ?? 'C2',
            'module_key' => $nativeOwner,
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $data['evidence_ref'] ?? '',
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'purpose' => $purpose,
                'subjects' => Sanitizer::textList($data['subjects'] ?? [], 20, 80),
                'fields' => Sanitizer::textList($data['fields'] ?? [], 100, 100),
                'source' => Sanitizer::key($data['source'] ?? '', 120),
                'destinations' => Sanitizer::textList($data['destinations'] ?? [], 30, 120),
                'native_owner' => $nativeOwner,
                'lawful_basis' => $lawfulBasis,
                'consent_category' => Sanitizer::key($data['consent_category'] ?? '', 100),
                'recipients' => Sanitizer::textList($data['recipients'] ?? [], 30, 120),
                'regions' => Sanitizer::textList($data['regions'] ?? [], 30, 80),
                'retention_rule' => Sanitizer::key($data['retention_rule'] ?? '', 120),
                'deletion_route' => Sanitizer::key($data['deletion_route'] ?? '', 120),
                'dpia_status' => Sanitizer::key($data['dpia_status'] ?? 'not-assessed', 40),
            ],
        ], absint($data['expected_version'] ?? 0));
    }

    /** @param array<string,mixed> $data @return string|\WP_Error */
    public function recordConsent(array $data): string|\WP_Error
    {
        $category = Sanitizer::key($data['category'] ?? '', 100);
        $purpose = Sanitizer::key($data['purpose'] ?? '', 100);
        $noticeVersion = Sanitizer::text($data['notice_version'] ?? '', 40);
        $subjectRef = Sanitizer::opaqueReference($data['subject_ref'] ?? '');
        if ($category === '' || $purpose === '' || $noticeVersion === '' || $subjectRef === '') {
            return new \WP_Error('spcrc_consent_identity_invalid', 'Consent category, purpose, notice version and opaque subject reference are required.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'consent',
            'artifact_key' => $data['consent_key'] ?? '',
            'title' => $data['title'] ?? 'Consent record',
            'status' => $data['status'] ?? 'recorded',
            'classification' => 'C3',
            'module_key' => $data['module_key'] ?? 'file-00-membership',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $data['evidence_ref'] ?? '',
            'effective_at' => $data['recorded_at'] ?? gmdate('c'),
            'expires_at' => $data['expires_at'] ?? '',
            'payload' => [
                'category' => $category,
                'purpose' => $purpose,
                'notice_version' => $noticeVersion,
                'language' => Sanitizer::key($data['language'] ?? 'en-US', 20),
                'method' => Sanitizer::key($data['method'] ?? '', 60),
                'subject_ref' => $subjectRef,
                'guardian_ref' => Sanitizer::opaqueReference($data['guardian_ref'] ?? ''),
                'withdrawal_route' => Sanitizer::key($data['withdrawal_route'] ?? '', 120),
            ],
        ], absint($data['expected_version'] ?? 0));
    }

    /** @param array<string,mixed> $data @return string|\WP_Error */
    public function recordLegalHold(array $data): string|\WP_Error
    {
        $scope = Sanitizer::textList($data['scope'] ?? [], 50, 120);
        if ($scope === []) {
            return new \WP_Error('spcrc_legal_hold_scope_missing', 'A category-specific legal-hold scope is required.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'legal-hold',
            'artifact_key' => $data['hold_key'] ?? '',
            'title' => $data['title'] ?? '',
            'status' => $data['status'] ?? 'requested',
            'classification' => 'C5',
            'module_key' => $data['module_key'] ?? 'file-24-security-center',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $data['evidence_ref'] ?? '',
            'effective_at' => $data['effective_at'] ?? '',
            'expires_at' => $data['expires_at'] ?? '',
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'scope' => $scope,
                'authority_basis' => Sanitizer::key($data['authority_basis'] ?? '', 100),
                'subject_ref' => Sanitizer::opaqueReference($data['subject_ref'] ?? ''),
                'preservation_ref' => Sanitizer::opaqueReference($data['preservation_ref'] ?? ''),
            ],
        ], absint($data['expected_version'] ?? 0));
    }

    /** @param array<string,mixed> $data @return string|\WP_Error */
    public function recordTransfer(array $data): string|\WP_Error
    {
        $origin = Sanitizer::text($data['origin_region'] ?? '', 80);
        $destination = Sanitizer::text($data['destination_region'] ?? '', 80);
        $vendorRef = Sanitizer::opaqueReference($data['vendor_ref'] ?? '');
        $classes = array_values(array_unique(array_map('strtoupper', Sanitizer::textList($data['data_classes'] ?? [], 6, 2))));
        if ($origin === '' || $destination === '' || $vendorRef === '' || $classes === []) {
            return new \WP_Error('spcrc_transfer_invalid', 'Origin, destination, vendor reference and data classes are required.');
        }
        foreach ($classes as $dataClass) {
            if (! in_array($dataClass, ['C0', 'C1', 'C2', 'C3', 'C4', 'C5'], true)) {
                return new \WP_Error('spcrc_transfer_data_class_invalid', 'International transfers require recognized C0-C5 data classifications.');
            }
        }
        $locationAssurance = Sanitizer::key($data['location_assurance'] ?? '', 40);
        if (array_intersect($classes, ['C4', 'C5']) !== [] && $locationAssurance !== 'verified') {
            return new \WP_Error('spcrc_transfer_restricted_location_unknown', 'C4/C5 data cannot be transferred to an unverified provider location.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'processing-activity',
            'artifact_key' => $data['transfer_key'] ?? '',
            'title' => $data['title'] ?? 'International transfer assessment',
            'status' => $data['status'] ?? 'under-review',
            'classification' => in_array('C5', $classes, true) ? 'C5' : (in_array('C4', $classes, true) ? 'C4' : 'C3'),
            'module_key' => $data['module_key'] ?? 'file-24-security-center',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $data['evidence_ref'] ?? '',
            'reviewed_at' => $data['reviewed_at'] ?? '',
            'next_review_at' => $data['next_review_at'] ?? '',
            'payload' => [
                'record_kind' => 'international-transfer',
                'origin_region' => $origin,
                'destination_region' => $destination,
                'vendor_ref' => $vendorRef,
                'data_classes' => $classes,
                'purpose' => Sanitizer::text($data['purpose'] ?? '', 500),
                'mechanism' => Sanitizer::key($data['mechanism'] ?? '', 100),
                'encryption_assurance' => Sanitizer::key($data['encryption_assurance'] ?? '', 60),
                'onward_transfer' => Sanitizer::boolean($data['onward_transfer'] ?? false),
                'deletion_plan_ref' => Sanitizer::opaqueReference($data['deletion_plan_ref'] ?? ''),
                'exit_plan_ref' => Sanitizer::opaqueReference($data['exit_plan_ref'] ?? ''),
                'location_assurance' => $locationAssurance,
            ],
        ], absint($data['expected_version'] ?? 0));
    }

    /** @param array<string,mixed> $data @return string|\WP_Error */
    public function recordDeletionObligation(array $data): string|\WP_Error
    {
        $moduleKey = Sanitizer::key($data['module_key'] ?? '', 120);
        $subjectRef = Sanitizer::opaqueReference($data['subject_ref'] ?? '');
        $requestRef = Sanitizer::opaqueReference($data['request_ref'] ?? '');
        if ($moduleKey === '' || $subjectRef === '' || $requestRef === '') {
            return new \WP_Error('spcrc_deletion_ledger_invalid', 'Module, subject and privacy-request references are required.');
        }
        return $this->artifacts->save([
            'artifact_type' => 'deletion-ledger',
            'artifact_key' => $data['ledger_key'] ?? '',
            'title' => $data['title'] ?? 'Cross-file deletion obligation',
            'status' => $data['status'] ?? 'pending',
            'classification' => 'C4',
            'module_key' => $moduleKey,
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $data['evidence_ref'] ?? '',
            'payload' => [
                'module_key' => $moduleKey,
                'subject_ref' => $subjectRef,
                'request_ref' => $requestRef,
                'deletion_scope' => Sanitizer::textList($data['deletion_scope'] ?? [], 50, 100),
                'attempts' => absint($data['attempts'] ?? 0),
                'next_retry_at' => Sanitizer::isoTime($data['next_retry_at'] ?? ''),
                'last_error_code' => Sanitizer::key($data['last_error_code'] ?? '', 120),
                'legal_hold_ref' => Sanitizer::opaqueReference($data['legal_hold_ref'] ?? ''),
            ],
        ], absint($data['expected_version'] ?? 0));
    }

    public function activeLegalHold(string $holdKey): bool
    {
        $record = $this->artifacts->get('legal-hold', $holdKey);
        return is_array($record)
            && ($record['status'] ?? '') === 'active'
            && (($record['expires_at'] ?? '') === '' || strtotime((string) $record['expires_at']) > time());
    }
}
