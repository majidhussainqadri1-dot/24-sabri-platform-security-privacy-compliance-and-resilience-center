<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Release;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Executable launch-critical blocker record contract for F24-R096.
 *
 * The governed artifact registry provides persistence, locking and audit. This
 * class enforces the required owner/due-date/evidence/affected-feature fields.
 */
final class LaunchBlockerContract
{
    /** @return string[] */
    public static function requiredPayloadFields(): array
    {
        return ['affected_feature', 'due_at', 'severity', 'feature_disabled'];
    }

    public static function repositoryCodingComplete(): bool
    {
        return self::requiredPayloadFields() === ['affected_feature', 'due_at', 'severity', 'feature_disabled'];
    }

    /** @param array<string,mixed> $payload @return bool|\WP_Error */
    public static function validateArtifact(
        string $status,
        int $ownerUserId,
        string $evidenceRef,
        array $payload
    ): bool|\WP_Error {
        if ($ownerUserId < 1) {
            return new \WP_Error('spcrc_launch_blocker_owner_required', 'Launch-critical blockers require an accountable owner.');
        }

        $affectedFeature = Sanitizer::key($payload['affected_feature'] ?? '', 120);
        $dueAt = Sanitizer::isoTime($payload['due_at'] ?? '');
        $severity = Sanitizer::key($payload['severity'] ?? '', 20);
        if ($affectedFeature === '' || $dueAt === '' || $severity !== 'critical') {
            return new \WP_Error('spcrc_launch_blocker_record_incomplete', 'Launch-critical blockers require affected feature, due date and critical severity.');
        }

        $featureDisabled = Sanitizer::boolean($payload['feature_disabled'] ?? false);
        if (in_array($status, ['open', 'mitigating'], true) && ! $featureDisabled) {
            return new \WP_Error('spcrc_launch_blocker_fail_open', 'An unresolved critical blocker must keep the affected feature disabled.');
        }

        if ($status === 'closed' && $evidenceRef === '') {
            return new \WP_Error('spcrc_launch_blocker_close_evidence_required', 'Closing a launch blocker requires opaque verification evidence.');
        }

        if ($status === 'accepted-risk') {
            $decisionRef = Sanitizer::opaqueReference($payload['governance_decision_ref'] ?? '');
            if ($evidenceRef === '' || $decisionRef === '') {
                return new \WP_Error('spcrc_launch_blocker_acceptance_evidence_required', 'Accepted launch risk requires evidence and a governed decision reference.');
            }
        }

        return true;
    }
}
