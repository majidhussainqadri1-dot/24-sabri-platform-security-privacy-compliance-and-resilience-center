<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Incident;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Support\Sanitizer;

/** Coordinates SEV-0–SEV-4 incident workflow without storing forensic payloads. */
final class IncidentCoordinator
{
    private const PLAYBOOKS = [
        'administrator-takeover', 'key-leak', 'patient-breach', 'ransomware',
        'dns-hijack', 'ai-data-leak', 'vendor-breach',
    ];

    public function __construct(
        private IncidentRepository $incidents,
        private GovernedArtifactRegistry $artifacts
    ) {
    }

    /** @return string|\WP_Error */
    public function declare(array $data): string|\WP_Error
    {
        if (! current_user_can('spcrc_manage_incidents')) {
            return new \WP_Error('spcrc_incident_declaration_forbidden', 'Incident declaration requires incident-management authority.');
        }

        $severity = Sanitizer::key($data['severity'] ?? '', 20);
        $playbook = Sanitizer::key($data['playbook'] ?? '', 80);
        if (! in_array($severity, ['sev0', 'sev1', 'sev2', 'sev3', 'sev4'], true)) {
            return new \WP_Error('spcrc_incident_severity_invalid', 'Incident severity must be SEV-0 through SEV-4.');
        }
        if (! in_array($playbook, self::PLAYBOOKS, true)) {
            return new \WP_Error('spcrc_incident_playbook_invalid', 'A supported incident playbook is required.');
        }

        $created = $this->incidents->create([
            'title' => $data['title'] ?? '',
            'severity' => $severity,
            'summary' => $data['summary'] ?? '',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $data['evidence_ref'] ?? '',
        ]);
        if (is_wp_error($created)) {
            return $created;
        }

        $action = $this->artifacts->save([
            'artifact_type' => 'incident-action',
            'artifact_key' => 'declare-' . substr(hash('sha256', $created), 0, 32),
            'title' => 'Incident declaration and command assignment',
            'status' => 'in-progress',
            'classification' => 'C5',
            'owner_user_id' => $data['owner_user_id'] ?? get_current_user_id(),
            'evidence_ref' => $data['evidence_ref'] ?? '',
            'payload' => [
                'incident_uuid' => $created,
                'severity' => $severity,
                'playbook' => $playbook,
                'commander_user_id' => absint($data['commander_user_id'] ?? get_current_user_id()),
                'alternate_commander_user_id' => absint($data['alternate_commander_user_id'] ?? 0),
                'legal_privacy_assessment' => 'pending',
                'out_of_band_channel_ref' => Sanitizer::opaqueReference($data['out_of_band_channel_ref'] ?? ''),
            ],
        ]);
        if (is_wp_error($action)) {
            $this->recordPartialDeclarationGap($created, 'incident_action_creation_failed', $action);
            return new \WP_Error('spcrc_incident_declaration_partial', 'Incident was created but declaration evidence could not be completed.', ['incident_uuid' => $created, 'cause' => $action->get_error_code()]);
        }

        $validated = $this->incidents->transition($created, 'validated', [
            'reason' => 'Incident detection was validated against the selected File 24 playbook.',
            'evidence_ref' => $data['evidence_ref'] ?? '',
        ]);
        if (is_wp_error($validated)) {
            $this->recordPartialDeclarationGap($created, 'incident_validation_transition_failed', $validated);
            return new \WP_Error('spcrc_incident_declaration_partial', 'Incident was created but validation transition could not be completed.', ['incident_uuid' => $created, 'cause' => $validated->get_error_code()]);
        }
        $declared = $this->incidents->transition($created, 'declared', [
            'reason' => 'Incident command, severity and playbook were formally declared.',
            'evidence_ref' => $data['evidence_ref'] ?? '',
        ]);
        if (is_wp_error($declared)) {
            $this->recordPartialDeclarationGap($created, 'incident_declaration_transition_failed', $declared);
            return new \WP_Error('spcrc_incident_declaration_partial', 'Incident was validated but declaration transition could not be completed.', ['incident_uuid' => $created, 'cause' => $declared->get_error_code()]);
        }
        return $created;
    }

    private function recordPartialDeclarationGap(string $incidentUuid, string $reason, \WP_Error $error): void
    {
        AuditGapStore::record('spcrc_incident_audit_gap', 'incident-declaration', $incidentUuid, $reason, [
            'error_code' => $error->get_error_code(),
        ]);
    }

    /** @return bool|\WP_Error */
    public function advance(string $incidentUuid, string $targetStatus, string $reason, string $evidenceRef, array $approvalRefs = []): bool|\WP_Error
    {
        if (! current_user_can('spcrc_manage_incidents')) {
            return new \WP_Error('spcrc_incident_transition_forbidden', 'Incident transition requires incident-management authority.');
        }

        $incident = $this->incidents->get($incidentUuid);
        if (! is_array($incident)) {
            return new \WP_Error('spcrc_incident_not_found', 'Incident could not be found.');
        }

        $targetStatus = Sanitizer::key($targetStatus, 40);
        $criticalClosure = in_array($targetStatus, ['closed', 'cancelled'], true)
            && in_array((string) ($incident['severity'] ?? ''), ['sev0', 'sev1'], true);
        $normalizedApprovals = [];

        if ($criticalClosure) {
            if (! current_user_can('spcrc_close_critical_incidents')) {
                return new \WP_Error('spcrc_critical_incident_close_forbidden', 'Closing a critical incident requires separately delegated authority.');
            }
            foreach (array_slice($approvalRefs, 0, 6) as $approvalRef) {
                $normalized = Sanitizer::opaqueReference($approvalRef);
                if ($normalized !== '' && ! in_array($normalized, $normalizedApprovals, true)) {
                    $normalizedApprovals[] = $normalized;
                }
            }
            if (count($normalizedApprovals) < 2) {
                return new \WP_Error('spcrc_critical_incident_dual_approval_required', 'SEV0/SEV1 closure requires two distinct opaque human approval references.');
            }

            $approvalEvidence = $this->artifacts->save([
                'artifact_type' => 'incident-action',
                'artifact_key' => 'dual-close-' . substr(hash('sha256', $incidentUuid . '|' . $targetStatus . '|' . $evidenceRef), 0, 32),
                'title' => 'Critical incident dual-control closure approval',
                'status' => 'completed',
                'classification' => 'C5',
                'owner_user_id' => get_current_user_id(),
                'evidence_ref' => $evidenceRef,
                'payload' => [
                    'incident_uuid' => Sanitizer::uuid($incidentUuid),
                    'target_status' => $targetStatus,
                    'approval_refs' => $normalizedApprovals,
                ],
            ]);
            if (is_wp_error($approvalEvidence)) {
                return new \WP_Error('spcrc_critical_incident_approval_evidence_failed', 'Critical incident closure approval evidence could not be persisted.', ['cause' => $approvalEvidence->get_error_code()]);
            }
        }

        return $this->incidents->transition($incidentUuid, $targetStatus, [
            'reason' => $reason,
            'evidence_ref' => $evidenceRef,
            'dual_approval_refs' => $normalizedApprovals,
        ]);
    }

    /** @return string|\WP_Error */
    public function recordAction(string $incidentUuid, string $actionKey, string $title, string $status, string $evidenceRef, array $payload = []): string|\WP_Error
    {
        if (! current_user_can('spcrc_manage_incidents')) {
            return new \WP_Error('spcrc_incident_action_forbidden', 'Incident action recording requires incident-management authority.');
        }

        $incident = $this->incidents->get($incidentUuid);
        if (! is_array($incident)) {
            return new \WP_Error('spcrc_incident_not_found', 'Incident could not be found.');
        }
        $payload['incident_uuid'] = Sanitizer::uuid($incidentUuid);
        return $this->artifacts->save([
            'artifact_type' => 'incident-action',
            'artifact_key' => Sanitizer::key($incidentUuid . '-' . $actionKey, 120),
            'title' => $title,
            'status' => $status,
            'classification' => 'C5',
            'owner_user_id' => get_current_user_id(),
            'evidence_ref' => $evidenceRef,
            'payload' => $payload,
        ]);
    }

    /** @return array<string,mixed> */
    public static function readiness(): array
    {
        $contactTree = Sanitizer::opaqueReference(apply_filters('spcrc/incident_contact_tree_ref', ''));
        $alternateAdmin = Sanitizer::boolean(apply_filters('spcrc/alternate_administrator_access_ready', false));
        $chainOfCustody = Sanitizer::opaqueReference(apply_filters('spcrc/chain_of_custody_template_ref', ''));
        $templates = Sanitizer::opaqueReference(apply_filters('spcrc/incident_public_templates_ref', ''));
        return [
            'contact_tree_ready' => $contactTree !== '',
            'alternate_administrator_ready' => $alternateAdmin,
            'chain_of_custody_ready' => $chainOfCustody !== '',
            'communication_templates_ready' => $templates !== '',
            'ready' => $contactTree !== '' && $alternateAdmin && $chainOfCustody !== '' && $templates !== '',
        ];
    }
}
