<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Monitoring;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Support\Sanitizer;

final class DetectionEngine
{
    private bool $guard = false;

    /** @var array<string,array<string,mixed>> */
    private const RULES = [
        'privileged-change' => ['events' => ['governance_decision_saved', 'security_state_requested', 'risk_accepted'], 'minimum_risk' => 'medium'],
        'audit-failure' => ['events' => ['audit_write_failed', 'security_event_failed'], 'minimum_risk' => 'high'],
        'privacy-failure' => ['events' => ['privacy_request_failed', 'privacy_deletion_replay_completed'], 'minimum_risk' => 'medium'],
        'backup-failure' => ['events' => ['backup_failed', 'restore_drill_failed'], 'minimum_risk' => 'high'],
        'integrity-change' => ['events' => ['schema_integrity_failed', 'package_integrity_failed'], 'minimum_risk' => 'critical'],
        'credential-expiry' => ['events' => ['credential_expiring', 'key_rotation_due'], 'minimum_risk' => 'medium'],
    ];

    public function __construct(private GovernedArtifactRegistry $artifacts)
    {
    }

    public function registerHooks(): void
    {
        add_action('spcrc/external_security_event', [$this, 'observe'], 30, 1);
    }

    /** @param array<string,mixed> $event */
    public function observe(array $event): void
    {
        if ($this->guard || ($event['event_type'] ?? '') === 'governed_artifact_saved') {
            return;
        }
        $eventType = Sanitizer::key($event['event_type'] ?? '', 120);
        $risk = Sanitizer::key($event['risk_level'] ?? 'low', 20);
        foreach (apply_filters('spcrc/detection_rules', self::RULES) as $ruleKey => $rule) {
            if (! is_string($ruleKey) || ! is_array($rule)) {
                continue;
            }
            $events = Sanitizer::textList($rule['events'] ?? [], 50, 120);
            if (! in_array($eventType, $events, true)) {
                continue;
            }
            $this->createAlert($ruleKey, $event, $risk);
        }
    }

    /** @param array<string,mixed> $event */
    private function createAlert(string $ruleKey, array $event, string $risk): void
    {
        $ruleKey = Sanitizer::key($ruleKey, 80);
        $eventUuid = Sanitizer::uuid($event['event_uuid'] ?? '');
        if ($ruleKey === '' || $eventUuid === '') {
            return;
        }
        $bucket = gmdate('YmdH');
        $key = $ruleKey . '-' . substr(hash('sha256', $eventUuid . '|' . $bucket), 0, 24);
        $this->guard = true;
        try {
            $this->artifacts->save([
                'artifact_type' => 'alert',
                'artifact_key' => $key,
                'title' => 'Security detection: ' . $ruleKey,
                'status' => 'open',
                'classification' => 'C4',
                'module_key' => Sanitizer::key($event['module_key'] ?? 'file-24-security-center', 120),
                'owner_user_id' => get_current_user_id(),
                'payload' => [
                    'rule_key' => $ruleKey,
                    'event_uuid' => $eventUuid,
                    'event_type' => Sanitizer::key($event['event_type'] ?? '', 120),
                    'risk_level' => $risk,
                    'correlation_id' => Sanitizer::uuid($event['correlation_id'] ?? ''),
                    'detected_at' => gmdate('c'),
                ],
            ]);
        } finally {
            $this->guard = false;
        }
    }
}
