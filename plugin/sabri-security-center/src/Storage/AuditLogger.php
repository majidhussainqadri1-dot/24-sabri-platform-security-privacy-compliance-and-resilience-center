<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\Support\SecureIdentifier;

if (! class_exists(Sanitizer::class, false)) {
    require_once dirname(__DIR__) . '/Support/Sanitizer.php';
}
if (! class_exists(SecureIdentifier::class, false)) {
    require_once dirname(__DIR__) . '/Support/SecureIdentifier.php';
}

final class AuditLogger
{
    private const ALLOWED_RISK_LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];
    private const ALLOWED_RESULTS = [
        'recorded', 'success', 'successful', 'failure', 'failed', 'open', 'closed',
        'created', 'updated', 'deleted', 'pending', 'approved', 'accepted', 'rejected',
        'revoked', 'expired', 'reopened', 'resolved', 'withdrawn', 'superseded',
        'requested', 'authorized', 'completed', 'partial', 'queued', 'dispatched',
        'dispatching', 'processing', 'reconciled', 'restored', 'rolled-back',
        'locked', 'held', 'blocked', 'deferred', 'cancelled', 'skipped', 'unknown',
        'unavailable', 'not-started', 'recovery-required', 'storage-failed',
        'audit-evidence-missing', 'received', 'triaged', 'in-progress',
        'accepted-risk', 'false-positive', 'informational', 'warning', 'critical',
        'operational', 'foundation', 'unassessed', 'planned', 'implemented',
        'tested', 'restricted', 'exited', 'verified', 'pass', 'recovery-scheduled',
    ];    private const MAX_CONTEXT_ITEMS = 50;
    private const MAX_CONTEXT_DEPTH = 5;
    private const MAX_STRING_LENGTH = 500;

    /** @param array<string,mixed> $context
     *  @return string|\WP_Error
     */
    public function record(
        string $eventType,
        string $moduleKey,
        string $result = 'recorded',
        string $riskLevel = 'low',
        array $context = []
    ): string|\WP_Error {
        global $wpdb;

        $eventType = Sanitizer::key($eventType, 120);
        $moduleKey = Sanitizer::key($moduleKey, 120);
        $result = Sanitizer::key($result, 40);
        $riskLevel = in_array($riskLevel, self::ALLOWED_RISK_LEVELS, true) ? $riskLevel : 'low';

        if ($eventType === '' || $moduleKey === '' || ! in_array($result, self::ALLOWED_RESULTS, true)) {
            return new \WP_Error('spcrc_invalid_audit_event', 'Audit event type, module key and result are required and must use approved semantics.');
        }

        $eventUuid = SecureIdentifier::uuid4('audit-event');
        if (is_wp_error($eventUuid)) {
            do_action('spcrc/security_event_failed', $eventUuid, [
                'event_type' => $eventType,
                'module_key' => $moduleKey,
                'risk_level' => $riskLevel,
            ]);
            return $eventUuid;
        }
        $safeContext = $this->redact($context);
        $correlationId = $this->correlationId($safeContext, $eventUuid);
        $json = function_exists('wp_json_encode')
            ? wp_json_encode($safeContext, JSON_UNESCAPED_SLASHES)
            : json_encode($safeContext, JSON_UNESCAPED_SLASHES);
        if (! is_string($json)) {
            $error = new \WP_Error(
                'spcrc_audit_context_encode_failed',
                'The bounded security-event context could not be encoded safely.'
            );
            do_action('spcrc/security_event_failed', $error, [
                'event_type' => $eventType,
                'module_key' => $moduleKey,
                'risk_level' => $riskLevel,
            ]);
            return $error;
        }

        $payload = [
            'event_uuid' => $eventUuid,
            'event_type' => $eventType,
            'module_key' => $moduleKey,
            'actor_user_id' => get_current_user_id() ?: null,
            'result' => $result,
            'risk_level' => $riskLevel,
            'correlation_id' => $correlationId,
            'context_json' => $json,
            'created_at' => current_time('mysql', true),
        ];

        $inserted = $wpdb->insert(
            $wpdb->prefix . 'spcrc_security_events',
            $payload,
            ['%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s']
        );

        if ($inserted !== 1) {
            $error = new \WP_Error('spcrc_audit_write_failed', 'The security event could not be stored exactly once.');
            do_action('spcrc/security_event_failed', $error, $payload);
            return $error;
        }

        do_action('spcrc/security_event_recorded', $eventUuid, $eventType, $moduleKey, $riskLevel);
        do_action('spcrc/external_security_event', [
            'event_uuid' => $eventUuid,
            'event_type' => $eventType,
            'module_key' => $moduleKey,
            'actor_user_id' => $payload['actor_user_id'],
            'result' => $payload['result'],
            'risk_level' => $riskLevel,
            'correlation_id' => $payload['correlation_id'],
            'context' => $safeContext,
            'created_at' => $payload['created_at'],
        ]);

        return $eventUuid;
    }

    /** @param array<mixed> $context
     *  @return array<mixed>
     */
    private function redact(array $context, int $depth = 0): array
    {
        if ($depth >= self::MAX_CONTEXT_DEPTH) {
            return ['_truncated' => 'maximum_depth'];
        }

        $blocked = [
            'password', 'passwd', 'passphrase', 'token', 'secret', 'api_key', 'apikey',
            'authorization', 'cookie', 'session', 'nonce', 'otp', 'totp', 'recovery',
            'cvv', 'pan', 'card_number', 'message_body', 'clinical_note', 'private_key',
            'passport', 'national_id', 'identity_document',
        ];

        $safe = [];
        $items = 0;
        foreach ($context as $key => $value) {
            if ($items >= self::MAX_CONTEXT_ITEMS) {
                $safe['_truncated'] = 'maximum_items';
                break;
            }
            ++$items;

            $rawKey = (string) $key;
            $normalized = strtolower($rawKey);
            $safeKey = Sanitizer::key($rawKey, 80);
            if ($safeKey === '') {
                $safeKey = 'field_' . substr(hash('sha256', $rawKey), 0, 16);
            }
            if (array_key_exists($safeKey, $safe)) {
                $safeKey .= '_' . substr(hash('sha256', $rawKey . '|' . $items), 0, 8);
            }
            foreach ($blocked as $needle) {
                if (str_contains($normalized, $needle)) {
                    $safe[$safeKey] = '[REDACTED]';
                    continue 2;
                }
            }

            if (preg_match('/(^|_)(ip|ip_address|remote_addr)($|_)/', $normalized) === 1) {
                $safe[$safeKey] = $this->pseudonymize((string) $value, 'ip');
                continue;
            }

            if (preg_match('/(^|_)user_agent($|_)/', $normalized) === 1) {
                $safe[$safeKey] = $this->pseudonymize((string) $value, 'ua');
                continue;
            }

            if (preg_match('/(^|_)(email|email_address|phone|phone_number|mobile|mobile_number|address|postal_address|guardian_contact)($|_)/', $normalized) === 1) {
                $safe[$safeKey] = $this->pseudonymize((string) $value, 'contact');
                continue;
            }

            if (is_array($value)) {
                $safe[$safeKey] = $this->redact($value, $depth + 1);
            } elseif (is_string($value)) {
                $safe[$safeKey] = $this->redactString($value);
            } elseif (is_scalar($value) || $value === null) {
                $safe[$safeKey] = $value;
            } else {
                $safe[$safeKey] = '[UNSERIALIZABLE]';
            }
        }

        return $safe;
    }

    private function redactString(string $value): string
    {
        $value = Sanitizer::text($value, self::MAX_STRING_LENGTH);
        if (
            Sanitizer::containsSensitiveMaterial($value)
            || preg_match('/-----BEGIN [A-Z ]*PRIVATE KEY-----/i', $value) === 1
            || preg_match('/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/i', $value) === 1
            || preg_match('/^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$/', $value) === 1
        ) {
            return '[REDACTED]';
        }

        return $value;
    }

    private function pseudonymize(string $value, string $purpose): string
    {
        if ($value === '') {
            return '';
        }

        $salt = defined('AUTH_SALT') ? (string) AUTH_SALT : '';
        if (strlen($salt) < 16 && function_exists('wp_salt')) {
            $salt = (string) wp_salt('auth');
        }
        if (strlen($salt) < 16) {
            $salt = (string) apply_filters('spcrc/audit_pseudonymization_key', '');
        }
        if (strlen($salt) < 16) {
            return '[REDACTED]';
        }
        return 'sha256:' . hash_hmac('sha256', $value, $salt . '|' . $purpose);
    }

    /** @param array<mixed> $safeContext */
    private function correlationId(array &$safeContext, string $eventUuid): string
    {
        $incoming = isset($_SERVER['HTTP_X_CORRELATION_ID'])
            ? trim((string) wp_unslash($_SERVER['HTTP_X_CORRELATION_ID']))
            : '';

        if (preg_match('/^[A-Za-z0-9._-]{8,80}$/', $incoming) === 1) {
            $safeContext['_incoming_correlation_hash'] = $this->pseudonymize($incoming, 'correlation');
        }

        $generated = SecureIdentifier::uuid4('correlation');
        if (is_wp_error($generated)) {
            do_action('spcrc/correlation_identifier_unavailable', $generated->get_error_code(), $eventUuid);
            return $eventUuid;
        }
        return $generated;
    }
}
