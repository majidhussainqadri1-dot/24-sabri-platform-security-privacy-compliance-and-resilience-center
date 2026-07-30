<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

final class AuditLogger
{
    private const ALLOWED_RISK_LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];
    private const MAX_CONTEXT_BYTES = 16384;
    private const MAX_DEPTH = 5;
    private const MAX_ITEMS = 50;

    /** @param array<string,mixed> $context */
    public function record(
        string $eventType,
        string $moduleKey,
        string $result = 'recorded',
        string $riskLevel = 'low',
        array $context = []
    ): string|\WP_Error {
        global $wpdb;

        $eventType = $this->truncate(sanitize_key($eventType), 120);
        $moduleKey = $this->truncate(sanitize_key($moduleKey), 120);
        if ($eventType === '' || $moduleKey === '') {
            return new \WP_Error('spcrc_invalid_audit_event', 'Audit event type and module key are required.');
        }

        $eventUuid = wp_generate_uuid4();
        $riskLevel = in_array($riskLevel, self::ALLOWED_RISK_LEVELS, true) ? $riskLevel : 'low';
        $result = $this->truncate(sanitize_key($result) ?: 'recorded', 40);
        $context = $this->redact($context);
        $json = wp_json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if (! is_string($json)) {
            $json = '{"_encoding_error":true}';
        } elseif (strlen($json) > self::MAX_CONTEXT_BYTES) {
            $json = (string) wp_json_encode([
                '_truncated' => true,
                'original_bytes' => strlen($json),
            ]);
        }

        $payload = [
            'event_uuid' => $eventUuid,
            'event_type' => $eventType,
            'module_key' => $moduleKey,
            'environment' => $this->truncate(sanitize_key(wp_get_environment_type()) ?: 'production', 20),
            'actor_user_id' => max(0, (int) get_current_user_id()),
            'result' => $result,
            'risk_level' => $riskLevel,
            'correlation_id' => $this->correlationId(),
            'context_json' => $json,
            'created_at' => current_time('mysql', true),
        ];

        $inserted = $wpdb->insert(
            Schema::tables()['events'],
            $payload,
            ['%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s']
        );

        if ($inserted === false) {
            do_action('spcrc/security_event_failed', $payload, (string) $wpdb->last_error);
            return new \WP_Error('spcrc_audit_insert_failed', 'The security event could not be persisted.');
        }

        do_action('spcrc/security_event_recorded', $eventUuid, $payload);
        return $eventUuid;
    }

    /** @param array<string,mixed> $context
     *  @return array<string,mixed>
     */
    private function redact(array $context, int $depth = 0): array
    {
        if ($depth >= self::MAX_DEPTH) {
            return ['_truncated_depth' => true];
        }

        $blocked = [
            'password', 'passphrase', 'authorization', 'cookie', 'session', 'token', 'secret',
            'otp', 'totp', 'recovery_code', 'nonce', 'api_key', 'private_key', 'encryption_key', 'cvv',
            'pan', 'message_body', 'clinical_note', 'patient', 'identity_document', 'passport',
            'national_id', 'date_of_birth', 'dob', 'phone', 'email', 'address',
        ];

        $redacted = [];
        $count = 0;
        foreach ($context as $key => $value) {
            if ($count >= self::MAX_ITEMS) {
                $redacted['_truncated_items'] = true;
                break;
            }
            ++$count;

            $safeKey = $this->truncate((string) $key, 120);
            $normalized = strtolower($safeKey);
            foreach ($blocked as $needle) {
                if (str_contains($normalized, $needle)) {
                    $redacted[$safeKey] = '[REDACTED]';
                    continue 2;
                }
            }

            if (is_array($value)) {
                $redacted[$safeKey] = $this->redact($value, $depth + 1);
            } elseif (is_string($value)) {
                $redacted[$safeKey] = $this->redactString($value);
            } elseif (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
                $redacted[$safeKey] = $value;
            } else {
                $redacted[$safeKey] = '[UNSERIALIZABLE]';
            }
        }

        return $redacted;
    }

    private function redactString(string $value): string
    {
        $value = wp_strip_all_tags($value, true);
        $value = preg_replace('/Bearer\s+[A-Za-z0-9._~+\/=:-]+/i', 'Bearer [REDACTED]', $value) ?? $value;
        $value = preg_replace('/-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----/is', '[PRIVATE KEY REDACTED]', $value) ?? $value;

        return $this->truncate($value, 500);
    }

    private function correlationId(): string
    {
        $incoming = isset($_SERVER['HTTP_X_CORRELATION_ID'])
            ? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_CORRELATION_ID']))
            : '';

        if ($incoming !== '' && preg_match('/^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/', $incoming) === 1) {
            return $incoming;
        }

        return wp_generate_uuid4();
    }

    private function truncate(string $value, int $length): string
    {
        return function_exists('mb_substr') ? mb_substr($value, 0, $length) : substr($value, 0, $length);
    }
}
