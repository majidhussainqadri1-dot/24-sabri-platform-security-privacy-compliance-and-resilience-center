<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\System;

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Storage\Schema;
use Sabri\Platform\Security\Support\Sanitizer;

final class SystemCheck
{
    private const STATUSES = ['pass', 'warning', 'critical', 'unknown'];

    public function __construct(private ModuleRegistry $modules)
    {
    }

    /** @return array<int,array<string,mixed>> */
    public function run(): array
    {
        $checks = [
            $this->checkWordPress(),
            $this->checkPhp(),
            $this->checkHttps(),
            $this->checkDebugDisplay(),
            $this->checkSchema(),
            $this->checkIdentityAuthority(),
            $this->checkPublicBrowsingCompatibility(),
            $this->checkFile20Adapter(),
            $this->checkModuleRegistry(),
            $this->checkExternalLogAdapter(),
            $this->checkBackupEvidenceAdapter(),
            $this->checkAuditGaps(),
            $this->checkUpgradeError(),
        ];

        return $this->normalize(apply_filters('spcrc/system_checks', $checks, $this->modules));
    }

    /** @return array<string,mixed> */
    private function checkWordPress(): array
    {
        global $wp_version;
        $version = (string) $wp_version;
        return $this->result('wordpress_version', 'WordPress 6.5 or newer', version_compare($version, '6.5', '>='), $version);
    }

    /** @return array<string,mixed> */
    private function checkPhp(): array
    {
        return $this->result('php_version', 'PHP 8.0 or newer', version_compare(PHP_VERSION, '8.0', '>='), PHP_VERSION);
    }

    /** @return array<string,mixed> */
    private function checkHttps(): array
    {
        $ok = is_ssl() || wp_parse_url(home_url(), PHP_URL_SCHEME) === 'https';
        return $this->result('https', 'HTTPS enabled', $ok, $ok ? 'Enabled' : 'Not detected');
    }

    /** @return array<string,mixed> */
    private function checkDebugDisplay(): array
    {
        $debugEnabled = defined('WP_DEBUG') && WP_DEBUG;
        $displayEnabled = defined('WP_DEBUG_DISPLAY') ? (bool) WP_DEBUG_DISPLAY : $debugEnabled;
        $iniValue = strtolower(trim((string) ini_get('display_errors')));
        $iniDisplay = ! in_array($iniValue, ['', '0', 'off', 'false', 'no'], true);
        $publicDisplay = $displayEnabled || $iniDisplay;

        return $this->result(
            'debug_display',
            'Public debug display disabled',
            ! $publicDisplay,
            $publicDisplay ? 'Enabled or inherited from PHP/WordPress debug settings' : 'Disabled'
        );
    }

    /** @return array<string,mixed> */
    private function checkSchema(): array
    {
        global $wpdb;
        $missing = [];
        foreach (Schema::tables() as $key => $table) {
            $found = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table)));
            if ($found !== $table) {
                $missing[] = $key;
            }
        }

        $installedVersion = (string) get_option('spcrc_schema_version', '');
        $versionMatches = $installedVersion === Schema::VERSION;
        $integrity = $missing === [] ? Schema::verify() : new \WP_Error('spcrc_schema_integrity_failed', 'Required File 24 tables are missing.');
        $integrityOk = ! is_wp_error($integrity);
        $passed = $missing === [] && $versionMatches && $integrityOk;
        $detail = $missing !== []
            ? 'Missing: ' . implode(', ', $missing)
            : (! $integrityOk
                ? 'Schema column or table integrity verification failed: ' . $integrity->get_error_code()
                : ($versionMatches ? 'All required tables and governed columns detected; schema ' . Schema::VERSION : 'Tables detected but installed schema is ' . ($installedVersion !== '' ? $installedVersion : 'unknown')));

        return $this->result(
            'schema',
            'File 24 database schema available and current',
            $passed,
            $detail
        );
    }

    /** @return array<string,mixed> */
    private function checkIdentityAuthority(): array
    {
        $detected = defined('SMC_VERSION') && function_exists('smc_user_status') && function_exists('smc_is_founder');
        $available = Sanitizer::boolean(apply_filters('spcrc/identity_authority_available', $detected));
        return $this->result('identity_authority', 'File 00 identity authority available', $available, $available ? 'Available' : 'Not detected');
    }

    /** @return array<string,mixed> */
    private function checkPublicBrowsingCompatibility(): array
    {
        $compatible = Sanitizer::boolean(apply_filters('spcrc/public_browsing_compatible', true));
        return $this->result(
            'public_browsing_compatibility',
            'Public browsing remains available while actions require login',
            $compatible,
            $compatible ? 'Compatible' : 'A registered identity gate appears to redirect anonymous public browsing',
            'warning'
        );
    }

    /** @return array<string,mixed> */
    private function checkFile20Adapter(): array
    {
        $detected = defined('SABRI_SHELL_VERSION') && class_exists('Sabri\\UnifiedShell\\SafeMode');
        $available = Sanitizer::boolean(apply_filters('spcrc/file20_adapter_available', $detected));
        $safeMode = Sanitizer::boolean(apply_filters('spcrc/file20_safe_mode_active', false));
        $detail = $available ? ($safeMode ? 'Available; File 20 safe mode is active' : 'Available; no active File 20 safe mode detected') : 'Not detected';
        return $this->result('file20_adapter', 'File 20 shell adapter available', $available, $detail, 'warning');
    }

    /** @return array<string,mixed> */
    private function checkModuleRegistry(): array
    {
        $count = count($this->modules->all());
        return $this->result('module_registry', 'At least one module manifest registered', $count > 0, (string) $count);
    }

    /** @return array<string,mixed> */
    private function checkExternalLogAdapter(): array
    {
        $available = Sanitizer::boolean(apply_filters('spcrc/external_log_adapter_available', false));
        return $this->result('external_log_adapter', 'External security evidence adapter', $available, $available ? 'Available' : 'Not configured', 'warning');
    }

    /** @return array<string,mixed> */
    private function checkBackupEvidenceAdapter(): array
    {
        $evidence = apply_filters('spcrc/backup_evidence', []);
        $status = is_array($evidence) ? Sanitizer::key($evidence['status'] ?? '', 40) : '';
        $lastSuccess = is_array($evidence) ? Sanitizer::isoTime($evidence['last_success_at'] ?? '') : '';
        $restoreTest = is_array($evidence) ? Sanitizer::isoTime($evidence['restore_tested_at'] ?? '') : '';
        $evidenceRef = is_array($evidence) ? Sanitizer::opaqueReference($evidence['evidence_ref'] ?? '') : '';
        $lastTimestamp = $lastSuccess === '' ? false : strtotime($lastSuccess);
        $restoreTimestamp = $restoreTest === '' ? false : strtotime($restoreTest);
        $chronologyValid = $status === 'verified'
            && $evidenceRef !== ''
            && $lastTimestamp !== false
            && $restoreTimestamp !== false
            && $restoreTimestamp >= $lastTimestamp
            && $lastTimestamp <= time() + 300
            && $restoreTimestamp <= time() + 300;

        return $this->result(
            'backup_evidence',
            'Backup and restore evidence adapter',
            $chronologyValid,
            $chronologyValid
                ? 'Verified backup and later restore-test evidence received'
                : 'Complete, chronological backup and restore evidence is not configured',
            'warning'
        );
    }

    /** @return array<string,mixed> */
    private function checkAuditGaps(): array
    {
        $options = [
            'governance' => 'spcrc_governance_audit_gap',
            'security-state' => 'spcrc_security_state_audit_gap',
            'assurance' => 'spcrc_assurance_audit_gap',
            'risk' => 'spcrc_risk_audit_gap',
            'finding' => 'spcrc_finding_audit_gap',
            'incident' => 'spcrc_incident_audit_gap',
            'control' => 'spcrc_control_audit_gap',
            'risk-reopen' => 'spcrc_risk_reopen_audit_gap',
            'finding-reopen' => 'spcrc_finding_reopen_audit_gap',
            'governance-batch' => 'spcrc_governance_batch_audit_gap',
            'privacy' => 'spcrc_privacy_audit_gap',
            'privacy-recovery' => 'spcrc_privacy_recovery_audit_gap',
            'retention' => 'spcrc_retention_audit_gap',
            'admin' => 'spcrc_admin_audit_gap',
        ];
        $counts = [];
        foreach ($options as $label => $option) {
            $raw = get_option($option, []);
            if (! is_array($raw) || $raw === []) {
                continue;
            }
            $isLegacySingle = isset($raw['reason'])
                || isset($raw['request_id'])
                || isset($raw['risk_uuid'])
                || isset($raw['finding_uuid'])
                || isset($raw['incident_uuid'])
                || isset($raw['control_key'])
                || isset($raw['count'])
                || isset($raw['recorded_at']);
            $counts[$label] = $isLegacySingle ? 1 : count($raw);
        }

        $total = array_sum($counts);
        $detail = $total === 0
            ? 'No unresolved File 24 audit-evidence gaps detected'
            : 'Unresolved audit-evidence gaps: ' . implode(', ', array_map(
                static fn (string $label, int $count): string => $label . '=' . $count,
                array_keys($counts),
                array_values($counts)
            ));
        return $this->result('audit_gaps', 'No unresolved File 24 audit-evidence gaps', $total === 0, $detail);
    }

    /** @return array<string,mixed> */
    private function checkUpgradeError(): array
    {
        $raw = get_option('spcrc_last_upgrade_error', '');
        if (is_array($raw)) {
            $code = Sanitizer::key($raw['error_code'] ?? '', 120);
            $at = Sanitizer::isoTime($raw['at'] ?? '');
            $from = Sanitizer::text($raw['from_schema'] ?? '', 40);
            $target = Sanitizer::text($raw['target_schema'] ?? '', 40);
            $parts = [];
            if ($code !== '') {
                $parts[] = 'Code: ' . $code;
            }
            if ($from !== '' || $target !== '') {
                $parts[] = 'Schema: ' . ($from !== '' ? $from : 'unknown') . ' → ' . ($target !== '' ? $target : 'unknown');
            }
            if ($at !== '') {
                $parts[] = 'Recorded: ' . $at;
            }
            $detail = $parts !== [] ? implode('; ', $parts) : 'Unrecognized structured upgrade failure evidence';
            return $this->result('upgrade_error', 'No unresolved File 24 upgrade error', false, $detail);
        }

        $error = Sanitizer::text($raw, 300);
        return $this->result('upgrade_error', 'No unresolved File 24 upgrade error', $error === '', $error === '' ? 'None' : $error);
    }

    /** @return array<string,mixed> */
    private function result(string $key, string $label, bool $passed, string $detail, string $failureLevel = 'critical'): array
    {
        return [
            'key' => Sanitizer::key($key, 80),
            'label' => Sanitizer::text($label, 160),
            'status' => $passed ? 'pass' : (in_array($failureLevel, self::STATUSES, true) ? $failureLevel : 'critical'),
            'detail' => Sanitizer::text($detail, 500),
        ];
    }

    /** @return array<int,array<string,mixed>> */
    private function normalize(mixed $checks): array
    {
        if (! is_array($checks)) {
            return [$this->result('invalid_check_collection', 'System-check collection valid', false, 'A system-check filter returned an invalid value.')];
        }

        $normalized = [];
        foreach (array_slice($checks, 0, 100) as $check) {
            if (! is_array($check)) {
                continue;
            }
            $key = Sanitizer::key($check['key'] ?? '', 80);
            $label = Sanitizer::text($check['label'] ?? '', 160);
            $status = Sanitizer::key($check['status'] ?? 'unknown', 20);
            $detail = Sanitizer::text($check['detail'] ?? '', 500);
            if ($key === '' || $label === '') {
                continue;
            }
            $normalized[] = [
                'key' => $key,
                'label' => $label,
                'status' => in_array($status, self::STATUSES, true) ? $status : 'unknown',
                'detail' => $detail,
            ];
        }

        return $normalized;
    }
}
