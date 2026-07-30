<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\System;

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Storage\Retention;
use Sabri\Platform\Security\Storage\Schema;

final class SystemCheck
{
    private const ALLOWED_STATUSES = ['pass', 'warning', 'critical'];

    public function __construct(private ModuleRegistry $modules)
    {
    }

    /** @return array<int,array<string,mixed>> */
    public function run(): array
    {
        $checks = [
            $this->checkPhp(),
            $this->checkWordPress(),
            $this->checkHttps(),
            $this->checkDebugDisplay(),
            $this->checkFileEditor(),
            $this->checkSchema(),
            $this->checkIdentityAuthority(),
            $this->checkModuleRegistry(),
            $this->checkCompanionModules(),
            $this->checkExternalLogAdapter(),
            $this->checkBackupEvidenceAdapter(),
            $this->checkRetentionSchedule(),
        ];

        $additional = apply_filters('spcrc/additional_system_checks', [], $this->modules);
        if (is_array($additional)) {
            $checks = array_merge($checks, array_slice($additional, 0, 50));
        }

        $normalized = [];
        foreach (array_slice($checks, 0, 100) as $check) {
            if (! is_array($check)) {
                continue;
            }
            $key = sanitize_key((string) ($check['key'] ?? ''));
            $label = sanitize_text_field((string) ($check['label'] ?? ''));
            $status = sanitize_key((string) ($check['status'] ?? 'warning'));
            $detail = sanitize_text_field((string) ($check['detail'] ?? 'No detail supplied'));
            if ($key === '' || $label === '') {
                continue;
            }
            if (! in_array($status, self::ALLOWED_STATUSES, true)) {
                $status = 'warning';
            }
            $normalized[] = compact('key', 'label', 'status', 'detail');
        }

        return $normalized;
    }

    /** @return array<string,mixed> */
    private function checkPhp(): array
    {
        return $this->result('php_version', 'PHP 8.0 or newer', version_compare(PHP_VERSION, '8.0', '>='), PHP_VERSION);
    }

    /** @return array<string,mixed> */
    private function checkWordPress(): array
    {
        $version = (string) get_bloginfo('version');
        return $this->result('wordpress_version', 'WordPress 6.5 or newer', version_compare($version, '6.5', '>='), $version);
    }

    /** @return array<string,mixed> */
    private function checkHttps(): array
    {
        $homeScheme = wp_parse_url(home_url(), PHP_URL_SCHEME);
        $siteScheme = wp_parse_url(site_url(), PHP_URL_SCHEME);
        $ok = $homeScheme === 'https' && $siteScheme === 'https';
        return $this->result('https', 'WordPress URLs use HTTPS', $ok, $ok ? 'Home and Site URLs use HTTPS' : 'Home or Site URL is not configured for HTTPS');
    }

    /** @return array<string,mixed> */
    private function checkDebugDisplay(): array
    {
        $debugEnabled = defined('WP_DEBUG') && WP_DEBUG;
        $displayEnabled = defined('WP_DEBUG_DISPLAY') ? (bool) WP_DEBUG_DISPLAY : $debugEnabled;
        $iniDisplay = filter_var((string) ini_get('display_errors'), FILTER_VALIDATE_BOOLEAN);
        $publicDisplay = $displayEnabled || $iniDisplay;

        return $this->result(
            'debug_display',
            'Public debug display disabled',
            ! $publicDisplay,
            $publicDisplay ? 'Enabled or inherited from PHP/WordPress debug settings' : 'Disabled'
        );
    }

    /** @return array<string,mixed> */
    private function checkFileEditor(): array
    {
        $disabled = defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT;
        return $this->result('file_editor', 'Plugin and theme editor disabled', $disabled, $disabled ? 'Disabled' : 'Not disabled', 'warning');
    }

    /** @return array<string,mixed> */
    private function checkSchema(): array
    {
        $missingTables = Schema::missingTables();
        $missingColumns = $missingTables === [] ? Schema::missingColumns() : [];
        $ok = $missingTables === [] && $missingColumns === [];
        $detail = $ok
            ? 'All required tables and columns found'
            : sprintf('%d table(s) and %d column(s) missing', count($missingTables), count($missingColumns));
        return $this->result('schema', 'Security Center schema verified', $ok, $detail);
    }

    /** @return array<string,mixed> */
    private function checkIdentityAuthority(): array
    {
        $evidence = apply_filters('spcrc/identity_authority_available', false);
        if (is_array($evidence) && (bool) ($evidence['available'] ?? false)) {
            $fresh = $this->validRecentDate((string) ($evidence['tested_at'] ?? ''), 30 * DAY_IN_SECONDS);
            return [
                'key' => 'identity_authority',
                'label' => 'File 00 identity authority available',
                'status' => $fresh ? 'pass' : 'warning',
                'detail' => $fresh ? 'Structured evidence received; end-to-end authorization testing remains required' : 'Reported available but recent test evidence is missing',
            ];
        }

        if ((bool) $evidence) {
            return [
                'key' => 'identity_authority',
                'label' => 'File 00 identity authority available',
                'status' => 'warning',
                'detail' => 'Boolean availability reported without structured test evidence',
            ];
        }

        return $this->result('identity_authority', 'File 00 identity authority available', false, 'Not reported');
    }

    /** @return array<string,mixed> */
    private function checkModuleRegistry(): array
    {
        $count = count($this->modules->all());
        return $this->result('module_registry', 'Module registry initialized', $count > 0, (string) $count);
    }

    /** @return array<string,mixed> */
    private function checkCompanionModules(): array
    {
        $count = $this->modules->companionCount();
        return $this->result('companion_modules', 'Companion module manifests registered', $count > 0, (string) $count, 'warning');
    }

    /** @return array<string,mixed> */
    private function checkExternalLogAdapter(): array
    {
        $evidence = apply_filters('spcrc/external_log_adapter_available', false);
        if (is_array($evidence) && (bool) ($evidence['available'] ?? false)) {
            $fresh = $this->validRecentDate((string) ($evidence['tested_at'] ?? ''), 7 * DAY_IN_SECONDS);
            return [
                'key' => 'external_log_adapter',
                'label' => 'External security evidence adapter',
                'status' => $fresh ? 'pass' : 'warning',
                'detail' => $fresh ? 'Recent structured delivery evidence received' : 'Reported available but recent delivery evidence is missing',
            ];
        }

        return $this->result(
            'external_log_adapter',
            'External security evidence adapter',
            false,
            (bool) $evidence ? 'Boolean availability reported without structured delivery evidence' : 'Not configured',
            'warning'
        );
    }

    /** @return array<string,mixed> */
    private function checkBackupEvidenceAdapter(): array
    {
        $evidence = apply_filters('spcrc/backup_evidence', []);
        $maxBackupAge = (int) apply_filters('spcrc/max_backup_age_seconds', 7 * DAY_IN_SECONDS);
        $maxRestoreAge = (int) apply_filters('spcrc/max_restore_test_age_seconds', 180 * DAY_IN_SECONDS);
        $maxBackupAge = max(HOUR_IN_SECONDS, min(YEAR_IN_SECONDS, $maxBackupAge));
        $maxRestoreAge = max(DAY_IN_SECONDS, min(2 * YEAR_IN_SECONDS, $maxRestoreAge));

        $valid = is_array($evidence)
            && in_array((string) ($evidence['status'] ?? ''), ['pass', 'ok'], true)
            && $this->validRecentDate((string) ($evidence['last_backup_at'] ?? ''), $maxBackupAge)
            && $this->validRecentDate((string) ($evidence['restore_tested_at'] ?? ''), $maxRestoreAge);

        return $this->result(
            'backup_evidence',
            'Backup and restore evidence adapter',
            $valid,
            $valid ? 'Backup and restore-test evidence received' : 'Missing valid backup or restore-test evidence',
            'warning'
        );
    }

    /** @return array<string,mixed> */
    private function checkRetentionSchedule(): array
    {
        $scheduled = (bool) wp_next_scheduled(Retention::HOOK);
        return $this->result('retention_schedule', 'Security retention job scheduled', $scheduled, $scheduled ? 'Scheduled' : 'Not scheduled', 'warning');
    }

    /** @return array<string,mixed> */
    private function result(string $key, string $label, bool $passed, string $detail, string $failureLevel = 'critical'): array
    {
        return [
            'key' => $key,
            'label' => $label,
            'status' => $passed ? 'pass' : $failureLevel,
            'detail' => $detail,
        ];
    }

    private function validRecentDate(string $value, int $maximumAge): bool
    {
        if ($value === '') {
            return false;
        }
        $timestamp = strtotime($value);
        $now = time();
        return $timestamp !== false
            && $timestamp <= ($now + 300)
            && $timestamp >= ($now - $maximumAge);
    }
}
