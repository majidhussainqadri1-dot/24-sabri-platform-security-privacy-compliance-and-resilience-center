<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\System;

use Sabri\Platform\Security\Registry\ModuleRegistry;

final class SystemCheck
{
    public function __construct(private ModuleRegistry $modules)
    {
    }

    /** @return array<int,array<string,mixed>> */
    public function run(): array
    {
        $checks = [
            $this->checkPhp(),
            $this->checkHttps(),
            $this->checkDebugDisplay(),
            $this->checkIdentityAuthority(),
            $this->checkModuleRegistry(),
            $this->checkExternalLogAdapter(),
            $this->checkBackupEvidenceAdapter(),
        ];

        return apply_filters('spcrc/system_checks', $checks, $this->modules);
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
    private function checkIdentityAuthority(): array
    {
        $available = (bool) apply_filters('spcrc/identity_authority_available', false);
        return $this->result('identity_authority', 'File 00 identity authority available', $available, $available ? 'Available' : 'Unknown');
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
        $available = (bool) apply_filters('spcrc/external_log_adapter_available', false);
        return $this->result('external_log_adapter', 'External security evidence adapter', $available, $available ? 'Available' : 'Not configured', 'warning');
    }

    /** @return array<string,mixed> */
    private function checkBackupEvidenceAdapter(): array
    {
        $evidence = apply_filters('spcrc/backup_evidence', []);
        $available = is_array($evidence) && ! empty($evidence);
        return $this->result('backup_evidence', 'Backup and restore evidence adapter', $available, $available ? 'Evidence received' : 'Not configured', 'warning');
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
}
