<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

use Sabri\Platform\Security\Capabilities;

final class ModuleRegistry
{
    /** @var array<string,array<string,mixed>> */
    private array $manifests = [];

    public function registerHooks(): void
    {
        add_action('spcrc/register_module_manifest', [$this, 'register'], 10, 1);
        add_action('init', [$this, 'collect'], 50);
    }

    public function collect(): void
    {
        $this->register($this->selfManifest());

        /** @var array<int,array<string,mixed>> $manifests */
        $manifests = apply_filters('spcrc/module_manifests', []);
        foreach ($manifests as $manifest) {
            $this->register($manifest);
        }

        do_action('spcrc/module_registry_ready', $this);
    }

    /** @param array<string,mixed> $manifest */
    public function register(array $manifest): bool
    {
        $validated = $this->validate($manifest);
        if (is_wp_error($validated)) {
            do_action('spcrc/invalid_module_manifest', $manifest, $validated);
            return false;
        }

        $key = $validated['module_key'];
        $this->manifests[$key] = $validated;
        $this->persist($validated);

        return true;
    }

    /** @return array<string,array<string,mixed>> */
    public function all(): array
    {
        return $this->manifests;
    }

    /** @return array<string,mixed>|null */
    public function get(string $moduleKey): ?array
    {
        return $this->manifests[$moduleKey] ?? null;
    }

    /**
     * @param array<string,mixed> $manifest
     * @return array<string,mixed>|\WP_Error
     */
    private function validate(array $manifest)
    {
        $required = ['module_key', 'name', 'version', 'owner', 'data_classes', 'public_routes', 'private_routes'];
        foreach ($required as $field) {
            if (! array_key_exists($field, $manifest)) {
                return new \WP_Error('spcrc_manifest_missing_field', sprintf('Missing manifest field: %s', $field));
            }
        }

        $moduleKey = sanitize_key((string) $manifest['module_key']);
        if ($moduleKey === '') {
            return new \WP_Error('spcrc_manifest_invalid_key', 'Module key is invalid.');
        }

        $manifest['module_key'] = $moduleKey;
        $manifest['name'] = sanitize_text_field((string) $manifest['name']);
        $manifest['version'] = sanitize_text_field((string) $manifest['version']);
        $manifest['owner'] = sanitize_text_field((string) $manifest['owner']);
        $manifest['posture'] = sanitize_key((string) ($manifest['posture'] ?? 'unassessed'));
        $manifest['last_security_test'] = sanitize_text_field((string) ($manifest['last_security_test'] ?? ''));

        foreach (['data_classes', 'public_routes', 'private_routes', 'capabilities', 'external_vendors'] as $listField) {
            $manifest[$listField] = array_values(array_map('sanitize_text_field', (array) ($manifest[$listField] ?? [])));
        }

        return $manifest;
    }

    /** @param array<string,mixed> $manifest */
    private function persist(array $manifest): void
    {
        global $wpdb;
        $table = $wpdb->prefix . 'spcrc_module_manifests';
        $json = wp_json_encode($manifest, JSON_UNESCAPED_SLASHES);
        if (! is_string($json)) {
            return;
        }

        $wpdb->replace(
            $table,
            [
                'module_key' => $manifest['module_key'],
                'module_version' => $manifest['version'],
                'manifest_hash' => hash('sha256', $json),
                'posture' => $manifest['posture'],
                'manifest_json' => $json,
                'last_seen_at' => current_time('mysql', true),
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s']
        );
    }

    /** @return array<string,mixed> */
    private function selfManifest(): array
    {
        return [
            'module_key' => 'file-24-security-center',
            'name' => 'Sabri Platform Security, Privacy, Compliance and Resilience Center',
            'version' => SPCRC_VERSION,
            'owner' => 'File 24',
            'posture' => 'foundation',
            'data_classes' => ['C1 Internal', 'C2 Personal Metadata', 'C5 Security Evidence References'],
            'public_routes' => ['/wp-json/sabri-security/v1/trust'],
            'private_routes' => ['/wp-admin/admin.php?page=sabri-security-center', '/wp-json/sabri-security/v1/status'],
            'capabilities' => Capabilities::all(),
            'external_vendors' => [],
            'last_security_test' => '',
        ];
    }
}
