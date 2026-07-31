<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

use Sabri\Platform\Security\Capabilities;
use Sabri\Platform\Security\Support\Sanitizer;

final class ModuleRegistry
{
    private const MAX_MANIFESTS = 100;
    private const HEARTBEAT_SECONDS = 3600;
    private const ALLOWED_POSTURES = ['unassessed', 'foundation', 'warning', 'critical', 'accepted', 'operational'];

    /** @var array<string,array<string,mixed>> */
    private array $manifests = [];
    private bool $collected = false;

    public function registerHooks(): void
    {
        add_action('spcrc/register_module_manifest', [$this, 'register'], 10, 1);
        add_action('init', [$this, 'collect'], 50);
    }

    public function collect(): void
    {
        if ($this->collected) {
            return;
        }
        $this->collected = true;

        $this->register($this->selfManifest());
        $filtered = apply_filters('spcrc/module_manifests', []);
        if (! is_array($filtered)) {
            do_action('spcrc/invalid_module_manifest_collection', $filtered);
            $filtered = [];
        }

        foreach (array_slice($filtered, 0, self::MAX_MANIFESTS - 1) as $manifest) {
            if (! is_array($manifest)) {
                do_action('spcrc/invalid_module_manifest', $manifest, new \WP_Error('spcrc_manifest_not_array', 'Manifest must be an array.'));
                continue;
            }
            $this->register($manifest);
        }

        do_action('spcrc/module_registry_ready', $this);
    }

    /** @param array<string,mixed> $manifest */
    public function register(array $manifest): bool
    {
        $incomingKey = Sanitizer::key($manifest['module_key'] ?? '', 120);
        if (! isset($this->manifests[$incomingKey]) && count($this->manifests) >= self::MAX_MANIFESTS) {
            do_action('spcrc/invalid_module_manifest', $manifest, new \WP_Error('spcrc_manifest_limit', 'Module manifest limit reached.'));
            return false;
        }

        $validated = $this->validate($manifest);
        if (is_wp_error($validated)) {
            do_action('spcrc/invalid_module_manifest', $manifest, $validated);
            return false;
        }

        $key = $validated['module_key'];
        $this->manifests[$key] = $validated;
        $persisted = $this->persist($validated);
        if (! $persisted) {
            do_action('spcrc/module_manifest_persist_failed', $validated);
        }

        return $persisted;
    }

    /** @return array<string,array<string,mixed>> */
    public function all(): array
    {
        return $this->manifests;
    }

    /** @return array<string,mixed>|null */
    public function get(string $moduleKey): ?array
    {
        return $this->manifests[Sanitizer::key($moduleKey)] ?? null;
    }

    public function has(string $moduleKey): bool
    {
        return $this->get($moduleKey) !== null;
    }

    /** @param array<string,mixed> $manifest
     *  @return array<string,mixed>|\WP_Error
     */
    public function validate(array $manifest): array|\WP_Error
    {
        $required = ['module_key', 'name', 'version', 'owner', 'data_classes', 'public_routes', 'private_routes'];
        foreach ($required as $field) {
            if (! array_key_exists($field, $manifest)) {
                return new \WP_Error('spcrc_manifest_missing_field', sprintf('Missing manifest field: %s', $field));
            }
        }

        $moduleKey = Sanitizer::key($manifest['module_key'], 120);
        $name = Sanitizer::text($manifest['name'], 200);
        $version = Sanitizer::text($manifest['version'], 60);
        $owner = Sanitizer::text($manifest['owner'], 120);
        if ($moduleKey === '' || $name === '' || $version === '' || $owner === '') {
            return new \WP_Error('spcrc_manifest_invalid_identity', 'Manifest identity fields are invalid.');
        }

        $posture = Sanitizer::key($manifest['posture'] ?? 'unassessed', 40);
        if (! in_array($posture, self::ALLOWED_POSTURES, true)) {
            $posture = 'unassessed';
        }

        return [
            'module_key' => $moduleKey,
            'name' => $name,
            'version' => $version,
            'owner' => $owner,
            'posture' => $posture,
            'data_classes' => Sanitizer::textList($manifest['data_classes'], 20, 120),
            'public_routes' => Sanitizer::textList($manifest['public_routes'], 50, 300),
            'private_routes' => Sanitizer::textList($manifest['private_routes'], 50, 300),
            'capabilities' => Sanitizer::textList($manifest['capabilities'] ?? [], 100, 120),
            'external_vendors' => Sanitizer::textList($manifest['external_vendors'] ?? [], 50, 160),
            'privacy_operations' => Sanitizer::textList($manifest['privacy_operations'] ?? [], 20, 60),
            'last_security_test' => Sanitizer::isoTime($manifest['last_security_test'] ?? ''),
        ];
    }

    /** @param array<string,mixed> $manifest */
    private function persist(array $manifest): bool
    {
        global $wpdb;
        $table = $wpdb->prefix . 'spcrc_module_manifests';
        $json = wp_json_encode($manifest, JSON_UNESCAPED_SLASHES);
        if (! is_string($json)) {
            return false;
        }

        $hash = hash('sha256', $json);
        $existing = $wpdb->get_row(
            $wpdb->prepare("SELECT manifest_hash, last_seen_at FROM {$table} WHERE module_key = %s", $manifest['module_key']),
            ARRAY_A
        );

        if (is_array($existing) && hash_equals((string) $existing['manifest_hash'], $hash)) {
            $lastSeen = strtotime((string) $existing['last_seen_at'] . ' UTC');
            if ($lastSeen !== false && (time() - $lastSeen) < self::HEARTBEAT_SECONDS) {
                return true;
            }

            return $wpdb->update(
                $table,
                ['last_seen_at' => current_time('mysql', true)],
                ['module_key' => $manifest['module_key']],
                ['%s'],
                ['%s']
            ) !== false;
        }

        return $wpdb->replace(
            $table,
            [
                'module_key' => $manifest['module_key'],
                'module_version' => $manifest['version'],
                'manifest_hash' => $hash,
                'posture' => $manifest['posture'],
                'manifest_json' => $json,
                'last_seen_at' => current_time('mysql', true),
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s']
        ) !== false;
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
            'private_routes' => ['/wp-admin/admin.php?page=sabri-security-center', '/wp-admin/admin.php?page=sabri-security-findings', '/wp-admin/admin.php?page=sabri-security-privacy-requests', '/wp-json/sabri-security/v1/status'],
            'capabilities' => Capabilities::all(),
            'external_vendors' => [],
            'privacy_operations' => [],
            'last_security_test' => '',
        ];
    }
}
