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
                do_action(
                    'spcrc/invalid_module_manifest',
                    $manifest,
                    new \WP_Error('spcrc_manifest_not_array', 'Manifest must be an array.')
                );
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
            do_action(
                'spcrc/invalid_module_manifest',
                $manifest,
                new \WP_Error('spcrc_manifest_limit', 'Module manifest limit reached.')
            );
            return false;
        }

        $validated = $this->validate($manifest);
        if (is_wp_error($validated)) {
            do_action('spcrc/invalid_module_manifest', $manifest, $validated);
            return false;
        }

        $key = (string) $validated['module_key'];
        $memoryExisting = $this->manifests[$key] ?? null;
        if (is_array($memoryExisting) && ! $this->sameIdentity($memoryExisting, $validated)) {
            $error = new \WP_Error(
                'spcrc_manifest_identity_collision',
                'A module key cannot be rebound to a different module name or owner.'
            );
            do_action('spcrc/invalid_module_manifest', $manifest, $error);
            return false;
        }

        $persisted = $this->persist($validated);
        if (is_wp_error($persisted)) {
            do_action('spcrc/module_manifest_persist_failed', $validated, $persisted);
            return false;
        }

        // Update runtime state only after durable persistence succeeds. A failed
        // write must not make an untrusted manifest appear canonical in memory.
        $this->manifests[$key] = $validated;
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

    /** @param array<string,mixed> $manifest
     *  @return true|\WP_Error
     */
    private function persist(array $manifest): true|\WP_Error
    {
        global $wpdb;

        $table = $wpdb->prefix . 'spcrc_module_manifests';
        $json = wp_json_encode($manifest, JSON_UNESCAPED_SLASHES);
        if (! is_string($json)) {
            return new \WP_Error('spcrc_manifest_encode_failed', 'Module manifest could not be encoded.');
        }

        $hash = hash('sha256', $json);
        $existing = $this->stored($table, (string) $manifest['module_key']);
        if (is_array($existing)) {
            $storedManifest = $this->decodeStoredManifest($existing);
            if (is_wp_error($storedManifest)) {
                return $storedManifest;
            }
            if (! $this->sameIdentity($storedManifest, $manifest)) {
                return new \WP_Error(
                    'spcrc_manifest_identity_collision',
                    'A module key cannot be rebound to a different module name or owner.'
                );
            }

            if (hash_equals((string) ($existing['manifest_hash'] ?? ''), $hash)) {
                $lastSeen = strtotime((string) ($existing['last_seen_at'] ?? '') . ' UTC');
                if ($lastSeen !== false && (time() - $lastSeen) < self::HEARTBEAT_SECONDS) {
                    return true;
                }

                $heartbeat = $wpdb->update(
                    $table,
                    ['last_seen_at' => current_time('mysql', true)],
                    [
                        'module_key' => $manifest['module_key'],
                        'manifest_hash' => (string) $existing['manifest_hash'],
                    ],
                    ['%s'],
                    ['%s', '%s']
                );
                return $heartbeat === false
                    ? new \WP_Error('spcrc_manifest_heartbeat_failed', 'Module manifest heartbeat could not be stored.')
                    : true;
            }

            $written = $wpdb->update(
                $table,
                [
                    'module_version' => $manifest['version'],
                    'manifest_hash' => $hash,
                    'posture' => $manifest['posture'],
                    'manifest_json' => $json,
                    'last_seen_at' => current_time('mysql', true),
                ],
                [
                    'module_key' => $manifest['module_key'],
                    'manifest_hash' => (string) $existing['manifest_hash'],
                ],
                ['%s', '%s', '%s', '%s', '%s'],
                ['%s', '%s']
            );
            if ($written === false) {
                return new \WP_Error('spcrc_manifest_update_failed', 'Module manifest could not be updated.');
            }
            if ($written === 1) {
                return true;
            }

            return $this->resolveConcurrentWrite($table, $manifest, $hash, 'update');
        }

        $inserted = $wpdb->insert(
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
        );
        if ($inserted !== false) {
            return true;
        }

        return $this->resolveConcurrentWrite($table, $manifest, $hash, 'insert');
    }

    /** @return array<string,mixed>|null */
    private function stored(string $table, string $moduleKey): ?array
    {
        global $wpdb;

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT module_version, manifest_hash, manifest_json, last_seen_at FROM {$table} WHERE module_key = %s",
                $moduleKey
            ),
            ARRAY_A
        );
        return is_array($row) ? $row : null;
    }

    /** @param array<string,mixed> $stored
     *  @return array<string,mixed>|\WP_Error
     */
    private function decodeStoredManifest(array $stored): array|\WP_Error
    {
        $decoded = json_decode((string) ($stored['manifest_json'] ?? ''), true);
        if (! is_array($decoded)) {
            return new \WP_Error(
                'spcrc_manifest_stored_identity_invalid',
                'Stored module identity could not be verified safely.'
            );
        }
        return $decoded;
    }

    /** @param array<string,mixed> $manifest
     *  @return true|\WP_Error
     */
    private function resolveConcurrentWrite(string $table, array $manifest, string $hash, string $operation): true|\WP_Error
    {
        $current = $this->stored($table, (string) $manifest['module_key']);
        if (! is_array($current)) {
            return new \WP_Error(
                'spcrc_manifest_' . $operation . '_failed',
                'Module manifest could not be stored.'
            );
        }

        $storedManifest = $this->decodeStoredManifest($current);
        if (is_wp_error($storedManifest)) {
            return $storedManifest;
        }
        if (! $this->sameIdentity($storedManifest, $manifest)) {
            return new \WP_Error(
                'spcrc_manifest_identity_collision',
                'A concurrent writer attempted to bind the module key to a different identity.'
            );
        }
        if (hash_equals((string) ($current['manifest_hash'] ?? ''), $hash)) {
            return true;
        }

        return new \WP_Error(
            'spcrc_manifest_concurrent_' . $operation,
            'Module manifest changed concurrently and was not overwritten.'
        );
    }

    /** @param array<string,mixed> $left
     *  @param array<string,mixed> $right
     */
    private function sameIdentity(array $left, array $right): bool
    {
        return hash_equals(
            Sanitizer::text($left['name'] ?? '', 200),
            Sanitizer::text($right['name'] ?? '', 200)
        ) && hash_equals(
            Sanitizer::text($left['owner'] ?? '', 120),
            Sanitizer::text($right['owner'] ?? '', 120)
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
            'private_routes' => [
                '/wp-admin/admin.php?page=sabri-security-center',
                '/wp-admin/admin.php?page=sabri-security-findings',
                '/wp-admin/admin.php?page=sabri-security-privacy-requests',
                '/wp-admin/admin.php?page=sabri-security-assurance',
                '/wp-json/sabri-security/v1/status',
            ],
            'capabilities' => Capabilities::all(),
            'external_vendors' => [],
            'privacy_operations' => [],
            'last_security_test' => '',
        ];
    }
}
