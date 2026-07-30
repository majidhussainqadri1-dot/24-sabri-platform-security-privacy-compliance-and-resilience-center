<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Registry;

use Sabri\Platform\Security\Capabilities;
use Sabri\Platform\Security\Storage\Schema;

final class ModuleRegistry
{
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

        $manifests = apply_filters('spcrc/module_manifests', []);
        if (! is_array($manifests)) {
            do_action('spcrc/invalid_module_manifest_collection', $manifests);
            $manifests = [];
        }

        foreach (array_slice($manifests, 0, 100) as $manifest) {
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
        $validated = $this->validate($manifest);
        if (is_wp_error($validated)) {
            do_action('spcrc/invalid_module_manifest', $manifest, $validated);
            return false;
        }

        $key = (string) $validated['module_key'];
        if (isset($this->manifests[$key])) {
            $existing = $this->manifests[$key];
            if (! hash_equals($this->manifestHash($existing), $this->manifestHash($validated))) {
                do_action('spcrc/module_manifest_conflict', $key, $existing, $validated);
                return false;
            }
            return true;
        }

        if (! $this->persist($validated)) {
            do_action('spcrc/module_manifest_persist_failed', $validated);
            return false;
        }

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
        return $this->manifests[$this->truncate(sanitize_key($moduleKey), 120)] ?? null;
    }

    public function companionCount(): int
    {
        return count(array_filter(
            array_keys($this->manifests),
            static fn (string $key): bool => $key !== 'file-24-security-center'
        ));
    }

    /** @param array<string,mixed> $manifest
     *  @return array<string,mixed>|\WP_Error
     */
    private function validate(array $manifest)
    {
        $required = ['module_key', 'name', 'version', 'owner', 'data_classes', 'public_routes', 'private_routes'];
        foreach ($required as $field) {
            if (! array_key_exists($field, $manifest)) {
                return new \WP_Error('spcrc_manifest_missing_field', sprintf('Missing manifest field: %s', $field));
            }
        }

        $moduleKey = $this->truncate(sanitize_key((string) $manifest['module_key']), 120);
        $name = $this->truncate(sanitize_text_field((string) $manifest['name']), 200);
        $version = $this->truncate(sanitize_text_field((string) $manifest['version']), 60);
        $owner = $this->truncate(sanitize_text_field((string) $manifest['owner']), 120);
        if ($moduleKey === '' || $name === '' || $version === '' || $owner === '') {
            return new \WP_Error('spcrc_manifest_invalid_identity', 'Module key, name, version, and owner are required.');
        }

        $allowedPostures = ['unassessed', 'foundation', 'unknown', 'warning', 'critical', 'pass'];
        $posture = sanitize_key((string) ($manifest['posture'] ?? 'unassessed'));
        if (! in_array($posture, $allowedPostures, true)) {
            $posture = 'unassessed';
        }

        // Return a canonical allowlisted record so arbitrary fields or secrets cannot enter the registry.
        return [
            'module_key' => $moduleKey,
            'name' => $name,
            'version' => $version,
            'owner' => $owner,
            'posture' => $posture,
            'data_classes' => $this->sanitizeList((array) $manifest['data_classes']),
            'public_routes' => $this->sanitizeList((array) $manifest['public_routes']),
            'private_routes' => $this->sanitizeList((array) $manifest['private_routes']),
            'capabilities' => $this->sanitizeList((array) ($manifest['capabilities'] ?? [])),
            'external_vendors' => $this->sanitizeList((array) ($manifest['external_vendors'] ?? [])),
            'last_security_test' => $this->normalizeDate((string) ($manifest['last_security_test'] ?? '')),
        ];
    }

    /** @param mixed[] $values
     *  @return string[]
     */
    private function sanitizeList(array $values): array
    {
        $clean = [];
        foreach (array_slice($values, 0, 100) as $value) {
            if (! is_scalar($value)) {
                continue;
            }
            $item = $this->truncate(sanitize_text_field((string) $value), 255);
            if ($item !== '') {
                $clean[] = $item;
            }
        }

        return array_values(array_unique($clean));
    }

    /** @param array<string,mixed> $manifest */
    private function persist(array $manifest): bool
    {
        global $wpdb;
        $table = Schema::tables()['manifests'];
        $json = wp_json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (! is_string($json)) {
            return false;
        }

        $now = current_time('mysql', true);
        $hash = hash('sha256', $json);
        $existing = $wpdb->get_row(
            $wpdb->prepare("SELECT id, manifest_hash, manifest_json, last_seen_at FROM {$table} WHERE module_key = %s", $manifest['module_key']),
            ARRAY_A
        );

        if (is_array($existing) && (int) ($existing['id'] ?? 0) > 0) {
            $stored = json_decode((string) ($existing['manifest_json'] ?? ''), true);
            if (is_array($stored) && $this->identityChanged($stored, $manifest)) {
                $authorized = (bool) apply_filters(
                    'spcrc/authorize_module_manifest_identity_change',
                    false,
                    $stored,
                    $manifest
                );
                if (! $authorized) {
                    do_action('spcrc/module_manifest_identity_conflict', $manifest['module_key'], $stored, $manifest);
                    return false;
                }
            }

            $sameHash = hash_equals((string) ($existing['manifest_hash'] ?? ''), $hash);
            $lastSeen = strtotime((string) ($existing['last_seen_at'] ?? '')) ?: 0;
            if ($sameHash && $lastSeen >= (time() - HOUR_IN_SECONDS)) {
                return true;
            }

            $data = ['last_seen_at' => $now];
            $formats = ['%s'];
            if (! $sameHash) {
                $data = [
                    'module_version' => $manifest['version'],
                    'manifest_hash' => $hash,
                    'posture' => $manifest['posture'],
                    'manifest_json' => $json,
                    'last_seen_at' => $now,
                ];
                $formats = ['%s', '%s', '%s', '%s', '%s'];
            }

            return $wpdb->update(
                $table,
                $data,
                ['id' => (int) $existing['id']],
                $formats,
                ['%d']
            ) !== false;
        }

        return $wpdb->insert(
            $table,
            [
                'module_key' => $manifest['module_key'],
                'module_version' => $manifest['version'],
                'manifest_hash' => $hash,
                'posture' => $manifest['posture'],
                'manifest_json' => $json,
                'first_seen_at' => $now,
                'last_seen_at' => $now,
            ],
            ['%s', '%s', '%s', '%s', '%s', '%s', '%s']
        ) !== false;
    }

    /** @param array<string,mixed> $stored
     *  @param array<string,mixed> $incoming
     */
    private function identityChanged(array $stored, array $incoming): bool
    {
        return (string) ($stored['name'] ?? '') !== (string) $incoming['name']
            || (string) ($stored['owner'] ?? '') !== (string) $incoming['owner'];
    }

    /** @param array<string,mixed> $manifest */
    private function manifestHash(array $manifest): string
    {
        return hash('sha256', (string) wp_json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
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

    private function normalizeDate(string $value): string
    {
        if ($value === '') {
            return '';
        }
        $timestamp = strtotime($value);
        if ($timestamp === false || $timestamp > (time() + 300)) {
            return '';
        }
        return gmdate('c', $timestamp);
    }

    private function truncate(string $value, int $length): string
    {
        return function_exists('mb_substr') ? mb_substr($value, 0, $length) : substr($value, 0, $length);
    }
}
