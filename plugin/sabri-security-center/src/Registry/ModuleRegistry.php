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
        if (preg_match('/^\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?$/', $version) !== 1) {
            return new \WP_Error('spcrc_manifest_version_invalid', 'Manifest version must use a bounded numeric release identity.');
        }

        $posture = Sanitizer::key($manifest['posture'] ?? 'unassessed', 40);
        if (! in_array($posture, self::ALLOWED_POSTURES, true)) {
            $posture = 'unassessed';
        }
        foreach ([$name, $version, $owner] as $identityValue) {
            if (Sanitizer::containsSensitiveMaterial($identityValue)) {
                return new \WP_Error('spcrc_manifest_sensitive_identity', 'Manifest identity fields must not contain URLs, contact data, credentials or storage paths.');
            }
        }
        $publicRoutes = $this->routes($manifest['public_routes']);
        $privateRoutes = $this->routes($manifest['private_routes']);
        if (is_wp_error($publicRoutes) || is_wp_error($privateRoutes)) {
            return is_wp_error($publicRoutes) ? $publicRoutes : $privateRoutes;
        }
        $lastSecurityTest = Sanitizer::isoTime($manifest['last_security_test'] ?? '');
        if ($lastSecurityTest !== '' && strtotime($lastSecurityTest) > time() + 300) {
            return new \WP_Error('spcrc_manifest_security_test_future', 'Manifest security-test evidence cannot be dated in the future.');
        }
        $contractVersion = Sanitizer::text($manifest['contract_version'] ?? '1.0.0', 40);
        if (preg_match('/^\d+\.\d+(?:\.\d+)?$/', $contractVersion) !== 1) {
            return new \WP_Error('spcrc_manifest_contract_version_invalid', 'Manifest contract version must be explicit and numeric.');
        }
        $canonicalDataOwner = Sanitizer::text($manifest['canonical_data_owner'] ?? $owner, 120);
        $canonicalActionOwner = Sanitizer::text($manifest['canonical_action_owner'] ?? $owner, 160);
        $evidenceSource = Sanitizer::opaqueReference($manifest['evidence_source'] ?? '');
        foreach ([$canonicalDataOwner, $canonicalActionOwner] as $canonicalOwner) {
            if ($canonicalOwner === '' || Sanitizer::containsSensitiveMaterial($canonicalOwner)) {
                return new \WP_Error('spcrc_manifest_canonical_owner_invalid', 'Canonical ownership statements must be bounded and non-sensitive.');
            }
        }
        $dataClasses = $this->safeList($manifest['data_classes'], 20, 120, 'data_classes');
        $capabilities = $this->safeList($manifest['capabilities'] ?? [], 100, 120, 'capabilities');
        $externalVendors = $this->safeList($manifest['external_vendors'] ?? [], 50, 160, 'external_vendors');
        $privacyOperations = $this->safeList($manifest['privacy_operations'] ?? [], 20, 60, 'privacy_operations');
        foreach ([$dataClasses, $capabilities, $externalVendors, $privacyOperations] as $list) {
            if (is_wp_error($list)) {
                return $list;
            }
        }
        $degradedBehavior = Sanitizer::text($manifest['degraded_behavior'] ?? 'Unknown/unavailable; no permissive fallback.', 300);
        $releaseGate = Sanitizer::text($manifest['release_gate'] ?? 'Evidence not supplied.', 300);
        if (Sanitizer::containsSensitiveMaterial($degradedBehavior) || Sanitizer::containsSensitiveMaterial($releaseGate)) {
            return new \WP_Error('spcrc_manifest_sensitive_operational_text', 'Manifest operational text must not contain URLs, contact data, credentials or storage paths.');
        }

        return [
            'module_key' => $moduleKey,
            'name' => $name,
            'version' => $version,
            'owner' => $owner,
            'posture' => $posture,
            'data_classes' => $dataClasses,
            'public_routes' => $publicRoutes,
            'private_routes' => $privateRoutes,
            'capabilities' => $capabilities,
            'external_vendors' => $externalVendors,
            'privacy_operations' => $privacyOperations,
            'last_security_test' => $lastSecurityTest,
            'contract_version' => $contractVersion,
            'canonical_data_owner' => $canonicalDataOwner,
            'canonical_action_owner' => $canonicalActionOwner,
            'evidence_source' => $evidenceSource,
            'degraded_behavior' => $degradedBehavior,
            'release_gate' => $releaseGate,
        ];
    }


    /** @return string[]|\WP_Error */
    private function routes(mixed $routes): array|\WP_Error
    {
        if (! is_array($routes)) {
            return new \WP_Error('spcrc_manifest_routes_invalid', 'Manifest routes must be a bounded array of same-origin absolute paths.');
        }
        $safe = [];
        foreach (array_slice($routes, 0, 50) as $route) {
            if (! is_scalar($route) && $route !== null) {
                return new \WP_Error('spcrc_manifest_route_invalid', 'Manifest route is invalid.');
            }
            $route = trim((string) $route);
            if (
                $route === ''
                || strlen($route) > 300
                || ! str_starts_with($route, '/')
                || str_starts_with($route, '//')
                || str_contains($route, '\\')
                || str_contains($route, '?')
                || str_contains($route, '#')
                || preg_match('/[\x00-\x1F\x7F]/', $route) === 1
                || preg_match('/^[a-z][a-z0-9+.-]*:\/\//i', $route) === 1
                || preg_match('/(?:^|\/)\.{1,2}(?:\/|$)/', rawurldecode($route)) === 1
                || preg_match('/%(?:2e|2f|5c)/i', $route) === 1
            ) {
                return new \WP_Error('spcrc_manifest_route_invalid', 'Manifest routes must be same-origin absolute paths without query strings, fragments or credentials.');
            }
            $safe[] = $route;
        }
        return array_values(array_unique($safe));
    }

    /** @param array<string,mixed> $manifest
     *  @return bool|\WP_Error
     */
    private function persist(array $manifest): bool|\WP_Error
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
                if ($heartbeat === false) {
                    return new \WP_Error('spcrc_manifest_heartbeat_failed', 'Module manifest heartbeat could not be stored.');
                }
                if ($heartbeat === 1) {
                    return true;
                }

                // A zero-row heartbeat is not success: a concurrent writer may
                // have changed the manifest hash after the initial read. Re-read
                // and accept only an identical, identity-bound manifest.
                return $this->resolveConcurrentWrite($table, $manifest, $hash, 'heartbeat');
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
        if ($inserted === 1) {
            return true;
        }
        if ($inserted !== false) {
            return new \WP_Error('spcrc_manifest_insert_inexact', 'Module manifest insert did not store exactly one row.');
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
        $json = (string) ($stored['manifest_json'] ?? '');
        $storedHash = strtolower((string) ($stored['manifest_hash'] ?? ''));
        if (preg_match('/^[0-9a-f]{64}$/', $storedHash) !== 1 || ! hash_equals($storedHash, hash('sha256', $json))) {
            return new \WP_Error('spcrc_manifest_stored_hash_invalid', 'Stored module manifest hash does not match its canonical JSON evidence.');
        }
        $decoded = json_decode($json, true);
        if (! is_array($decoded)) {
            return new \WP_Error(
                'spcrc_manifest_stored_identity_invalid',
                'Stored module identity could not be verified safely.'
            );
        }
        $decodedVersion = Sanitizer::text($decoded['version'] ?? '', 60);
        if ($decodedVersion === '' || ! hash_equals($decodedVersion, Sanitizer::text($stored['module_version'] ?? '', 60))) {
            return new \WP_Error('spcrc_manifest_stored_version_invalid', 'Stored module version does not match its canonical manifest evidence.');
        }
        return $decoded;
    }

    /** @return string[]|\WP_Error */
    private function safeList(mixed $values, int $maxItems, int $maxLength, string $field): array|\WP_Error
    {
        if (! is_array($values)) {
            return new \WP_Error('spcrc_manifest_list_invalid', sprintf('Manifest field %s must be a bounded list.', $field));
        }
        $safe = [];
        foreach (array_slice($values, 0, max(0, $maxItems)) as $value) {
            if (! is_scalar($value) && $value !== null) {
                return new \WP_Error('spcrc_manifest_list_value_invalid', sprintf('Manifest field %s contains an invalid value.', $field));
            }
            $value = Sanitizer::text($value, $maxLength);
            if ($value === '' || Sanitizer::containsSensitiveMaterial($value)) {
                return new \WP_Error('spcrc_manifest_list_sensitive', sprintf('Manifest field %s contains sensitive or unsafe material.', $field));
            }
            $safe[] = $value;
        }
        return array_values(array_unique($safe));
    }

    /** @param array<string,mixed> $manifest
     *  @return bool|\WP_Error
     */
    private function resolveConcurrentWrite(string $table, array $manifest, string $hash, string $operation): bool|\WP_Error
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
                '/wp-admin/admin.php?page=sabri-security-governance',
                '/wp-json/sabri-security/v1/status',
            ],
            'capabilities' => Capabilities::all(),
            'external_vendors' => [],
            'privacy_operations' => [],
            'last_security_test' => '',
            'contract_version' => '1.0.0',
            'canonical_data_owner' => 'File 24',
            'canonical_action_owner' => 'Native owners; File 24 assurance only',
            'evidence_source' => 'release:file-24-0.28.0',
            'degraded_behavior' => 'Native controls remain authoritative; privileged assurance writes fail closed.',
            'release_gate' => 'Staging, independent penetration test, restore drill and Founder production approval',
        ];
    }
}
