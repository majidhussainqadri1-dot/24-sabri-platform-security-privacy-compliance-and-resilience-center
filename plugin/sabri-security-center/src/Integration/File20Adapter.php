<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Integration;

final class File20Adapter
{
    public function registerHooks(): void
    {
        add_filter('spcrc/file20_adapter_available', [$this, 'adapterAvailable']);
        add_filter('spcrc/module_manifests', [$this, 'manifest']);
        add_filter('spcrc/file20_safe_mode_active', [$this, 'safeModeActive']);
        add_action('spcrc/security_state_requested', [$this, 'observeStateRequest']);
    }

    public function available(): bool
    {
        return defined('SABRI_SHELL_VERSION')
            && class_exists('Sabri\\UnifiedShell\\SafeMode');
    }

    public function adapterAvailable(bool $current): bool
    {
        return $current || $this->available();
    }

    public function safeModeActive(bool $current): bool
    {
        if ($current || ! $this->available()) {
            return $current;
        }

        return (bool) \Sabri\UnifiedShell\SafeMode::disabled();
    }

    /** @param mixed $manifests
     *  @return array<int,array<string,mixed>>
     */
    public function manifest(mixed $manifests): array
    {
        $manifests = is_array($manifests) ? $manifests : [];
        if (! $this->available()) {
            return $manifests;
        }

        $manifests[] = [
            'module_key' => 'file-20-unified-shell',
            'name' => 'Sabri Unified Application Shell',
            'version' => (string) SABRI_SHELL_VERSION,
            'owner' => 'File 20',
            'posture' => 'foundation',
            'data_classes' => ['C1 Internal Configuration'],
            'public_routes' => ['/'],
            'private_routes' => ['/wp-admin/admin.php?page=sabri-shell'],
            'capabilities' => ['manage_options'],
            'external_vendors' => [],
            'privacy_operations' => [],
            'last_security_test' => '',
        ];

        return $manifests;
    }

    /** @param array<string,mixed> $record */
    public function observeStateRequest(array $record): void
    {
        if (! $this->available()) {
            return;
        }

        // Foundation 0.25.1 deliberately does not mutate File 20 settings.
        // It exposes a reviewed observation hook until File 20 adds a native,
        // versioned enforcement contract.
        do_action('spcrc/file20_security_state_observed', $record, \Sabri\UnifiedShell\SafeMode::disabled());
    }
}
