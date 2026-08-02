<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Admin;

final class AssetLoader
{
    private const PAGES = [
        'sabri-security-findings',
        'sabri-security-privacy-requests',
        'sabri-security-assurance',
    ];

    public function registerHooks(): void
    {
        add_action('admin_enqueue_scripts', [$this, 'enqueue']);
    }

    public function enqueue(string $hook): void
    {
        $page = isset($_GET['page']) ? sanitize_key((string) wp_unslash($_GET['page'])) : '';
        if (! in_array($page, self::PAGES, true)) {
            return;
        }

        wp_enqueue_style('spcrc-admin', SPCRC_PLUGIN_URL . 'assets/admin.css', [], SPCRC_VERSION);
    }
}
