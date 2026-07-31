<?php

declare(strict_types=1);

const SPCRC_PLUGIN_URL = 'https://example.test/wp-content/plugins/sabri-security-center/';
const SPCRC_VERSION = '0.25.1';

$GLOBALS['enqueued_styles'] = [];
function sanitize_key(string $value): string { return preg_replace('/[^a-z0-9_\-]/', '', strtolower($value)) ?? ''; }
function wp_unslash(mixed $value): mixed { return $value; }
function wp_enqueue_style(string $handle, string $src, array $deps = [], string|bool|null $version = false): void
{
    $GLOBALS['enqueued_styles'][$handle] = [$src, $version];
}

require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Admin/AssetLoader.php';

use Sabri\Platform\Security\Admin\AssetLoader;

function expectAdminAsset(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$loader = new AssetLoader();

$_GET['page'] = 'sabri-security-findings';
$loader->enqueue('security-center_page_sabri-security-findings');
expectAdminAsset(isset($GLOBALS['enqueued_styles']['spcrc-admin']), 'Findings submenu must load the shared Security Center stylesheet.');

$GLOBALS['enqueued_styles'] = [];
$_GET['page'] = 'sabri-security-privacy-requests';
$loader->enqueue('security-center_page_sabri-security-privacy-requests');
expectAdminAsset(isset($GLOBALS['enqueued_styles']['spcrc-admin']), 'Privacy submenu must load the shared Security Center stylesheet.');

$GLOBALS['enqueued_styles'] = [];
$_GET['page'] = 'unrelated-page';
$loader->enqueue('settings_page_unrelated-page');
expectAdminAsset($GLOBALS['enqueued_styles'] === [], 'Unrelated admin pages must not receive File 24 styles.');

$css = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/assets/admin.css');
expectAdminAsset(is_string($css) && str_contains($css, '.spcrc-table-scroll') && str_contains($css, 'overflow-x: auto'), 'Responsive table containment must exist in the actual stylesheet.');

echo "PASS: scoped admin assets and responsive table containment\n";
