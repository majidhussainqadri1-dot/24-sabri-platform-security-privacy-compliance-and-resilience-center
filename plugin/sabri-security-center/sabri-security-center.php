<?php
/**
 * Plugin Name: Sabri Platform Security, Privacy, Compliance and Resilience Center
 * Plugin URI:  https://sabrihomeopathy.com/
 * Description: Central security governance and assurance control plane for the Sabri Social Homeopathy Platform.
 * Version:     0.25.4
 * Author:      Dr. Allamah Majid Hussain Sabri Muhaddith Mursheed
 * Text Domain: sabri-security-center
 * Requires at least: 6.5
 * Requires PHP: 8.0
 * License:     GPL-2.0-or-later
 */

declare(strict_types=1);

if (! defined('ABSPATH')) {
    exit;
}

define('SPCRC_VERSION', '0.25.4');
define('SPCRC_PLUGIN_FILE', __FILE__);
define('SPCRC_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('SPCRC_PLUGIN_URL', plugin_dir_url(__FILE__));

spl_autoload_register(static function (string $class): void {
    $prefix = 'Sabri\\Platform\\Security\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $path = SPCRC_PLUGIN_DIR . 'src/' . str_replace('\\', '/', $relative) . '.php';

    if (is_readable($path)) {
        require_once $path;
    }
});

register_activation_hook(__FILE__, [Sabri\Platform\Security\Activation::class, 'activate']);
register_deactivation_hook(__FILE__, [Sabri\Platform\Security\Deactivation::class, 'deactivate']);

add_action('plugins_loaded', static function (): void {
    Sabri\Platform\Security\Plugin::instance()->boot();
}, 20);
