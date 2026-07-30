<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Admin;

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\System\SystemCheck;

final class Dashboard
{
    public function __construct(
        private ModuleRegistry $modules,
        private SecurityStateRegistry $states,
        private SystemCheck $checks,
        private AuditLogger $audit
    ) {
    }

    public function registerHooks(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        add_action('admin_post_spcrc_run_system_check', [$this, 'handleSystemCheck']);
    }

    public function menu(): void
    {
        add_menu_page(
            __('Security Center', 'sabri-security-center'),
            __('Security Center', 'sabri-security-center'),
            'spcrc_view_overview',
            'sabri-security-center',
            [$this, 'render'],
            'dashicons-shield-alt',
            3
        );
    }

    public function assets(string $hook): void
    {
        if ($hook !== 'toplevel_page_sabri-security-center') {
            return;
        }

        wp_enqueue_style('spcrc-admin', SPCRC_PLUGIN_URL . 'assets/admin.css', [], SPCRC_VERSION);
    }

    public function handleSystemCheck(): void
    {
        if (! current_user_can('spcrc_run_security_assessments')) {
            wp_die(esc_html__('You are not allowed to run security assessments.', 'sabri-security-center'));
        }

        check_admin_referer('spcrc_run_system_check');
        $checks = $this->checks->run();
        set_transient('spcrc_last_system_check_' . get_current_user_id(), $checks, 10 * MINUTE_IN_SECONDS);
        $this->audit->record('system_check_run', 'file-24-security-center', 'completed', 'informational', ['check_count' => count($checks)]);

        wp_safe_redirect(add_query_arg(['page' => 'sabri-security-center', 'checked' => '1'], admin_url('admin.php')));
        exit;
    }

    public function render(): void
    {
        if (! current_user_can('spcrc_view_overview')) {
            wp_die(esc_html__('You are not allowed to view the Security Center.', 'sabri-security-center'));
        }

        $checks = get_transient('spcrc_last_system_check_' . get_current_user_id());
        if (! is_array($checks)) {
            $checks = $this->checks->run();
        }

        $manifests = $this->modules->all();
        $stateRequests = $this->states->all();
        ?>
        <div class="wrap spcrc-wrap">
            <h1><?php esc_html_e('Sabri Platform Security Center', 'sabri-security-center'); ?></h1>
            <p class="spcrc-intro"><?php esc_html_e('Central governance and assurance dashboard. Native modules retain their own authentication, authorization, and data ownership.', 'sabri-security-center'); ?></p>

            <div class="spcrc-grid" aria-label="<?php esc_attr_e('Security overview', 'sabri-security-center'); ?>">
                <?php $this->metric(__('Registered modules', 'sabri-security-center'), (string) count($manifests)); ?>
                <?php $this->metric(__('Open state requests', 'sabri-security-center'), (string) count($stateRequests)); ?>
                <?php $this->metric(__('Plugin version', 'sabri-security-center'), SPCRC_VERSION); ?>
                <?php $this->metric(__('Environment', 'sabri-security-center'), wp_get_environment_type()); ?>
            </div>

            <section class="spcrc-panel">
                <div class="spcrc-panel-heading">
                    <h2><?php esc_html_e('System checks', 'sabri-security-center'); ?></h2>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="spcrc_run_system_check">
                        <?php wp_nonce_field('spcrc_run_system_check'); ?>
                        <?php submit_button(__('Run checks', 'sabri-security-center'), 'secondary', 'submit', false); ?>
                    </form>
                </div>
                <table class="widefat striped">
                    <thead><tr><th><?php esc_html_e('Check', 'sabri-security-center'); ?></th><th><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th><?php esc_html_e('Detail', 'sabri-security-center'); ?></th></tr></thead>
                    <tbody>
                    <?php foreach ($checks as $check) : ?>
                        <tr>
                            <td><?php echo esc_html((string) $check['label']); ?></td>
                            <td><span class="spcrc-status spcrc-status--<?php echo esc_attr((string) $check['status']); ?>"><?php echo esc_html(strtoupper((string) $check['status'])); ?></span></td>
                            <td><?php echo esc_html((string) $check['detail']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </section>

            <section class="spcrc-panel">
                <h2><?php esc_html_e('Module posture', 'sabri-security-center'); ?></h2>
                <table class="widefat striped">
                    <thead><tr><th><?php esc_html_e('Module', 'sabri-security-center'); ?></th><th><?php esc_html_e('Version', 'sabri-security-center'); ?></th><th><?php esc_html_e('Owner', 'sabri-security-center'); ?></th><th><?php esc_html_e('Posture', 'sabri-security-center'); ?></th></tr></thead>
                    <tbody>
                    <?php foreach ($manifests as $manifest) : ?>
                        <tr>
                            <td><?php echo esc_html((string) $manifest['name']); ?></td>
                            <td><?php echo esc_html((string) $manifest['version']); ?></td>
                            <td><?php echo esc_html((string) $manifest['owner']); ?></td>
                            <td><?php echo esc_html((string) $manifest['posture']); ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </section>

            <div class="notice notice-info inline">
                <p><?php esc_html_e('This dashboard never displays passwords, OTPs, encryption keys, identity documents, patient records, or private message bodies.', 'sabri-security-center'); ?></p>
            </div>
        </div>
        <?php
    }

    private function metric(string $label, string $value): void
    {
        ?>
        <div class="spcrc-card">
            <span class="spcrc-card__label"><?php echo esc_html($label); ?></span>
            <strong class="spcrc-card__value"><?php echo esc_html($value); ?></strong>
        </div>
        <?php
    }
}
