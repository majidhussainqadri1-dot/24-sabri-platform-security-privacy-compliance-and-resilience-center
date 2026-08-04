<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Admin;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Support\Sanitizer;

/** Capability-protected wp-admin fallback for all governed metadata domains. */
final class RegistryAdmin
{
    public function __construct(private GovernedArtifactRegistry $artifacts)
    {
    }

    public function registerHooks(): void
    {
        add_action('admin_menu', [$this, 'menu'], 20);
        add_action('admin_post_spcrc_save_governed_artifact', [$this, 'save']);
    }

    public function menu(): void
    {
        add_submenu_page(
            'sabri-security-center',
            __('Governed Registries', 'sabri-security-center'),
            __('Governed Registries', 'sabri-security-center'),
            'spcrc_view_overview',
            'sabri-security-registries',
            [$this, 'render']
        );
    }

    public function save(): void
    {
        $type = Sanitizer::key($_POST['artifact_type'] ?? '', 60);
        $capability = self::requiredCapability($type);
        if ($type === '' || ! current_user_can($capability)) {
            wp_die(esc_html__('You are not allowed to manage this governed registry.', 'sabri-security-center'));
        }
        if (check_admin_referer('spcrc_save_governed_artifact') === false) {
            wp_die(esc_html__('The security token is invalid or expired.', 'sabri-security-center'));
        }
        $payloadRaw = is_scalar($_POST['payload_json'] ?? null) ? (string) wp_unslash($_POST['payload_json']) : '{}';
        $payload = json_decode($payloadRaw, true);
        if (! is_array($payload)) {
            $payload = [];
        }
        $result = $this->artifacts->save([
            'artifact_type' => $type,
            'artifact_key' => $_POST['artifact_key'] ?? '',
            'title' => $_POST['title'] ?? '',
            'status' => $_POST['status'] ?? '',
            'classification' => $_POST['classification'] ?? 'C1',
            'module_key' => $_POST['module_key'] ?? 'file-24-security-center',
            'owner_user_id' => get_current_user_id(),
            'evidence_ref' => $_POST['evidence_ref'] ?? '',
            'effective_at' => $_POST['effective_at'] ?? '',
            'expires_at' => $_POST['expires_at'] ?? '',
            'reviewed_at' => $_POST['reviewed_at'] ?? '',
            'next_review_at' => $_POST['next_review_at'] ?? '',
            'payload' => $payload,
        ], absint($_POST['expected_version'] ?? 0));
        $message = is_wp_error($result) ? $result->get_error_message() : __('Governed artifact was saved.', 'sabri-security-center');
        set_transient('spcrc_registry_notice_' . get_current_user_id(), [
            'type' => is_wp_error($result) ? 'error' : 'success',
            'message' => $message,
        ], 300);
        wp_safe_redirect(admin_url('admin.php?page=sabri-security-registries'));
        exit;
    }

    public function render(): void
    {
        if (! current_user_can('spcrc_view_overview')) {
            wp_die(esc_html__('You are not allowed to view governed registries.', 'sabri-security-center'));
        }
        $selected = Sanitizer::key($_GET['type'] ?? 'policy', 60);
        if (! in_array($selected, GovernedArtifactRegistry::types(), true)) {
            $selected = 'policy';
        }
        $records = $this->artifacts->recent($selected, 50);
        $notice = get_transient('spcrc_registry_notice_' . get_current_user_id());
        if (is_array($notice)) {
            delete_transient('spcrc_registry_notice_' . get_current_user_id());
        }
        ?>
        <div class="wrap spcrc-wrap">
            <h1><?php esc_html_e('Governed Registries', 'sabri-security-center'); ?></h1>
            <p><?php esc_html_e('Public-safe governance and assurance metadata only. Secrets, raw evidence, patient records, message bodies and private runbooks must remain outside this registry.', 'sabri-security-center'); ?></p>
            <?php if (is_array($notice)) : ?>
                <div class="notice notice-<?php echo esc_attr(($notice['type'] ?? '') === 'error' ? 'error' : 'success'); ?>"><p><?php echo esc_html((string) ($notice['message'] ?? '')); ?></p></div>
            <?php endif; ?>
            <nav class="nav-tab-wrapper" aria-label="<?php esc_attr_e('Registry domains', 'sabri-security-center'); ?>">
                <?php foreach (GovernedArtifactRegistry::types() as $type) : ?>
                    <a class="nav-tab <?php echo $selected === $type ? 'nav-tab-active' : ''; ?>" href="<?php echo esc_url(admin_url('admin.php?page=sabri-security-registries&type=' . rawurlencode($type))); ?>"><?php echo esc_html($type); ?></a>
                <?php endforeach; ?>
            </nav>
            <h2><?php echo esc_html(sprintf(__('Recent %s records', 'sabri-security-center'), $selected)); ?></h2>
            <table class="widefat striped"><thead><tr><th><?php esc_html_e('Key', 'sabri-security-center'); ?></th><th><?php esc_html_e('Title', 'sabri-security-center'); ?></th><th><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th><?php esc_html_e('Version', 'sabri-security-center'); ?></th><th><?php esc_html_e('Updated', 'sabri-security-center'); ?></th></tr></thead><tbody>
            <?php if ($records === []) : ?><tr><td colspan="5"><?php esc_html_e('No records.', 'sabri-security-center'); ?></td></tr><?php endif; ?>
            <?php foreach ($records as $record) : ?><tr><td><?php echo esc_html((string) ($record['artifact_key'] ?? '')); ?></td><td><?php echo esc_html((string) ($record['title'] ?? '')); ?></td><td><?php echo esc_html((string) ($record['status'] ?? '')); ?></td><td><?php echo esc_html((string) ($record['version'] ?? '')); ?></td><td><?php echo esc_html((string) ($record['updated_at'] ?? '')); ?></td></tr><?php endforeach; ?>
            </tbody></table>
            <?php if (current_user_can(self::requiredCapability($selected))) : ?>
            <h2><?php esc_html_e('Create or update record', 'sabri-security-center'); ?></h2>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="spcrc_save_governed_artifact">
                <input type="hidden" name="artifact_type" value="<?php echo esc_attr($selected); ?>">
                <?php wp_nonce_field('spcrc_save_governed_artifact'); ?>
                <table class="form-table"><tbody>
                <tr><th><label for="spcrc-artifact-key"><?php esc_html_e('Stable key', 'sabri-security-center'); ?></label></th><td><input class="regular-text" id="spcrc-artifact-key" name="artifact_key" required></td></tr>
                <tr><th><label for="spcrc-title"><?php esc_html_e('Title', 'sabri-security-center'); ?></label></th><td><input class="regular-text" id="spcrc-title" name="title" required></td></tr>
                <tr><th><label for="spcrc-status"><?php esc_html_e('Status', 'sabri-security-center'); ?></label></th><td><select id="spcrc-status" name="status"><?php foreach (GovernedArtifactRegistry::statuses($selected) as $status) : ?><option value="<?php echo esc_attr($status); ?>"><?php echo esc_html($status); ?></option><?php endforeach; ?></select></td></tr>
                <tr><th><label for="spcrc-classification"><?php esc_html_e('Classification', 'sabri-security-center'); ?></label></th><td><select id="spcrc-classification" name="classification"><?php foreach (['C0','C1','C2','C3','C4','C5'] as $class) : ?><option><?php echo esc_html($class); ?></option><?php endforeach; ?></select></td></tr>
                <tr><th><label for="spcrc-evidence"><?php esc_html_e('Opaque evidence reference', 'sabri-security-center'); ?></label></th><td><input class="regular-text" id="spcrc-evidence" name="evidence_ref"></td></tr>
                <tr><th><label for="spcrc-payload"><?php esc_html_e('Bounded JSON metadata', 'sabri-security-center'); ?></label></th><td><textarea class="large-text code" rows="8" id="spcrc-payload" name="payload_json">{}</textarea></td></tr>
                </tbody></table>
                <?php submit_button(__('Save governed record', 'sabri-security-center')); ?>
            </form>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function requiredCapability(string $type): string
    {
        return $type === 'key-metadata'
            ? 'spcrc_manage_key_metadata'
            : GovernedArtifactRegistry::capability($type);
    }
}
