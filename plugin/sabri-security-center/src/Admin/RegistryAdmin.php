<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Admin;

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\Trust\TrustCenterService;

/** Capability-protected wp-admin fallback for governed metadata domains. */
final class RegistryAdmin
{
    /** @var string[] */
    private const RESTRICTED_READ_TYPES = [
        'consent', 'legal-hold', 'processing-activity', 'vulnerability',
        'secret-metadata', 'key-metadata', 'deletion-ledger', 'alert',
        'remote-evidence', 'incident-action', 'upload-assurance', 'private-delivery',
        'trust-claim',
    ];

    public function __construct(
        private GovernedArtifactRegistry $artifacts,
        private TrustCenterService $trustCenter
    ) {
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
        $status = Sanitizer::key($_POST['status'] ?? '', 40);
        if ($type === '' || ! in_array($type, GovernedArtifactRegistry::types(), true) || ! self::canWriteType($type, $status)) {
            wp_die(esc_html__('You are not allowed to manage this governed registry or status.', 'sabri-security-center'));
        }
        if (check_admin_referer('spcrc_save_governed_artifact') === false) {
            wp_die(esc_html__('The security token is invalid or expired.', 'sabri-security-center'));
        }

        $payloadRaw = is_scalar($_POST['payload_json'] ?? null) ? (string) wp_unslash($_POST['payload_json']) : '{}';
        $payload = json_decode($payloadRaw, true);
        if (! is_array($payload)) {
            $payload = [];
        }

        $data = [
            'artifact_type' => $type,
            'artifact_key' => $_POST['artifact_key'] ?? '',
            'title' => $_POST['title'] ?? '',
            'status' => $status,
            'classification' => $_POST['classification'] ?? 'C1',
            'module_key' => $_POST['module_key'] ?? 'file-24-security-center',
            'owner_user_id' => get_current_user_id(),
            'expected_version' => absint($_POST['expected_version'] ?? 0),
            'evidence_ref' => $_POST['evidence_ref'] ?? '',
            'effective_at' => $_POST['effective_at'] ?? '',
            'expires_at' => $_POST['expires_at'] ?? '',
            'reviewed_at' => $_POST['reviewed_at'] ?? '',
            'next_review_at' => $_POST['next_review_at'] ?? '',
            'payload' => $payload,
        ];

        if ($type === 'trust-claim') {
            $data['claim_key'] = $data['artifact_key'];
            $data['claim_type'] = $payload['claim_type'] ?? '';
            $data['summary'] = $payload['summary'] ?? '';
            $data['independent'] = $payload['independent'] ?? false;
            $result = $this->trustCenter->saveClaim($data);
        } else {
            $result = $this->artifacts->save($data, (int) $data['expected_version']);
        }

        $message = is_wp_error($result) ? $result->get_error_message() : __('Governed artifact was saved.', 'sabri-security-center');
        set_transient('spcrc_registry_notice_' . get_current_user_id(), [
            'type' => is_wp_error($result) ? 'error' : 'success',
            'message' => $message,
        ], 300);
        wp_safe_redirect(admin_url('admin.php?page=sabri-security-registries&type=' . rawurlencode($type)));
        exit;
    }

    public function render(): void
    {
        if (! current_user_can('spcrc_view_overview')) {
            wp_die(esc_html__('You are not allowed to view governed registries.', 'sabri-security-center'));
        }

        $readableTypes = array_values(array_filter(
            GovernedArtifactRegistry::types(),
            static fn (string $type): bool => self::canReadType($type)
        ));
        if ($readableTypes === []) {
            wp_die(esc_html__('No governed registry is available to your current duties.', 'sabri-security-center'));
        }

        $selected = Sanitizer::key($_GET['type'] ?? $readableTypes[0], 60);
        if (! in_array($selected, $readableTypes, true)) {
            $selected = $readableTypes[0];
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
                <?php foreach ($readableTypes as $type) : ?>
                    <a class="nav-tab <?php echo $selected === $type ? 'nav-tab-active' : ''; ?>" href="<?php echo esc_url(admin_url('admin.php?page=sabri-security-registries&type=' . rawurlencode($type))); ?>"><?php echo esc_html($type); ?></a>
                <?php endforeach; ?>
            </nav>
            <h2><?php echo esc_html(sprintf(__('Recent %s records', 'sabri-security-center'), $selected)); ?></h2>
            <table class="widefat striped"><thead><tr><th><?php esc_html_e('Key', 'sabri-security-center'); ?></th><th><?php esc_html_e('Title', 'sabri-security-center'); ?></th><th><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th><?php esc_html_e('Version', 'sabri-security-center'); ?></th><th><?php esc_html_e('Updated', 'sabri-security-center'); ?></th></tr></thead><tbody>
            <?php if ($records === []) : ?><tr><td colspan="5"><?php esc_html_e('No records.', 'sabri-security-center'); ?></td></tr><?php endif; ?>
            <?php foreach ($records as $record) : ?><tr><td><?php echo esc_html((string) ($record['artifact_key'] ?? '')); ?></td><td><?php echo esc_html((string) ($record['title'] ?? '')); ?></td><td><?php echo esc_html((string) ($record['status'] ?? '')); ?></td><td><?php echo esc_html((string) ($record['version'] ?? '')); ?></td><td><?php echo esc_html((string) ($record['updated_at'] ?? '')); ?></td></tr><?php endforeach; ?>
            </tbody></table>
            <?php if (self::canDisplayWriteForm($selected)) : ?>
            <h2><?php echo esc_html($selected === 'trust-claim' ? __('Draft or independently approve public claim', 'sabri-security-center') : __('Create or update record', 'sabri-security-center')); ?></h2>
            <?php if ($selected === 'trust-claim') : ?><p class="description"><?php esc_html_e('A manager authors or edits a draft. A different governance approver verifies the unchanged current version with opaque evidence, a completed review time and a future expiry.', 'sabri-security-center'); ?></p><?php endif; ?>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="spcrc_save_governed_artifact">
                <input type="hidden" name="artifact_type" value="<?php echo esc_attr($selected); ?>">
                <?php wp_nonce_field('spcrc_save_governed_artifact'); ?>
                <table class="form-table"><tbody>
                <tr><th><label for="spcrc-artifact-key"><?php esc_html_e('Stable key', 'sabri-security-center'); ?></label></th><td><input class="regular-text" id="spcrc-artifact-key" name="artifact_key" required></td></tr>
                <tr><th><label for="spcrc-expected-version"><?php esc_html_e('Expected version', 'sabri-security-center'); ?></label></th><td><input type="number" min="0" step="1" id="spcrc-expected-version" name="expected_version" value="0" required><p class="description"><?php esc_html_e('Use 0 only for a new key. For an update or approval, copy the current version shown in the table; stale or missing versions fail closed.', 'sabri-security-center'); ?></p></td></tr>
                <tr><th><label for="spcrc-title"><?php esc_html_e('Title', 'sabri-security-center'); ?></label></th><td><input class="regular-text" id="spcrc-title" name="title" required></td></tr>
                <tr><th><label for="spcrc-status"><?php esc_html_e('Status', 'sabri-security-center'); ?></label></th><td><select id="spcrc-status" name="status"><?php foreach (GovernedArtifactRegistry::statuses($selected) as $status) : ?><?php if (self::canWriteType($selected, $status)) : ?><option value="<?php echo esc_attr($status); ?>"><?php echo esc_html($status); ?></option><?php endif; ?><?php endforeach; ?></select></td></tr>
                <tr><th><label for="spcrc-classification"><?php esc_html_e('Classification', 'sabri-security-center'); ?></label></th><td><select id="spcrc-classification" name="classification"><?php foreach (['C0','C1','C2','C3','C4','C5'] as $class) : ?><option<?php selected($selected === 'trust-claim' ? 'C0' : 'C1', $class); ?>><?php echo esc_html($class); ?></option><?php endforeach; ?></select></td></tr>
                <tr><th><label for="spcrc-evidence"><?php esc_html_e('Opaque evidence reference', 'sabri-security-center'); ?></label></th><td><input class="regular-text" id="spcrc-evidence" name="evidence_ref"></td></tr>
                <tr><th><label for="spcrc-reviewed-at"><?php esc_html_e('Reviewed at — ISO 8601', 'sabri-security-center'); ?></label></th><td><input class="regular-text" id="spcrc-reviewed-at" name="reviewed_at" placeholder="2026-08-04T12:00:00Z"></td></tr>
                <tr><th><label for="spcrc-expires-at"><?php esc_html_e('Expires at — ISO 8601', 'sabri-security-center'); ?></label></th><td><input class="regular-text" id="spcrc-expires-at" name="expires_at" placeholder="2026-11-04T12:00:00Z"></td></tr>
                <tr><th><label for="spcrc-next-review-at"><?php esc_html_e('Next review at — ISO 8601', 'sabri-security-center'); ?></label></th><td><input class="regular-text" id="spcrc-next-review-at" name="next_review_at"></td></tr>
                <tr><th><label for="spcrc-payload"><?php esc_html_e('Bounded JSON metadata', 'sabri-security-center'); ?></label></th><td><textarea class="large-text code" rows="8" id="spcrc-payload" name="payload_json"><?php echo esc_textarea($selected === 'trust-claim' ? wp_json_encode(['claim_type' => '', 'summary' => '', 'independent' => false], JSON_PRETTY_PRINT) : '{}'); ?></textarea><p class="description"><?php echo esc_html($selected === 'trust-claim' ? __('Trust claims require claim_type and summary; certification drafts must declare independent evidence truthfully.', 'sabri-security-center') : __('Only bounded public-safe metadata is accepted.', 'sabri-security-center')); ?></p></td></tr>
                </tbody></table>
                <?php submit_button(__('Save governed record', 'sabri-security-center')); ?>
            </form>
            <?php endif; ?>
        </div>
        <?php
    }

    private static function canReadType(string $type): bool
    {
        if (! in_array($type, self::RESTRICTED_READ_TYPES, true)) {
            return current_user_can('spcrc_view_overview');
        }
        return current_user_can(self::requiredCapability($type))
            || ($type === 'trust-claim' && current_user_can('spcrc_approve_governance_decision'))
            || current_user_can('spcrc_view_forensic_metadata');
    }

    private static function canWriteType(string $type, string $status): bool
    {
        if ($type === 'trust-claim') {
            return $status === 'verified'
                ? current_user_can('spcrc_approve_governance_decision')
                : current_user_can('spcrc_manage_trust_center');
        }
        return current_user_can(self::requiredCapability($type));
    }

    private static function canDisplayWriteForm(string $type): bool
    {
        return $type === 'trust-claim'
            ? current_user_can('spcrc_manage_trust_center') || current_user_can('spcrc_approve_governance_decision')
            : current_user_can(self::requiredCapability($type));
    }

    private static function requiredCapability(string $type): string
    {
        return $type === 'key-metadata'
            ? 'spcrc_manage_key_metadata'
            : GovernedArtifactRegistry::capability($type);
    }
}
