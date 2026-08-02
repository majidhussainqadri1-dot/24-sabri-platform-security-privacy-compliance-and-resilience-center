<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Admin;

use Sabri\Platform\Security\Storage\AssuranceRepository;

final class AssuranceAdmin
{
    private string $pageHook = '';

    public function __construct(private AssuranceRepository $assurance)
    {
    }

    public function registerHooks(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        add_action('admin_post_spcrc_upsert_assurance', [$this, 'handleUpsert']);
    }

    public function menu(): void
    {
        $this->pageHook = (string) add_submenu_page(
            'sabri-security-center',
            __('Assurance Registry', 'sabri-security-center'),
            __('Assurance', 'sabri-security-center'),
            'spcrc_manage_assurance',
            'sabri-security-assurance',
            [$this, 'render']
        );
    }

    public function assets(string $hook): void
    {
        if ($this->pageHook === '' || $hook !== $this->pageHook) {
            return;
        }
        wp_enqueue_style('spcrc-admin', SPCRC_PLUGIN_URL . 'assets/admin.css', [], SPCRC_VERSION);
    }

    public function handleUpsert(): void
    {
        $this->assertCapability();
        check_admin_referer('spcrc_upsert_assurance');

        $data = is_array($_POST) ? wp_unslash($_POST) : [];
        $classes = isset($data['data_classes']) && is_scalar($data['data_classes'])
            ? preg_split('/\s*,\s*/', (string) $data['data_classes'], -1, PREG_SPLIT_NO_EMPTY)
            : [];
        $data['data_classes'] = is_array($classes) ? $classes : [];

        $result = $this->assurance->upsert($data);
        if (is_wp_error($result)) {
            $this->redirect('error', $result->get_error_message());
        }
        $this->redirect('success', 'Assurance record was saved.');
    }

    public function render(): void
    {
        $this->assertCapability();
        $notice = get_transient('spcrc_assurance_notice_' . get_current_user_id());
        if (is_array($notice)) {
            delete_transient('spcrc_assurance_notice_' . get_current_user_id());
        }
        $rows = $this->assurance->recent(null, 50);
        ?>
        <div class="wrap spcrc-wrap">
            <h1><?php esc_html_e('Compliance, Vendor and Backup Assurance', 'sabri-security-center'); ?></h1>
            <p><?php esc_html_e('Store bounded status metadata and opaque evidence references only. Do not enter credentials, contracts, personal contact data, backup locations, URLs, file paths or forensic evidence.', 'sabri-security-center'); ?></p>

            <?php if (is_array($notice)) : ?>
                <div class="notice notice-<?php echo esc_attr(($notice['type'] ?? '') === 'error' ? 'error' : 'success'); ?> is-dismissible"><p><?php echo esc_html((string) ($notice['message'] ?? '')); ?></p></div>
            <?php endif; ?>

            <section class="spcrc-panel" aria-labelledby="spcrc-assurance-form-heading">
                <h2 id="spcrc-assurance-form-heading"><?php esc_html_e('Record assurance metadata', 'sabri-security-center'); ?></h2>
                <form class="spcrc-form-grid" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="spcrc_upsert_assurance">
                    <?php wp_nonce_field('spcrc_upsert_assurance'); ?>
                    <p><label><?php esc_html_e('Type', 'sabri-security-center'); ?><select required name="record_type">
                        <?php foreach (AssuranceRepository::types() as $type) : ?>
                            <option value="<?php echo esc_attr($type); ?>"><?php echo esc_html(ucfirst($type)); ?></option>
                        <?php endforeach; ?>
                    </select></label></p>
                    <p><label><?php esc_html_e('Record key', 'sabri-security-center'); ?><input required maxlength="120" name="record_key" type="text" placeholder="gdpr-applicability"></label></p>
                    <p><label><?php esc_html_e('Title', 'sabri-security-center'); ?><input required maxlength="200" name="title" type="text"></label></p>
                    <p><label><?php esc_html_e('Status', 'sabri-security-center'); ?><select required name="status">
                        <?php foreach ($this->allStatuses() as $status) : ?>
                            <option value="<?php echo esc_attr($status); ?>"><?php echo esc_html(ucwords(str_replace('-', ' ', $status))); ?></option>
                        <?php endforeach; ?>
                    </select></label></p>
                    <p><label><?php esc_html_e('Jurisdiction', 'sabri-security-center'); ?><input maxlength="80" name="jurisdiction" type="text"></label></p>
                    <p><label><?php esc_html_e('Data classes', 'sabri-security-center'); ?><input maxlength="300" name="data_classes" type="text" placeholder="C2 Personal, C3 Sensitive"></label></p>
                    <p class="spcrc-form-wide"><label><?php esc_html_e('Opaque evidence reference', 'sabri-security-center'); ?><input maxlength="255" name="evidence_ref" type="text" placeholder="vault:assessment-2026-08"></label></p>
                    <p class="spcrc-form-wide"><label><?php esc_html_e('Sanitized notes', 'sabri-security-center'); ?><textarea maxlength="500" name="notes" rows="3"></textarea></label></p>
                    <p><label><?php esc_html_e('Reviewed at (UTC)', 'sabri-security-center'); ?><input name="reviewed_at" type="datetime-local"></label></p>
                    <p><label><?php esc_html_e('Next review at (UTC)', 'sabri-security-center'); ?><input name="next_review_at" type="datetime-local"></label></p>
                    <p><label><?php esc_html_e('Backup completed at (UTC)', 'sabri-security-center'); ?><input name="backup_completed_at" type="datetime-local"></label></p>
                    <p><label><?php esc_html_e('Restore tested at (UTC)', 'sabri-security-center'); ?><input name="restore_tested_at" type="datetime-local"></label></p>
                    <p class="spcrc-form-actions"><?php submit_button(__('Save assurance record', 'sabri-security-center'), 'primary', 'submit', false); ?></p>
                </form>
            </section>

            <section class="spcrc-panel" aria-labelledby="spcrc-assurance-table-heading">
                <h2 id="spcrc-assurance-table-heading"><?php esc_html_e('Recent assurance records', 'sabri-security-center'); ?></h2>
                <div class="spcrc-table-scroll">
                    <table class="widefat striped spcrc-data-table">
                        <caption class="screen-reader-text"><?php esc_html_e('Recent bounded assurance metadata', 'sabri-security-center'); ?></caption>
                        <thead><tr><th scope="col"><?php esc_html_e('Record', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Type', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Jurisdiction', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Evidence', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Review/restore', 'sabri-security-center'); ?></th></tr></thead>
                        <tbody>
                        <?php if ($rows === []) : ?>
                            <tr><td colspan="6"><?php esc_html_e('No assurance records are available.', 'sabri-security-center'); ?></td></tr>
                        <?php else : foreach ($rows as $row) : ?>
                            <tr>
                                <td><strong><?php echo esc_html((string) ($row['title'] ?? '')); ?></strong><br><code><?php echo esc_html((string) ($row['record_key'] ?? '')); ?></code></td>
                                <td><?php echo esc_html((string) ($row['record_type'] ?? '')); ?></td>
                                <td><?php echo esc_html((string) ($row['status'] ?? '')); ?></td>
                                <td><?php echo esc_html((string) ($row['jurisdiction'] ?? '')); ?></td>
                                <td><?php echo esc_html((string) ($row['evidence_ref'] ?? '')); ?></td>
                                <td><?php echo esc_html((string) (($row['restore_tested_at'] ?? '') !== '' ? $row['restore_tested_at'] : ($row['next_review_at'] ?? ''))); ?></td>
                            </tr>
                        <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
        <?php
    }

    /** @return string[] */
    private function allStatuses(): array
    {
        $statuses = [];
        foreach (AssuranceRepository::types() as $type) {
            $statuses = array_merge($statuses, AssuranceRepository::statuses($type));
        }
        return array_values(array_unique($statuses));
    }

    private function assertCapability(): void
    {
        if (! current_user_can('spcrc_manage_assurance')) {
            wp_die(esc_html__('You are not allowed to manage assurance records.', 'sabri-security-center'));
        }
    }

    private function redirect(string $type, string $message): void
    {
        set_transient('spcrc_assurance_notice_' . get_current_user_id(), [
            'type' => $type,
            'message' => $message,
        ], 5 * MINUTE_IN_SECONDS);
        wp_safe_redirect(add_query_arg(['page' => 'sabri-security-assurance'], admin_url('admin.php')));
        exit;
    }
}
