<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Admin;

use Sabri\Platform\Security\Storage\FindingRepository;

final class FindingAdmin
{
    public function __construct(private FindingRepository $findings)
    {
    }

    public function registerHooks(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_post_spcrc_create_finding', [$this, 'handleCreate']);
        add_action('admin_post_spcrc_update_finding', [$this, 'handleStatus']);
    }

    public function menu(): void
    {
        add_submenu_page(
            'sabri-security-center',
            __('Security Findings', 'sabri-security-center'),
            __('Findings', 'sabri-security-center'),
            'spcrc_manage_findings',
            'sabri-security-findings',
            [$this, 'render']
        );
    }

    public function handleCreate(): void
    {
        $this->assertCapability('spcrc_manage_findings', 'You are not allowed to manage security findings.');
        check_admin_referer('spcrc_create_finding');

        $result = $this->findings->create($this->postData());
        if (is_wp_error($result)) {
            $this->redirect('error', $result->get_error_message());
        }
        $this->redirect('success', 'Security finding was recorded.');
    }

    public function handleStatus(): void
    {
        $this->assertCapability('spcrc_manage_findings', 'You are not allowed to manage security findings.');
        check_admin_referer('spcrc_update_finding');

        $data = $this->postData();
        $status = isset($data['status']) ? (string) $data['status'] : '';
        if ($status === 'accepted-risk') {
            $this->assertCapability('spcrc_accept_critical_risk', 'You are not allowed to accept security risk.');
        }

        $result = $this->findings->setStatus(
            isset($data['finding_uuid']) ? (string) $data['finding_uuid'] : '',
            $status,
            [
                'expected_status' => $data['expected_status'] ?? '',
                'note' => $data['note'] ?? '',
            ]
        );
        if (is_wp_error($result)) {
            $this->redirect('error', $result->get_error_message());
        }
        $this->redirect('success', 'Security finding status was updated.');
    }

    public function render(): void
    {
        $this->assertCapability('spcrc_manage_findings', 'You are not allowed to view security findings.');
        $notice = get_transient('spcrc_finding_notice_' . get_current_user_id());
        if (is_array($notice)) {
            delete_transient('spcrc_finding_notice_' . get_current_user_id());
        }
        $rows = $this->findings->recent(50);
        ?>
        <div class="wrap spcrc-wrap">
            <h1><?php esc_html_e('Security Findings', 'sabri-security-center'); ?></h1>
            <p><?php esc_html_e('Record, triage and close sanitized security findings. Do not enter passwords, keys, patient data, identity documents or exploit payloads.', 'sabri-security-center'); ?></p>

            <?php if (is_array($notice)) : ?>
                <div class="notice notice-<?php echo esc_attr(($notice['type'] ?? '') === 'error' ? 'error' : 'success'); ?> is-dismissible"><p><?php echo esc_html((string) ($notice['message'] ?? '')); ?></p></div>
            <?php endif; ?>

            <section class="spcrc-panel" aria-labelledby="spcrc-new-finding-heading">
                <h2 id="spcrc-new-finding-heading"><?php esc_html_e('Record a finding', 'sabri-security-center'); ?></h2>
                <form class="spcrc-form-grid" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="spcrc_create_finding">
                    <?php wp_nonce_field('spcrc_create_finding'); ?>
                    <p><label><?php esc_html_e('Title', 'sabri-security-center'); ?><input required maxlength="200" name="title" type="text"></label></p>
                    <p><label><?php esc_html_e('Module key', 'sabri-security-center'); ?><input required maxlength="120" name="module_key" type="text" value="file-24-security-center"></label></p>
                    <p><label><?php esc_html_e('Severity', 'sabri-security-center'); ?><select name="severity">
                        <?php foreach (FindingRepository::severities() as $severity) : ?>
                            <option value="<?php echo esc_attr($severity); ?>"<?php selected($severity, 'medium'); ?>><?php echo esc_html(ucwords(str_replace('-', ' ', $severity))); ?></option>
                        <?php endforeach; ?>
                    </select></label></p>
                    <p><label><?php esc_html_e('Due date', 'sabri-security-center'); ?><input name="due_at" type="date"></label></p>
                    <p class="spcrc-form-wide"><label><?php esc_html_e('Opaque evidence reference', 'sabri-security-center'); ?><input maxlength="255" name="evidence_ref" type="text" placeholder="private-evidence:case-17"></label></p>
                    <p class="spcrc-form-actions"><?php submit_button(__('Record finding', 'sabri-security-center'), 'primary', 'submit', false); ?></p>
                </form>
            </section>

            <section class="spcrc-panel" aria-labelledby="spcrc-findings-heading">
                <h2 id="spcrc-findings-heading"><?php esc_html_e('Recent findings', 'sabri-security-center'); ?></h2>
                <p><?php echo esc_html(sprintf(__('Open findings: %d', 'sabri-security-center'), $this->findings->openCount())); ?></p>
                <div class="spcrc-table-scroll">
                    <table class="widefat striped spcrc-data-table">
                        <caption class="screen-reader-text"><?php esc_html_e('Recent security findings and controlled status actions', 'sabri-security-center'); ?></caption>
                        <thead><tr><th scope="col"><?php esc_html_e('Finding', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Module', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Severity', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Due', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Action', 'sabri-security-center'); ?></th></tr></thead>
                        <tbody>
                        <?php if ($rows === []) : ?>
                            <tr><td colspan="6"><?php esc_html_e('No findings recorded.', 'sabri-security-center'); ?></td></tr>
                        <?php else : foreach ($rows as $row) : ?>
                            <?php $current = (string) ($row['status'] ?? 'open'); $next = FindingRepository::allowedNextStatuses($current); ?>
                            <tr>
                                <td><strong><?php echo esc_html((string) ($row['title'] ?? '')); ?></strong><br><code><?php echo esc_html((string) ($row['finding_uuid'] ?? '')); ?></code><?php if (($row['evidence_ref'] ?? '') !== '') : ?><br><span><?php echo esc_html((string) $row['evidence_ref']); ?></span><?php endif; ?></td>
                                <td><?php echo esc_html((string) ($row['module_key'] ?? '')); ?></td>
                                <td><?php echo esc_html(strtoupper((string) ($row['severity'] ?? ''))); ?></td>
                                <td><?php echo esc_html($current); ?></td>
                                <td><?php echo esc_html((string) ($row['due_at'] ?? '')); ?></td>
                                <td>
                                    <?php if ($next === []) : ?>
                                        <?php esc_html_e('No transition available.', 'sabri-security-center'); ?>
                                    <?php else : ?>
                                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                            <input type="hidden" name="action" value="spcrc_update_finding">
                                            <input type="hidden" name="finding_uuid" value="<?php echo esc_attr((string) ($row['finding_uuid'] ?? '')); ?>">
                                            <input type="hidden" name="expected_status" value="<?php echo esc_attr($current); ?>">
                                            <?php wp_nonce_field('spcrc_update_finding'); ?>
                                            <label><span class="screen-reader-text"><?php esc_html_e('New status', 'sabri-security-center'); ?></span><select required name="status">
                                                <option value=""><?php esc_html_e('Select status', 'sabri-security-center'); ?></option>
                                                <?php foreach ($next as $candidate) : ?>
                                                    <?php if ($candidate === 'accepted-risk' && ! current_user_can('spcrc_accept_critical_risk')) { continue; } ?>
                                                    <option value="<?php echo esc_attr($candidate); ?>"><?php echo esc_html(ucwords(str_replace('-', ' ', $candidate))); ?></option>
                                                <?php endforeach; ?>
                                            </select></label>
                                            <label><span class="screen-reader-text"><?php esc_html_e('Sanitized status note', 'sabri-security-center'); ?></span><textarea required maxlength="1000" name="note" rows="2" placeholder="<?php esc_attr_e('Required accountability note', 'sabri-security-center'); ?>"></textarea></label>
                                            <?php submit_button(__('Update', 'sabri-security-center'), 'secondary small', 'submit', false); ?>
                                        </form>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; endif; ?>
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
        <?php
    }

    private function assertCapability(string $capability, string $message): void
    {
        if (! current_user_can($capability)) {
            wp_die(esc_html__($message, 'sabri-security-center'));
        }
    }

    /** @return array<string,mixed> */
    private function postData(): array
    {
        return is_array($_POST) ? wp_unslash($_POST) : [];
    }

    private function redirect(string $type, string $message): void
    {
        set_transient(
            'spcrc_finding_notice_' . get_current_user_id(),
            ['type' => $type === 'error' ? 'error' : 'success', 'message' => $message],
            5 * MINUTE_IN_SECONDS
        );
        wp_safe_redirect(add_query_arg(['page' => 'sabri-security-findings'], admin_url('admin.php')));
        exit;
    }
}
