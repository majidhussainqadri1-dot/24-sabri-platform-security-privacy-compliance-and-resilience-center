<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Admin;

use Sabri\Platform\Security\Storage\GovernanceRepository;

final class GovernanceAdmin
{
    private string $pageHook = '';

    public function __construct(private GovernanceRepository $governance)
    {
    }

    public function registerHooks(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        add_action('admin_post_spcrc_request_governance', [$this, 'handleRequest']);
        add_action('admin_post_spcrc_decide_governance', [$this, 'handleDecision']);
        add_action('admin_post_spcrc_reconcile_governance_audit', [$this, 'handleReconciliation']);
    }

    public function menu(): void
    {
        $this->pageHook = (string) add_submenu_page(
            'sabri-security-center',
            __('Governance Decisions', 'sabri-security-center'),
            __('Governance', 'sabri-security-center'),
            'spcrc_view_overview',
            'sabri-security-governance',
            [$this, 'render']
        );
    }

    public function assets(string $hook): void
    {
        if ($this->pageHook !== '' && $hook === $this->pageHook) {
            wp_enqueue_style('spcrc-admin', SPCRC_PLUGIN_URL . 'assets/admin.css', [], SPCRC_VERSION);
        }
    }

    public function handleRequest(): void
    {
        $this->assertCapability('spcrc_request_governance_decision');
        check_admin_referer('spcrc_request_governance');
        $data = is_array($_POST) ? wp_unslash($_POST) : [];
        $result = $this->governance->request($data);
        $this->redirect(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : 'Governance decision request was recorded.');
    }

    public function handleDecision(): void
    {
        $this->assertCapability('spcrc_approve_governance_decision');
        check_admin_referer('spcrc_decide_governance');
        $data = is_array($_POST) ? wp_unslash($_POST) : [];
        $result = $this->governance->decide(
            (string) ($data['decision_uuid'] ?? ''),
            (string) ($data['status'] ?? ''),
            [
                'expected_lock_version' => $data['expected_lock_version'] ?? -1,
                'step_up_reference' => $data['step_up_reference'] ?? '',
                'note' => $data['note'] ?? '',
            ]
        );
        $this->redirect(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : 'Governance decision was recorded.');
    }

    public function handleReconciliation(): void
    {
        $this->assertCapability('spcrc_approve_governance_decision');
        check_admin_referer('spcrc_reconcile_governance_audit');
        $data = is_array($_POST) ? wp_unslash($_POST) : [];
        $result = $this->governance->reconcileAuditGap(
            (string) ($data['decision_uuid'] ?? ''),
            [
                'step_up_reference' => $data['step_up_reference'] ?? '',
                'note' => $data['note'] ?? '',
            ]
        );
        $this->redirect(is_wp_error($result) ? 'error' : 'success', is_wp_error($result) ? $result->get_error_message() : 'Governance audit gap was reconciled.');
    }

    public function render(): void
    {
        if (! current_user_can('spcrc_request_governance_decision') && ! current_user_can('spcrc_approve_governance_decision')) {
            wp_die(esc_html__('You are not allowed to view governance decisions.', 'sabri-security-center'));
        }
        $notice = get_transient('spcrc_governance_notice_' . get_current_user_id());
        if (is_array($notice)) {
            delete_transient('spcrc_governance_notice_' . get_current_user_id());
        }
        $rows = $this->governance->recent(100);
        ?>
        <div class="wrap spcrc-wrap">
            <h1><?php esc_html_e('Governance Decisions', 'sabri-security-center'); ?></h1>
            <p><?php esc_html_e('High-risk decisions are time-bounded, evidence-referenced, separately approved and bound to one subject. Raw evidence and secrets do not belong here.', 'sabri-security-center'); ?></p>
            <?php if (is_array($notice)) : ?><div class="notice notice-<?php echo esc_attr(($notice['type'] ?? '') === 'error' ? 'error' : 'success'); ?> is-dismissible"><p><?php echo esc_html((string) ($notice['message'] ?? '')); ?></p></div><?php endif; ?>

            <?php if (current_user_can('spcrc_request_governance_decision')) : ?>
            <section class="spcrc-panel">
                <h2><?php esc_html_e('Request decision', 'sabri-security-center'); ?></h2>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="spcrc-grid-form">
                    <input type="hidden" name="action" value="spcrc_request_governance">
                    <?php wp_nonce_field('spcrc_request_governance'); ?>
                    <p><label><?php esc_html_e('Decision type', 'sabri-security-center'); ?><select required name="decision_type"><?php foreach (GovernanceRepository::types() as $type) : ?><option value="<?php echo esc_attr($type); ?>"><?php echo esc_html(ucwords(str_replace('-', ' ', $type))); ?></option><?php endforeach; ?></select></label></p>
                    <p><label><?php esc_html_e('Subject key', 'sabri-security-center'); ?><input required maxlength="120" name="subject_key" type="text"></label></p>
                    <p><label><?php esc_html_e('Module key', 'sabri-security-center'); ?><input required maxlength="120" name="module_key" type="text" value="file-24-security-center"></label></p>
                    <p><label><?php esc_html_e('Expires at', 'sabri-security-center'); ?><input required name="expires_at" type="datetime-local"></label></p>
                    <p class="spcrc-form-wide"><label><?php esc_html_e('Opaque evidence reference', 'sabri-security-center'); ?><input required maxlength="255" name="evidence_ref" type="text" placeholder="vault:decision-2026-001"></label></p>
                    <p class="spcrc-form-wide"><label><?php esc_html_e('Sanitized rationale', 'sabri-security-center'); ?><textarea required maxlength="500" name="rationale" rows="3"></textarea></label></p>
                    <?php submit_button(__('Request independent decision', 'sabri-security-center')); ?>
                </form>
            </section>
            <?php endif; ?>

            <section class="spcrc-panel">
                <h2><?php esc_html_e('Decision register', 'sabri-security-center'); ?></h2>
                <div class="spcrc-table-scroll"><table class="widefat striped"><thead><tr><th><?php esc_html_e('Decision', 'sabri-security-center'); ?></th><th><?php esc_html_e('Subject', 'sabri-security-center'); ?></th><th><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th><?php esc_html_e('Actors / expiry', 'sabri-security-center'); ?></th><th><?php esc_html_e('Independent decision', 'sabri-security-center'); ?></th></tr></thead><tbody>
                <?php if ($rows === []) : ?><tr><td colspan="5"><?php esc_html_e('No governance decisions recorded.', 'sabri-security-center'); ?></td></tr><?php else : foreach ($rows as $row) : ?>
                    <tr>
                        <td><strong><?php echo esc_html(ucwords(str_replace('-', ' ', (string) ($row['decision_type'] ?? '')))); ?></strong><br><code><?php echo esc_html((string) ($row['decision_uuid'] ?? '')); ?></code><br><?php echo esc_html((string) ($row['evidence_ref'] ?? '')); ?></td>
                        <td><?php echo esc_html((string) ($row['module_key'] ?? '')); ?><br><code><?php echo esc_html((string) ($row['subject_key'] ?? '')); ?></code></td>
                        <td><?php echo esc_html(strtoupper((string) ($row['status'] ?? ''))); ?></td>
                        <td><?php echo esc_html('Requester: ' . (string) ($row['requester_user_id'] ?? '')); ?><br><?php echo esc_html('Approver: ' . (string) ($row['approver_user_id'] ?? '')); ?><br><?php echo esc_html((string) ($row['expires_at'] ?? '')); ?></td>
                        <td><?php if (($row['status'] ?? '') === 'pending' && current_user_can('spcrc_approve_governance_decision')) : ?>
                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                <input type="hidden" name="action" value="spcrc_decide_governance"><input type="hidden" name="decision_uuid" value="<?php echo esc_attr((string) ($row['decision_uuid'] ?? '')); ?>"><input type="hidden" name="expected_lock_version" value="<?php echo esc_attr((string) ($row['lock_version'] ?? 0)); ?>">
                                <?php wp_nonce_field('spcrc_decide_governance'); ?>
                                <label><span class="screen-reader-text"><?php esc_html_e('Decision', 'sabri-security-center'); ?></span><select required name="status"><option value="approved"><?php esc_html_e('Approve', 'sabri-security-center'); ?></option><option value="rejected"><?php esc_html_e('Reject', 'sabri-security-center'); ?></option></select></label>
                                <label><span class="screen-reader-text"><?php esc_html_e('Step-up assurance reference', 'sabri-security-center'); ?></span><input required maxlength="255" name="step_up_reference" type="text" placeholder="assertion:recent-step-up"></label>
                                <label><span class="screen-reader-text"><?php esc_html_e('Decision note', 'sabri-security-center'); ?></span><textarea required maxlength="500" name="note" rows="2"></textarea></label>
                                <?php submit_button(__('Record decision', 'sabri-security-center'), 'secondary small', 'submit', false); ?>
                            </form>
                        <?php elseif ($this->governance->hasAuditGap((string) ($row['decision_uuid'] ?? '')) && current_user_can('spcrc_approve_governance_decision')) : ?>
                            <strong><?php esc_html_e('Audit reconciliation required', 'sabri-security-center'); ?></strong>
                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                <input type="hidden" name="action" value="spcrc_reconcile_governance_audit"><input type="hidden" name="decision_uuid" value="<?php echo esc_attr((string) ($row['decision_uuid'] ?? '')); ?>">
                                <?php wp_nonce_field('spcrc_reconcile_governance_audit'); ?>
                                <label><span class="screen-reader-text"><?php esc_html_e('Fresh step-up assurance reference', 'sabri-security-center'); ?></span><input required maxlength="255" name="step_up_reference" type="text" placeholder="assertion:recent-step-up"></label>
                                <label><span class="screen-reader-text"><?php esc_html_e('Reconciliation note', 'sabri-security-center'); ?></span><textarea required maxlength="500" name="note" rows="2"></textarea></label>
                                <?php submit_button(__('Reconcile audit evidence', 'sabri-security-center'), 'secondary small', 'submit', false); ?>
                            </form>
                        <?php else : ?>—<?php endif; ?></td>
                    </tr>
                <?php endforeach; endif; ?></tbody></table></div>
            </section>
        </div>
        <?php
    }

    private function assertCapability(string $capability): void
    {
        if (! current_user_can($capability)) {
            wp_die(esc_html__('You are not allowed to manage governance decisions.', 'sabri-security-center'));
        }
    }

    private function redirect(string $type, string $message): void
    {
        set_transient('spcrc_governance_notice_' . get_current_user_id(), ['type' => $type, 'message' => $message], 5 * MINUTE_IN_SECONDS);
        wp_safe_redirect(add_query_arg(['page' => 'sabri-security-governance'], admin_url('admin.php')));
        exit;
    }
}
