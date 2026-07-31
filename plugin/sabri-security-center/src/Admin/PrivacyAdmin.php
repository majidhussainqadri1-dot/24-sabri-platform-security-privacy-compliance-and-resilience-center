<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Admin;

use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Privacy\PrivacyRequestPolicy;

final class PrivacyAdmin
{
    public function __construct(
        private PrivacyRequestPolicy $requests,
        private RequestDispatcher $dispatcher,
        private ModuleRegistry $modules
    ) {
    }

    public function registerHooks(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_post_spcrc_dispatch_privacy_request', [$this, 'handleDispatch']);
        add_action('admin_post_spcrc_retry_privacy_request', [$this, 'handleRetry']);
    }

    public function menu(): void
    {
        add_submenu_page(
            'sabri-security-center',
            __('Privacy Requests', 'sabri-security-center'),
            __('Privacy Requests', 'sabri-security-center'),
            'spcrc_manage_privacy_requests',
            'sabri-security-privacy-requests',
            [$this, 'render']
        );
    }

    public function handleDispatch(): void
    {
        $this->assertCapability('spcrc_manage_privacy_requests', 'You are not allowed to manage privacy requests.');
        check_admin_referer('spcrc_dispatch_privacy_request');

        $data = $this->postData();
        $requestType = isset($data['request_type']) ? sanitize_key((string) $data['request_type']) : '';
        $confirmation = isset($data['confirmation']) ? trim((string) $data['confirmation']) : '';
        if ($requestType === 'deletion' && ! hash_equals('DISPATCH DELETION', $confirmation)) {
            $this->redirect('error', 'Deletion dispatch requires the exact confirmation phrase: DISPATCH DELETION.');
        }

        $moduleKeys = isset($data['module_keys']) && is_array($data['module_keys'])
            ? array_slice($data['module_keys'], 0, 100)
            : [];
        $result = $this->dispatcher->dispatch([
            'request_uuid' => $data['request_uuid'] ?? '',
            'request_type' => $requestType,
            'requester_user_id' => $data['requester_user_id'] ?? 0,
            'assigned_user_id' => get_current_user_id(),
            'jurisdiction' => $data['jurisdiction'] ?? '',
            'due_at' => $data['due_at'] ?? '',
        ], $moduleKeys);

        $status = isset($result['status']) ? (string) $result['status'] : 'failed';
        $ok = ! empty($result['ok']);
        $message = $ok
            ? sprintf('Privacy request was dispatched with status: %s.', $status)
            : sprintf('Privacy request was not fully dispatched. Status: %s; error: %s.', $status, (string) ($result['error'] ?? 'module-or-storage-failure'));
        $this->redirect($ok ? 'success' : 'error', $message);
    }

    public function handleRetry(): void
    {
        $this->assertCapability('spcrc_manage_privacy_requests', 'You are not allowed to retry privacy requests.');
        $data = $this->postData();
        $requestUuid = isset($data['request_uuid']) ? sanitize_text_field((string) $data['request_uuid']) : '';
        check_admin_referer('spcrc_retry_privacy_request_' . $requestUuid);

        $result = $this->dispatcher->retry($requestUuid, get_current_user_id());
        $status = isset($result['status']) ? (string) $result['status'] : 'failed';
        $ok = ! empty($result['ok']);
        $message = $ok
            ? sprintf('Privacy request retry completed with status: %s.', $status)
            : sprintf('Privacy request retry was not completed. Status: %s; error: %s.', $status, (string) ($result['error'] ?? 'module-or-storage-failure'));
        $this->redirect($ok ? 'success' : 'error', $message);
    }

    public function render(): void
    {
        $this->assertCapability('spcrc_manage_privacy_requests', 'You are not allowed to view privacy requests.');
        $notice = get_transient('spcrc_privacy_notice_' . get_current_user_id());
        if (is_array($notice)) {
            delete_transient('spcrc_privacy_notice_' . get_current_user_id());
        }

        $manifests = $this->modules->all();
        $rows = $this->requests->recent(50);
        $detailUuid = isset($_GET['request_uuid'])
            ? sanitize_text_field((string) wp_unslash($_GET['request_uuid']))
            : '';
        $detail = $detailUuid !== '' ? $this->requests->get($detailUuid) : null;
        $detailResults = $detail !== null ? $this->requests->moduleResults($detailUuid) : [];
        ?>
        <div class="wrap spcrc-wrap">
            <h1><?php esc_html_e('Privacy Requests', 'sabri-security-center'); ?></h1>
            <p><?php esc_html_e('Dispatch a verified data-subject request only after identity and authority have been established. File 24 stores orchestration metadata, not exported personal data.', 'sabri-security-center'); ?></p>

            <?php if (is_array($notice)) : ?>
                <div class="notice notice-<?php echo esc_attr(($notice['type'] ?? '') === 'error' ? 'error' : 'success'); ?> is-dismissible"><p><?php echo esc_html((string) ($notice['message'] ?? '')); ?></p></div>
            <?php endif; ?>

            <section class="spcrc-panel" aria-labelledby="spcrc-privacy-dispatch-heading">
                <h2 id="spcrc-privacy-dispatch-heading"><?php esc_html_e('Dispatch a verified request', 'sabri-security-center'); ?></h2>
                <form class="spcrc-form-grid" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="spcrc_dispatch_privacy_request">
                    <input type="hidden" name="request_uuid" value="<?php echo esc_attr(wp_generate_uuid4()); ?>">
                    <?php wp_nonce_field('spcrc_dispatch_privacy_request'); ?>
                    <p><label><?php esc_html_e('WordPress user ID', 'sabri-security-center'); ?><input required min="1" name="requester_user_id" type="number"></label></p>
                    <p><label><?php esc_html_e('Request type', 'sabri-security-center'); ?><select required name="request_type">
                        <?php foreach (PrivacyRequestPolicy::types() as $type) : ?>
                            <option value="<?php echo esc_attr($type); ?>"><?php echo esc_html(ucwords(str_replace('-', ' ', $type))); ?></option>
                        <?php endforeach; ?>
                    </select></label></p>
                    <p><label><?php esc_html_e('Jurisdiction', 'sabri-security-center'); ?><input maxlength="80" name="jurisdiction" type="text" placeholder="Pakistan"></label></p>
                    <p><label><?php esc_html_e('Due date', 'sabri-security-center'); ?><input name="due_at" type="date"></label></p>
                    <p class="spcrc-form-wide"><label><?php esc_html_e('Deletion confirmation', 'sabri-security-center'); ?><input autocomplete="off" maxlength="40" name="confirmation" type="text" placeholder="DISPATCH DELETION"><small><?php esc_html_e('Required only for deletion requests. This prevents accidental destructive dispatch.', 'sabri-security-center'); ?></small></label></p>
                    <fieldset class="spcrc-form-wide">
                        <legend><?php esc_html_e('Native modules to dispatch', 'sabri-security-center'); ?></legend>
                        <div class="spcrc-checkbox-grid">
                        <?php $available = 0; foreach ($manifests as $manifest) : ?>
                            <?php $operations = (array) ($manifest['privacy_operations'] ?? []); if ($operations === []) { continue; } ++$available; ?>
                            <label>
                                <input type="checkbox" name="module_keys[]" value="<?php echo esc_attr((string) ($manifest['module_key'] ?? '')); ?>">
                                <span><strong><?php echo esc_html((string) ($manifest['name'] ?? '')); ?></strong><br><small><?php echo esc_html(implode(', ', array_map('strval', $operations))); ?></small></span>
                            </label>
                        <?php endforeach; ?>
                        <?php if ($available === 0) : ?>
                            <p><?php esc_html_e('No registered module currently declares privacy operations.', 'sabri-security-center'); ?></p>
                        <?php endif; ?>
                        </div>
                    </fieldset>
                    <p class="spcrc-form-actions"><?php submit_button(__('Dispatch request', 'sabri-security-center'), 'primary', 'submit', false, ['disabled' => $available === 0]); ?></p>
                </form>
            </section>

            <?php if ($detailUuid !== '') : ?>
                <section class="spcrc-panel" aria-labelledby="spcrc-privacy-detail-heading">
                    <h2 id="spcrc-privacy-detail-heading"><?php esc_html_e('Request detail and reconciliation evidence', 'sabri-security-center'); ?></h2>
                    <?php if ($detail === null) : ?>
                        <p><?php esc_html_e('The requested privacy record was not found.', 'sabri-security-center'); ?></p>
                    <?php else : ?>
                        <p>
                            <strong><?php esc_html_e('Request:', 'sabri-security-center'); ?></strong>
                            <code><?php echo esc_html((string) ($detail['request_uuid'] ?? '')); ?></code>
                            · <strong><?php esc_html_e('Status:', 'sabri-security-center'); ?></strong>
                            <?php echo esc_html((string) ($detail['status'] ?? '')); ?>
                            · <strong><?php esc_html_e('Attempts:', 'sabri-security-center'); ?></strong>
                            <?php echo esc_html((string) ($detail['dispatch_attempts'] ?? '0')); ?>
                        </p>
                        <p><?php esc_html_e('This view contains bounded orchestration evidence only. It must not contain exported personal data, identity documents, credentials or clinical records.', 'sabri-security-center'); ?></p>
                        <div class="spcrc-table-scroll">
                            <table class="widefat striped spcrc-data-table">
                                <caption class="screen-reader-text"><?php esc_html_e('Native module privacy-operation evidence', 'sabri-security-center'); ?></caption>
                                <thead><tr><th scope="col"><?php esc_html_e('Module', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Code', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Retry safe', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Reference', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Message', 'sabri-security-center'); ?></th></tr></thead>
                                <tbody>
                                <?php if ($detailResults === []) : ?>
                                    <tr><td colspan="6"><?php esc_html_e('No native module evidence is available.', 'sabri-security-center'); ?></td></tr>
                                <?php else : foreach ($detailResults as $moduleKey => $moduleResult) : ?>
                                    <tr>
                                        <td><code><?php echo esc_html((string) $moduleKey); ?></code></td>
                                        <td><?php echo esc_html((string) ($moduleResult['status'] ?? '')); ?></td>
                                        <td><?php echo esc_html((string) ($moduleResult['code'] ?? '')); ?></td>
                                        <td><?php echo str_starts_with((string) ($moduleResult['code'] ?? ''), 'retry-safe-') ? esc_html__('Yes', 'sabri-security-center') : esc_html__('No', 'sabri-security-center'); ?></td>
                                        <td><?php echo esc_html((string) ($moduleResult['reference'] ?? '')); ?></td>
                                        <td><?php echo esc_html((string) ($moduleResult['message'] ?? '')); ?></td>
                                    </tr>
                                <?php endforeach; endif; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </section>
            <?php endif; ?>

            <section class="spcrc-panel" aria-labelledby="spcrc-privacy-history-heading">
                <h2 id="spcrc-privacy-history-heading"><?php esc_html_e('Recent request metadata', 'sabri-security-center'); ?></h2>
                <p><?php echo esc_html(sprintf(__('Active or unresolved requests: %d', 'sabri-security-center'), $this->requests->activeCount())); ?></p>
                <div class="spcrc-table-scroll">
                    <table class="widefat striped spcrc-data-table">
                        <caption class="screen-reader-text"><?php esc_html_e('Recent privacy-request orchestration metadata', 'sabri-security-center'); ?></caption>
                        <thead><tr><th scope="col"><?php esc_html_e('Request', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Subject', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Type', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Attempts', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Last error', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Next retry', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Due', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Updated', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Action', 'sabri-security-center'); ?></th></tr></thead>
                        <tbody>
                        <?php if ($rows === []) : ?>
                            <tr><td colspan="10"><?php esc_html_e('No privacy requests have been dispatched.', 'sabri-security-center'); ?></td></tr>
                        <?php else : foreach ($rows as $row) : ?>
                            <tr>
                                <td><a href="<?php echo esc_url(add_query_arg(['page' => 'sabri-security-privacy-requests', 'request_uuid' => (string) ($row['request_uuid'] ?? '')], admin_url('admin.php'))); ?>"><code><?php echo esc_html((string) ($row['request_uuid'] ?? '')); ?></code></a></td>
                                <td><?php echo esc_html((string) ($row['requester_user_id'] ?? '')); ?></td>
                                <td><?php echo esc_html((string) ($row['request_type'] ?? '')); ?></td>
                                <td><?php echo esc_html((string) ($row['status'] ?? '')); ?></td>
                                <td><?php echo esc_html((string) ($row['dispatch_attempts'] ?? '0')); ?></td>
                                <td><?php echo esc_html((string) ($row['last_error_code'] ?? '')); ?></td>
                                <td><?php echo esc_html((string) ($row['next_retry_at'] ?? '')); ?></td>
                                <td><?php echo esc_html((string) ($row['due_at'] ?? '')); ?></td>
                                <td><?php echo esc_html((string) ($row['updated_at'] ?? '')); ?></td>
                                <td>
                                    <?php $eligibility = $this->requests->retryEligibility($row); ?>
                                    <?php if (! empty($eligibility['eligible'])) : ?>
                                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                            <input type="hidden" name="action" value="spcrc_retry_privacy_request">
                                            <input type="hidden" name="request_uuid" value="<?php echo esc_attr((string) ($row['request_uuid'] ?? '')); ?>">
                                            <?php wp_nonce_field('spcrc_retry_privacy_request_' . (string) ($row['request_uuid'] ?? '')); ?>
                                            <?php submit_button(sprintf(__('Retry %d safe module(s)', 'sabri-security-center'), (int) ($eligibility['retry_modules'] ?? 0)), 'secondary small', 'submit', false); ?>
                                        </form>
                                    <?php elseif (($eligibility['code'] ?? '') === 'not-due') : ?>
                                        <span><?php echo esc_html(sprintf(__('Retry available after %s UTC', 'sabri-security-center'), (string) ($eligibility['retry_at'] ?? ''))); ?></span>
                                    <?php elseif (($eligibility['code'] ?? '') === 'attempt-limit') : ?>
                                        <strong><?php esc_html_e('Attempt limit reached; manual reconciliation required.', 'sabri-security-center'); ?></strong>
                                    <?php elseif (($eligibility['code'] ?? '') === 'manual-reconciliation') : ?>
                                        <strong><?php esc_html_e('Automatic retry blocked; reconcile native evidence manually.', 'sabri-security-center'); ?></strong>
                                    <?php else : ?>
                                        <span aria-hidden="true">—</span><span class="screen-reader-text"><?php esc_html_e('No retry action available', 'sabri-security-center'); ?></span>
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
            'spcrc_privacy_notice_' . get_current_user_id(),
            ['type' => $type === 'error' ? 'error' : 'success', 'message' => $message],
            5 * MINUTE_IN_SECONDS
        );
        wp_safe_redirect(add_query_arg(['page' => 'sabri-security-privacy-requests'], admin_url('admin.php')));
        exit;
    }
}
