<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Admin;

use Sabri\Platform\Security\Privacy\PrivacyRequestPolicy;
use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;

/**
 * Verified privacy-operations interface. It stores only bounded orchestration
 * and verification references; never identity documents or exported data.
 */
final class VerifiedPrivacyAdmin
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
        $this->assertCapability();
        check_admin_referer('spcrc_dispatch_privacy_request');
        $data = $this->postData();
        $type = sanitize_key((string) ($data['request_type'] ?? ''));

        if (! hash_equals('IDENTITY VERIFIED', trim((string) ($data['verification_confirmation'] ?? '')))) {
            $this->redirect('error', 'Dispatch requires the exact attestation phrase: IDENTITY VERIFIED.');
        }
        if ($type === 'deletion' && ! hash_equals('DISPATCH DELETION', trim((string) ($data['deletion_confirmation'] ?? '')))) {
            $this->redirect('error', 'Deletion dispatch requires the exact phrase: DISPATCH DELETION.');
        }

        $modules = isset($data['module_keys']) && is_array($data['module_keys'])
            ? array_slice($data['module_keys'], 0, 100)
            : [];
        $result = $this->dispatcher->dispatch([
            'request_uuid' => $data['request_uuid'] ?? '',
            'request_type' => $type,
            'requester_user_id' => $data['requester_user_id'] ?? 0,
            'assigned_user_id' => get_current_user_id(),
            'jurisdiction' => $data['jurisdiction'] ?? '',
            'due_at' => $data['due_at'] ?? '',
            'verification_method' => $data['verification_method'] ?? '',
            'authority_basis' => $data['authority_basis'] ?? '',
            'verification_reference' => $data['verification_reference'] ?? '',
            'verified_by_user_id' => get_current_user_id(),
            'verified_at' => gmdate('c'),
            'verification_attested' => true,
        ], $modules);

        $this->redirect(
            ! empty($result['ok']) ? 'success' : 'error',
            sprintf(
                'Privacy dispatch status: %s; result: %s.',
                (string) ($result['status'] ?? 'failed'),
                (string) ($result['error'] ?? 'recorded')
            )
        );
    }

    public function handleRetry(): void
    {
        $this->assertCapability();
        $data = $this->postData();
        $uuid = sanitize_text_field((string) ($data['request_uuid'] ?? ''));
        check_admin_referer('spcrc_retry_privacy_request_' . $uuid);
        $record = $this->requests->get($uuid);
        if ($record === null) {
            $this->redirect('error', 'Privacy request could not be found.');
        }

        $authorization = [];
        if ((string) ($record['request_type'] ?? '') === 'deletion') {
            $expected = $this->deletionRetryPhrase($uuid);
            $provided = trim((string) ($data['retry_confirmation'] ?? ''));
            if (! hash_equals($expected, $provided)) {
                $this->redirect('error', sprintf('Deletion retry requires the exact phrase: %s', $expected));
            }
            $authorization['deletion_confirmation'] = $provided;
        }

        $result = $this->dispatcher->retry($uuid, get_current_user_id(), $authorization);
        $this->redirect(
            ! empty($result['ok']) ? 'success' : 'error',
            sprintf(
                'Privacy retry status: %s; result: %s.',
                (string) ($result['status'] ?? 'failed'),
                (string) ($result['error'] ?? 'recorded')
            )
        );
    }

    public function render(): void
    {
        $this->assertCapability();
        $notice = get_transient('spcrc_privacy_notice_' . get_current_user_id());
        if (is_array($notice)) {
            delete_transient('spcrc_privacy_notice_' . get_current_user_id());
        }
        $manifests = $this->modules->all();
        $rows = $this->requests->recent(50);
        ?>
        <div class="wrap spcrc-wrap">
            <h1><?php esc_html_e('Verified Privacy Requests', 'sabri-security-center'); ?></h1>
            <p><?php esc_html_e('Verify identity and legal authority before dispatch. Store only an opaque case reference—never identity documents, credentials, exported data or clinical records.', 'sabri-security-center'); ?></p>
            <?php if (is_array($notice)) : ?>
                <div class="notice notice-<?php echo esc_attr(($notice['type'] ?? '') === 'error' ? 'error' : 'success'); ?> is-dismissible"><p><?php echo esc_html((string) ($notice['message'] ?? '')); ?></p></div>
            <?php endif; ?>

            <section class="spcrc-panel" aria-labelledby="spcrc-verified-dispatch">
                <h2 id="spcrc-verified-dispatch"><?php esc_html_e('Dispatch verified request', 'sabri-security-center'); ?></h2>
                <form class="spcrc-form-grid" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                    <input type="hidden" name="action" value="spcrc_dispatch_privacy_request">
                    <input type="hidden" name="request_uuid" value="<?php echo esc_attr(wp_generate_uuid4()); ?>">
                    <?php wp_nonce_field('spcrc_dispatch_privacy_request'); ?>
                    <p><label><?php esc_html_e('WordPress user ID', 'sabri-security-center'); ?><input required min="1" name="requester_user_id" type="number"></label></p>
                    <p><label><?php esc_html_e('Request type', 'sabri-security-center'); ?><select required name="request_type"><?php foreach (PrivacyRequestPolicy::types() as $type) : ?><option value="<?php echo esc_attr($type); ?>"><?php echo esc_html($type); ?></option><?php endforeach; ?></select></label></p>
                    <p><label><?php esc_html_e('Verification method', 'sabri-security-center'); ?><select required name="verification_method"><?php foreach (PrivacyRequestPolicy::verificationMethods() as $method) : ?><option value="<?php echo esc_attr($method); ?>"><?php echo esc_html($method); ?></option><?php endforeach; ?></select></label></p>
                    <p><label><?php esc_html_e('Authority basis', 'sabri-security-center'); ?><select required name="authority_basis"><?php foreach (PrivacyRequestPolicy::authorityBases() as $basis) : ?><option value="<?php echo esc_attr($basis); ?>"><?php echo esc_html($basis); ?></option><?php endforeach; ?></select></label></p>
                    <p><label><?php esc_html_e('Jurisdiction', 'sabri-security-center'); ?><input maxlength="80" name="jurisdiction" type="text"></label></p>
                    <p><label><?php esc_html_e('Due date', 'sabri-security-center'); ?><input name="due_at" type="date"></label></p>
                    <p class="spcrc-form-wide"><label><?php esc_html_e('Opaque verification reference', 'sabri-security-center'); ?><input required maxlength="200" name="verification_reference" type="text" placeholder="case:privacy-2026-001"></label></p>
                    <p class="spcrc-form-wide"><label><?php esc_html_e('Identity attestation', 'sabri-security-center'); ?><input required autocomplete="off" maxlength="40" name="verification_confirmation" type="text" placeholder="IDENTITY VERIFIED"></label></p>
                    <p class="spcrc-form-wide"><label><?php esc_html_e('Deletion confirmation', 'sabri-security-center'); ?><input autocomplete="off" maxlength="40" name="deletion_confirmation" type="text" placeholder="DISPATCH DELETION"></label></p>
                    <fieldset class="spcrc-form-wide"><legend><?php esc_html_e('Native modules', 'sabri-security-center'); ?></legend><div class="spcrc-checkbox-grid">
                    <?php $available = 0; foreach ($manifests as $manifest) : $operations = (array) ($manifest['privacy_operations'] ?? []); if ($operations === []) { continue; } ++$available; ?>
                        <label><input type="checkbox" name="module_keys[]" value="<?php echo esc_attr((string) ($manifest['module_key'] ?? '')); ?>"><span><?php echo esc_html((string) ($manifest['name'] ?? '')); ?><br><small><?php echo esc_html(implode(', ', $operations)); ?></small></span></label>
                    <?php endforeach; ?>
                    </div></fieldset>
                    <p class="spcrc-form-actions"><?php submit_button(__('Dispatch verified request', 'sabri-security-center'), 'primary', 'submit', false, ['disabled' => $available === 0]); ?></p>
                </form>
            </section>

            <section class="spcrc-panel" aria-labelledby="spcrc-verified-history">
                <h2 id="spcrc-verified-history"><?php esc_html_e('Recent orchestration evidence', 'sabri-security-center'); ?></h2>
                <div class="spcrc-table-scroll"><table class="widefat striped spcrc-data-table">
                    <thead><tr><th><?php esc_html_e('Request', 'sabri-security-center'); ?></th><th><?php esc_html_e('Subject/type', 'sabri-security-center'); ?></th><th><?php esc_html_e('Verification', 'sabri-security-center'); ?></th><th><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th><?php esc_html_e('Action', 'sabri-security-center'); ?></th></tr></thead><tbody>
                    <?php if ($rows === []) : ?><tr><td colspan="5"><?php esc_html_e('No requests found.', 'sabri-security-center'); ?></td></tr><?php else : foreach ($rows as $row) : $eligibility = $this->requests->retryEligibility($row); ?>
                    <tr>
                        <td><code><?php echo esc_html((string) ($row['request_uuid'] ?? '')); ?></code></td>
                        <td><?php echo esc_html((string) ($row['requester_user_id'] ?? '')); ?> / <?php echo esc_html((string) ($row['request_type'] ?? '')); ?></td>
                        <td><?php echo esc_html((string) ($row['verification_method'] ?? 'missing')); ?><br><code><?php echo esc_html((string) ($row['verification_reference'] ?? '')); ?></code></td>
                        <td><?php echo esc_html((string) ($row['status'] ?? '')); ?><br><small><?php echo esc_html((string) ($eligibility['code'] ?? '')); ?></small></td>
                        <td>
                        <?php if (! empty($eligibility['eligible']) || ($eligibility['code'] ?? '') === 'deletion-reauthorization-required') : ?>
                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                <input type="hidden" name="action" value="spcrc_retry_privacy_request"><input type="hidden" name="request_uuid" value="<?php echo esc_attr((string) ($row['request_uuid'] ?? '')); ?>"><?php wp_nonce_field('spcrc_retry_privacy_request_' . (string) ($row['request_uuid'] ?? '')); ?>
                                <?php if ((string) ($row['request_type'] ?? '') === 'deletion') : $phrase = $this->deletionRetryPhrase((string) ($row['request_uuid'] ?? '')); ?><label><span class="screen-reader-text"><?php esc_html_e('Deletion retry confirmation', 'sabri-security-center'); ?></span><input required autocomplete="off" maxlength="80" name="retry_confirmation" type="text" placeholder="<?php echo esc_attr($phrase); ?>"></label><?php endif; ?>
                                <?php submit_button(__('Retry safely', 'sabri-security-center'), 'secondary small', 'submit', false); ?>
                            </form>
                        <?php else : ?><span><?php echo esc_html((string) ($eligibility['code'] ?? 'not-available')); ?></span><?php endif; ?>
                        </td>
                    </tr>
                    <?php endforeach; endif; ?>
                    </tbody>
                </table></div>
            </section>
        </div>
        <?php
    }

    private function assertCapability(): void
    {
        if (! current_user_can('spcrc_manage_privacy_requests')) {
            wp_die(esc_html__('You are not allowed to manage privacy requests.', 'sabri-security-center'));
        }
    }

    /** @return array<string,mixed> */
    private function postData(): array
    {
        return is_array($_POST) ? wp_unslash($_POST) : [];
    }

    private function deletionRetryPhrase(string $requestUuid): string
    {
        return 'RETRY DELETION ' . strtolower(trim($requestUuid));
    }

    private function redirect(string $type, string $message): void
    {
        set_transient('spcrc_privacy_notice_' . get_current_user_id(), ['type' => $type, 'message' => $message], 5 * MINUTE_IN_SECONDS);
        wp_safe_redirect(add_query_arg(['page' => 'sabri-security-privacy-requests'], admin_url('admin.php')));
        exit;
    }
}
