<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Admin;

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Storage\RiskRepository;
use Sabri\Platform\Security\System\Repair;
use Sabri\Platform\Security\System\SystemCheck;

final class Dashboard
{
    public function __construct(
        private ModuleRegistry $modules,
        private SecurityStateRegistry $states,
        private SystemCheck $checks,
        private AuditLogger $audit,
        private RiskRepository $risks,
        private IncidentRepository $incidents,
        private ControlRepository $controls,
        private Repair $repair
    ) {
    }

    public function registerHooks(): void
    {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
        add_action('admin_post_spcrc_run_system_check', [$this, 'handleSystemCheck']);
        add_action('admin_post_spcrc_create_risk', [$this, 'handleCreateRisk']);
        add_action('admin_post_spcrc_create_incident', [$this, 'handleCreateIncident']);
        add_action('admin_post_spcrc_upsert_control', [$this, 'handleUpsertControl']);
        add_action('admin_post_spcrc_run_repair', [$this, 'handleRepair']);
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
        $this->assertCapability('spcrc_run_security_assessments', 'You are not allowed to run security assessments.');
        check_admin_referer('spcrc_run_system_check');

        $checks = $this->checks->run();
        set_transient('spcrc_last_system_check_' . get_current_user_id(), $checks, 10 * MINUTE_IN_SECONDS);
        $this->audit->record('system_check_run', 'file-24-security-center', 'completed', 'informational', ['check_count' => count($checks)]);
        $this->redirect('success', 'Security checks were refreshed.');
    }

    public function handleCreateRisk(): void
    {
        $this->assertCapability('spcrc_manage_risks', 'You are not allowed to manage risks.');
        check_admin_referer('spcrc_create_risk');

        $result = $this->risks->create($this->postData());
        if (is_wp_error($result)) {
            $this->audit->record('risk_create_failed', 'file-24-security-center', 'failed', 'medium', ['error_code' => $result->get_error_code()]);
            $this->redirect('error', $result->get_error_message());
        }

        $this->audit->record('risk_created', 'file-24-security-center', 'completed', 'medium', ['risk_uuid' => $result]);
        $this->redirect('success', 'Risk was recorded.');
    }

    public function handleCreateIncident(): void
    {
        $this->assertCapability('spcrc_manage_incidents', 'You are not allowed to manage incidents.');
        check_admin_referer('spcrc_create_incident');

        $result = $this->incidents->create($this->postData());
        if (is_wp_error($result)) {
            $this->audit->record('incident_create_failed', 'file-24-security-center', 'failed', 'high', ['error_code' => $result->get_error_code()]);
            $this->redirect('error', $result->get_error_message());
        }

        $this->audit->record('incident_created', 'file-24-security-center', 'completed', 'high', ['incident_uuid' => $result]);
        $this->redirect('success', 'Incident was opened.');
    }

    public function handleUpsertControl(): void
    {
        $this->assertCapability('spcrc_manage_controls', 'You are not allowed to manage controls.');
        check_admin_referer('spcrc_upsert_control');

        $result = $this->controls->upsert($this->postData());
        if (is_wp_error($result)) {
            $this->audit->record('control_write_failed', 'file-24-security-center', 'failed', 'medium', ['error_code' => $result->get_error_code()]);
            $this->redirect('error', $result->get_error_message());
        }

        $this->audit->record('control_saved', 'file-24-security-center', 'completed', 'informational', ['control_key' => $result]);
        $this->redirect('success', 'Control was saved.');
    }

    public function handleRepair(): void
    {
        $this->assertCapability('spcrc_manage_security_settings', 'You are not allowed to run repair.');
        check_admin_referer('spcrc_run_repair');

        $result = $this->repair->run();
        if (is_wp_error($result)) {
            $this->audit->record('non_destructive_repair_failed', 'file-24-security-center', 'failed', 'high', ['error_code' => $result->get_error_code()]);
            $this->redirect('error', $result->get_error_message());
        }

        $this->audit->record('non_destructive_repair_completed', 'file-24-security-center', 'completed', 'informational', $result);
        $this->redirect('success', 'Non-destructive repair completed.');
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

        $manifests = current_user_can('spcrc_view_module_posture') ? $this->modules->all() : [];
        $stateRequests = current_user_can('spcrc_view_module_posture') ? $this->states->all() : [];
        $notice = get_transient('spcrc_admin_notice_' . get_current_user_id());
        if (is_array($notice)) {
            delete_transient('spcrc_admin_notice_' . get_current_user_id());
        }

        $recentRisks = current_user_can('spcrc_manage_risks') ? $this->risks->recent(10) : [];
        $recentIncidents = current_user_can('spcrc_manage_incidents') ? $this->incidents->recent(10) : [];
        $recentControls = current_user_can('spcrc_manage_controls') ? $this->controls->recent(10) : [];
        ?>
        <div class="wrap spcrc-wrap">
            <h1><?php esc_html_e('Sabri Platform Security Center', 'sabri-security-center'); ?></h1>
            <p class="spcrc-intro"><?php esc_html_e('Central governance and assurance dashboard. Native modules retain their own authentication, authorization, and data ownership.', 'sabri-security-center'); ?></p>

            <?php if (is_array($notice)) : ?>
                <div class="notice notice-<?php echo esc_attr(($notice['type'] ?? '') === 'error' ? 'error' : 'success'); ?> is-dismissible"><p><?php echo esc_html((string) ($notice['message'] ?? '')); ?></p></div>
            <?php endif; ?>

            <div class="spcrc-grid" aria-label="<?php esc_attr_e('Security overview', 'sabri-security-center'); ?>">
                <?php $this->metric(__('Registered modules', 'sabri-security-center'), (string) count($manifests)); ?>
                <?php $this->metric(__('Open state requests', 'sabri-security-center'), (string) count($stateRequests)); ?>
                <?php $this->metric(__('Open risks', 'sabri-security-center'), current_user_can('spcrc_manage_risks') ? (string) $this->risks->openCount() : '—'); ?>
                <?php $this->metric(__('Open incidents', 'sabri-security-center'), current_user_can('spcrc_manage_incidents') ? (string) $this->incidents->openCount() : '—'); ?>
                <?php $this->metric(__('Controls', 'sabri-security-center'), current_user_can('spcrc_manage_controls') ? (string) $this->controls->count() : '—'); ?>
                <?php $this->metric(__('Plugin version', 'sabri-security-center'), SPCRC_VERSION); ?>
                <?php $this->metric(__('Schema version', 'sabri-security-center'), (string) get_option('spcrc_schema_version', 'unknown')); ?>
                <?php $this->metric(__('Environment', 'sabri-security-center'), wp_get_environment_type()); ?>
            </div>

            <?php $this->renderSystemChecks($checks); ?>
            <?php $this->renderModulePosture($manifests); ?>
            <?php $this->renderStateRequests($stateRequests); ?>
            <?php $this->renderRiskSection($recentRisks); ?>
            <?php $this->renderIncidentSection($recentIncidents); ?>
            <?php $this->renderControlSection($recentControls); ?>
            <?php $this->renderRepairSection(); ?>

            <div class="notice notice-info inline">
                <p><?php esc_html_e('This dashboard never displays passwords, OTPs, encryption keys, identity documents, patient records, or private message bodies.', 'sabri-security-center'); ?></p>
            </div>
        </div>
        <?php
    }

    /** @param array<int,array<string,mixed>> $checks */
    private function renderSystemChecks(array $checks): void
    {
        ?>
        <section class="spcrc-panel" aria-labelledby="spcrc-checks-heading">
            <div class="spcrc-panel-heading">
                <h2 id="spcrc-checks-heading"><?php esc_html_e('System checks', 'sabri-security-center'); ?></h2>
                <?php if (current_user_can('spcrc_run_security_assessments')) : ?>
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                        <input type="hidden" name="action" value="spcrc_run_system_check">
                        <?php wp_nonce_field('spcrc_run_system_check'); ?>
                        <?php submit_button(__('Run checks', 'sabri-security-center'), 'secondary', 'submit', false); ?>
                    </form>
                <?php endif; ?>
            </div>
            <table class="widefat striped">
                <caption class="screen-reader-text"><?php esc_html_e('Current File 24 security system checks', 'sabri-security-center'); ?></caption>
                <thead><tr><th scope="col"><?php esc_html_e('Check', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Detail', 'sabri-security-center'); ?></th></tr></thead>
                <tbody>
                <?php foreach ($checks as $check) : ?>
                    <tr>
                        <td><?php echo esc_html((string) ($check['label'] ?? '')); ?></td>
                        <td><span class="spcrc-status spcrc-status--<?php echo esc_attr((string) ($check['status'] ?? 'unknown')); ?>"><?php echo esc_html(strtoupper((string) ($check['status'] ?? 'unknown'))); ?></span></td>
                        <td><?php echo esc_html((string) ($check['detail'] ?? '')); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </section>
        <?php
    }

    /** @param array<string,array<string,mixed>> $manifests */
    private function renderModulePosture(array $manifests): void
    {
        if (! current_user_can('spcrc_view_module_posture')) {
            return;
        }
        ?>
        <section class="spcrc-panel" aria-labelledby="spcrc-module-heading">
            <h2 id="spcrc-module-heading"><?php esc_html_e('Module posture', 'sabri-security-center'); ?></h2>
            <table class="widefat striped">
                <caption class="screen-reader-text"><?php esc_html_e('Registered platform modules and security posture', 'sabri-security-center'); ?></caption>
                <thead><tr><th scope="col"><?php esc_html_e('Module', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Version', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Owner', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Posture', 'sabri-security-center'); ?></th></tr></thead>
                <tbody>
                <?php if ($manifests === []) : ?>
                    <tr><td colspan="4"><?php esc_html_e('No module manifests are registered.', 'sabri-security-center'); ?></td></tr>
                <?php else : ?>
                    <?php foreach ($manifests as $manifest) : ?>
                        <tr>
                            <td><?php echo esc_html((string) ($manifest['name'] ?? '')); ?></td>
                            <td><?php echo esc_html((string) ($manifest['version'] ?? '')); ?></td>
                            <td><?php echo esc_html((string) ($manifest['owner'] ?? '')); ?></td>
                            <td><?php echo esc_html((string) ($manifest['posture'] ?? 'unassessed')); ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>
        </section>
        <?php
    }

    /** @param array<int,array<string,mixed>> $stateRequests */
    private function renderStateRequests(array $stateRequests): void
    {
        if (! current_user_can('spcrc_view_module_posture') || $stateRequests === []) {
            return;
        }
        ?>
        <section class="spcrc-panel" aria-labelledby="spcrc-state-heading">
            <h2 id="spcrc-state-heading"><?php esc_html_e('Open security-state requests', 'sabri-security-center'); ?></h2>
            <table class="widefat striped">
                <caption class="screen-reader-text"><?php esc_html_e('Open advisory security-state requests', 'sabri-security-center'); ?></caption>
                <thead><tr><th scope="col"><?php esc_html_e('Module', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('State', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Expires', 'sabri-security-center'); ?></th></tr></thead>
                <tbody>
                <?php foreach ($stateRequests as $request) : ?>
                    <tr>
                        <td><?php echo esc_html((string) ($request['module_key'] ?? '')); ?></td>
                        <td><?php echo esc_html((string) ($request['state'] ?? '')); ?></td>
                        <td><?php echo esc_html((string) ($request['expires_at'] ?? '')); ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </section>
        <?php
    }

    /** @param array<int,array<string,mixed>> $rows */
    private function renderRiskSection(array $rows): void
    {
        if (! current_user_can('spcrc_manage_risks')) {
            return;
        }
        ?>
        <section class="spcrc-panel" aria-labelledby="spcrc-risk-heading">
            <h2 id="spcrc-risk-heading"><?php esc_html_e('Risk register', 'sabri-security-center'); ?></h2>
            <form class="spcrc-form-grid" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="spcrc_create_risk">
                <?php wp_nonce_field('spcrc_create_risk'); ?>
                <p><label><?php esc_html_e('Title', 'sabri-security-center'); ?><input required maxlength="200" name="title" type="text"></label></p>
                <p><label><?php esc_html_e('Module key', 'sabri-security-center'); ?><input required maxlength="120" name="module_key" type="text" value="file-24-security-center"></label></p>
                <p><label><?php esc_html_e('Likelihood (1–5)', 'sabri-security-center'); ?><input required min="1" max="5" name="likelihood" type="number" value="1"></label></p>
                <p><label><?php esc_html_e('Impact (1–5)', 'sabri-security-center'); ?><input required min="1" max="5" name="impact" type="number" value="1"></label></p>
                <p><label><?php esc_html_e('Treatment', 'sabri-security-center'); ?><select name="treatment"><option value="mitigate">Mitigate</option><option value="avoid">Avoid</option><option value="transfer">Transfer</option><option value="accept">Accept</option></select></label></p>
                <p><label><?php esc_html_e('Due date', 'sabri-security-center'); ?><input name="due_at" type="date"></label></p>
                <p class="spcrc-form-actions"><?php submit_button(__('Record risk', 'sabri-security-center'), 'primary', 'submit', false); ?></p>
            </form>
            <?php $this->riskTable($rows); ?>
        </section>
        <?php
    }

    /** @param array<int,array<string,mixed>> $rows */
    private function renderIncidentSection(array $rows): void
    {
        if (! current_user_can('spcrc_manage_incidents')) {
            return;
        }
        ?>
        <section class="spcrc-panel" aria-labelledby="spcrc-incident-heading">
            <h2 id="spcrc-incident-heading"><?php esc_html_e('Incident register', 'sabri-security-center'); ?></h2>
            <form class="spcrc-form-grid" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="spcrc_create_incident">
                <?php wp_nonce_field('spcrc_create_incident'); ?>
                <p><label><?php esc_html_e('Title', 'sabri-security-center'); ?><input required maxlength="200" name="title" type="text"></label></p>
                <p><label><?php esc_html_e('Severity', 'sabri-security-center'); ?><select name="severity"><option value="sev4">SEV-4</option><option value="sev3">SEV-3</option><option value="sev2">SEV-2</option><option value="sev1">SEV-1</option><option value="sev0">SEV-0</option></select></label></p>
                <p class="spcrc-form-wide"><label><?php esc_html_e('Sanitized summary', 'sabri-security-center'); ?><textarea maxlength="1000" name="summary" rows="3"></textarea></label></p>
                <p class="spcrc-form-actions"><?php submit_button(__('Open incident', 'sabri-security-center'), 'primary', 'submit', false); ?></p>
            </form>
            <?php $this->incidentTable($rows); ?>
        </section>
        <?php
    }

    /** @param array<int,array<string,mixed>> $rows */
    private function renderControlSection(array $rows): void
    {
        if (! current_user_can('spcrc_manage_controls')) {
            return;
        }
        ?>
        <section class="spcrc-panel" aria-labelledby="spcrc-control-heading">
            <h2 id="spcrc-control-heading"><?php esc_html_e('Control catalog', 'sabri-security-center'); ?></h2>
            <form class="spcrc-form-grid" method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="spcrc_upsert_control">
                <?php wp_nonce_field('spcrc_upsert_control'); ?>
                <p><label><?php esc_html_e('Control key', 'sabri-security-center'); ?><input required maxlength="120" name="control_key" type="text" placeholder="ac-01"></label></p>
                <p><label><?php esc_html_e('Title', 'sabri-security-center'); ?><input required maxlength="200" name="title" type="text"></label></p>
                <p><label><?php esc_html_e('Framework', 'sabri-security-center'); ?><input maxlength="120" name="framework" type="text" placeholder="NIST CSF 2.0"></label></p>
                <p><label><?php esc_html_e('Status', 'sabri-security-center'); ?><select name="status"><option value="unassessed">Unassessed</option><option value="planned">Planned</option><option value="implemented">Implemented</option><option value="tested">Tested</option><option value="failed">Failed</option><option value="accepted">Accepted</option></select></label></p>
                <p><label><?php esc_html_e('Evidence reference', 'sabri-security-center'); ?><input maxlength="255" name="evidence_ref" type="text"></label></p>
                <p><label><?php esc_html_e('Last tested', 'sabri-security-center'); ?><input name="last_tested_at" type="date"></label></p>
                <p class="spcrc-form-actions"><?php submit_button(__('Save control', 'sabri-security-center'), 'primary', 'submit', false); ?></p>
            </form>
            <?php $this->controlTable($rows); ?>
        </section>
        <?php
    }

    private function renderRepairSection(): void
    {
        if (! current_user_can('spcrc_manage_security_settings')) {
            return;
        }
        ?>
        <section class="spcrc-panel" aria-labelledby="spcrc-repair-heading">
            <h2 id="spcrc-repair-heading"><?php esc_html_e('Non-destructive repair', 'sabri-security-center'); ?></h2>
            <p><?php esc_html_e('Recreates only File 24 tables and capabilities. It does not delete evidence or modify companion-module data.', 'sabri-security-center'); ?></p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="spcrc_run_repair">
                <?php wp_nonce_field('spcrc_run_repair'); ?>
                <?php submit_button(__('Run non-destructive repair', 'sabri-security-center'), 'secondary', 'submit', false); ?>
            </form>
        </section>
        <?php
    }

    /** @param array<int,array<string,mixed>> $rows */
    private function riskTable(array $rows): void
    {
        ?>
        <table class="widefat striped spcrc-data-table"><caption class="screen-reader-text"><?php esc_html_e('Recent risks', 'sabri-security-center'); ?></caption><thead><tr><th scope="col"><?php esc_html_e('Title', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Module', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Score', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Treatment', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Status', 'sabri-security-center'); ?></th></tr></thead><tbody>
        <?php if ($rows === []) : ?><tr><td colspan="5"><?php esc_html_e('No risks recorded.', 'sabri-security-center'); ?></td></tr><?php else : foreach ($rows as $row) : ?>
            <tr><td><?php echo esc_html((string) ($row['title'] ?? '')); ?></td><td><?php echo esc_html((string) ($row['module_key'] ?? '')); ?></td><td><?php echo esc_html((string) ($row['inherent_score'] ?? '')); ?></td><td><?php echo esc_html((string) ($row['treatment'] ?? '')); ?></td><td><?php echo esc_html((string) ($row['status'] ?? '')); ?></td></tr>
        <?php endforeach; endif; ?></tbody></table>
        <?php
    }

    /** @param array<int,array<string,mixed>> $rows */
    private function incidentTable(array $rows): void
    {
        ?>
        <table class="widefat striped spcrc-data-table"><caption class="screen-reader-text"><?php esc_html_e('Recent incidents', 'sabri-security-center'); ?></caption><thead><tr><th scope="col"><?php esc_html_e('Title', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Severity', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Status', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Opened', 'sabri-security-center'); ?></th></tr></thead><tbody>
        <?php if ($rows === []) : ?><tr><td colspan="4"><?php esc_html_e('No incidents recorded.', 'sabri-security-center'); ?></td></tr><?php else : foreach ($rows as $row) : ?>
            <tr><td><?php echo esc_html((string) ($row['title'] ?? '')); ?></td><td><?php echo esc_html(strtoupper((string) ($row['severity'] ?? ''))); ?></td><td><?php echo esc_html((string) ($row['status'] ?? '')); ?></td><td><?php echo esc_html((string) ($row['opened_at'] ?? '')); ?></td></tr>
        <?php endforeach; endif; ?></tbody></table>
        <?php
    }

    /** @param array<int,array<string,mixed>> $rows */
    private function controlTable(array $rows): void
    {
        ?>
        <table class="widefat striped spcrc-data-table"><caption class="screen-reader-text"><?php esc_html_e('Recent security controls', 'sabri-security-center'); ?></caption><thead><tr><th scope="col"><?php esc_html_e('Key', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Title', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Framework', 'sabri-security-center'); ?></th><th scope="col"><?php esc_html_e('Status', 'sabri-security-center'); ?></th></tr></thead><tbody>
        <?php if ($rows === []) : ?><tr><td colspan="4"><?php esc_html_e('No controls recorded.', 'sabri-security-center'); ?></td></tr><?php else : foreach ($rows as $row) : ?>
            <tr><td><code><?php echo esc_html((string) ($row['control_key'] ?? '')); ?></code></td><td><?php echo esc_html((string) ($row['title'] ?? '')); ?></td><td><?php echo esc_html((string) ($row['framework'] ?? '')); ?></td><td><?php echo esc_html((string) ($row['status'] ?? '')); ?></td></tr>
        <?php endforeach; endif; ?></tbody></table>
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
            'spcrc_admin_notice_' . get_current_user_id(),
            ['type' => $type === 'error' ? 'error' : 'success', 'message' => $message],
            5 * MINUTE_IN_SECONDS
        );
        wp_safe_redirect(add_query_arg(['page' => 'sabri-security-center'], admin_url('admin.php')));
        exit;
    }
}
