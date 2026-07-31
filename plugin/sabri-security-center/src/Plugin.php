<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Admin\AssetLoader;
use Sabri\Platform\Security\Admin\AssuranceAdmin;
use Sabri\Platform\Security\Admin\Dashboard;
use Sabri\Platform\Security\Admin\FindingAdmin;
use Sabri\Platform\Security\Admin\VerifiedPrivacyAdmin;
use Sabri\Platform\Security\Integration\File00Adapter;
use Sabri\Platform\Security\Integration\File20Adapter;
use Sabri\Platform\Security\Privacy\PrivacyRequestPolicy;
use Sabri\Platform\Security\Privacy\RecoveryManager;
use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Rest\StatusController;
use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\FindingRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;
use Sabri\Platform\Security\Storage\RiskRepository;
use Sabri\Platform\Security\System\Repair;
use Sabri\Platform\Security\System\SystemCheck;

final class Plugin
{
    private static ?self $instance = null;
    private bool $booted = false;

    public static function instance(): self
    {
        return self::$instance ??= new self();
    }

    public function boot(): void
    {
        if ($this->booted) {
            return;
        }
        $this->booted = true;
        load_plugin_textdomain('sabri-security-center', false, dirname(plugin_basename(SPCRC_PLUGIN_FILE)) . '/languages');

        $upgrade = UpgradeManager::maybeUpgrade();
        if (is_wp_error($upgrade)) {
            $this->registerUpgradeFailureNotice();
            do_action('spcrc/boot_blocked', $upgrade);
            return;
        }

        Capabilities::registerHooks();
        $audit = new AuditLogger();
        $modules = new ModuleRegistry();
        $states = new SecurityStateRegistry($modules, $audit);
        $findings = new FindingRepository($audit);
        $risks = new RiskRepository($audit);
        $incidents = new IncidentRepository($audit);
        $controls = new ControlRepository($audit);
        $assurance = new AssuranceRepository($audit);
        $checks = new SystemCheck($modules);
        $privacyStorage = new PrivacyRequestRepository();
        $privacyRequests = new PrivacyRequestPolicy($privacyStorage);
        $privacy = new RequestDispatcher($audit, $modules, $privacyRequests);
        $privacyRecovery = new RecoveryManager($privacyStorage, $audit);
        $repair = new Repair();

        (new File00Adapter())->registerHooks();
        (new File20Adapter())->registerHooks();
        (new RetentionManager($audit))->registerHooks();
        $modules->registerHooks();
        $states->registerHooks();
        $findings->registerHooks();
        $assurance->registerHooks();
        $privacy->registerHooks();
        $privacyRecovery->registerHooks();
        (new AssetLoader())->registerHooks();
        (new Dashboard($modules, $states, $checks, $audit, $risks, $incidents, $controls, $repair))->registerHooks();
        (new FindingAdmin($findings))->registerHooks();
        (new AssuranceAdmin($assurance))->registerHooks();
        (new VerifiedPrivacyAdmin($privacyRequests, $privacy, $modules))->registerHooks();
        (new StatusController($modules, $states, $checks, $risks, $incidents, $controls, $findings, $assurance))->registerHooks();

        do_action('spcrc/booted', $this);
    }

    private function registerUpgradeFailureNotice(): void
    {
        add_action('admin_notices', static function (): void {
            if (! current_user_can('activate_plugins')) {
                return;
            }
            ?>
            <div class="notice notice-error">
                <p><?php esc_html_e('File 24 Security Center did not start because a required schema, retention, privacy-recovery or version-state integrity check failed. No File 24 operational service was booted. Review the recorded upgrade evidence and repair the staging environment before retrying.', 'sabri-security-center'); ?></p>
            </div>
            <?php
        });
    }
}
