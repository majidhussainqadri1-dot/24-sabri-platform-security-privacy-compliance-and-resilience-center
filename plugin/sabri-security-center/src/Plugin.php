<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Admin\AssetLoader;
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

        UpgradeManager::maybeUpgrade();
        Capabilities::registerHooks();
        $audit = new AuditLogger();
        $modules = new ModuleRegistry();
        $states = new SecurityStateRegistry($modules, $audit);
        $findings = new FindingRepository($audit);
        $risks = new RiskRepository($audit);
        $incidents = new IncidentRepository($audit);
        $controls = new ControlRepository($audit);
        $checks = new SystemCheck($modules);
        $privacyStorage = new PrivacyRequestRepository();
        $privacyRequests = new PrivacyRequestPolicy($privacyStorage);
        $privacy = new RequestDispatcher($audit, $modules, $privacyRequests);
        $privacyRecovery = new RecoveryManager($privacyStorage, $audit);
        $repair = new Repair($audit, $modules);

        (new File00Adapter())->registerHooks();
        (new File20Adapter())->registerHooks();
        (new RetentionManager($audit))->registerHooks();
        $modules->registerHooks();
        $states->registerHooks();
        $findings->registerHooks();
        $risks->registerHooks();
        $incidents->registerHooks();
        $controls->registerHooks();
        $privacy->registerHooks();
        $privacyRecovery->registerHooks();
        $repair->registerHooks();
        (new AssetLoader())->registerHooks();
        (new Dashboard($modules, $states, $checks, $audit, $risks, $incidents, $controls, $repair))->registerHooks();
        (new FindingAdmin($findings))->registerHooks();
        (new VerifiedPrivacyAdmin($privacyRequests, $privacy, $modules))->registerHooks();
        (new StatusController($modules, $states, $checks, $risks, $incidents, $controls, $findings))->registerHooks();

        do_action('spcrc/booted', $this);
    }
}
