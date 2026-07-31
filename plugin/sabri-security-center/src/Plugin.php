<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Admin\Dashboard;
use Sabri\Platform\Security\Integration\File00Adapter;
use Sabri\Platform\Security\Integration\File20Adapter;
use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Rest\StatusController;
use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
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
        $risks = new RiskRepository($audit);
        $incidents = new IncidentRepository($audit);
        $controls = new ControlRepository($audit);
        $checks = new SystemCheck($modules);
        $privacy = new RequestDispatcher($audit, $modules);
        $repair = new Repair($audit, $modules);

        (new File00Adapter())->registerHooks();
        (new File20Adapter())->registerHooks();
        (new RetentionManager($audit))->registerHooks();
        $modules->registerHooks();
        $states->registerHooks();
        $risks->registerHooks();
        $incidents->registerHooks();
        $controls->registerHooks();
        $privacy->registerHooks();
        $repair->registerHooks();
        (new Dashboard($modules, $states, $checks, $audit, $risks, $incidents, $controls, $repair))->registerHooks();
        (new StatusController($modules, $states, $checks, $risks, $incidents, $controls))->registerHooks();

        do_action('spcrc/booted', $this);
    }
}
