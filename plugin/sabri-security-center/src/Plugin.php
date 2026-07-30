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

    private ModuleRegistry $modules;
    private SecurityStateRegistry $states;
    private AuditLogger $audit;
    private RequestDispatcher $privacy;
    private SystemCheck $systemCheck;
    private RiskRepository $risks;
    private IncidentRepository $incidents;
    private ControlRepository $controls;
    private Repair $repair;

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

        $this->modules = new ModuleRegistry();
        $this->audit = new AuditLogger();
        $this->states = new SecurityStateRegistry($this->modules, $this->audit);
        $this->privacy = new RequestDispatcher($this->audit, $this->modules);
        $this->systemCheck = new SystemCheck($this->modules);
        $this->risks = new RiskRepository();
        $this->incidents = new IncidentRepository();
        $this->controls = new ControlRepository();
        $this->repair = new Repair();

        Capabilities::register();
        (new File00Adapter())->registerHooks();
        (new File20Adapter())->registerHooks();
        $this->modules->registerHooks();
        $this->states->registerHooks();
        $this->privacy->registerHooks();

        (new StatusController(
            $this->modules,
            $this->states,
            $this->systemCheck,
            $this->risks,
            $this->incidents,
            $this->controls
        ))->registerHooks();

        if (is_admin()) {
            (new Dashboard(
                $this->modules,
                $this->states,
                $this->systemCheck,
                $this->audit,
                $this->risks,
                $this->incidents,
                $this->controls,
                $this->repair
            ))->registerHooks();
        }

        do_action('spcrc/booted', $this);
    }

    public function modules(): ModuleRegistry
    {
        return $this->modules;
    }

    public function states(): SecurityStateRegistry
    {
        return $this->states;
    }

    public function audit(): AuditLogger
    {
        return $this->audit;
    }

    public function privacy(): RequestDispatcher
    {
        return $this->privacy;
    }

    public function risks(): RiskRepository
    {
        return $this->risks;
    }

    public function incidents(): IncidentRepository
    {
        return $this->incidents;
    }

    public function controls(): ControlRepository
    {
        return $this->controls;
    }
}
