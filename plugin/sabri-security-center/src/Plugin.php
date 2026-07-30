<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Admin\Dashboard;
use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Rest\StatusController;
use Sabri\Platform\Security\Storage\AuditLogger;
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
        $this->modules = new ModuleRegistry();
        $this->states = new SecurityStateRegistry();
        $this->audit = new AuditLogger();
        $this->privacy = new RequestDispatcher($this->audit);
        $this->systemCheck = new SystemCheck($this->modules);

        Capabilities::register();
        $this->modules->registerHooks();
        $this->states->registerHooks();
        $this->privacy->registerHooks();

        (new StatusController($this->modules, $this->states, $this->systemCheck))->registerHooks();

        if (is_admin()) {
            (new Dashboard($this->modules, $this->states, $this->systemCheck, $this->audit))->registerHooks();
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
}
