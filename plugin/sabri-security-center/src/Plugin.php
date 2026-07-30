<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Admin\Dashboard;
use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Rest\StatusController;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\Retention;
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
    private Retention $retention;

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
        add_action('init', static function (): void {
            load_plugin_textdomain('sabri-security-center', false, dirname(plugin_basename(SPCRC_PLUGIN_FILE)) . '/languages');
        }, 1);

        if (! UpgradeManager::maybeUpgrade()) {
            if (is_admin()) {
                add_action('admin_notices', [UpgradeManager::class, 'blockedNotice']);
            }
            return;
        }

        $this->audit = new AuditLogger();
        $this->modules = new ModuleRegistry();
        $this->states = new SecurityStateRegistry($this->audit);
        $this->privacy = new RequestDispatcher($this->audit);
        $this->systemCheck = new SystemCheck($this->modules);
        $this->retention = new Retention($this->audit);

        $this->modules->registerHooks();
        $this->states->registerHooks();
        $this->privacy->registerHooks();
        $this->retention->registerHooks();

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

    public function privacy(): RequestDispatcher
    {
        return $this->privacy;
    }
}
