<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Admin\AssetLoader;
use Sabri\Platform\Security\Admin\AssuranceAdmin;
use Sabri\Platform\Security\Admin\Dashboard;
use Sabri\Platform\Security\Admin\FindingAdmin;
use Sabri\Platform\Security\Admin\GovernanceAdmin;
use Sabri\Platform\Security\Admin\RegistryAdmin;
use Sabri\Platform\Security\Admin\VerifiedPrivacyAdmin;
use Sabri\Platform\Security\Incident\IncidentCoordinator;
use Sabri\Platform\Security\Integration\File00Adapter;
use Sabri\Platform\Security\Integration\File02Adapter;
use Sabri\Platform\Security\Integration\File20Adapter;
use Sabri\Platform\Security\Monitoring\DetectionEngine;
use Sabri\Platform\Security\Monitoring\PerformanceMonitor;
use Sabri\Platform\Security\Monitoring\RemoteEvidenceQueue;
use Sabri\Platform\Security\Policy\GovernancePolicyService;
use Sabri\Platform\Security\Privacy\DataGovernanceRegistry;
use Sabri\Platform\Security\Privacy\DeletionReplayManager;
use Sabri\Platform\Security\Privacy\PrivacyRequestPolicy;
use Sabri\Platform\Security\Privacy\RecoveryManager;
use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Resilience\ResilienceCoordinator;
use Sabri\Platform\Security\Rest\GovernanceController;
use Sabri\Platform\Security\Rest\StatusController;
use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Security\SecurityHeaders;
use Sabri\Platform\Security\Security\VulnerabilityManager;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\FindingRepository;
use Sabri\Platform\Security\Storage\GovernanceRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;
use Sabri\Platform\Security\Storage\RiskRepository;
use Sabri\Platform\Security\System\CompletionCheck;
use Sabri\Platform\Security\System\Repair;
use Sabri\Platform\Security\System\SystemCheck;
use Sabri\Platform\Security\Trust\TrustCenterService;

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
        $governance = new GovernanceRepository($audit);
        $findings = new FindingRepository($audit, $governance);
        $risks = new RiskRepository($audit, $governance);
        $incidents = new IncidentRepository($audit);
        $controls = new ControlRepository($audit);
        $assurance = new AssuranceRepository($audit);
        $artifacts = new GovernedArtifactRegistry($audit);
        $checks = new SystemCheck($modules);
        $privacyStorage = new PrivacyRequestRepository();
        $privacyRequests = new PrivacyRequestPolicy($privacyStorage);
        $privacy = new RequestDispatcher($audit, $modules, $privacyRequests);
        $privacyRecovery = new RecoveryManager($privacyStorage, $audit);
        $repair = new Repair();
        $trust = new TrustCenterService($artifacts);
        $performance = new PerformanceMonitor();
        $incidentCoordinator = new IncidentCoordinator($incidents, $artifacts);
        $resilience = new ResilienceCoordinator($artifacts, $assurance, $findings);
        $releaseGates = new ReleaseGateManager($artifacts);

        (new File00Adapter())->registerHooks();
        (new File02Adapter())->registerHooks();
        (new File20Adapter())->registerHooks();
        (new SecurityHeaders())->registerHooks();
        (new RetentionManager($audit))->registerHooks();
        (new DeletionReplayManager($artifacts, $audit))->registerHooks();
        (new RemoteEvidenceQueue($artifacts))->registerHooks();
        (new DetectionEngine($artifacts))->registerHooks();
        (new CompletionCheck($artifacts))->registerHooks();
        $resilience->registerHooks();
        $releaseGates->registerHooks();
        $modules->registerHooks();
        $states->registerHooks();
        $governance->registerHooks();
        $risks->registerHooks();
        $findings->registerHooks();
        $assurance->registerHooks();
        $privacy->registerHooks();
        $privacyRecovery->registerHooks();

        (new AssetLoader())->registerHooks();
        (new Dashboard($modules, $states, $checks, $audit, $risks, $incidents, $controls, $repair))->registerHooks();
        (new FindingAdmin($findings))->registerHooks();
        (new GovernanceAdmin($governance))->registerHooks();
        (new AssuranceAdmin($assurance))->registerHooks();
        (new VerifiedPrivacyAdmin($privacyRequests, $privacy, $modules))->registerHooks();
        (new RegistryAdmin($artifacts, $trust))->registerHooks();

        (new StatusController(
            $modules,
            $states,
            $checks,
            $risks,
            $incidents,
            $controls,
            $findings,
            $assurance,
            $governance,
            $artifacts,
            $trust,
            $performance,
            $resilience
        ))->registerHooks();
        (new GovernanceController($artifacts, $trust))->registerHooks();

        // Register service objects without transferring native domain ownership.
        add_filter('spcrc/governed_artifact_registry', static fn (): GovernedArtifactRegistry => $artifacts);
        add_filter('spcrc/data_governance_registry', static fn (): DataGovernanceRegistry => new DataGovernanceRegistry($artifacts));
        add_filter('spcrc/policy_service', static fn (): GovernancePolicyService => new GovernancePolicyService($artifacts));
        add_filter('spcrc/vulnerability_manager', static fn (): VulnerabilityManager => new VulnerabilityManager($artifacts, $findings));
        add_filter('spcrc/incident_coordinator', static fn (): IncidentCoordinator => $incidentCoordinator);
        add_filter('spcrc/resilience_coordinator', static fn (): ResilienceCoordinator => $resilience);
        add_filter('spcrc/performance_monitor', static fn (): PerformanceMonitor => $performance);
        add_filter('spcrc/trust_center_service', static fn (): TrustCenterService => $trust);

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
