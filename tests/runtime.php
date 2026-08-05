<?php

declare(strict_types=1);

$GLOBALS['hooks'] = [];

final class RuntimeRole
{
    public array $caps = [];
    public function add_cap(string $capability): void { $this->caps[$capability] = true; }
    public function remove_cap(string $capability): void { unset($this->caps[$capability]); }
}
$GLOBALS['runtime_role'] = new RuntimeRole();

function add_action(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void
{
    $GLOBALS['hooks'][$hook][] = [$callback, $priority, $acceptedArgs];
}
function do_action(string $hook, mixed ...$args): void {}
function get_role(string $role): RuntimeRole|false
{
    return $role === 'administrator' ? $GLOBALS['runtime_role'] : false;
}

require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Capabilities.php';

use Sabri\Platform\Security\Capabilities;

function expectRuntime(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

expectRuntime(method_exists(Capabilities::class, 'registerHooks'), 'Plugin boot must not call a missing capability hook method.');
Capabilities::registerHooks();
expectRuntime(isset($GLOBALS['hooks']['init']), 'Capability registration must be attached to init.');
expectRuntime(in_array('spcrc_accept_critical_risk', Capabilities::all(), true), 'Risk-acceptance capability must be declared.');
expectRuntime(! in_array('spcrc_accept_critical_risk', Capabilities::autoGranted(), true), 'Risk acceptance must not be auto-granted.');
Capabilities::install();
expectRuntime(! empty($GLOBALS['runtime_role']->caps['spcrc_manage_findings']), 'Finding management must remain in the bounded bootstrap Security Administrator bundle.');
expectRuntime(! empty($GLOBALS['runtime_role']->caps['spcrc_request_governance_decision']), 'The bootstrap Security Administrator must be able to request governance action.');
expectRuntime(empty($GLOBALS['runtime_role']->caps['spcrc_manage_assurance']), 'Assurance management must require the separately delegated backup-operator duty.');
expectRuntime(empty($GLOBALS['runtime_role']->caps['spcrc_manage_privacy_requests']), 'Privacy-rights management must require the separately delegated Privacy Officer duty.');
expectRuntime(empty($GLOBALS['runtime_role']->caps['spcrc_manage_incidents']), 'Incident command must require a separately delegated Incident Commander duty.');
expectRuntime(empty($GLOBALS['runtime_role']->caps['spcrc_approve_governance_decision']), 'Governance approval must remain separate from governance request authority.');
expectRuntime(empty($GLOBALS['runtime_role']->caps['spcrc_accept_critical_risk']), 'Critical risk acceptance must require explicit delegation.');

echo "PASS: runtime capability contracts\n";
