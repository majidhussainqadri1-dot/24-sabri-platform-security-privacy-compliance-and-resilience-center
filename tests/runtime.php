<?php

declare(strict_types=1);

$GLOBALS['hooks'] = [];

final class RuntimeRole
{
    public array $caps = [];
    public function add_cap(string $capability): void { $this->caps[$capability] = true; }
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
expectRuntime(! empty($GLOBALS['runtime_role']->caps['spcrc_manage_findings']), 'Finding management must be granted to administrators.');
expectRuntime(empty($GLOBALS['runtime_role']->caps['spcrc_accept_critical_risk']), 'Critical risk acceptance must require explicit delegation.');

echo "PASS: runtime capability contracts\n";
