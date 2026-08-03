<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';
$base = __DIR__ . '/../plugin/sabri-security-center/src/';
require_once $base . 'Support/Sanitizer.php';
require_once $base . 'Support/AtomicOptionLock.php';
require_once $base . 'Storage/Schema.php';
require_once $base . 'Storage/AuditLogger.php';
require_once $base . 'Storage/AuditGapStore.php';
require_once $base . 'Capabilities.php';
require_once $base . 'Registry/ModuleRegistry.php';
require_once $base . 'Registry/SecurityStateRegistry.php';

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditGapStore;
use Sabri\Platform\Security\Storage\AuditLogger;

$assertions = 0;
$assert = static function (bool $condition, string $message) use (&$assertions): void {
    if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
    ++$assertions;
};

$modules = new ModuleRegistry();
$modules->register([
    'module_key' => 'cycle27-module', 'name' => 'Cycle 27 Module', 'version' => '1.0.0', 'owner' => 'Cycle 27',
    'posture' => 'foundation', 'data_classes' => [], 'public_routes' => [], 'private_routes' => [],
]);
$states = new SecurityStateRegistry($modules, new AuditLogger());

$GLOBALS['wp_options']['spcrc_security_state_lock'] = ['token' => 'active-state-writer', 'expires_at' => time() + 30];
$assert(! $states->request('cycle27-module', 'restricted-writes', ['reason' => 'Contended state request test.']), 'Active state lock must block a competing request.');
$assert(($GLOBALS['wp_options']['spcrc_security_state_lock']['token'] ?? '') === 'active-state-writer', 'Competing request must preserve active lock ownership.');

$GLOBALS['wp_options']['spcrc_security_state_lock'] = ['token' => 'expired-state-writer', 'expires_at' => time() - 1];
$assert($states->request('cycle27-module', 'restricted-writes', ['reason' => 'Atomic stale state-lock reclamation test.']), 'Expired state lock must be reclaimed atomically.');
$visible = $states->all();
$assert(count($visible) === 1, 'Audited state request must remain visible.');
$requestId = (string) array_key_first($visible);
$assert(get_option('spcrc_security_state_lock', false) === false, 'State lock must be released by exact owner.');

$reflection = new ReflectionClass(SecurityStateRegistry::class);
$recordGap = $reflection->getMethod('recordAuditGap');
$recordGap->setAccessible(true);
$recordGap->invoke($states, $requestId, 'forced_cycle27_gap');
$assert(AuditGapStore::count('spcrc_security_state_audit_gap') === 1, 'Security-state gap must use the bounded central gap store.');
$assert($states->all() === [], 'A state request with unresolved audit evidence must be hidden from enforcement consumers.');
$assert(! $states->resolve($requestId), 'A gapped state request must not be resolved through the ordinary state path.');

for ($i = 0; $i < 110; ++$i) {
    $recordGap->invoke($states, '', 'bounded_gap_' . $i);
}
$assert(AuditGapStore::count('spcrc_security_state_audit_gap') === 100, 'Security-state audit gaps must remain bounded to the central maximum.');

$source = (string) file_get_contents($base . 'Registry/SecurityStateRegistry.php');
$assert(str_contains($source, 'AtomicOptionLock::acquire(self::LOCK_OPTION, self::LOCK_TTL)'), 'State lock must use atomic exact-value acquisition.');
$assert(substr_count($source, '$this->refreshLock($lockToken)') >= 4, 'State mutations and rollbacks must renew ownership before writes.');
$assert(str_contains($source, 'AuditGapStore::record('), 'State audit failures must use the central bounded gap store.');
$assert(! str_contains($source, 'update_option(self::AUDIT_GAP_OPTION, $gaps'), 'Legacy unguarded state-gap writes must be removed.');

echo "PASS: {$assertions} Cycle 27 security-state atomicity assertions\n";
