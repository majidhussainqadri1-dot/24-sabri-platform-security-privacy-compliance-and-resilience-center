<?php

declare(strict_types=1);

const ARRAY_A = 'ARRAY_A';
$GLOBALS['filters'] = [];
$GLOBALS['users'] = [7 => true, 99 => true];
$GLOBALS['current_user_id'] = 99;

final class WP_Error
{
    public function __construct(private string $code, private string $message) {}
    public function get_error_code(): string { return $this->code; }
    public function get_error_message(): string { return $this->message; }
}

function add_filter(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void
{
    $GLOBALS['filters'][$hook][$priority][] = [$callback, $acceptedArgs];
}
function add_action(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void { add_filter($hook, $callback, $priority, $acceptedArgs); }
function apply_filters(string $hook, mixed $value, mixed ...$args): mixed
{
    if (empty($GLOBALS['filters'][$hook])) return $value;
    ksort($GLOBALS['filters'][$hook]);
    foreach ($GLOBALS['filters'][$hook] as $callbacks) {
        foreach ($callbacks as [$callback, $accepted]) {
            $value = $callback(...array_slice([$value, ...$args], 0, $accepted));
        }
    }
    return $value;
}
function do_action(string $hook, mixed ...$args): void {}
function sanitize_key(string $value): string { return substr(preg_replace('/[^a-z0-9_\-]/', '', strtolower($value)) ?? '', 0, 255); }
function sanitize_text_field(string $value): string { return trim(preg_replace('/[\r\n\t]+/', ' ', strip_tags($value)) ?? ''); }
function wp_json_encode(mixed $value, int $flags = 0): string|false { return json_encode($value, $flags); }
function wp_generate_uuid4(): string { static $n = 1; return sprintf('60000000-0000-4000-8000-%012d', $n++); }
function current_time(string $type, bool $gmt = false): string { return gmdate('Y-m-d H:i:s'); }
function get_current_user_id(): int { return $GLOBALS['current_user_id']; }
function current_user_can(string $capability): bool { return $capability === 'spcrc_manage_privacy_requests'; }
function get_userdata(int $id): object|false { return ! empty($GLOBALS['users'][$id]) ? (object) ['ID' => $id] : false; }
function absint(mixed $value): int { return abs((int) $value); }
function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
function wp_salt(string $scheme = 'auth'): string { return 'policy-test-' . $scheme; }

final class PolicyWpdb
{
    public string $prefix = 'wp_';
    public array $privacy = [];
    public array $manifests = [];
    public array $events = [];

    public function prepare(string $query, mixed ...$args): array { return ['query' => $query, 'args' => $args]; }
    public function get_row(mixed $prepared, mixed $output = null): mixed
    {
        if (! is_array($prepared)) return null;
        $query = (string) $prepared['query'];
        $key = (string) ($prepared['args'][0] ?? '');
        if (str_contains($query, 'spcrc_privacy_requests')) return $this->privacy[$key] ?? null;
        if (str_contains($query, 'spcrc_module_manifests')) return $this->manifests[$key] ?? null;
        return null;
    }
    public function get_var(mixed $query): mixed { return 0; }
    public function get_results(mixed $prepared, mixed $output = null): array
    {
        $query = is_array($prepared) ? (string) $prepared['query'] : '';
        if (str_contains($query, 'updated_at <')) {
            $cutoff = strtotime((string) ($prepared['args'][1] ?? '') . ' UTC');
            return array_values(array_filter($this->privacy, static function (array $row) use ($cutoff): bool {
                $at = strtotime((string) ($row['updated_at'] ?? '') . ' UTC');
                return ($row['status'] ?? '') === 'dispatching' && $at !== false && $cutoff !== false && $at < $cutoff;
            }));
        }
        return array_values($this->privacy);
    }
    public function insert(string $table, array $data, array $formats = []): int|false
    {
        if (str_contains($table, 'spcrc_security_events')) { $this->events[] = $data; return 1; }
        if (str_contains($table, 'spcrc_privacy_requests')) {
            if (isset($this->privacy[(string) $data['request_uuid']])) return false;
            $this->privacy[(string) $data['request_uuid']] = $data;
            return 1;
        }
        return 1;
    }
    public function replace(string $table, array $data, array $formats = []): int|false
    {
        if (str_contains($table, 'spcrc_module_manifests')) $this->manifests[(string) $data['module_key']] = $data;
        return 1;
    }
    public function update(string $table, array $data, array $where, array $formats = [], array $whereFormats = []): int|false
    {
        $uuid = (string) ($where['request_uuid'] ?? '');
        if (! isset($this->privacy[$uuid])) return 0;
        if (isset($where['status']) && ($this->privacy[$uuid]['status'] ?? '') !== $where['status']) return 0;
        if (isset($where['lock_version']) && (int) ($this->privacy[$uuid]['lock_version'] ?? 0) !== (int) $where['lock_version']) return 0;
        $this->privacy[$uuid] = array_merge($this->privacy[$uuid], $data);
        return 1;
    }
}
$GLOBALS['wpdb'] = new PolicyWpdb();

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
require_once $base . 'Support/Sanitizer.php';
require_once $base . 'Storage/AuditLogger.php';
require_once $base . 'Storage/PrivacyRequestRepository.php';
require_once $base . 'Registry/ModuleRegistry.php';
require_once $base . 'Privacy/PrivacyRequestPolicy.php';
require_once $base . 'Privacy/RequestDispatcher.php';

use Sabri\Platform\Security\Privacy\PrivacyRequestPolicy;
use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;

function expectPolicy(bool $condition, string $message): void
{
    if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

/** @param array<string,mixed> $request
 *  @return array<string,mixed>
 */
function verifiedPolicyRequest(array $request): array
{
    return $request + [
        'assigned_user_id' => 99,
        'verification_method' => 'manual-document-review',
        'authority_basis' => 'self',
        'verification_reference' => 'case:policy-test',
        'verified_by_user_id' => 99,
        'verified_at' => gmdate('c'),
        'verification_attested' => true,
    ];
}

$modules = new ModuleRegistry();
expectPolicy($modules->register([
    'module_key' => 'policy-module',
    'name' => 'Policy Module',
    'version' => '1.0.0',
    'owner' => 'Test',
    'posture' => 'foundation',
    'data_classes' => ['C2'],
    'public_routes' => [],
    'private_routes' => [],
    'privacy_operations' => ['access', 'deletion'],
]), 'Policy module must register.');
expectPolicy($modules->register([
    'module_key' => 'access-only-module',
    'name' => 'Access Only',
    'version' => '1.0.0',
    'owner' => 'Test',
    'posture' => 'foundation',
    'data_classes' => ['C2'],
    'public_routes' => [],
    'private_routes' => [],
    'privacy_operations' => ['access'],
]), 'Access-only module must register.');

$repository = new PrivacyRequestRepository();
$policy = new PrivacyRequestPolicy($repository);
$dispatcher = new RequestDispatcher(new AuditLogger(), $modules, $policy);

$preflightUnknown = $dispatcher->dispatch(verifiedPolicyRequest([
    'request_uuid' => '60000000-0000-4000-8000-000000000100',
    'request_type' => 'access',
    'requester_user_id' => 7,
]), ['unknown-module']);
expectPolicy(($preflightUnknown['error'] ?? '') === 'spcrc_privacy_module_unknown', 'Unknown modules must fail before durable request creation.');
expectPolicy($repository->get('60000000-0000-4000-8000-000000000100') === null, 'Unknown-module preflight must not pollute privacy storage.');

$preflightOperation = $dispatcher->dispatch(verifiedPolicyRequest([
    'request_uuid' => '60000000-0000-4000-8000-000000000105',
    'request_type' => 'deletion',
    'requester_user_id' => 7,
]), ['access-only-module']);
expectPolicy(($preflightOperation['error'] ?? '') === 'spcrc_privacy_operation_not_declared', 'Undeclared operations must fail before dispatch.');
expectPolicy($repository->get('60000000-0000-4000-8000-000000000105') === null, 'Operation preflight failure must not create a request record.');

$missingVerification = $dispatcher->dispatch([
    'request_uuid' => '60000000-0000-4000-8000-000000000106',
    'request_type' => 'access',
    'requester_user_id' => 7,
], ['policy-module']);
expectPolicy(($missingVerification['error'] ?? '') === 'spcrc_privacy_verification_attestation_required', 'Identity verification must be explicit, not inferred from account existence.');

$mismatch = verifiedPolicyRequest([
    'request_uuid' => '60000000-0000-4000-8000-000000000108',
    'request_type' => 'access',
    'requester_user_id' => 7,
]);
$mismatch['verification_method'] = 'guardian-verified';
$mismatch['authority_basis'] = 'self';
$mismatchResult = $dispatcher->dispatch($mismatch, ['policy-module']);
expectPolicy(($mismatchResult['error'] ?? '') === 'spcrc_privacy_verification_authority_mismatch', 'Verification method and authority basis must be semantically compatible.');

$future = verifiedPolicyRequest([
    'request_uuid' => '60000000-0000-4000-8000-000000000109',
    'request_type' => 'access',
    'requester_user_id' => 7,
]);
$future['verified_at'] = gmdate('c', time() + 3600);
$futureResult = $dispatcher->dispatch($future, ['policy-module']);
expectPolicy(($futureResult['error'] ?? '') === 'spcrc_privacy_verified_at_invalid', 'Future verification evidence must fail closed.');

$missingUuid = '60000000-0000-4000-8000-000000000101';
$missing = $dispatcher->dispatch(verifiedPolicyRequest([
    'request_uuid' => $missingUuid,
    'request_type' => 'access',
    'requester_user_id' => 7,
]), ['policy-module']);
expectPolicy($missing['status'] === 'failed', 'Missing handler must produce a terminal failed request.');
$missingResult = $repository->moduleResults($missingUuid)['policy-module'] ?? [];
expectPolicy(! str_starts_with((string) ($missingResult['code'] ?? ''), 'retry-safe-'), 'Missing handler must never be marked retry-safe.');
$GLOBALS['wpdb']->privacy[$missingUuid]['next_retry_at'] = gmdate('Y-m-d H:i:s', time() - 1);
$missingRetry = $dispatcher->retry($missingUuid, 99);
expectPolicy(($missingRetry['error'] ?? '') === 'spcrc_privacy_retry_modules_missing', 'Missing handler must not be replayed indefinitely.');

add_filter('spcrc/authorize_privacy_module_callback', static fn (bool $allowed, int $actor, string $requestUuid, string $moduleKey, string $reference): bool => $actor === 99 && $reference === 'callback:policy-module', 10, 5);
$callbackUuid = '60000000-0000-4000-8000-000000000102';
$begin = $policy->begin(verifiedPolicyRequest([
    'request_uuid' => $callbackUuid,
    'request_type' => 'access',
    'requester_user_id' => 7,
    'module_keys' => ['policy-module'],
]));
expectPolicy(! is_wp_error($begin), 'Pre-dispatch request must be created.');
$early = $dispatcher->completeModule($callbackUuid, 'policy-module', ['ok' => true, 'status' => 'completed', 'callback_reference' => 'callback:policy-module']);
expectPolicy(($early['error'] ?? '') === 'spcrc_privacy_callback_module_unclaimed', 'Callback cannot fabricate completion before a module dispatch claim.');

expectPolicy($repository->claimModule($callbackUuid, 'policy-module') === true, 'Module claim must succeed.');
expectPolicy($repository->storeModuleResult($callbackUuid, 'policy-module', ['ok' => true, 'status' => 'pending']) === true, 'Pending result must store.');
expectPolicy($repository->finalize($callbackUuid, 'pending') === true, 'Pending request must finalize.');
$unsafe = $dispatcher->completeModule($callbackUuid, 'policy-module', ['ok' => false, 'status' => 'failed', 'code' => 'uncertain', 'callback_reference' => 'callback:policy-module']);
expectPolicy($unsafe['status'] === 'failed', 'Unsafe failed callback must be durably recorded as failed reconciliation evidence.');
$unsafeResult = $repository->moduleResults($callbackUuid)['policy-module'] ?? [];
expectPolicy(($unsafeResult['status'] ?? '') === 'failed' && ! str_starts_with((string) ($unsafeResult['code'] ?? ''), 'retry-safe-'), 'Unsafe callback evidence must remain non-retryable.');
$GLOBALS['wpdb']->privacy[$callbackUuid]['next_retry_at'] = gmdate('Y-m-d H:i:s', time() - 1);
$unsafeRetry = $dispatcher->retry($callbackUuid, 99);
expectPolicy(($unsafeRetry['error'] ?? '') === 'spcrc_privacy_retry_modules_missing', 'Unsafe callback must require reconciliation instead of replay.');

$safeCalls = 0;
add_filter('spcrc/privacy_request/policy-module', static function ($current, $type, $context) use (&$safeCalls) {
    ++$safeCalls;
    return ['ok' => false, 'status' => 'failed', 'code' => 'temporary', 'retry_safe' => true];
}, 10, 3);
$safeUuid = '60000000-0000-4000-8000-000000000103';
$safe = $dispatcher->dispatch(verifiedPolicyRequest([
    'request_uuid' => $safeUuid,
    'request_type' => 'access',
    'requester_user_id' => 7,
]), ['policy-module']);
expectPolicy($safe['status'] === 'failed', 'Explicit retry-safe failure must remain retryable.');
$GLOBALS['wpdb']->privacy[$safeUuid]['next_retry_at'] = gmdate('Y-m-d H:i:s', time() + 3600);
$tooSoon = $dispatcher->retry($safeUuid, 99);
expectPolicy(($tooSoon['error'] ?? '') === 'spcrc_privacy_retry_not_due', 'Backend must enforce retry timing, not only the UI.');
$GLOBALS['wpdb']->privacy[$safeUuid]['next_retry_at'] = 'not-a-time';
$invalidTime = $dispatcher->retry($safeUuid, 99);
expectPolicy(($invalidTime['error'] ?? '') === 'spcrc_privacy_retry_time_invalid', 'Malformed retry schedules must fail closed.');
$GLOBALS['wpdb']->privacy[$safeUuid]['next_retry_at'] = gmdate('Y-m-d H:i:s', time() - 1);
$GLOBALS['wpdb']->privacy[$safeUuid]['dispatch_attempts'] = 5;
$exhausted = $dispatcher->retry($safeUuid, 99);
expectPolicy(($exhausted['error'] ?? '') === 'spcrc_privacy_retry_attempt_limit', 'Bounded attempt limit must stop retry storms.');

$GLOBALS['wpdb']->privacy[$safeUuid]['dispatch_attempts'] = 1;
$GLOBALS['wpdb']->privacy[$safeUuid]['verification_method'] = '';
$legacyBlocked = $dispatcher->retry($safeUuid, 99);
expectPolicy(($legacyBlocked['error'] ?? '') === 'spcrc_privacy_retry_verification_missing', 'Legacy requests without verification evidence must not become automatically retryable after migration.');
$GLOBALS['wpdb']->privacy[$safeUuid]['verification_method'] = 'manual-document-review';

$deletionUuid = '60000000-0000-4000-8000-000000000107';
$deletion = $dispatcher->dispatch(verifiedPolicyRequest([
    'request_uuid' => $deletionUuid,
    'request_type' => 'deletion',
    'requester_user_id' => 7,
]), ['policy-module']);
expectPolicy($deletion['status'] === 'failed', 'Deletion test must produce a retry-safe failure.');
$GLOBALS['wpdb']->privacy[$deletionUuid]['next_retry_at'] = gmdate('Y-m-d H:i:s', time() - 1);
$deletionBlocked = $dispatcher->retry($deletionUuid, 99);
expectPolicy(($deletionBlocked['error'] ?? '') === 'spcrc_privacy_deletion_retry_confirmation_required', 'Deletion retry must require a fresh destructive confirmation.');
add_filter('spcrc/verify_step_up_assurance', static fn (bool $ok, int $actor, string $purpose, string $reference): bool => $actor === 99 && $purpose === 'privacy:deletion-retry' && $reference === 'file00:deletion-retry', 10, 4);
$beforeDeletionRetry = $safeCalls;
$deletionRetried = $dispatcher->retry($deletionUuid, 99, ['deletion_confirmation' => 'RETRY DELETION ' . $deletionUuid, 'step_up_reference' => 'file00:deletion-retry']);
expectPolicy(! isset($deletionRetried['error']) && ($deletionRetried['status'] ?? '') === 'failed' && $safeCalls === $beforeDeletionRetry + 1, 'Confirmed deletion retry must reach only the policy-approved native module exactly once.');

$staleUuid = '60000000-0000-4000-8000-000000000104';
$staleBegin = $policy->begin(verifiedPolicyRequest([
    'request_uuid' => $staleUuid,
    'request_type' => 'access',
    'requester_user_id' => 7,
    'module_keys' => ['policy-module'],
]));
expectPolicy(! is_wp_error($staleBegin), 'Stale test request must begin.');
expectPolicy($repository->claimModule($staleUuid, 'policy-module') === true, 'Stale module must be claimed.');
$GLOBALS['wpdb']->privacy[$staleUuid]['updated_at'] = '2000-01-01 00:00:00';
expectPolicy($repository->markStaleDispatching(900, 10) === 1, 'Stale dispatch must be found.');
$staleResult = $repository->moduleResults($staleUuid)['policy-module'] ?? [];
expectPolicy(($staleResult['status'] ?? '') === 'dispatching', 'Stale in-flight module evidence must remain visibly uncertain rather than being falsely completed.');
$staleRetry = $dispatcher->retry($staleUuid, 99);
expectPolicy(($staleRetry['error'] ?? '') === 'spcrc_privacy_retry_modules_missing', 'Stale uncertain operation must require manual reconciliation instead of replay.');

echo "PASS: privacy verification, preflight, destructive retry and reconciliation controls\n";
