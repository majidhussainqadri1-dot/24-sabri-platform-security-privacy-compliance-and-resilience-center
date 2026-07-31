<?php

declare(strict_types=1);

const ARRAY_A = 'ARRAY_A';
const SPCRC_VERSION = '0.25.1';

$GLOBALS['privacy_filters'] = [];
$GLOBALS['privacy_actions'] = [];
$GLOBALS['privacy_users'] = [7 => true, 8 => true];
$GLOBALS['current_user_id'] = 99;

final class WP_Error
{
    public function __construct(private string $code, private string $message) {}
    public function get_error_code(): string { return $this->code; }
    public function get_error_message(): string { return $this->message; }
}

function add_filter(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void
{
    $GLOBALS['privacy_filters'][$hook][$priority][] = [$callback, $acceptedArgs];
}
function add_action(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void
{
    add_filter($hook, $callback, $priority, $acceptedArgs);
}
function apply_filters(string $hook, mixed $value, mixed ...$args): mixed
{
    if (empty($GLOBALS['privacy_filters'][$hook])) return $value;
    ksort($GLOBALS['privacy_filters'][$hook]);
    foreach ($GLOBALS['privacy_filters'][$hook] as $callbacks) {
        foreach ($callbacks as [$callback, $accepted]) {
            $value = $callback(...array_slice([$value, ...$args], 0, $accepted));
        }
    }
    return $value;
}
function do_action(string $hook, mixed ...$args): void
{
    $GLOBALS['privacy_actions'][] = [$hook, $args];
}
function sanitize_key(string $value): string { return substr(preg_replace('/[^a-z0-9_\-]/', '', strtolower($value)) ?? '', 0, 255); }
function sanitize_text_field(string $value): string { return trim(preg_replace('/[\r\n\t]+/', ' ', strip_tags($value)) ?? ''); }
function wp_json_encode(mixed $value, int $flags = 0): string|false { return json_encode($value, $flags); }
function wp_generate_uuid4(): string
{
    static $counter = 100;
    return sprintf('00000000-0000-4000-8000-%012d', $counter++);
}
function current_time(string $type, bool $gmt = false): string { return '2026-07-31 09:00:00'; }
function get_current_user_id(): int { return (int) $GLOBALS['current_user_id']; }
function get_userdata(int $userId): object|false { return ! empty($GLOBALS['privacy_users'][$userId]) ? (object) ['ID' => $userId] : false; }
function absint(mixed $value): int { return abs((int) $value); }
function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
function wp_salt(string $scheme = 'auth'): string { return 'privacy-test-salt-' . $scheme; }
function wp_unslash(mixed $value): mixed { return $value; }

final class PrivacyWpdb
{
    public string $prefix = 'wp_';
    public array $privacy = [];
    public array $manifests = [];
    public array $events = [];
    public bool $failPrivacyInsert = false;
    public bool $failFinalize = false;

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
    public function get_var(mixed $query): mixed
    {
        if (is_string($query) && str_contains($query, 'spcrc_privacy_requests') && str_contains($query, 'COUNT(*)')) {
            return count(array_filter($this->privacy, static fn (array $row): bool => in_array($row['status'] ?? '', ['received', 'dispatching', 'pending', 'partial'], true)));
        }
        return null;
    }
    public function get_results(mixed $prepared, mixed $output = null): array
    {
        $limit = is_array($prepared) ? max(1, (int) ($prepared['args'][0] ?? 50)) : 50;
        return array_slice(array_reverse(array_values($this->privacy)), 0, $limit);
    }
    public function insert(string $table, array $data, array $formats = []): int|false
    {
        if (str_contains($table, 'spcrc_security_events')) {
            $this->events[] = $data;
            return 1;
        }
        if (str_contains($table, 'spcrc_privacy_requests')) {
            if ($this->failPrivacyInsert || isset($this->privacy[(string) $data['request_uuid']])) return false;
            $this->privacy[(string) $data['request_uuid']] = $data;
            return 1;
        }
        return 1;
    }
    public function update(string $table, array $data, array $where, array $formats = [], array $whereFormats = []): int|false
    {
        if (! str_contains($table, 'spcrc_privacy_requests')) return 1;
        if ($this->failFinalize && ($data['status'] ?? '') !== 'dispatching') return false;
        $uuid = (string) ($where['request_uuid'] ?? '');
        if (! isset($this->privacy[$uuid])) return 0;
        if (isset($where['status']) && ($this->privacy[$uuid]['status'] ?? '') !== $where['status']) return 0;
        $this->privacy[$uuid] = array_merge($this->privacy[$uuid], $data);
        return 1;
    }
    public function replace(string $table, array $data, array $formats = []): int|false
    {
        if (str_contains($table, 'spcrc_module_manifests')) {
            $this->manifests[(string) $data['module_key']] = $data;
        }
        return 1;
    }
}
$GLOBALS['wpdb'] = new PrivacyWpdb();

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
require_once $base . 'Support/Sanitizer.php';
require_once $base . 'Storage/AuditLogger.php';
require_once $base . 'Storage/PrivacyRequestRepository.php';
require_once $base . 'Registry/ModuleRegistry.php';
require_once $base . 'Privacy/RequestDispatcher.php';

use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;

function expectPrivacy(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$modules = new ModuleRegistry();
expectPrivacy($modules->register([
    'module_key' => 'file-00-membership-core',
    'name' => 'Membership',
    'version' => '1.0.0',
    'owner' => 'File 00',
    'posture' => 'foundation',
    'data_classes' => ['C2'],
    'public_routes' => [],
    'private_routes' => ['/private'],
    'privacy_operations' => ['access', 'deletion'],
]), 'Test privacy module must register.');

$requests = new PrivacyRequestRepository();
$dispatcher = new RequestDispatcher(new AuditLogger(), $modules, $requests);

$upstream = ['ok' => true, 'status' => 'completed', 'request_uuid' => 'upstream'];
expectPrivacy($dispatcher->filterDispatch($upstream, [], []) === $upstream, 'Existing filter result must not be overwritten or redispatched.');

$handlerCalls = 0;
add_filter('spcrc/privacy_request/file-00-membership-core', static function ($result, $type, $request) use (&$handlerCalls) {
    ++$handlerCalls;
    return ['ok' => true, 'status' => 'queued', 'reference' => 'native-workflow:test'];
}, 10, 3);

$unverified = $dispatcher->dispatch([
    'request_uuid' => '10000000-0000-4000-8000-000000000001',
    'request_type' => 'access',
    'requester_user_id' => 999,
], ['file-00-membership-core']);
expectPrivacy(($unverified['error'] ?? '') === 'spcrc_privacy_subject_unverified', 'Unverified subject must fail before dispatch.');
expectPrivacy($handlerCalls === 0, 'No module handler may run when durable pre-dispatch validation fails.');

$uuid = '10000000-0000-4000-8000-000000000002';
$pending = $dispatcher->dispatch([
    'request_uuid' => $uuid,
    'request_type' => 'access',
    'requester_user_id' => 7,
    'jurisdiction' => 'Pakistan',
], ['file-00-membership-core']);
expectPrivacy($pending['ok'] === true && $pending['status'] === 'pending', 'Queued native workflow must be pending, not falsely completed.');
expectPrivacy(($GLOBALS['wpdb']->privacy[$uuid]['status'] ?? '') === 'pending', 'Pending aggregate status must be durably stored.');
expectPrivacy($handlerCalls === 1, 'Validated request must dispatch exactly once.');
expectPrivacy($requests->activeCount() === 1, 'Pending request must remain active.');

$replay = $dispatcher->dispatch([
    'request_uuid' => $uuid,
    'request_type' => 'access',
    'requester_user_id' => 7,
], ['file-00-membership-core']);
expectPrivacy(($replay['error'] ?? '') === 'spcrc_privacy_already_processed', 'Processed request UUID must be replay-resistant.');
expectPrivacy($handlerCalls === 1, 'Replay rejection must happen before native-module processing.');

$collision = $dispatcher->dispatch([
    'request_uuid' => $uuid,
    'request_type' => 'access',
    'requester_user_id' => 8,
], ['file-00-membership-core']);
expectPrivacy(($collision['error'] ?? '') === 'spcrc_privacy_request_collision', 'Request UUID cannot be rebound to another subject.');
expectPrivacy($handlerCalls === 1, 'Collision must not trigger module processing.');

$failedUuid = '10000000-0000-4000-8000-000000000003';
$failed = $dispatcher->dispatch([
    'request_uuid' => $failedUuid,
    'request_type' => 'deletion',
    'requester_user_id' => 7,
], ['unknown-module']);
expectPrivacy($failed['ok'] === false && $failed['status'] === 'failed', 'Unknown module must produce a durable failed request.');
expectPrivacy(($GLOBALS['wpdb']->privacy[$failedUuid]['status'] ?? '') === 'failed', 'Failed dispatch status must be stored.');

$GLOBALS['wpdb']->failFinalize = true;
$storageUuid = '10000000-0000-4000-8000-000000000004';
$storageFailed = $dispatcher->dispatch([
    'request_uuid' => $storageUuid,
    'request_type' => 'access',
    'requester_user_id' => 7,
], ['file-00-membership-core']);
expectPrivacy($storageFailed['ok'] === false && $storageFailed['status'] === 'storage-failed', 'Post-operation finalization failure must surface recovery-required state.');
expectPrivacy(($GLOBALS['wpdb']->privacy[$storageUuid]['status'] ?? '') === 'dispatching', 'Failed finalization must leave durable dispatching evidence rather than claim completion.');
$GLOBALS['wpdb']->failFinalize = false;

expectPrivacy(count($requests->recent(10)) === 3, 'Privacy request repository must return bounded recent metadata.');

echo "PASS: privacy dispatch durability, idempotency and truthful status aggregation\n";
