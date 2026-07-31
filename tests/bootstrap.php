<?php

declare(strict_types=1);

const ARRAY_A = 'ARRAY_A';
const MINUTE_IN_SECONDS = 60;
const HOUR_IN_SECONDS = 3600;
const DAY_IN_SECONDS = 86400;
const ABSPATH = '/tmp/wordpress/';
const SPCRC_VERSION = '0.25.6';

@mkdir(ABSPATH . 'wp-admin/includes', 0777, true);
if (! file_exists(ABSPATH . 'wp-admin/includes/upgrade.php')) {
    file_put_contents(ABSPATH . 'wp-admin/includes/upgrade.php', "<?php\n");
}

$GLOBALS['wp_filters'] = [];
$GLOBALS['wp_options'] = [];
$GLOBALS['wp_transients'] = [];
$GLOBALS['wp_actions'] = [];
$GLOBALS['wp_scheduled'] = [];
$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps'] = array_fill_keys([
    'spcrc_view_overview',
    'spcrc_view_module_posture',
    'spcrc_manage_controls',
    'spcrc_manage_findings',
    'spcrc_manage_risks',
    'spcrc_manage_incidents',
    'spcrc_manage_assurance',
    'spcrc_manage_security_settings',
    'spcrc_run_security_assessments',
], true);
$GLOBALS['wp_version'] = '7.0.1';

final class WP_Error
{
    public function __construct(private string $code, private string $message) {}
    public function get_error_code(): string { return $this->code; }
    public function get_error_message(): string { return $this->message; }
}

final class WP_REST_Response
{
    private array $headers = [];
    public function __construct(private mixed $data) {}
    public function header(string $name, string $value): void { $this->headers[$name] = $value; }
    public function get_data(): mixed { return $this->data; }
    public function get_headers(): array { return $this->headers; }
}

final class FakeRole
{
    public array $caps = [];
    public function add_cap(string $cap): void { $this->caps[$cap] = true; }
    public function remove_cap(string $cap): void { unset($this->caps[$cap]); }
}

final class FakeWpRoles
{
    public array $role_objects;
    public function __construct(FakeRole $administrator) { $this->role_objects = ['administrator' => $administrator]; }
}

final class FakeWpdb
{
    public string $prefix = 'wp_';
    public bool $failInsert = false;
    public bool $zeroUpdate = false;
    public int $manifestInsertCount = 0;
    public int $manifestUpdateCount = 0;
    public array $events = [];
    public array $privacy = [];
    public array $manifests = [];
    public array $risks = [];
    public array $incidents = [];
    public array $controls = [];
    public array $assurance = [];
    public string $last_error = '';

    public function get_charset_collate(): string { return 'DEFAULT CHARACTER SET utf8mb4'; }
    public function esc_like(string $value): string { return $value; }
    public function prepare(string $query, mixed ...$args): array { return ['query' => $query, 'args' => $args]; }

    public function get_var(mixed $prepared): mixed
    {
        if (is_string($prepared)) {
            if (str_contains($prepared, 'spcrc_risks') && str_contains($prepared, 'COUNT(*)')) return count(array_filter($this->risks, static fn(array $r): bool => ($r['status'] ?? '') === 'open'));
            if (str_contains($prepared, 'spcrc_incidents') && str_contains($prepared, 'COUNT(*)')) return count(array_filter($this->incidents, static fn(array $r): bool => ($r['status'] ?? '') === 'open'));
            if (str_contains($prepared, 'spcrc_controls') && str_contains($prepared, 'COUNT(*)')) return count($this->controls);
            if (str_contains($prepared, 'spcrc_assurance_records') && str_contains($prepared, 'COUNT(*)')) return count($this->assurance);
            return null;
        }

        $query = (string) ($prepared['query'] ?? '');
        $args = (array) ($prepared['args'] ?? []);
        if (str_starts_with($query, 'SHOW TABLES LIKE')) return $args[0] ?? null;
        if (str_contains($query, 'spcrc_privacy_requests') && str_contains($query, 'SELECT id')) return isset($this->privacy[(string) ($args[0] ?? '')]) ? 1 : null;
        if (str_contains($query, 'spcrc_controls') && str_contains($query, 'SELECT id')) return isset($this->controls[(string) ($args[0] ?? '')]) ? 1 : null;
        if (str_contains($query, 'spcrc_assurance_records') && str_contains($query, 'COUNT(*)')) {
            $type = (string) ($args[0] ?? '');
            return count(array_filter($this->assurance, static fn(array $r): bool => ($r['record_type'] ?? '') === $type));
        }
        return null;
    }

    public function get_row(mixed $prepared, mixed $output = null): mixed
    {
        $query = is_array($prepared) ? (string) ($prepared['query'] ?? '') : (string) $prepared;
        $args = is_array($prepared) ? (array) ($prepared['args'] ?? []) : [];
        if (str_contains($query, 'spcrc_module_manifests')) return $this->manifests[(string) ($args[0] ?? '')] ?? null;
        if (str_contains($query, 'spcrc_assurance_records')) {
            if (str_contains($query, "record_type = 'backup'")) {
                $rows = array_values(array_filter($this->assurance, static fn(array $r): bool => ($r['record_type'] ?? '') === 'backup' && ($r['status'] ?? '') === 'verified'));
                usort($rows, static fn(array $a, array $b): int => strcmp((string) ($b['restore_tested_at'] ?? ''), (string) ($a['restore_tested_at'] ?? '')));
                return $rows[0] ?? null;
            }
            return $this->assurance[(string) ($args[0] ?? '') . ':' . (string) ($args[1] ?? '')] ?? null;
        }
        if (str_contains($query, 'spcrc_privacy_requests')) return $this->privacy[(string) ($args[0] ?? '')] ?? null;
        return null;
    }

    public function get_results(mixed $prepared, mixed $output = null): array
    {
        $query = is_array($prepared) ? (string) ($prepared['query'] ?? '') : (string) $prepared;
        $args = is_array($prepared) ? (array) ($prepared['args'] ?? []) : [];
        $limit = max(1, (int) ($args[array_key_last($args)] ?? 10));
        if (str_contains($query, 'spcrc_risks')) return array_slice(array_reverse(array_values($this->risks)), 0, $limit);
        if (str_contains($query, 'spcrc_incidents')) return array_slice(array_reverse(array_values($this->incidents)), 0, $limit);
        if (str_contains($query, 'spcrc_controls')) return array_slice(array_reverse(array_values($this->controls)), 0, $limit);
        if (str_contains($query, 'spcrc_assurance_records')) {
            $type = str_contains($query, 'WHERE record_type = %s') ? (string) ($args[0] ?? '') : '';
            $rows = array_values(array_filter($this->assurance, static fn(array $r): bool => $type === '' || ($r['record_type'] ?? '') === $type));
            return array_slice(array_reverse($rows), 0, $limit);
        }
        return [];
    }

    public function insert(string $table, array $data, array $formats = []): int|false
    {
        if ($this->failInsert) { $this->last_error = 'forced failure'; return false; }
        if (str_contains($table, 'spcrc_security_events')) $this->events[] = $data;
        elseif (str_contains($table, 'spcrc_privacy_requests')) $this->privacy[(string) $data['request_uuid']] = $data;
        elseif (str_contains($table, 'spcrc_risks')) $this->risks[(string) $data['risk_uuid']] = $data;
        elseif (str_contains($table, 'spcrc_incidents')) $this->incidents[(string) $data['incident_uuid']] = $data;
        elseif (str_contains($table, 'spcrc_controls')) $this->controls[(string) $data['control_key']] = $data;
        elseif (str_contains($table, 'spcrc_module_manifests')) {
            ++$this->manifestInsertCount;
            $key = (string) $data['module_key'];
            if (isset($this->manifests[$key])) return false;
            $this->manifests[$key] = $data;
        } elseif (str_contains($table, 'spcrc_assurance_records')) {
            $id = (string) $data['record_type'] . ':' . (string) $data['record_key'];
            if (isset($this->assurance[$id])) return false;
            $this->assurance[$id] = $data;
        }
        return 1;
    }

    public function update(string $table, array $data, array $where, array $formats = [], array $whereFormats = []): int|false
    {
        if ($this->failInsert) return false;
        if ($this->zeroUpdate) return 0;
        if (str_contains($table, 'spcrc_module_manifests')) {
            ++$this->manifestUpdateCount;
            $key = (string) $where['module_key'];
            if (! isset($this->manifests[$key])) return 0;
            if (isset($where['manifest_hash']) && ($this->manifests[$key]['manifest_hash'] ?? '') !== $where['manifest_hash']) return 0;
            $this->manifests[$key] = array_merge($this->manifests[$key], $data);
            return 1;
        }
        if (str_contains($table, 'spcrc_privacy_requests')) {
            $uuid = (string) $where['request_uuid'];
            if (! isset($this->privacy[$uuid])) return 0;
            $this->privacy[$uuid] = array_merge($this->privacy[$uuid], $data);
            return 1;
        }
        if (str_contains($table, 'spcrc_controls')) {
            $key = (string) $where['control_key'];
            if (! isset($this->controls[$key])) return 0;
            $this->controls[$key] = array_merge($this->controls[$key], $data);
            return 1;
        }
        if (str_contains($table, 'spcrc_assurance_records')) {
            $id = (string) $where['record_type'] . ':' . (string) $where['record_key'];
            if (! isset($this->assurance[$id])) return 0;
            $this->assurance[$id] = array_merge($this->assurance[$id], $data);
            return 1;
        }
        return 1;
    }
}

$GLOBALS['wpdb'] = new FakeWpdb();
$GLOBALS['administrator_role'] = new FakeRole();
$GLOBALS['wp_roles_object'] = new FakeWpRoles($GLOBALS['administrator_role']);

function add_filter(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void { $GLOBALS['wp_filters'][$hook][$priority][] = [$callback, $acceptedArgs]; }
function add_action(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void { add_filter($hook, $callback, $priority, $acceptedArgs); }
function has_action(string $hook, mixed $callback = false): int|false
{
    if (empty($GLOBALS['wp_filters'][$hook])) return false;
    foreach ($GLOBALS['wp_filters'][$hook] as $priority => $callbacks) foreach ($callbacks as [$registered]) if ($callback === false || $registered === $callback) return (int) $priority;
    return false;
}
function apply_filters(string $hook, mixed $value, mixed ...$args): mixed
{
    if (empty($GLOBALS['wp_filters'][$hook])) return $value;
    ksort($GLOBALS['wp_filters'][$hook]);
    foreach ($GLOBALS['wp_filters'][$hook] as $callbacks) foreach ($callbacks as [$callback, $accepted]) $value = $callback(...array_slice([$value, ...$args], 0, $accepted));
    return $value;
}
function do_action(string $hook, mixed ...$args): void
{
    $GLOBALS['wp_actions'][] = [$hook, $args];
    if (empty($GLOBALS['wp_filters'][$hook])) return;
    ksort($GLOBALS['wp_filters'][$hook]);
    foreach ($GLOBALS['wp_filters'][$hook] as $callbacks) foreach ($callbacks as [$callback, $accepted]) $callback(...array_slice($args, 0, $accepted));
}
function __return_true(): bool { return true; }
function sanitize_key(string $value): string { return substr(preg_replace('/[^a-z0-9_\-]/', '', strtolower($value)) ?? '', 0, 255); }
function sanitize_text_field(string $value): string { return trim(preg_replace('/[\r\n\t]+/', ' ', strip_tags($value)) ?? ''); }
function wp_json_encode(mixed $value, int $flags = 0): string|false { return json_encode($value, $flags); }
function wp_generate_uuid4(): string { static $counter = 1; return sprintf('00000000-0000-4000-8000-%012d', $counter++); }
function current_time(string $type, bool $gmt = false): string { return gmdate('Y-m-d H:i:s'); }
function get_current_user_id(): int { return (int) $GLOBALS['current_user_id']; }
function current_user_can(string $capability): bool { return ! empty($GLOBALS['current_user_caps'][$capability]); }
function wp_salt(string $scheme = 'auth'): string { return 'unit-test-salt-' . $scheme; }
function wp_unslash(mixed $value): mixed { return $value; }
function absint(mixed $value): int { return abs((int) $value); }
function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
function get_option(string $key, mixed $default = false): mixed { return $GLOBALS['wp_options'][$key] ?? $default; }
function update_option(string $key, mixed $value, bool $autoload = true): bool { $GLOBALS['wp_options'][$key] = $value; return true; }
function delete_option(string $key): bool { unset($GLOBALS['wp_options'][$key]); return true; }
function set_transient(string $key, mixed $value, int $expiration): bool { $GLOBALS['wp_transients'][$key] = $value; return true; }
function get_transient(string $key): mixed { return $GLOBALS['wp_transients'][$key] ?? false; }
function delete_transient(string $key): bool { unset($GLOBALS['wp_transients'][$key]); return true; }
function get_role(string $role): FakeRole|false { return $role === 'administrator' ? $GLOBALS['administrator_role'] : false; }
function wp_roles(): FakeWpRoles { return $GLOBALS['wp_roles_object']; }
function get_userdata(int $userId): object|false { return $userId > 0 ? (object) ['ID' => $userId, 'user_email' => 'user@example.test'] : false; }
function wp_get_environment_type(): string { return 'staging'; }
function is_ssl(): bool { return true; }
function home_url(): string { return 'https://example.test'; }
function wp_parse_url(string $url, int $component): mixed { return parse_url($url, $component); }
function wp_next_scheduled(string $hook): int|false { return $GLOBALS['wp_scheduled'][$hook] ?? false; }
function wp_schedule_event(int $timestamp, string $recurrence, string $hook): bool { $GLOBALS['wp_scheduled'][$hook] = $timestamp; return true; }
function wp_clear_scheduled_hook(string $hook): int { unset($GLOBALS['wp_scheduled'][$hook]); return 1; }
function dbDelta(string $sql): void {}
