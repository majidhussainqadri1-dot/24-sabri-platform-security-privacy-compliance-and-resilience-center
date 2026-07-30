<?php

declare(strict_types=1);

const ARRAY_A = 'ARRAY_A';
const MINUTE_IN_SECONDS = 60;
const HOUR_IN_SECONDS = 3600;
const DAY_IN_SECONDS = 86400;
const ABSPATH = '/tmp/wordpress/';
const SPCRC_VERSION = '0.25.1';

@mkdir(ABSPATH . 'wp-admin/includes', 0777, true);
if (! file_exists(ABSPATH . 'wp-admin/includes/upgrade.php')) {
    file_put_contents(ABSPATH . 'wp-admin/includes/upgrade.php', "<?php\n");
}

$GLOBALS['wp_filters'] = [];
$GLOBALS['wp_options'] = [];
$GLOBALS['wp_transients'] = [];
$GLOBALS['wp_actions'] = [];
$GLOBALS['current_user_id'] = 7;
$GLOBALS['current_user_caps'] = array_fill_keys([
    'spcrc_view_overview',
    'spcrc_view_module_posture',
    'spcrc_manage_controls',
    'spcrc_manage_risks',
    'spcrc_manage_incidents',
    'spcrc_manage_security_settings',
    'spcrc_run_security_assessments',
], true);
$GLOBALS['wp_version'] = '7.0.1';

final class WP_Error
{
    public function __construct(private string $code, private string $message)
    {
    }
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
    public function __construct(FakeRole $administrator)
    {
        $this->role_objects = ['administrator' => $administrator];
    }
}

final class FakeWpdb
{
    public string $prefix = 'wp_';
    public bool $failInsert = false;
    public int $replaceCount = 0;
    public array $events = [];
    public array $privacy = [];
    public array $manifests = [];
    public array $risks = [];
    public array $incidents = [];
    public array $controls = [];
    public string $last_error = '';

    public function get_charset_collate(): string { return 'DEFAULT CHARACTER SET utf8mb4'; }
    public function esc_like(string $value): string { return $value; }
    public function prepare(string $query, mixed ...$args): array { return ['query' => $query, 'args' => $args]; }

    public function get_var(mixed $prepared): mixed
    {
        if (is_string($prepared)) {
            if (str_contains($prepared, 'spcrc_risks') && str_contains($prepared, 'COUNT(*)')) {
                return count(array_filter($this->risks, static fn (array $row): bool => ($row['status'] ?? '') === 'open'));
            }
            if (str_contains($prepared, 'spcrc_incidents') && str_contains($prepared, 'COUNT(*)')) {
                return count(array_filter($this->incidents, static fn (array $row): bool => ($row['status'] ?? '') === 'open'));
            }
            if (str_contains($prepared, 'spcrc_controls') && str_contains($prepared, 'COUNT(*)')) {
                return count($this->controls);
            }
            return null;
        }

        if (is_array($prepared)) {
            $query = (string) $prepared['query'];
            $args = (array) $prepared['args'];
            if (str_starts_with($query, 'SHOW TABLES LIKE')) {
                return $args[0] ?? null;
            }
            if (str_contains($query, 'spcrc_privacy_requests') && str_contains($query, 'SELECT id')) {
                $uuid = (string) ($args[0] ?? '');
                return isset($this->privacy[$uuid]) ? 1 : null;
            }
            if (str_contains($query, 'spcrc_controls') && str_contains($query, 'SELECT id')) {
                $key = (string) ($args[0] ?? '');
                return isset($this->controls[$key]) ? 1 : null;
            }
        }

        return null;
    }

    public function get_row(mixed $prepared, mixed $output = null): mixed
    {
        if (! is_array($prepared)) {
            return null;
        }

        $query = (string) $prepared['query'];
        $key = (string) ($prepared['args'][0] ?? '');
        if (str_contains($query, 'spcrc_module_manifests')) {
            return $this->manifests[$key] ?? null;
        }
        if (str_contains($query, 'spcrc_privacy_requests')) {
            if (! isset($this->privacy[$key])) {
                return null;
            }
            return [
                'id' => 1,
                'requester_user_id' => $this->privacy[$key]['requester_user_id'] ?? null,
                'request_type' => $this->privacy[$key]['request_type'] ?? '',
            ];
        }
        return null;
    }

    public function get_results(mixed $prepared, mixed $output = null): array
    {
        $query = is_array($prepared) ? (string) $prepared['query'] : (string) $prepared;
        $limit = is_array($prepared) ? max(1, (int) ($prepared['args'][0] ?? 10)) : 10;

        if (str_contains($query, 'spcrc_risks')) {
            return array_slice(array_reverse(array_values($this->risks)), 0, $limit);
        }
        if (str_contains($query, 'spcrc_incidents')) {
            return array_slice(array_reverse(array_values($this->incidents)), 0, $limit);
        }
        if (str_contains($query, 'spcrc_controls')) {
            return array_slice(array_reverse(array_values($this->controls)), 0, $limit);
        }
        return [];
    }

    public function insert(string $table, array $data, array $formats = []): int|false
    {
        if ($this->failInsert) {
            $this->last_error = 'forced failure';
            return false;
        }
        if (str_contains($table, 'spcrc_security_events')) {
            $this->events[] = $data;
        } elseif (str_contains($table, 'spcrc_privacy_requests')) {
            $this->privacy[(string) $data['request_uuid']] = $data;
        } elseif (str_contains($table, 'spcrc_risks')) {
            $this->risks[(string) $data['risk_uuid']] = $data;
        } elseif (str_contains($table, 'spcrc_incidents')) {
            $this->incidents[(string) $data['incident_uuid']] = $data;
        } elseif (str_contains($table, 'spcrc_controls')) {
            $this->controls[(string) $data['control_key']] = $data;
        }
        return 1;
    }

    public function replace(string $table, array $data, array $formats = []): int|false
    {
        ++$this->replaceCount;
        if ($this->failInsert) {
            return false;
        }
        if (str_contains($table, 'spcrc_module_manifests')) {
            $this->manifests[(string) $data['module_key']] = [
                'manifest_hash' => $data['manifest_hash'],
                'last_seen_at' => $data['last_seen_at'],
            ];
        }
        return 1;
    }

    public function update(string $table, array $data, array $where, array $formats = [], array $whereFormats = []): int|false
    {
        if ($this->failInsert) {
            return false;
        }
        if (str_contains($table, 'spcrc_module_manifests')) {
            $key = (string) $where['module_key'];
            $this->manifests[$key] = array_merge($this->manifests[$key] ?? [], $data);
        } elseif (str_contains($table, 'spcrc_privacy_requests')) {
            $uuid = (string) $where['request_uuid'];
            $this->privacy[$uuid] = array_merge($this->privacy[$uuid] ?? [], $data);
        } elseif (str_contains($table, 'spcrc_controls')) {
            $key = (string) $where['control_key'];
            $this->controls[$key] = array_merge($this->controls[$key] ?? [], $data);
        }
        return 1;
    }
}

$GLOBALS['wpdb'] = new FakeWpdb();
$GLOBALS['administrator_role'] = new FakeRole();
$GLOBALS['wp_roles_object'] = new FakeWpRoles($GLOBALS['administrator_role']);

function add_filter(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void
{
    $GLOBALS['wp_filters'][$hook][$priority][] = [$callback, $acceptedArgs];
}
function add_action(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void
{
    add_filter($hook, $callback, $priority, $acceptedArgs);
}
function has_action(string $hook, mixed $callback = false): int|false
{
    if (empty($GLOBALS['wp_filters'][$hook])) return false;
    foreach ($GLOBALS['wp_filters'][$hook] as $priority => $callbacks) {
        foreach ($callbacks as [$registered]) {
            if ($callback === false || $registered === $callback) return (int) $priority;
        }
    }
    return false;
}
function apply_filters(string $hook, mixed $value, mixed ...$args): mixed
{
    if (empty($GLOBALS['wp_filters'][$hook])) return $value;
    ksort($GLOBALS['wp_filters'][$hook]);
    foreach ($GLOBALS['wp_filters'][$hook] as $callbacks) {
        foreach ($callbacks as [$callback, $accepted]) {
            $value = $callback(...array_slice([$value, ...$args], 0, $accepted));
        }
    }
    return $value;
}
function do_action(string $hook, mixed ...$args): void
{
    $GLOBALS['wp_actions'][] = [$hook, $args];
    if (empty($GLOBALS['wp_filters'][$hook])) return;
    ksort($GLOBALS['wp_filters'][$hook]);
    foreach ($GLOBALS['wp_filters'][$hook] as $callbacks) {
        foreach ($callbacks as [$callback, $accepted]) {
            $callback(...array_slice($args, 0, $accepted));
        }
    }
}
function __return_true(): bool { return true; }
function sanitize_key(string $value): string { return substr(preg_replace('/[^a-z0-9_\-]/', '', strtolower($value)) ?? '', 0, 255); }
function sanitize_text_field(string $value): string { return trim(preg_replace('/[\r\n\t]+/', ' ', strip_tags($value)) ?? ''); }
function wp_json_encode(mixed $value, int $flags = 0): string|false { return json_encode($value, $flags); }
function wp_generate_uuid4(): string
{
    static $counter = 1;
    return sprintf('00000000-0000-4000-8000-%012d', $counter++);
}
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
function dbDelta(string $sql): void {}
