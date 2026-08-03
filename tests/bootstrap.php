<?php

declare(strict_types=1);

const ARRAY_A = 'ARRAY_A';
const MINUTE_IN_SECONDS = 60;
const HOUR_IN_SECONDS = 3600;
const DAY_IN_SECONDS = 86400;
const ABSPATH = '/tmp/wordpress/';
const SPCRC_VERSION = '0.25.8';

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
    'spcrc_request_governance_decision',
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
    public bool $failAuditInsert = false;
    public bool $zeroUpdate = false;
    public int $manifestInsertCount = 0;
    public int $manifestUpdateCount = 0;
    public array $events = [];
    public array $privacy = [];
    public array $manifests = [];
    public array $risks = [];
    public array $findings = [];
    public array $incidents = [];
    public array $controls = [];
    public array $assurance = [];
    public array $governance = [];
    public string $last_error = '';
    public array $missingColumns = [];

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
            if (str_contains($prepared, 'spcrc_governance_decisions') && str_contains($prepared, 'COUNT(*)')) return count(array_filter($this->governance, static fn(array $r): bool => ($r['status'] ?? '') === 'pending'));
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
        if (str_contains($query, 'spcrc_governance_decisions') && str_contains($query, 'SELECT decision_uuid')) {
            $type = (string) ($args[0] ?? '');
            $subject = (string) ($args[1] ?? '');
            foreach ($this->governance as $row) {
                if (($row['decision_type'] ?? '') === $type && ($row['subject_key'] ?? '') === $subject && ($row['status'] ?? '') === 'pending') return $row['decision_uuid'];
            }
            return null;
        }
        if (str_contains($query, 'spcrc_governance_decisions') && str_contains($query, 'COUNT(*)')) {
            return count(array_filter($this->governance, static fn(array $r): bool => ($r['status'] ?? '') === 'pending'));
        }
        return null;
    }

    public function get_col(string $query, int $column = 0): array
    {
        $columns = [
            'spcrc_security_events' => ['id', 'event_uuid', 'event_type', 'module_key', 'actor_user_id', 'result', 'risk_level', 'correlation_id', 'context_json', 'created_at'],
            'spcrc_incidents' => ['id', 'incident_uuid', 'title', 'severity', 'status', 'owner_user_id', 'summary', 'evidence_ref', 'opened_at', 'updated_at', 'closed_at'],
            'spcrc_findings' => ['id', 'finding_uuid', 'module_key', 'title', 'severity', 'status', 'owner_user_id', 'due_at', 'evidence_ref', 'governance_decision_uuid', 'acceptance_expires_at', 'created_at', 'updated_at'],
            'spcrc_risks' => ['id', 'risk_uuid', 'module_key', 'title', 'likelihood', 'impact', 'inherent_score', 'status', 'treatment', 'owner_user_id', 'due_at', 'governance_decision_uuid', 'accepted_by_user_id', 'accepted_at', 'acceptance_expires_at', 'created_at', 'updated_at'],
            'spcrc_controls' => ['id', 'control_key', 'title', 'framework', 'status', 'owner_user_id', 'evidence_ref', 'last_tested_at', 'created_at', 'updated_at'],
            'spcrc_privacy_requests' => ['id', 'request_uuid', 'requester_user_id', 'request_type', 'status', 'assigned_user_id', 'jurisdiction', 'due_at', 'verification_method', 'authority_basis', 'verification_reference', 'verified_by_user_id', 'verified_at', 'module_results_json', 'dispatch_attempts', 'lock_version', 'next_retry_at', 'last_error_code', 'completed_at', 'created_at', 'updated_at'],
            'spcrc_module_manifests' => ['id', 'module_key', 'module_version', 'manifest_hash', 'posture', 'manifest_json', 'last_seen_at'],
            'spcrc_governance_decisions' => ['id', 'decision_uuid', 'decision_type', 'subject_key', 'module_key', 'status', 'requester_user_id', 'approver_user_id', 'evidence_ref', 'rationale_hash', 'requested_at', 'expires_at', 'decided_at', 'revoked_at', 'lock_version'],
            'spcrc_assurance_records' => ['id', 'record_uuid', 'record_type', 'record_key', 'title', 'status', 'owner_user_id', 'jurisdiction', 'data_classes_json', 'evidence_ref', 'notes', 'reviewed_at', 'next_review_at', 'backup_completed_at', 'restore_tested_at', 'created_at', 'updated_at'],
        ];
        foreach ($columns as $table => $available) {
            if (str_contains($query, $table)) {
                return array_values(array_diff($available, $this->missingColumns[$table] ?? []));
            }
        }
        return [];
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
        if (str_contains($query, 'spcrc_governance_decisions')) return $this->governance[(string) ($args[0] ?? '')] ?? null;
        if (str_contains($query, 'spcrc_risks') && str_contains($query, 'WHERE risk_uuid')) return $this->risks[(string) ($args[0] ?? '')] ?? null;
        if (str_contains($query, 'spcrc_findings') && str_contains($query, 'WHERE finding_uuid')) return $this->findings[(string) ($args[0] ?? '')] ?? null;
        if (str_contains($query, 'spcrc_controls') && str_contains($query, 'WHERE control_key')) return $this->controls[(string) ($args[0] ?? '')] ?? null;
        if (str_contains($query, 'spcrc_incidents') && str_contains($query, 'WHERE incident_uuid')) return $this->incidents[(string) ($args[0] ?? '')] ?? null;
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
        if (str_contains($query, 'spcrc_governance_decisions')) return array_slice(array_reverse(array_values($this->governance)), 0, $limit);
        if (str_contains($query, 'spcrc_assurance_records')) {
            $type = str_contains($query, 'WHERE record_type = %s') ? (string) ($args[0] ?? '') : '';
            $rows = array_values(array_filter($this->assurance, static fn(array $r): bool => $type === '' || ($r['record_type'] ?? '') === $type));
            return array_slice(array_reverse($rows), 0, $limit);
        }
        return [];
    }

    public function insert(string $table, array $data, array $formats = []): int|false
    {
        if ($this->failInsert || ($this->failAuditInsert && str_contains($table, 'spcrc_security_events'))) { $this->last_error = 'forced failure'; return false; }
        if (str_contains($table, 'spcrc_security_events')) $this->events[] = $data;
        elseif (str_contains($table, 'spcrc_privacy_requests')) $this->privacy[(string) $data['request_uuid']] = $data;
        elseif (str_contains($table, 'spcrc_risks')) $this->risks[(string) $data['risk_uuid']] = $data;
        elseif (str_contains($table, 'spcrc_findings')) $this->findings[(string) $data['finding_uuid']] = $data;
        elseif (str_contains($table, 'spcrc_incidents')) $this->incidents[(string) $data['incident_uuid']] = $data;
        elseif (str_contains($table, 'spcrc_controls')) $this->controls[(string) $data['control_key']] = $data;
        elseif (str_contains($table, 'spcrc_module_manifests')) {
            ++$this->manifestInsertCount;
            $key = (string) $data['module_key'];
            if (isset($this->manifests[$key])) return false;
            $this->manifests[$key] = $data;
        } elseif (str_contains($table, 'spcrc_governance_decisions')) {
            $key = (string) $data['decision_uuid'];
            if (isset($this->governance[$key])) return false;
            $this->governance[$key] = $data;
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
        if (str_contains($table, 'spcrc_governance_decisions')) {
            $uuid = (string) ($where['decision_uuid'] ?? '');
            if (! isset($this->governance[$uuid])) return 0;
            foreach ($where as $key => $value) if (($this->governance[$uuid][$key] ?? null) != $value) return 0;
            $this->governance[$uuid] = array_merge($this->governance[$uuid], $data);
            return 1;
        }
        if (str_contains($table, 'spcrc_risks')) {
            $uuid = (string) ($where['risk_uuid'] ?? '');
            if (! isset($this->risks[$uuid])) return 0;
            if (isset($where['status']) && ($this->risks[$uuid]['status'] ?? '') !== $where['status']) return 0;
            $this->risks[$uuid] = array_merge($this->risks[$uuid], $data);
            return 1;
        }
        if (str_contains($table, 'spcrc_findings')) {
            $uuid = (string) ($where['finding_uuid'] ?? '');
            if (! isset($this->findings[$uuid])) return 0;
            if (isset($where['status']) && ($this->findings[$uuid]['status'] ?? '') !== $where['status']) return 0;
            $this->findings[$uuid] = array_merge($this->findings[$uuid], $data);
            return 1;
        }
        if (str_contains($table, 'spcrc_incidents')) {
            $uuid = (string) ($where['incident_uuid'] ?? '');
            if (! isset($this->incidents[$uuid])) return 0;
            $this->incidents[$uuid] = array_merge($this->incidents[$uuid], $data);
            return 1;
        }
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

    public function delete(string $table, array $where, array $formats = []): int|false
    {
        if (str_contains($table, 'spcrc_governance_decisions')) {
            $uuid = (string) ($where['decision_uuid'] ?? '');
            if (! isset($this->governance[$uuid])) return 0;
            unset($this->governance[$uuid]);
            return 1;
        }
        if (str_contains($table, 'spcrc_assurance_records')) {
            $recordUuid = (string) ($where['record_uuid'] ?? '');
            foreach ($this->assurance as $id => $row) {
                if (($row['record_uuid'] ?? '') === $recordUuid) {
                    unset($this->assurance[$id]);
                    return 1;
                }
            }
            return 0;
        }
        foreach ([
            'spcrc_risks' => ['risk_uuid', 'risks'],
            'spcrc_findings' => ['finding_uuid', 'findings'],
            'spcrc_incidents' => ['incident_uuid', 'incidents'],
            'spcrc_controls' => ['control_key', 'controls'],
        ] as $needle => [$keyName, $property]) {
            if (str_contains($table, $needle)) {
                $key = (string) ($where[$keyName] ?? '');
                if (! isset($this->{$property}[$key])) return 0;
                unset($this->{$property}[$key]);
                return 1;
            }
        }
        return 0;
    }

    public function query(mixed $prepared): int|false
    {
        $query = is_array($prepared) ? (string) ($prepared['query'] ?? '') : (string) $prepared;
        if (str_contains($query, 'spcrc_governance_decisions')) {
            $count = 0;
            foreach ($this->governance as &$row) {
                if (($row['status'] ?? '') === 'pending' && strtotime((string) ($row['expires_at'] ?? '') . ' UTC') <= time()) {
                    $row['status'] = 'expired'; ++$count;
                }
            }
            unset($row);
            return $count;
        }
        if (str_contains($query, 'spcrc_risks')) {
            $count = 0;
            foreach ($this->risks as &$row) {
                if (($row['status'] ?? '') === 'accepted' && strtotime((string) ($row['acceptance_expires_at'] ?? '') . ' UTC') <= time()) {
                    $row['status'] = 'open'; $row['treatment'] = 'mitigate'; $row['governance_decision_uuid'] = null; $row['acceptance_expires_at'] = null; ++$count;
                }
            }
            unset($row);
            return $count;
        }
        if (str_contains($query, 'spcrc_findings')) {
            $count = 0;
            foreach ($this->findings as &$row) {
                if (($row['status'] ?? '') === 'accepted-risk' && strtotime((string) ($row['acceptance_expires_at'] ?? '') . ' UTC') <= time()) {
                    $row['status'] = 'triaged'; $row['governance_decision_uuid'] = null; $row['acceptance_expires_at'] = null; ++$count;
                }
            }
            unset($row);
            return $count;
        }
        return 0;
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
function add_option(string $key, mixed $value = '', string $deprecated = '', bool|string|null $autoload = null): bool { if (array_key_exists($key, $GLOBALS['wp_options'])) return false; $GLOBALS['wp_options'][$key] = $value; return true; }
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
