<?php

declare(strict_types=1);

const ARRAY_A = 'ARRAY_A';
$GLOBALS['filters'] = [];
$GLOBALS['caps'] = [];

final class WP_Error
{
    public function __construct(private string $code, private string $message) {}
    public function get_error_code(): string { return $this->code; }
    public function get_error_message(): string { return $this->message; }
}

function add_filter(string $hook, callable $callback, int $priority = 10, int $acceptedArgs = 1): void
{
    $GLOBALS['filters'][$hook][] = [$callback, $acceptedArgs];
}
function do_action(string $hook, mixed ...$args): void {}
function sanitize_key(string $value): string { return substr(preg_replace('/[^a-z0-9_\-]/', '', strtolower($value)) ?? '', 0, 255); }
function sanitize_text_field(string $value): string { return trim(preg_replace('/[\r\n\t]+/', ' ', strip_tags($value)) ?? ''); }
function wp_generate_uuid4(): string { static $counter = 1; return sprintf('00000000-0000-4000-8000-%012d', $counter++); }
function current_time(string $type, bool $gmt = false): string { return '2026-07-31 03:00:00'; }
function get_current_user_id(): int { return 7; }
function current_user_can(string $capability): bool { return ! empty($GLOBALS['caps'][$capability]); }
function absint(mixed $value): int { return abs((int) $value); }
function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }

final class FindingWpdb
{
    public string $prefix = 'wp_';
    public array $findings = [];
    public bool $failWrite = false;
    public bool $concurrentChange = false;

    public function insert(string $table, array $data, array $formats = []): int|false
    {
        if ($this->failWrite) return false;
        $this->findings[(string) $data['finding_uuid']] = $data;
        return 1;
    }

    public function update(string $table, array $data, array $where, array $formats = [], array $whereFormats = []): int|false
    {
        if ($this->failWrite) return false;
        if ($this->concurrentChange) return 0;
        $uuid = (string) ($where['finding_uuid'] ?? '');
        if (! isset($this->findings[$uuid])) return 0;
        if (($where['status'] ?? '') !== ($this->findings[$uuid]['status'] ?? '')) return 0;
        $this->findings[$uuid] = array_merge($this->findings[$uuid], $data);
        return 1;
    }

    public function get_row(mixed $prepared, mixed $output = null): mixed
    {
        if (! is_array($prepared)) return null;
        $uuid = (string) ($prepared['args'][0] ?? '');
        return $this->findings[$uuid] ?? null;
    }

    public function get_var(mixed $query): mixed
    {
        return count(array_filter(
            $this->findings,
            static fn (array $row): bool => in_array($row['status'] ?? '', ['open', 'triaged', 'in-progress'], true)
        ));
    }

    public function prepare(string $query, mixed ...$args): array
    {
        return ['query' => $query, 'args' => $args];
    }

    public function get_results(mixed $prepared, mixed $output = null): array
    {
        $limit = max(1, (int) ($prepared['args'][0] ?? 10));
        return array_slice(array_reverse(array_values($this->findings)), 0, $limit);
    }
}
$GLOBALS['wpdb'] = new FindingWpdb();

require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/FindingRepository.php';

use Sabri\Platform\Security\Storage\FindingRepository;

function expectFinding(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$repository = new FindingRepository();
$invalid = $repository->create(['module_key' => 'file-03']);
expectFinding(is_wp_error($invalid), 'Finding without a title must be rejected.');

$uuid = $repository->create([
    'module_key' => 'File 03',
    'title' => '<b>Public profile leaked a private field</b>',
    'severity' => 'critical',
    'evidence_ref' => 'private-evidence:case-17',
]);
expectFinding(is_string($uuid), 'Valid finding must be stored.');
$row = $GLOBALS['wpdb']->findings[$uuid];
expectFinding($row['module_key'] === 'file03', 'Module key must be sanitized.');
expectFinding($row['title'] === 'Public profile leaked a private field', 'Finding title must be sanitized.');
expectFinding($row['severity'] === 'critical' && $row['status'] === 'open', 'Finding severity and initial status must be bounded.');
expectFinding($repository->openCount() === 1, 'Open count must include active findings.');

$invalidTransition = $repository->setStatus($uuid, 'accepted-risk', ['note' => 'Unreviewed exception']);
expectFinding(is_wp_error($invalidTransition) && $invalidTransition->get_error_code() === 'spcrc_finding_transition_invalid', 'Risk acceptance must require triage first.');

$missingNote = $repository->setStatus($uuid, 'triaged');
expectFinding(is_wp_error($missingNote) && $missingNote->get_error_code() === 'spcrc_finding_note_required', 'Every status transition must require an accountability note.');

expectFinding($repository->setStatus($uuid, 'triaged', ['expected_status' => 'open', 'note' => 'Validated']) === true, 'Open finding must move to triaged.');
$stale = $repository->setStatus($uuid, 'resolved', ['expected_status' => 'open', 'note' => 'Fixed']);
expectFinding(is_wp_error($stale) && $stale->get_error_code() === 'spcrc_finding_stale_status', 'Stale status updates must fail closed.');

$forbidden = $repository->setStatus($uuid, 'accepted-risk', ['expected_status' => 'triaged', 'note' => 'Exception requested']);
expectFinding(is_wp_error($forbidden) && $forbidden->get_error_code() === 'spcrc_finding_risk_acceptance_forbidden', 'Risk acceptance must require separate capability.');

$GLOBALS['caps']['spcrc_accept_critical_risk'] = true;
expectFinding($repository->setStatus($uuid, 'accepted-risk', ['expected_status' => 'triaged', 'note' => 'Approved exception']) === true, 'Authorized risk acceptance must succeed.');
expectFinding($repository->openCount() === 0, 'Accepted-risk findings must leave the open count.');
expectFinding($repository->setStatus($uuid, 'triaged', ['expected_status' => 'accepted-risk', 'note' => 'Risk reopened']) === true, 'Terminal finding must be explicitly reopenable to triage.');

$GLOBALS['wpdb']->concurrentChange = true;
$concurrent = $repository->setStatus($uuid, 'in-progress', ['expected_status' => 'triaged', 'note' => 'Work started']);
expectFinding(is_wp_error($concurrent) && $concurrent->get_error_code() === 'spcrc_finding_concurrent_change', 'Concurrent changes must not be overwritten.');
$GLOBALS['wpdb']->concurrentChange = false;

expectFinding(is_wp_error($repository->setStatus($uuid, 'deleted')), 'Unknown finding status must fail closed.');
expectFinding(is_wp_error($repository->setStatus('11111111-1111-4111-8111-111111111111', 'resolved', ['note' => 'Not found'])), 'Unknown UUID must not report success.');
expectFinding(count($repository->recent(10)) === 1, 'Recent findings must return bounded stored records.');

$GLOBALS['wpdb']->failWrite = true;
expectFinding(is_wp_error($repository->create(['module_key' => 'file-03', 'title' => 'Write failure'])), 'Storage failure must return WP_Error.');

echo "PASS: hardened security finding lifecycle\n";
