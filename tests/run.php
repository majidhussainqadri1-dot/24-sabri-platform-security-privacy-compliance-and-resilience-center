<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
foreach ([
    'Support/Sanitizer.php',
    'Capabilities.php',
    'Storage/Schema.php',
    'Storage/AuditLogger.php',
    'Storage/RiskRepository.php',
    'Storage/IncidentRepository.php',
    'Storage/ControlRepository.php',
    'Registry/ModuleRegistry.php',
    'Registry/SecurityStateRegistry.php',
    'Privacy/RequestDispatcher.php',
    'System/SystemCheck.php',
    'System/Repair.php',
    'Rest/StatusController.php',
] as $file) {
    require_once $base . $file;
}

use Sabri\Platform\Security\Privacy\RequestDispatcher;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Rest\StatusController;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Storage\RiskRepository;
use Sabri\Platform\Security\Storage\Schema;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\System\Repair;
use Sabri\Platform\Security\System\SystemCheck;

$tests = 0;
function expect(bool $condition, string $message): void
{
    global $tests;
    ++$tests;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

expect(Sanitizer::boolean('false') === false, 'Boolean sanitizer must not cast string false to true.');
expect(Sanitizer::uuid('bad') === '', 'Invalid UUID must be rejected.');
expect(Schema::VERSION === '0.25.2' && count(Schema::tables()) === 7, 'Corrective schema must expose seven owned tables.');

$registry = new ModuleRegistry();
$manifest = [
    'module_key' => 'test-module',
    'name' => 'Test Module',
    'version' => '1.0.0',
    'owner' => 'Test',
    'posture' => 'not-real',
    'data_classes' => ['C1'],
    'public_routes' => ['/public'],
    'private_routes' => ['/private'],
    'privacy_operations' => ['access'],
    'unknown_secret' => 'must-not-persist',
];
$validated = $registry->validate($manifest);
expect(is_array($validated), 'Valid manifest must pass validation.');
expect(! array_key_exists('unknown_secret', $validated), 'Unknown manifest fields must be discarded.');
expect($validated['posture'] === 'unassessed', 'Unknown posture must become unassessed.');
expect($registry->register($manifest), 'Manifest registration must succeed.');
$writes = $GLOBALS['wpdb']->replaceCount;
expect($registry->register($manifest), 'Duplicate manifest registration must remain valid.');
expect($GLOBALS['wpdb']->replaceCount === $writes, 'Unchanged manifest must not be replaced every time.');
$GLOBALS['wpdb']->failInsert = true;
$failedManifest = $manifest;
$failedManifest['module_key'] = 'failed-persist-module';
expect(! $registry->register($failedManifest), 'Manifest persistence failure must not be reported as success.');
$GLOBALS['wpdb']->failInsert = false;

$audit = new AuditLogger();
$result = $audit->record('login_attempt', 'test-module', 'blocked', 'high', [
    'token' => 'secret-value',
    'remote_ip' => '192.0.2.1',
    'shipping_method' => 'courier',
]);
expect(is_string($result), 'Audit write must return an event UUID on success.');
$event = end($GLOBALS['wpdb']->events);
$context = json_decode($event['context_json'], true);
expect($context['token'] === '[REDACTED]', 'Token must be redacted.');
expect(str_starts_with($context['remote_ip'], 'sha256:'), 'IP must be pseudonymized.');
expect($context['shipping_method'] === 'courier', 'Words containing ip must not be misclassified as IP fields.');
$GLOBALS['wpdb']->failInsert = true;
expect(is_wp_error($audit->record('write_failure', 'test-module')), 'Audit storage failure must return WP_Error.');
$GLOBALS['wpdb']->failInsert = false;

$states = new SecurityStateRegistry($registry, $audit);
expect(! $states->request('unknown-module', 'elevated-monitoring'), 'Unknown modules must not request security state.');
expect($states->request('test-module', 'elevated-monitoring', ['reason' => 'test']), 'Registered module state request must succeed.');
expect(count($states->all()) === 1, 'Security state request must persist across registry access.');

$privacy = new RequestDispatcher($audit, $registry);
$failed = $privacy->dispatch(['request_type' => 'access', 'requester_user_id' => 7], ['test-module']);
expect($failed['ok'] === false && $failed['status'] === 'failed', 'Missing privacy handler must fail.');
add_filter('spcrc/privacy_request/test-module', static fn ($result, $type, $request) => ['ok' => true, 'status' => 'completed'], 10, 3);
$passed = $privacy->dispatch(['request_type' => 'access', 'requester_user_id' => 7], ['test-module']);
expect($passed['ok'] === true && $passed['status'] === 'completed', 'Declared privacy handler must complete.');
$collision = $privacy->dispatch([
    'request_uuid' => $passed['request_uuid'],
    'request_type' => 'access',
    'requester_user_id' => 8,
], ['test-module']);
expect(
    $collision['ok'] === false
    && $collision['status'] === 'failed'
    && ($collision['error'] ?? '') === 'spcrc_privacy_request_collision',
    'A privacy UUID cannot be reassigned to another requester.'
);

$risks = new RiskRepository();
$riskUuid = $risks->create([
    'title' => 'Test risk',
    'module_key' => 'test-module',
    'likelihood' => 5,
    'impact' => 4,
    'treatment' => 'mitigate',
]);
expect(is_string($riskUuid), 'Risk repository must create a bounded risk.');
expect($risks->openCount() === 1, 'Open risk count must reflect stored risks.');
expect(($risks->recent(1)[0]['inherent_score'] ?? 0) === 20, 'Risk score must equal likelihood times impact.');

$incidents = new IncidentRepository();
$incidentUuid = $incidents->create(['title' => 'Test incident', 'severity' => 'sev1', 'summary' => 'Sanitized summary']);
expect(is_string($incidentUuid), 'Incident repository must create an incident.');
expect($incidents->openCount() === 1, 'Open incident count must reflect stored incidents.');

$controls = new ControlRepository();
expect($controls->upsert(['control_key' => 'ac-01', 'title' => 'Access control', 'status' => 'implemented']) === 'ac-01', 'Control must be inserted.');
expect($controls->upsert(['control_key' => 'ac-01', 'title' => 'Access control revised', 'status' => 'tested']) === 'ac-01', 'Existing control must update without destructive replacement.');
expect($controls->count() === 1 && ($controls->recent(1)[0]['status'] ?? '') === 'tested', 'Control update must preserve one canonical record.');

$repair = new Repair();
$repairResult = $repair->run();
expect(is_array($repairResult) && get_option('spcrc_schema_version') === '0.25.2', 'Non-destructive repair must verify schema and record version.');
expect(! empty($GLOBALS['administrator_role']->caps['spcrc_manage_risks']), 'Repair must reapply administrator capabilities.');

add_filter('spcrc/public_browsing_compatible', '__return_false');
function __return_false(): bool { return false; }
$checks = new SystemCheck($registry);
$checkMap = [];
foreach ($checks->run() as $check) {
    $checkMap[$check['key']] = $check;
}
expect(($checkMap['public_browsing_compatibility']['status'] ?? '') === 'warning', 'Anonymous public-browsing conflict must be surfaced as a warning.');

$controller = new StatusController($registry, $states, $checks, $risks, $incidents, $controls);
add_filter('spcrc/public_trust_payload', static function (array $payload): array {
    $payload['privacy_request_available'] = 'false';
    $payload['private_secret'] = 'must-not-leak';
    return $payload;
});
$trustResponse = $controller->trust();
$trust = $trustResponse->get_data();
expect($trust['privacy_request_available'] === false, 'Public boolean string false must remain false.');
expect(! array_key_exists('private_secret', $trust), 'Unapproved Trust Center fields must be discarded.');
expect(($trustResponse->get_headers()['X-Content-Type-Options'] ?? '') === 'nosniff', 'REST responses must set nosniff.');

$status = $controller->status()->get_data();
expect(($status['counts']['open_risks'] ?? 0) === 1 && ($status['counts']['controls'] ?? 0) === 1, 'Private status aggregates must honor repositories and capabilities.');
expect(! array_key_exists('private_routes', $status['modules'][0] ?? []), 'Private status module summaries must not expose private routes.');

fwrite(STDOUT, "PASS: {$tests} foundation contract assertions\n");
