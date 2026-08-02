<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
foreach ([
    'Support/Sanitizer.php',
    'Capabilities.php',
    'Storage/AuditLogger.php',
    'Storage/IncidentRepository.php',
    'Storage/AssuranceRepository.php',
    'Storage/GovernanceRepository.php',
    'Registry/ModuleRegistry.php',
    'Registry/SecurityStateRegistry.php',
    'Storage/RiskRepository.php',
    'Storage/ControlRepository.php',
    'Storage/FindingRepository.php',
    'System/SystemCheck.php',
    'Rest/StatusController.php',
] as $file) {
    require_once $base . $file;
}

use Sabri\Platform\Security\Capabilities;
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Rest\StatusController;
use Sabri\Platform\Security\Storage\AssuranceRepository;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\FindingRepository;
use Sabri\Platform\Security\Storage\GovernanceRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Storage\RiskRepository;
use Sabri\Platform\Security\Support\Sanitizer;
use Sabri\Platform\Security\System\SystemCheck;

$assertions = 0;
function expectCycle12(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

expectCycle12(Sanitizer::opaqueReference('vault:case-2026-001') === 'vault:case-2026-001', 'Opaque evidence reference must be accepted.');
foreach (['https://example.test/x', '/private/evidence', 'C:\\secret\\file', 'person@example.test', 'no-namespace'] as $raw) {
    expectCycle12(Sanitizer::opaqueReference($raw) === '', 'Raw URL/path/contact/non-opaque reference must be rejected: ' . $raw);
}
expectCycle12(Sanitizer::containsSensitiveMaterial('api_key=top-secret'), 'Credential assignment must be detected.');
expectCycle12(Sanitizer::containsSensitiveMaterial('Contact person@example.test'), 'E-mail must be detected as sensitive.');
expectCycle12(! Sanitizer::containsSensitiveMaterial('Qualified review is pending.'), 'Ordinary bounded note must remain usable.');

$audit = new AuditLogger();
$event = $audit->record('adversarial_event', 'file-24-security-center', 'recorded', 'high', [
    'detail' => 'Contact person@example.test',
    'evidence_ref' => 'vault:case-2026-001',
]);
expectCycle12(is_string($event), 'Audit event must persist.');
$context = json_decode((string) ($GLOBALS['wpdb']->events[array_key_last($GLOBALS['wpdb']->events)]['context_json'] ?? '{}'), true);
expectCycle12(($context['detail'] ?? '') === '[REDACTED]', 'Sensitive value under an unrecognized key must still be redacted.');
expectCycle12(($context['evidence_ref'] ?? '') === 'vault:case-2026-001', 'Opaque evidence reference may remain as bounded metadata.');

$incidents = new IncidentRepository();
$missing = $incidents->create(['title' => 'Critical incident', 'severity' => 'sev1', 'summary' => 'Sanitized summary']);
expectCycle12(is_wp_error($missing) && $missing->get_error_code() === 'spcrc_incident_evidence_required', 'Critical incident must require private evidence reference.');
$sensitive = $incidents->create(['title' => 'Sensitive incident', 'severity' => 'sev2', 'summary' => 'password=secret']);
expectCycle12(is_wp_error($sensitive) && $sensitive->get_error_code() === 'spcrc_incident_summary_sensitive', 'Sensitive incident details must be rejected from bounded metadata.');
$incident = $incidents->create(['title' => 'Critical incident', 'severity' => 'sev1', 'summary' => 'Sanitized summary', 'evidence_ref' => 'vault:incident-001']);
expectCycle12(is_string($incident), 'Critical incident with opaque evidence must persist.');

Capabilities::install();
expectCycle12(empty($GLOBALS['administrator_role']->caps['spcrc_approve_governance_decision']), 'Governance approval capability must never be auto-granted.');
expectCycle12(empty($GLOBALS['administrator_role']->caps['spcrc_accept_critical_risk']), 'Critical-risk acceptance capability must never be auto-granted.');
expectCycle12(! empty($GLOBALS['administrator_role']->caps['spcrc_request_governance_decision']), 'Request capability may be operationally auto-granted to administrators.');

$registry = new ModuleRegistry();
$valid = $registry->validate([
    'module_key' => 'file-17-communication-network',
    'name' => 'Sabri Communication Network',
    'version' => '2.0.0',
    'owner' => 'File 17',
    'posture' => 'foundation',
    'data_classes' => ['C3 Sensitive Personal'],
    'public_routes' => ['/network/'],
    'private_routes' => ['/messages/'],
    'contract_version' => '2.0.0',
    'canonical_data_owner' => 'File 17',
    'canonical_action_owner' => 'File 17',
    'evidence_source' => 'release:file-17-2.0.0',
    'degraded_behavior' => 'New privileged writes fail closed.',
    'release_gate' => 'Hostinger staging and provider validation',
]);
expectCycle12(is_array($valid) && ($valid['contract_version'] ?? '') === '2.0.0', 'Expanded versioned module contract must survive validation.');
expectCycle12(($valid['evidence_source'] ?? '') === 'release:file-17-2.0.0', 'Opaque module evidence source must survive validation.');
$unsafeManifest = $registry->validate([
    'module_key' => 'unsafe', 'name' => 'Unsafe', 'version' => '1', 'owner' => 'Test',
    'data_classes' => [], 'public_routes' => [], 'private_routes' => [],
    'evidence_source' => 'https://private.example/evidence',
]);
expectCycle12(is_array($unsafeManifest) && ($unsafeManifest['evidence_source'] ?? 'x') === '', 'Raw evidence location must be discarded from manifest.');

$governance = new GovernanceRepository($audit);
$GLOBALS['current_user_caps']['spcrc_approve_governance_decision'] = true;
$first = '33333333-3333-4333-8333-333333333333';
$second = '44444444-4444-4444-8444-444444444444';
foreach ([$first, $second] as $id) {
    $GLOBALS['wpdb']->governance[$id] = [
        'decision_uuid' => $id,
        'decision_type' => 'policy-exception',
        'subject_key' => $id === $first ? 'first' : 'second',
        'module_key' => 'file-24-security-center',
        'status' => 'approved',
        'requester_user_id' => 7,
        'approver_user_id' => 8,
        'evidence_ref' => 'vault:decision-' . substr($id, 0, 8),
        'rationale_hash' => hash('sha256', $id),
        'requested_at' => gmdate('Y-m-d H:i:s', time() - 3600),
        'expires_at' => gmdate('Y-m-d H:i:s', time() + 3600),
        'decided_at' => gmdate('Y-m-d H:i:s'),
        'revoked_at' => null,
        'lock_version' => 1,
    ];
}
$GLOBALS['wp_options']['spcrc_governance_audit_gap'] = ['decision_uuid' => $first];
expectCycle12(! $governance->isApprovedFor($first, 'policy-exception', 'first'), 'Audit-gapped decision must fail closed.');
expectCycle12($governance->isApprovedFor($second, 'policy-exception', 'second'), 'Unrelated valid decision must not be globally disabled.');
unset($GLOBALS['wp_options']['spcrc_governance_audit_gap']);

$modules = new ModuleRegistry();
$states = new SecurityStateRegistry($modules, $audit);
$checks = new SystemCheck($modules);
$controller = new StatusController($modules, $states, $checks, new RiskRepository(), new IncidentRepository(), new ControlRepository(), new FindingRepository(), new AssuranceRepository(), $governance);
add_filter('spcrc/public_trust_payload', static function (array $payload): array {
    $payload['security_program'] = '100% Secure and ISO Certified';
    $payload['private_incident'] = 'must never be rendered';
    return $payload;
});
$trust = $controller->trust()->get_data();
expectCycle12(($trust['security_program'] ?? '') === 'Foundation candidate; production assurance pending', 'Public filter must not elevate security/certification claims.');
expectCycle12(! array_key_exists('private_incident', $trust), 'Unapproved Trust Center data must be discarded.');
expectCycle12(in_array('No claim of unhackable security', $trust['unsupported_claims'] ?? [], true), 'Trust Center must retain explicit unsupported-claim boundary.');

$source = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/GovernanceRepository.php');
expectCycle12(is_string($source) && ! str_contains($source, "add_action('spcrc/upsert"), 'Governance registry must not expose a generic write-through hook.');
expectCycle12(is_string($source) && str_contains($source, 'spcrc/verify_step_up_assurance'), 'Governance approval must require File 00 step-up assurance.');

echo "PASS: {$assertions} Cycle 12 fresh adversarial assertions\n";
