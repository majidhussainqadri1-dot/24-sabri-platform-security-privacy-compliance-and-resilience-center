<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\ControlRepository;
use Sabri\Platform\Security\Storage\FindingRepository;
use Sabri\Platform\Security\Storage\IncidentRepository;
use Sabri\Platform\Security\Storage\RiskRepository;

function c194(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$audit = new AuditLogger();
$risk = (new RiskRepository($audit))->create([
    'title' => 'Cycle 194 risk owner integrity',
    'module_key' => 'file-24-security-center',
    'likelihood' => 2,
    'impact' => 3,
    'owner_user_id' => -7,
]);
c194(is_wp_error($risk) && $risk->get_error_code() === 'spcrc_risk_owner_invalid', 'Negative risk owner must not be converted into user 7.');

$finding = (new FindingRepository($audit))->create([
    'title' => 'Cycle 194 finding owner integrity',
    'module_key' => 'file-24-security-center',
    'severity' => 'medium',
    'owner_user_id' => '-7',
]);
c194(is_wp_error($finding) && $finding->get_error_code() === 'spcrc_finding_owner_invalid', 'Negative finding owner string must fail closed.');

$incident = (new IncidentRepository($audit))->create([
    'title' => 'Cycle 194 incident owner integrity',
    'severity' => 'sev3',
    'summary' => 'Public-safe summary.',
    'owner_user_id' => -7,
]);
c194(is_wp_error($incident) && $incident->get_error_code() === 'spcrc_incident_owner_invalid', 'Negative incident owner must not be re-attributed to another user.');

$control = (new ControlRepository($audit))->upsert([
    'control_key' => 'cycle194-control-owner',
    'title' => 'Cycle 194 control owner integrity',
    'framework' => 'File24',
    'status' => 'implemented',
    'owner_user_id' => '7users',
]);
c194(is_wp_error($control) && $control->get_error_code() === 'spcrc_control_owner_invalid', 'Malformed control owner must not be accepted through integer-prefix coercion.');

$valid = (new ControlRepository($audit))->upsert([
    'control_key' => 'cycle194-control-valid',
    'title' => 'Cycle 194 valid control',
    'framework' => 'File24',
    'status' => 'implemented',
    'owner_user_id' => 7,
]);
c194(is_string($valid), 'A valid positive control owner must remain supported after strict parsing.');

echo "PASS: cycle194 core risk/finding/incident/control owner-identity coercion defects fixed and retested\n";
