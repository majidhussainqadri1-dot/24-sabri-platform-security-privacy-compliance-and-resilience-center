<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\AutomatedRemediationPolicy;
use Sabri\Platform\Security\Future\FutureSecurityAssurance;
use Sabri\Platform\Security\Future\FutureSecurityCapabilityCatalog;

function expectCycle125(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$policy = new AutomatedRemediationPolicy();
$forgedCount = $policy->decide([
    'action_type' => 'disable_account',
    'risk_level' => 'critical',
    'reversible' => true,
    'previewed' => true,
    'rollback_reference' => 'rollback:acct-125',
    'human_approvals' => 2,
    'human_approval_refs' => ['approval:user-1', 'approval:user-1'],
    'step_up_verified' => true,
]);
expectCycle125($forgedCount['decision'] === 'block' && in_array('approval_evidence_mismatch', $forgedCount['reasons'], true), 'A numeric dual-approval claim cannot substitute for two distinct human approval references.');

$dual = $policy->decide([
    'action_type' => 'disable_account',
    'risk_level' => 'critical',
    'reversible' => true,
    'previewed' => true,
    'rollback_reference' => 'rollback:acct-125',
    'human_approvals' => 2,
    'human_approval_refs' => ['approval:user-1', 'approval:user-2'],
    'step_up_verified' => true,
]);
expectCycle125($dual['decision'] === 'dual_approved_recommendation' && $dual['distinct_human_approval_count'] === 2, 'Critical remediation must require two distinct bounded approval references.');
expectCycle125($dual['execute_by'] === 'native_owner', 'Even dual-approved remediation must remain native-owner execution.');

expectCycle125(FutureSecurityCapabilityCatalog::count() === 25 && FutureSecurityCapabilityCatalog::repositoryCodingComplete(), 'Final future catalogue gate must remain 25/25.');
expectCycle125(FutureSecurityAssurance::supportedIds() === array_keys(FutureSecurityCapabilityCatalog::all()), 'Final assurance/catalogue IDs must remain in exact parity.');

echo "PASS: cycle125 remediation approval/release-gate defects fixed and retested\n";
