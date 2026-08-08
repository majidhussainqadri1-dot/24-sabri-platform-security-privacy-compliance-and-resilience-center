<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

use Sabri\Platform\Security\Support\Sanitizer;

final class AutomatedRemediationPolicy
{
    private const LOW_RISK_ALLOWLIST = ['revoke_expired_token','quarantine_suspicious_upload','purge_protected_cache','disable_expired_device'];

    /** @param array<string,mixed> $request
     *  @return array<string,mixed>
     */
    public function decide(array $request): array
    {
        $action = Sanitizer::key($request['action_type'] ?? '', 80);
        $risk = Sanitizer::key($request['risk_level'] ?? '', 20);
        $reversible = Sanitizer::boolean($request['reversible'] ?? false);
        $previewed = Sanitizer::boolean($request['previewed'] ?? false);
        $rollback = Sanitizer::opaqueReference($request['rollback_reference'] ?? '');
        $approvals = max(0, (int) ($request['human_approvals'] ?? 0));
        $stepUp = Sanitizer::boolean($request['step_up_verified'] ?? false);
        $reasons = [];
        if ($action === '' || ! in_array($risk, ['low','medium','high','critical'], true)) $reasons[] = 'invalid_action_or_risk';
        if (! $reversible || ! $previewed || $rollback === '') $reasons[] = 'reversibility_evidence_missing';

        if ($reasons === []) {
            if ($risk === 'low' && in_array($action, self::LOW_RISK_ALLOWLIST, true)) {
                return ['decision' => 'auto_recommend', 'execute_by' => 'native_owner', 'reasons' => [], 'rollback_reference' => $rollback];
            }
            if ($risk === 'medium' && $approvals >= 1 && $stepUp) {
                return ['decision' => 'approved_recommendation', 'execute_by' => 'native_owner', 'reasons' => [], 'rollback_reference' => $rollback];
            }
            if (in_array($risk, ['high','critical'], true) && $approvals >= 2 && $stepUp) {
                return ['decision' => 'dual_approved_recommendation', 'execute_by' => 'native_owner', 'reasons' => [], 'rollback_reference' => $rollback];
            }
            $reasons[] = 'human_approval_policy_not_satisfied';
        }

        return ['decision' => 'block', 'execute_by' => 'none', 'reasons' => $reasons, 'rollback_reference' => $rollback];
    }
}
