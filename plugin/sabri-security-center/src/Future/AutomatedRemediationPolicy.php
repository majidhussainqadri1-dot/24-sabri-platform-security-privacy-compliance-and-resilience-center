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
        $reportedApprovals = Sanitizer::strictInteger($request['human_approvals'] ?? 0, 0, 10);
        [$approvalRefs, $approvalEvidenceValid] = $this->approvalReferences($request['human_approval_refs'] ?? []);
        $approvals = count($approvalRefs);
        $stepUp = Sanitizer::boolean($request['step_up_verified'] ?? false);
        $reasons = [];

        if ($action === '' || ! in_array($risk, ['low','medium','high','critical'], true)) $reasons[] = 'invalid_action_or_risk';
        if (! $reversible || ! $previewed || $rollback === '') $reasons[] = 'reversibility_evidence_missing';
        if (! $approvalEvidenceValid) $reasons[] = 'approval_evidence_invalid';
        if ($reportedApprovals === null) $reasons[] = 'approval_count_invalid';
        elseif ($reportedApprovals !== $approvals) $reasons[] = 'approval_evidence_mismatch';

        if ($reasons === []) {
            if ($risk === 'low' && in_array($action, self::LOW_RISK_ALLOWLIST, true) && $approvals === 0) {
                return $this->result('auto_recommend', 'native_owner', [], $rollback, $approvals);
            }
            if ($risk === 'medium' && $approvals >= 1 && $stepUp) {
                return $this->result('approved_recommendation', 'native_owner', [], $rollback, $approvals);
            }
            if (in_array($risk, ['high','critical'], true) && $approvals >= 2 && $stepUp) {
                return $this->result('dual_approved_recommendation', 'native_owner', [], $rollback, $approvals);
            }
            $reasons[] = 'human_approval_policy_not_satisfied';
        }

        return $this->result('block', 'none', array_values(array_unique($reasons)), $rollback, $approvals);
    }

    /** @return array{0:string[],1:bool} */
    private function approvalReferences(mixed $value): array
    {
        if (! is_array($value) || count($value) > 10 || array_keys($value) !== range(0, count($value) - 1)) {
            return [[], false];
        }
        $refs = [];
        foreach ($value as $candidate) {
            $ref = Sanitizer::opaqueReference($candidate, 180);
            if ($ref === '' || isset($refs[$ref])) {
                return [array_keys($refs), false];
            }
            $refs[$ref] = true;
        }
        return [array_keys($refs), true];
    }

    /** @param string[] $reasons
     *  @return array<string,mixed>
     */
    private function result(string $decision, string $executeBy, array $reasons, string $rollback, int $approvals): array
    {
        return [
            'decision' => $decision,
            'execute_by' => $executeBy,
            'reasons' => $reasons,
            'rollback_reference' => $rollback,
            'distinct_human_approval_count' => $approvals,
        ];
    }
}
