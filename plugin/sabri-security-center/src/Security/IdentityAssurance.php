<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Security;

use Sabri\Platform\Security\Support\Sanitizer;

/**
 * Combines File 00 membership/identity assertions with File 02 authentication
 * assurance. It never creates an alternate identity or role truth.
 */
final class IdentityAssurance
{
    /** @param array<string,mixed> $context @return array<string,mixed>|\WP_Error */
    public function authorizeSensitiveAction(int $userId, string $purpose, array $context = []): array|\WP_Error
    {
        $purpose = Sanitizer::key($purpose, 100);
        if ($userId < 1 || $purpose === '') {
            return new \WP_Error('spcrc_identity_request_invalid', 'A valid user and bounded purpose are required.');
        }

        $identityAvailable = Sanitizer::boolean(apply_filters('spcrc/identity_authority_available', false));
        $authenticationAvailable = Sanitizer::boolean(apply_filters('spcrc/authentication_authority_available', false));
        if (! $identityAvailable || ! $authenticationAvailable) {
            return new \WP_Error('spcrc_identity_authority_unavailable', 'Identity or credential-authentication authority is unavailable; sensitive action is blocked.');
        }

        $membership = apply_filters('spcrc/membership_assertions', [], $userId, $purpose, $context);
        $membership = is_array($membership) ? $membership : [];
        if (
            ! Sanitizer::boolean($membership['approved'] ?? false)
            || Sanitizer::boolean($membership['suspended'] ?? false)
            || Sanitizer::key($membership['state'] ?? '', 40) === 'invalid-application'
        ) {
            return new \WP_Error('spcrc_membership_not_eligible', 'Current membership assertions do not permit this sensitive action.');
        }
        if (Sanitizer::boolean($membership['guardian_required'] ?? false)
            && ! Sanitizer::boolean($membership['guardian_verified'] ?? false)
        ) {
            return new \WP_Error('spcrc_guardian_assurance_missing', 'Verified guardian context is required for this action.');
        }

        $auth = apply_filters('spcrc/authentication_assurance', [], $userId, $purpose, $context);
        $auth = is_array($auth) ? $auth : [];
        if (! Sanitizer::boolean($auth['authenticated'] ?? false)) {
            return new \WP_Error('spcrc_authentication_missing', 'Authenticated session assurance is required.');
        }
        if (! Sanitizer::boolean($auth['recent_authentication'] ?? false)) {
            return new \WP_Error('spcrc_recent_authentication_missing', 'Recent authentication is required.');
        }

        $requiresMfa = Sanitizer::boolean($context['require_mfa'] ?? true);
        if ($requiresMfa && ! Sanitizer::boolean($auth['mfa_satisfied'] ?? false)) {
            return new \WP_Error('spcrc_mfa_assurance_missing', 'Current MFA assurance is insufficient.');
        }

        $reference = Sanitizer::opaqueReference($auth['assurance_ref'] ?? '');
        if ($reference === '') {
            return new \WP_Error('spcrc_authentication_evidence_missing', 'A bounded authentication-assurance reference is required.');
        }

        return [
            'authorized' => true,
            'user_id' => $userId,
            'purpose' => $purpose,
            'membership_state' => Sanitizer::key($membership['state'] ?? 'approved', 40),
            'authentication_assurance_ref' => $reference,
            'mfa_satisfied' => Sanitizer::boolean($auth['mfa_satisfied'] ?? false),
            'session_risk' => Sanitizer::key($auth['session_risk'] ?? 'unknown', 20),
        ];
    }
}
