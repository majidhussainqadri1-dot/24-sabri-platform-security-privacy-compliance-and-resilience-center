<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Rest;

use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\System\SystemCheck;

final class StatusController
{
    private const NAMESPACE = 'sabri-security/v1';
    private const MAX_EVIDENCE_AGE = 15552000; // 180 days.

    public function __construct(
        private ModuleRegistry $modules,
        private SecurityStateRegistry $states,
        private SystemCheck $checks
    ) {
    }

    public function registerHooks(): void
    {
        add_action('rest_api_init', [$this, 'registerRoutes']);
    }

    public function registerRoutes(): void
    {
        register_rest_route(self::NAMESPACE, '/status', [
            'methods' => 'GET',
            'callback' => [$this, 'status'],
            'permission_callback' => static fn (): bool => current_user_can('spcrc_view_overview'),
        ]);

        register_rest_route(self::NAMESPACE, '/trust', [
            'methods' => 'GET',
            'callback' => [$this, 'trust'],
            'permission_callback' => '__return_true',
        ]);
    }

    public function status(): \WP_REST_Response
    {
        $response = new \WP_REST_Response([
            'version' => SPCRC_VERSION,
            'environment' => wp_get_environment_type(),
            'modules' => array_values($this->modules->all()),
            'security_state_requests' => array_values($this->states->all()),
            'checks' => $this->checks->run(),
            'generated_at' => gmdate('c'),
        ]);
        $response->header('Cache-Control', 'private, no-store, max-age=0');
        $response->header('Pragma', 'no-cache');
        $response->header('X-Robots-Tag', 'noindex, nofollow, noarchive');
        return $response;
    }

    public function trust(): \WP_REST_Response
    {
        $canonicalClaims = [
            'No claim of unhackable security',
            'No claim of certification without independent evidence',
            'No claim of end-to-end encryption without audited implementation',
        ];

        // Availability is verified before the extension filter and cannot be elevated by it.
        $privacyAvailable = $this->availabilityVerified(
            apply_filters('spcrc/privacy_request_intake_available', [])
        );
        $disclosureAvailable = $this->availabilityVerified(
            apply_filters('spcrc/responsible_disclosure_channel_available', [])
        );

        $payload = [
            'platform' => 'Sabri Social Homeopathy Platform',
            'security_program' => 'Foundation under active development',
            'privacy_request_available' => $privacyAvailable,
            'responsible_disclosure_available' => $disclosureAvailable,
            'privacy_url' => '',
            'security_contact_url' => '',
            'policy_version' => '',
            'last_reviewed_at' => '',
            'unsupported_claims' => $canonicalClaims,
            'generated_at' => gmdate('c'),
        ];

        $filtered = apply_filters('spcrc/public_trust_payload', $payload);
        if (! is_array($filtered)) {
            $filtered = [];
        }

        $claims = $canonicalClaims;
        foreach ((array) ($filtered['unsupported_claims'] ?? []) as $claim) {
            if (! is_scalar($claim)) {
                continue;
            }
            $clean = $this->truncate(sanitize_text_field((string) $claim), 240);
            if ($clean !== '') {
                $claims[] = $clean;
            }
        }
        $claims = array_slice(array_values(array_unique($claims)), 0, 10);

        // Canonical identity, program status, verified booleans and timestamp cannot be overridden.
        $sanitized = [
            'platform' => $payload['platform'],
            'security_program' => $payload['security_program'],
            'privacy_request_available' => $privacyAvailable,
            'responsible_disclosure_available' => $disclosureAvailable,
            'privacy_url' => esc_url_raw((string) ($filtered['privacy_url'] ?? '')),
            'security_contact_url' => esc_url_raw((string) ($filtered['security_contact_url'] ?? '')),
            'policy_version' => $this->truncate(sanitize_text_field((string) ($filtered['policy_version'] ?? '')), 80),
            'last_reviewed_at' => $this->validPublicDate((string) ($filtered['last_reviewed_at'] ?? '')),
            'unsupported_claims' => $claims,
            'generated_at' => gmdate('c'),
        ];

        $response = new \WP_REST_Response($sanitized);
        $response->header('Cache-Control', 'public, max-age=300');
        $response->header('X-Content-Type-Options', 'nosniff');
        return $response;
    }

    private function availabilityVerified($evidence): bool
    {
        if (! is_array($evidence) || ! (bool) ($evidence['available'] ?? false)) {
            return false;
        }

        $testedAt = strtotime((string) ($evidence['tested_at'] ?? ''));
        if ($testedAt === false) {
            return false;
        }

        $maximumAge = (int) apply_filters('spcrc/public_trust_evidence_max_age', self::MAX_EVIDENCE_AGE);
        $maximumAge = max(DAY_IN_SECONDS, min(YEAR_IN_SECONDS, $maximumAge));
        $now = time();

        return $testedAt <= ($now + 300) && $testedAt >= ($now - $maximumAge);
    }

    private function validPublicDate(string $value): string
    {
        $timestamp = strtotime($value);
        if ($timestamp === false || $timestamp > (time() + 300)) {
            return '';
        }

        return gmdate('c', $timestamp);
    }

    private function truncate(string $value, int $length): string
    {
        return function_exists('mb_substr') ? mb_substr($value, 0, $length) : substr($value, 0, $length);
    }
}
