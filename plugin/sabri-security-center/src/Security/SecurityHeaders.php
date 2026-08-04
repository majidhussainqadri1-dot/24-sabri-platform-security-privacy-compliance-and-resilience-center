<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Security;

/**
 * Conservative baseline headers with File 24-private cache isolation.
 *
 * File 24 must not globally disable camera, microphone, geolocation or caching
 * needed by native owners such as Messages, Live Video and public content.
 */
final class SecurityHeaders
{
    public function registerHooks(): void
    {
        add_action('send_headers', [$this, 'send']);
        add_filter('rest_post_dispatch', [$this, 'restHeaders'], 20, 3);
    }

    public function send(): void
    {
        if (headers_sent()) {
            return;
        }

        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('X-Frame-Options: SAMEORIGIN');

        $permissionsPolicy = apply_filters('spcrc/security_headers/permissions_policy', '');
        if (is_string($permissionsPolicy)
            && $permissionsPolicy !== ''
            && strlen($permissionsPolicy) <= 1000
            && preg_match('/\A[a-zA-Z0-9_=(),* .";:\-]+\z/D', $permissionsPolicy) === 1
        ) {
            header('Permissions-Policy: ' . $permissionsPolicy);
        }

        if ($this->isFile24PrivateSurface()) {
            header('Cache-Control: private, no-store, max-age=0');
            header('X-Robots-Tag: noindex, noarchive');
        }
    }

    public function restHeaders(mixed $response, mixed $server, mixed $request): mixed
    {
        if (is_object($response) && method_exists($response, 'header')) {
            $response->header('X-Content-Type-Options', 'nosniff');
            $route = is_object($request) && method_exists($request, 'get_route') ? (string) $request->get_route() : '';
            if (str_starts_with($route, '/sabri-security/v1/') && $route !== '/sabri-security/v1/trust') {
                $response->header('Cache-Control', 'private, no-store, max-age=0');
                $response->header('X-Robots-Tag', 'noindex, noarchive');
            }
        }
        return $response;
    }

    private function isFile24PrivateSurface(): bool
    {
        if (! is_admin()) {
            return false;
        }

        $page = isset($_GET['page']) && is_scalar($_GET['page'])
            ? strtolower(preg_replace('/[^a-z0-9_-]/i', '', (string) $_GET['page']) ?? '')
            : '';

        return $page !== '' && (str_starts_with($page, 'spcrc') || str_starts_with($page, 'sabri-security'));
    }
}
