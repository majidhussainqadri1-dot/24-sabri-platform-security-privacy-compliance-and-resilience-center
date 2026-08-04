<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Security;

/** Conservative security and cache headers. Native owners may add stricter policy. */
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
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
        header('X-Frame-Options: SAMEORIGIN');
        if (is_admin() || is_user_logged_in()) {
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
}
