<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
use Sabri\Platform\Security\Security\NetworkPolicy;
function c135(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }
c135(NetworkPolicy::sameOriginUrl('https://example.test/security-center'), 'Normal home-origin HTTPS URL must pass.');
c135(NetworkPolicy::sameOriginUrl('https://example.test:443/security-center'), 'Explicit default HTTPS port must equal the home origin.');
c135(! NetworkPolicy::sameOriginUrl('https://example.test:4443/security-center'), 'Same host and scheme on a different port is a different origin and must fail.');
c135(! NetworkPolicy::sameOriginUrl('http://example.test/security-center'), 'HTTP must not be treated as the HTTPS home origin.');
c135(! NetworkPolicy::sameOriginUrl('https://user:pass@example.test/security-center'), 'Credential-bearing URL must fail same-origin safety.');
echo "PASS: cycle135 same-origin scheme/port defect fixed and retested\n";
