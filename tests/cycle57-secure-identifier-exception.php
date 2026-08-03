<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Support\SecureIdentifier;
$GLOBALS['wp_uuid_throw'] = true;
$id = SecureIdentifier::uuid4('cycle57');
unset($GLOBALS['wp_uuid_throw']);
cycleReviewAssert(is_string($id), 'WordPress UUID exceptions must fall back to cryptographic random bytes.');
cycleReviewAssert(preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', (string) $id) === 1, 'Fallback identifier must remain UUIDv4.');
$source = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/SecureIdentifier.php');
cycleReviewAssert(is_string($source) && str_contains($source, 'wordpress_uuid_generation_failed'), 'UUID provider exception must emit bounded failure evidence.');

cycleReviewPass(57, 'secure-identifier-exception');
