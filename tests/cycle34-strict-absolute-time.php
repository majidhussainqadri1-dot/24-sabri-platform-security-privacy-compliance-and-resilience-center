<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';

use Sabri\Platform\Security\Support\Sanitizer;

$assertions = 0;
function expectCycle34(bool $condition, string $message): void
{
    global $assertions;
    ++$assertions;
    if (! $condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

expectCycle34(Sanitizer::isoTime('tomorrow') === '', 'Relative timestamps must be rejected.');
expectCycle34(Sanitizer::isoTime('next Thursday') === '', 'Natural-language timestamps must be rejected.');
expectCycle34(Sanitizer::isoTime('2026-02-30') === '', 'Calendar-invalid dates must not be normalized silently.');
expectCycle34(Sanitizer::isoTime('2026-13-01 00:00:00') === '', 'Invalid months must be rejected.');
expectCycle34(Sanitizer::isoTime('2026-08-03') === '2026-08-03T00:00:00+00:00', 'Date-only input must normalize to UTC midnight.');
expectCycle34(Sanitizer::isoTime('2026-08-03 11:22:33') === '2026-08-03T11:22:33+00:00', 'MySQL UTC timestamp must normalize exactly.');
expectCycle34(Sanitizer::isoTime('2026-08-03T16:22:33+05:00') === '2026-08-03T11:22:33+00:00', 'RFC 3339 offset input must normalize to UTC.');
expectCycle34(Sanitizer::isoTime('2026-08-03T11:22:33Z') === '2026-08-03T11:22:33+00:00', 'Zulu input must normalize to UTC.');
expectCycle34(Sanitizer::isoTime('2026-08-03T11:22+00:00') === '2026-08-03T11:22:00+00:00', 'Minute-precision absolute input must remain supported.');
expectCycle34(Sanitizer::isoTime('2026-08-03T11:22:33.12+00:00') === '2026-08-03T11:22:33+00:00', 'Bounded fractional seconds must parse without changing the second.');

printf("PASS: %d Cycle 34 strict absolute-time assertions\n", $assertions);
