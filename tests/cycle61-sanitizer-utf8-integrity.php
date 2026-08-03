<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Support\Sanitizer;
cycleReviewAssert(Sanitizer::text("\xC3\x28", 20) === '', 'Invalid UTF-8 must be rejected.');
$value = Sanitizer::text('علاج محفوظ', 5);
cycleReviewAssert($value !== '', 'Valid Urdu UTF-8 must survive sanitization.');
cycleReviewAssert(preg_match('//u', $value) === 1, 'Truncation must not split a UTF-8 sequence.');

cycleReviewPass(61, 'sanitizer-utf8-integrity');
