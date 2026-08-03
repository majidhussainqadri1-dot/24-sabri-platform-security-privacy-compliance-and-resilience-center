<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Support\Sanitizer;
cycleReviewAssert(Sanitizer::containsSensitiveMaterial('eyJabcdefgh.abcdefghijk.abcdefghijk'), 'JWT-like material must be detected.');
cycleReviewAssert(Sanitizer::containsSensitiveMaterial('ghp_' . 'abcdefghijklmnopqrstuvwxyz1234'), 'GitHub-token-like material must be detected.');
cycleReviewAssert(Sanitizer::containsSensitiveMaterial('AKIA' . 'ABCDEFGHIJKLMNOP'), 'AWS access-key-like material must be detected.');
cycleReviewAssert(! Sanitizer::containsSensitiveMaterial('foundation review completed'), 'Ordinary evidence text must remain usable.');

cycleReviewPass(62, 'sanitizer-secret-shapes');
