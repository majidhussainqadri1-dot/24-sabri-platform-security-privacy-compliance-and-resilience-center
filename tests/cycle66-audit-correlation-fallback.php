<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


$source = file_get_contents(dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php');
cycleReviewAssert(is_string($source) && str_contains($source, 'return $eventUuid;'), 'Correlation entropy failure must bind to the unique event UUID.');
cycleReviewAssert(is_string($source) && str_contains($source, 'correlation_identifier_unavailable'), 'Correlation fallback must emit bounded operational evidence.');
cycleReviewAssert(! str_contains($source, "return 'correlation-unavailable';"), 'Shared fallback correlation identities must not be used.');

cycleReviewPass(66, 'audit-correlation-fallback');
