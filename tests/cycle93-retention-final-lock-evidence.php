<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


$source=file_get_contents(dirname(__DIR__).'/plugin/sabri-security-center/src/Retention/RetentionManager.php');
cycleReviewAssert(is_string($source)&&str_contains($source,'retention_lock_lost_before_evidence'),'Retention must refresh ownership before final evidence and audit.');
cycleReviewAssert(is_string($source)&&substr_count($source,'refreshLock($lock)')>=4,'Retention must protect each destructive/evidence phase with lease refresh.');

cycleReviewPass(93, 'retention-final-lock-evidence');
