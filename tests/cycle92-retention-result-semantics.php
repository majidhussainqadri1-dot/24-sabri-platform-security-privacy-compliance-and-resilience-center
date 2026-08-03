<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Retention\RetentionManager;
use Sabri\Platform\Security\Storage\AuditLogger;
$manager=new RetentionManager(new AuditLogger());
$m=new ReflectionMethod(RetentionManager::class,'finish');$m->setAccessible(true);
$result=$m->invoke($manager,'arbitrary',-1,-2,'Unsafe Error Code!');
cycleReviewAssert(($result['status']??'')==='failed','Unknown retention status must normalize to failed.');
cycleReviewAssert(($result['age_deleted']??-1)===0&&($result['overflow_deleted']??-1)===0,'Retention counts must never become negative.');
cycleReviewAssert(($result['error_code']??'')==='unsafeerrorcode','Retention error codes must use bounded canonical keys.');

cycleReviewPass(92, 'retention-result-semantics');
