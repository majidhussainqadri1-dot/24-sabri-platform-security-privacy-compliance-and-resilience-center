<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
$states=new SecurityStateRegistry(new ModuleRegistry(),new AuditLogger());
$merged=$states->merge(['forged'=>['request_id'=>'forged','module_key'=>'evil','state'=>'platform-read-only','reason'=>'x','requested_by'=>1,'requested_at'=>gmdate('c'),'expires_at'=>gmdate('c',time()+60),'status'=>'open']]);
cycleReviewAssert($merged===[], 'Malformed external security-state records must be discarded.');
cycleReviewAssert(! isset($merged['forged']), 'External filter data must not inject non-UUID authority state.');

cycleReviewPass(82, 'security-state-merge-boundary');
