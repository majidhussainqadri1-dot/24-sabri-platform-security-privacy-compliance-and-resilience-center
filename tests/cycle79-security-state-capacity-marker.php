<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
$states = new SecurityStateRegistry(new ModuleRegistry(), new AuditLogger());
$rp = new ReflectionProperty(SecurityStateRegistry::class, 'requests'); $rp->setAccessible(true);
$items=[]; for($i=0;$i<101;++$i){$id=sprintf('00000000-0000-4000-8000-%012d',$i+1);$items[$id]=['request_id'=>$id];}
$rp->setValue($states,$items);
$method=new ReflectionMethod(SecurityStateRegistry::class,'boundAndPersist');$method->setAccessible(true);
cycleReviewAssert($method->invoke($states) === false, 'Unresolved state capacity overflow must fail closed.');
$marker=get_option('spcrc_security_state_capacity_marker',[]);
cycleReviewAssert(($marker['unresolved_count']??0)===101,'Capacity overflow must persist durable count evidence.');

cycleReviewPass(79, 'security-state-capacity-marker');
