<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
$modules=new ModuleRegistry();$rp=new ReflectionProperty(ModuleRegistry::class,'manifests');$rp->setAccessible(true);$rp->setValue($modules,['cycle80'=>['module_key'=>'cycle80']]);
$states=new SecurityStateRegistry($modules,new AuditLogger());
cycleReviewAssert(!$states->request('cycle80','platform-read-only',['reason'=>'Critical containment']), 'Critical security-state request must require step-up.');
add_filter('spcrc/verify_step_up_assurance', static fn(): bool => true,10,5);
cycleReviewAssert($states->request('cycle80','platform-read-only',['reason'=>'Critical containment','step_up_reference'=>'file00:cycle80']), 'Critical request with verified step-up must persist.');

cycleReviewPass(80, 'security-state-request-step-up');
