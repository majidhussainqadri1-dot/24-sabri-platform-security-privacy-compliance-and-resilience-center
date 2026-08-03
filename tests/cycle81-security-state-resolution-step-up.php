<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
$modules=new ModuleRegistry();$rp=new ReflectionProperty(ModuleRegistry::class,'manifests');$rp->setAccessible(true);$rp->setValue($modules,['cycle81'=>['module_key'=>'cycle81']]);
add_filter('spcrc/verify_step_up_assurance', static fn(mixed $current,int $actor,string $purpose,string $reference): bool => str_contains($purpose,'request'),10,5);
$states=new SecurityStateRegistry($modules,new AuditLogger());
cycleReviewAssert($states->request('cycle81','incident-containment',['reason'=>'Critical incident','step_up_reference'=>'file00:request']), 'Critical state setup must persist.');
$id=(string)array_key_first($states->all());
cycleReviewAssert(!$states->resolve($id,'resolved'), 'Critical resolution must require a fresh independent step-up.');
add_filter('spcrc/verify_step_up_assurance', static fn(): bool => true,20,5);
cycleReviewAssert($states->resolve($id,'resolved',['step_up_reference'=>'file00:resolution']), 'Verified critical resolution must succeed.');

cycleReviewPass(81, 'security-state-resolution-step-up');
