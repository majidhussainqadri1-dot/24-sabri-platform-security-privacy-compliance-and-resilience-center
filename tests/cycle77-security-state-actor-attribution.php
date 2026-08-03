<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
$modules = new ModuleRegistry();
$rp = new ReflectionProperty(ModuleRegistry::class, 'manifests'); $rp->setAccessible(true); $rp->setValue($modules, ['cycle77'=>['module_key'=>'cycle77']]);
$GLOBALS['current_user_id'] = 0; $GLOBALS['current_user_caps'] = [];
add_filter('spcrc/authorize_security_state_request', static fn(): bool => true, 10, 4);
add_filter('spcrc/resolve_service_actor', static fn(): bool => true, 10, 6);
$states = new SecurityStateRegistry($modules, new AuditLogger());
$ok = $states->request('cycle77','restricted-writes',['reason'=>'Automated containment','actor_user_id'=>42]);
cycleReviewAssert($ok, 'Authorized service request must persist.');
$record = end($GLOBALS['wp_options']['spcrc_security_state_requests']);
cycleReviewAssert(($record['requested_by'] ?? 0) === 42, 'Service actor must be attributable and positive.');

cycleReviewPass(77, 'security-state-actor-attribution');
