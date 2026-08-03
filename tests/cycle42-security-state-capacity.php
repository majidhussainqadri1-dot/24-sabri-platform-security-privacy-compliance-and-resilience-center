<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Registry/ModuleRegistry.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Registry/SecurityStateRegistry.php';
use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
$n=0; function c42(bool $v,string $m):void{global $n;++$n;if(!$v){fwrite(STDERR,"FAIL: $m\n");exit(1);}}
$modules=new ModuleRegistry();
$rp=new ReflectionProperty($modules,'manifests');$rp->setAccessible(true);$rp->setValue($modules,['capacity-module'=>['module_key'=>'capacity-module']]);
$stored=[];for($i=1;$i<=100;$i++){ $id=sprintf('42000000-0000-4000-8000-%012d',$i);$stored[$id]=['request_id'=>$id,'module_key'=>'capacity-module','state'=>'elevated-monitoring','reason'=>'Existing bounded request '.$i,'requested_by'=>7,'requested_at'=>gmdate('c',time()-60),'expires_at'=>gmdate('c',time()+3600),'status'=>'open']; }
$GLOBALS['wp_options']['spcrc_security_state_requests']=$stored;
$registry=new SecurityStateRegistry($modules,new AuditLogger());
c42(count($registry->all())===100,'All unresolved requests must remain visible at capacity.');
c42(!$registry->request('capacity-module','restricted-writes',['reason'=>'New request must not evict unresolved evidence.']),'Capacity exhaustion must fail closed.');
c42(count(get_option('spcrc_security_state_requests',[]))===100,'Capacity failure must not evict the oldest unresolved request.');
c42(isset(get_option('spcrc_security_state_requests',[])['42000000-0000-4000-8000-000000000001']),'Oldest unresolved request must remain durable.');
$events=array_column($GLOBALS['wp_actions'],'0');
c42(in_array('spcrc/security_state_capacity_exhausted',$events,true),'Capacity exhaustion must emit an operational signal.');
c42(count($registry->all())===100,'Capacity failure must leave canonical state unchanged.');
echo "PASS: $n Cycle 42 security-state capacity assertions\n";
