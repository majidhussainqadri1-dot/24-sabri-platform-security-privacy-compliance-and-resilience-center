<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Registry/ModuleRegistry.php';
require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Registry/SecurityStateRegistry.php';
use Sabri\Platform\Security\Registry\ModuleRegistry;use Sabri\Platform\Security\Registry\SecurityStateRegistry;use Sabri\Platform\Security\Storage\AuditLogger;
$n=0;function c43(bool $v,string $m):void{global $n;++$n;if(!$v){fwrite(STDERR,"FAIL: $m\n");exit(1);}}
$m=new ModuleRegistry();$p=new ReflectionProperty($m,'manifests');$p->setAccessible(true);$p->setValue($m,['safe-module'=>['module_key'=>'safe-module']]);
$GLOBALS['wp_options']['spcrc_security_state_requests']=[
 'bad-id'=>['request_id'=>'bad-id','module_key'=>'safe-module','state'=>'restricted-writes','reason'=>'Valid reason','requested_by'=>7,'requested_at'=>gmdate('c'),'expires_at'=>gmdate('c',time()+3600),'status'=>'open'],
 '43000000-0000-4000-8000-000000000001'=>['request_id'=>'43000000-0000-4000-8000-000000000001','module_key'=>'unknown','state'=>'restricted-writes','reason'=>'Valid reason','requested_by'=>7,'requested_at'=>gmdate('c'),'expires_at'=>gmdate('c',time()+3600),'status'=>'open'],
 '43000000-0000-4000-8000-000000000002'=>['request_id'=>'43000000-0000-4000-8000-000000000002','module_key'=>'safe-module','state'=>'restricted-writes','reason'=>'token=secret-value','requested_by'=>7,'requested_at'=>gmdate('c'),'expires_at'=>gmdate('c',time()+3600),'status'=>'open'],
];
$r=new SecurityStateRegistry($m,new AuditLogger());c43($r->all()===[],'Malformed, orphaned or sensitive persisted requests must be rejected.');c43(get_option('spcrc_security_state_requests',[])===[],'Normalization must durably remove invalid state records.');
$GLOBALS['wp_uuid_override']='attacker-controlled';
c43($r->request('safe-module','restricted-writes',['reason'=>'A valid bounded restriction request.']),'Malformed pluggable UUID output must fall back to secure UUID generation.');
$all=$r->all();$id=(string)array_key_first($all);c43((bool)preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',$id),'Security-state identity must be a validated UUIDv4.');c43(($all[$id]['reason']??'')==='A valid bounded restriction request.','Normalized request reason must remain bounded and intact.');c43(count($all)===1,'Only the newly authorized state request may remain.');
echo "PASS: $n Cycle 43 security-state normalization assertions\n";
