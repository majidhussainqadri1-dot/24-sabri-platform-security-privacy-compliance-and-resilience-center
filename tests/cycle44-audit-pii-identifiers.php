<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Support/Sanitizer.php';require_once dirname(__DIR__) . '/plugin/sabri-security-center/src/Storage/AuditLogger.php';
use Sabri\Platform\Security\Storage\AuditLogger;
$n=0;function c44(bool $v,string $m):void{global $n;++$n;if(!$v){fwrite(STDERR,"FAIL: $m\n");exit(1);}}
$GLOBALS['wp_uuid_override']='invalid-audit-id';$_SERVER['HTTP_X_CORRELATION_ID']='bad id with spaces';
$id=(new AuditLogger())->record('contact_risk_detected','file-24-security-center','recorded','high',['email'=>'person@example.com','phone_number'=>'+92 300 1234567','postal_address'=>'Street 1, Gujrat','nested'=>['guardian_contact'=>'guardian@example.com'],'ordinary'=>'safe']);
c44(is_string($id),'Audit event must survive malformed pluggable UUID output.');c44((bool)preg_match('/^[0-9a-f-]{36}$/',$id),'Audit event must receive a validated UUID.');$event=$GLOBALS['wpdb']->events[0]??[];$json=(string)($event['context_json']??'');c44(!str_contains($json,'person@example.com')&&!str_contains($json,'1234567')&&!str_contains($json,'Street 1'),'Direct contact data must not remain in audit JSON.');c44(substr_count($json,'sha256:')>=4,'Email, phone, address and guardian contact must be pseudonymized.');c44(str_contains($json,'safe'),'Non-sensitive bounded context must remain useful.');c44((bool)preg_match('/^[0-9a-f]{8}-/i',(string)($event['correlation_id']??'')),'Invalid incoming correlation ID must be replaced securely.');c44(count($GLOBALS['wpdb']->events)===1,'Audit event must persist exactly once.');c44(($event['risk_level']??'')==='high','Risk level must remain bounded.');
echo "PASS: $n Cycle 44 audit PII and identifier assertions\n";
