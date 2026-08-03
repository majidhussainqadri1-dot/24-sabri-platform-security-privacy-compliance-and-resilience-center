<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Registry\ModuleRegistry;
use Sabri\Platform\Security\Registry\SecurityStateRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\AuditGapStore;
$GLOBALS['wp_options']['spcrc_security_state_requests'] = ['bad'=>['request_id'=>'bad','module_key'=>'x','state'=>'evil']];
$modules = new ModuleRegistry();
new SecurityStateRegistry($modules, new AuditLogger());
$marker = get_option('spcrc_security_state_tamper_marker', []);
cycleReviewAssert(($marker['rejected_records'] ?? 0) >= 1, 'Rejected persisted state must create durable tamper evidence.');
cycleReviewAssert(AuditGapStore::count('spcrc_security_state_audit_gap') >= 1, 'Normalization rejection must create a release-blocking gap.');

cycleReviewPass(78, 'security-state-tamper-evidence');
