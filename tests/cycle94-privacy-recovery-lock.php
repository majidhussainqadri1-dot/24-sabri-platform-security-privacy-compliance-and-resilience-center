<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Privacy\RecoveryManager;
use Sabri\Platform\Security\Storage\AuditLogger;
use Sabri\Platform\Security\Storage\PrivacyRequestRepository;
$GLOBALS['wp_options']['spcrc_privacy_recovery_scan_lock']=['token'=>str_repeat('a',32),'expires_at'=>time()+200];
$manager=new RecoveryManager(new PrivacyRequestRepository(),new AuditLogger());
$manager->scan();
$event=end($GLOBALS['wpdb']->events);
cycleReviewAssert(($event['event_type']??'')==='privacy_recovery_scan_locked','Concurrent recovery scan must be audited as locked.');
cycleReviewAssert(($event['result']??'')==='locked','Recovery lock contention must not be reported as completion.');

cycleReviewPass(94, 'privacy-recovery-lock');
