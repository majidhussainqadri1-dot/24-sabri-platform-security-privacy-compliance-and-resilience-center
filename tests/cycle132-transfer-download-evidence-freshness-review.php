<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
use Sabri\Platform\Security\Security\TransferDownloadAssurance;
function c132(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }
$now = strtotime('2026-08-08T10:00:00Z');
$transfer = ['verified_sender','authorized_recipient','sender_recipient_binding','purpose_binding','relationship_recheck','consent_recheck','multipart_or_chunked','pause_resume','interruption_recovery','checksum','mime_magic_validation','malware_scan','archive_bomb_scan','polyglot_scan','private_storage','short_lived_delivery_grant','expiry','revocation','audit'];
$stale = TransferDownloadAssurance::evaluateTransfer(['controls'=>$transfer,'max_bytes_per_file'=>1073741824,'evidence_ref'=>'evidence:transfer-old','tested_at'=>'2020-01-01T00:00:00Z'], $now);
c132(empty($stale['transfer_allowed']) && empty($stale['evidence_fresh']), 'Stale transfer security evidence must fail closed.');
$download = ['native_owner_eligibility','queue','progress','pause_resume','retry','checksum','range_requests','weak_connection_recovery','click_time_authorization','history','audit','expiry','revocation'];
$future = TransferDownloadAssurance::evaluateDownload(['controls'=>$download,'evidence_ref'=>'evidence:download-future','tested_at'=>'2099-01-01T00:00:00Z'], $now);
c132(empty($future['download_allowed']) && empty($future['evidence_fresh']), 'Future-dated download evidence must fail closed.');
$fresh = TransferDownloadAssurance::evaluateTransfer(['controls'=>$transfer,'max_bytes_per_file'=>1073741824,'evidence_ref'=>'evidence:transfer-fresh','tested_at'=>gmdate('c',$now-DAY_IN_SECONDS)], $now);
c132(($fresh['state'] ?? '') === 'verified' && ! empty($fresh['evidence_fresh']), 'Fresh complete transfer assurance must still verify.');
echo "PASS: cycle132 transfer/download evidence-freshness defects fixed and retested\n";
