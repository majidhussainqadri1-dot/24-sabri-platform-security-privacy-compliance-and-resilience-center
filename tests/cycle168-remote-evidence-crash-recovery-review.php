<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Monitoring\RemoteEvidenceQueue;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;

function c168(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$artifacts = new GovernedArtifactRegistry();
$queue = new RemoteEvidenceQueue($artifacts);

$old = $artifacts->save([
    'artifact_type' => 'remote-evidence',
    'artifact_key' => 'cycle168-stale-delivery',
    'title' => 'Stale delivery recovery',
    'status' => 'delivering',
    'classification' => 'C5',
    'module_key' => 'file-24-security-center',
    'payload' => [
        'event_uuid' => '11111111-1111-4111-8111-111111111111',
        'event_type' => 'cycle168-event',
        'module_key' => 'file-24-security-center',
        'attempts' => 1,
        'delivery_started_at' => gmdate('c', time() - 900),
    ],
]);
c168(! is_wp_error($old), 'Stale in-flight record must seed.');

$fresh = $artifacts->save([
    'artifact_type' => 'remote-evidence',
    'artifact_key' => 'cycle168-fresh-delivery',
    'title' => 'Fresh delivery must stay in flight',
    'status' => 'delivering',
    'classification' => 'C5',
    'module_key' => 'file-24-security-center',
    'payload' => [
        'event_uuid' => '22222222-2222-4222-8222-222222222222',
        'event_type' => 'cycle168-event',
        'module_key' => 'file-24-security-center',
        'attempts' => 1,
        'delivery_started_at' => gmdate('c', time() - 60),
    ],
]);
c168(! is_wp_error($fresh), 'Fresh in-flight record must seed.');

add_filter('spcrc/remote_evidence_deliver', static function (array $default, array $payload): array {
    return [
        'status' => 'delivered',
        'evidence_ref' => 'evidence:cycle168-' . substr(hash('sha256', (string) ($payload['event_uuid'] ?? '')), 0, 24),
        'error_code' => '',
    ];
}, 10, 2);

$result = $queue->process(100);
c168(($result['delivered'] ?? 0) === 1, 'Exactly one stale delivering record must recover and deliver.');
c168(($result['processed'] ?? 0) === 1, 'Fresh in-flight record must not be treated as recoverable work.');

$staleAfter = $artifacts->get('remote-evidence', 'cycle168-stale-delivery');
$freshAfter = $artifacts->get('remote-evidence', 'cycle168-fresh-delivery');
c168(is_array($staleAfter) && ($staleAfter['status'] ?? '') === 'delivered', 'Stale delivering record must transition to delivered after recovery.');
c168(is_array($freshAfter) && ($freshAfter['status'] ?? '') === 'delivering', 'Fresh delivering record must remain in-flight.');

echo "PASS: cycle168 remote-evidence stale delivering crash recovery fixed and retested\n";
