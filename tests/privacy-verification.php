<?php

declare(strict_types=1);

const ARRAY_A = 'ARRAY_A';
$GLOBALS['verification_confirmed'] = false;
$GLOBALS['current_user_id'] = 99;
$GLOBALS['users'] = [7 => true, 99 => true];

final class WP_Error
{
    public function __construct(private string $code, private string $message) {}
    public function get_error_code(): string { return $this->code; }
    public function get_error_message(): string { return $this->message; }
}

function sanitize_key(string $value): string { return substr(preg_replace('/[^a-z0-9_\-]/', '', strtolower($value)) ?? '', 0, 255); }
function sanitize_text_field(string $value): string { return trim(preg_replace('/[\r\n\t]+/', ' ', strip_tags($value)) ?? ''); }
function absint(mixed $value): int { return abs((int) $value); }
function current_time(string $type, bool $gmt = false): string { return gmdate('Y-m-d H:i:s'); }
function get_current_user_id(): int { return (int) $GLOBALS['current_user_id']; }
function current_user_can(string $capability): bool { return $capability === 'spcrc_manage_privacy_requests'; }
function get_userdata(int $userId): object|false { return ! empty($GLOBALS['users'][$userId]) ? (object) ['ID' => $userId] : false; }
function is_wp_error(mixed $value): bool { return $value instanceof WP_Error; }
function apply_filters(string $hook, mixed $value, mixed ...$args): mixed
{
    return $hook === 'spcrc/privacy_verification_confirmed'
        ? (bool) $GLOBALS['verification_confirmed']
        : $value;
}

final class VerificationWpdb
{
    public string $prefix = 'wp_';
    public array $privacy = [];

    public function prepare(string $query, mixed ...$args): array { return ['query' => $query, 'args' => $args]; }
    public function get_row(mixed $prepared, mixed $output = null): mixed
    {
        $uuid = is_array($prepared) ? (string) ($prepared['args'][0] ?? '') : '';
        return $this->privacy[$uuid] ?? null;
    }
    public function update(string $table, array $data, array $where, array $formats = [], array $whereFormats = []): int|false
    {
        $uuid = (string) ($where['request_uuid'] ?? '');
        if (! isset($this->privacy[$uuid])) return 0;
        if (isset($where['status']) && ($this->privacy[$uuid]['status'] ?? '') !== $where['status']) return 0;
        if (isset($where['lock_version']) && (int) ($this->privacy[$uuid]['lock_version'] ?? 0) !== (int) $where['lock_version']) return 0;
        $this->privacy[$uuid] = array_merge($this->privacy[$uuid], $data);
        return 1;
    }
}
$GLOBALS['wpdb'] = new VerificationWpdb();

$base = dirname(__DIR__) . '/plugin/sabri-security-center/src/';
require_once $base . 'Support/Sanitizer.php';
require_once $base . 'Privacy/PrivacyRequestPolicy.php';
require_once $base . 'Privacy/PrivacyVerificationStore.php';

use Sabri\Platform\Security\Privacy\PrivacyVerificationStore;

function expectVerification(bool $condition, string $message): void
{
    if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

function verificationRow(string $uuid, int $requester = 7): array
{
    return [
        'request_uuid' => $uuid,
        'requester_user_id' => $requester,
        'status' => 'dispatching',
        'lock_version' => 1,
        'verification_method' => '',
        'authority_basis' => '',
        'verification_reference' => '',
        'verified_by_user_id' => null,
        'verified_at' => null,
    ];
}

function evidence(string $method, string $reference, int $verifiedBy = 99): array
{
    return [
        'verification_method' => $method,
        'authority_basis' => 'self',
        'verification_reference' => $reference,
        'verified_by_user_id' => $verifiedBy,
        'verified_at' => gmdate('c'),
    ];
}

$store = new PrivacyVerificationStore();

$invalidUuid = '70000000-0000-4000-8000-000000000001';
$GLOBALS['wpdb']->privacy[$invalidUuid] = verificationRow($invalidUuid);
$invalid = $store->persist($invalidUuid, evidence('manual-document-review', 'John Smith 12345'));
expectVerification(is_wp_error($invalid) && $invalid->get_error_code() === 'spcrc_privacy_verification_evidence_invalid', 'Free-form personal text must not be accepted as an opaque verification reference.');
expectVerification(($GLOBALS['wpdb']->privacy[$invalidUuid]['verification_method'] ?? '') === '', 'Rejected verification evidence must not mutate the canonical row.');

$emailUuid = '70000000-0000-4000-8000-000000000002';
$GLOBALS['wpdb']->privacy[$emailUuid] = verificationRow($emailUuid);
$email = $store->persist($emailUuid, evidence('email-confirmed', 'case:email-001'));
expectVerification(is_wp_error($email) && $email->get_error_code() === 'spcrc_privacy_verification_proof_missing', 'Email-confirmed evidence must fail closed without a native confirmation adapter.');

$sessionUuid = '70000000-0000-4000-8000-000000000003';
$GLOBALS['wpdb']->privacy[$sessionUuid] = verificationRow($sessionUuid, 7);
$session = $store->persist($sessionUuid, evidence('authenticated-session', 'case:session-001', 99));
expectVerification(is_wp_error($session) && $session->get_error_code() === 'spcrc_privacy_verifier_forbidden', 'Authenticated-session evidence must belong to the same current subject and verifier.');

$manualUuid = '70000000-0000-4000-8000-000000000004';
$GLOBALS['wpdb']->privacy[$manualUuid] = verificationRow($manualUuid);
$manual = $store->persist($manualUuid, evidence('manual-document-review', 'case:manual-001'));
expectVerification($manual === true, 'Attested manual document review with an opaque reference must persist.');
expectVerification(($GLOBALS['wpdb']->privacy[$manualUuid]['verification_reference'] ?? '') === 'case:manual-001', 'Only the bounded opaque reference must be stored.');

$nativeUuid = '70000000-0000-4000-8000-000000000005';
$GLOBALS['wpdb']->privacy[$nativeUuid] = verificationRow($nativeUuid);
$GLOBALS['verification_confirmed'] = true;
$native = $store->persist($nativeUuid, evidence('email-confirmed', 'case:email-002'));
expectVerification($native === true, 'A native confirmation adapter may attest a non-manual verification method.');

$collision = $store->persist($manualUuid, evidence('manual-document-review', 'case:different-002'));
expectVerification(is_wp_error($collision) && $collision->get_error_code() === 'spcrc_privacy_verification_collision', 'Persisted verification evidence must be immutable and collision resistant.');

echo "PASS: opaque verification references and method-specific proof controls\n";
