<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Release\ReleaseGateManager;
use Sabri\Platform\Security\Storage\AuditLogger;

function v123ReviewProvenanceAssert(bool $ok, string $message): void
{
    if (! $ok) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$GLOBALS['current_user_caps'] = [
    'spcrc_manage_release_gates' => true,
    'spcrc_approve_governance_decision' => true,
];
add_filter('spcrc/verify_step_up_assurance', '__return_true', 10, 4);
add_filter('spcrc/release_blocking_p0_count', static fn (): int => 0, 10, 2);
add_filter('spcrc/release_blocking_defect_count', static fn (): int => 0, 10, 3);
add_filter('spcrc/release_external_acceptance_ready', '__return_true', 10, 3);
$registry = new GovernedArtifactRegistry(new AuditLogger());
$gates = new ReleaseGateManager($registry);
$gates->seed();

$context = [
    'step_up_reference' => 'assertion:v123-final-review-stepup',
    'approval_refs' => ['approval:v123-reviewer-alpha', 'approval:v123-reviewer-beta'],
];
$phases = ReleaseGateManager::phases();
foreach (array_slice($phases, 0, -1) as $index => $phase) {
    $early = $gates->decide($phase, 'passed', 1, 'evidence:v123-code-review-' . $index, [
        'Internal code phase fixture only',
    ], $context);
    v123ReviewProvenanceAssert(is_string($early), 'Source phase ' . $index . ' remains separately testable.');
}

$last = $phases[count($phases) - 1];
$final = static fn (): string|\WP_Error => $gates->decide(
    $last, 'passed', 1, 'evidence:v123-final-staging',
    ['Actual independent reviewer provenance must be externally verified'],
    $context
);

// Merely giving the plugin two arbitrary opaque strings is not proof that two
// independent people have approved a specific source package.
$missing = $final();
v123ReviewProvenanceAssert(
    is_wp_error($missing)
    && $missing->get_error_code() === 'spcrc_release_gate_review_verifier_missing',
    'Final phase must not accept two fabricated human-approval tokens with no verifier.'
);
v123ReviewProvenanceAssert(
    ($registry->get('release-gate', $last)['status'] ?? '') === 'pending',
    'Missing verifier cannot mutate final release gate.'
);

add_filter('spcrc/verify_independent_release_reviews', static fn (): bool => false, 10, 5);
$rejected = $final();
v123ReviewProvenanceAssert(
    is_wp_error($rejected)
    && $rejected->get_error_code() === 'spcrc_release_gate_independent_reviews_unverified',
    'Negative native-owner reviewer assertion must prevent final release.'
);
$GLOBALS['wp_filters']['spcrc/verify_independent_release_reviews'] = [];

$observed = [];
add_filter('spcrc/verify_independent_release_reviews', static function (
    bool $default, array $refs, string $phase, string $evidenceRef, int $actor
) use (&$observed): bool {
    $observed = compact('refs', 'phase', 'evidenceRef', 'actor');
    return count($refs) === 2
        && count(array_unique($refs)) === 2
        && $phase === '24l-independent-assurance-staging'
        && $evidenceRef === 'evidence:v123-final-staging'
        && $actor > 0;
}, 10, 5);
$passed = $final();
v123ReviewProvenanceAssert(is_string($passed), 'Explicit true external review provenance permits a final source fixture.');
v123ReviewProvenanceAssert(
    count($observed['refs'] ?? []) === 2,
    'Verifier receives both opaque references without public disclosure.'
);
v123ReviewProvenanceAssert(
    ($registry->get('release-gate', $last)['status'] ?? '') === 'passed',
    'Final gate reflects verified external approvals only in the test harness.'
);

echo "PASS: V12.3 final release requires authentic independent reviewer-provenance provider\n";
