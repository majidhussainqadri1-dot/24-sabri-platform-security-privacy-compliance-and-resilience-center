<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\ArtifactProvenanceVerifier;

function expectCycle123(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$verifier = new ArtifactProvenanceVerifier();
$valid = $verifier->verify([
    'source_commit' => str_repeat('a', 40),
    'artifact_sha256' => str_repeat('b', 64),
    'builder_identity' => 'builder:github-actions',
    'provenance_version' => 'slsa-v1.2',
    'signed_attestation' => true,
    'sbom_present' => true,
    'vex_status' => 'fixed',
]);
expectCycle123($valid['state'] === 'verified', 'Valid bounded provenance must verify.');

$unsigned = $verifier->verify([
    'source_commit' => str_repeat('a', 40),
    'artifact_sha256' => str_repeat('b', 64),
    'builder_identity' => 'builder:github-actions',
    'provenance_version' => 'slsa-v1.2',
    'signed_attestation' => false,
    'sbom_present' => true,
    'vex_status' => 'fixed',
]);
expectCycle123($unsigned['state'] === 'blocked' && in_array('signed_attestation', $unsigned['missing'], true), 'Unsigned provenance must remain blocked.');

$unsafeBuilder = $verifier->verify([
    'source_commit' => str_repeat('a', 40),
    'artifact_sha256' => str_repeat('b', 64),
    'builder_identity' => 'https://untrusted.example/build',
    'provenance_version' => 'slsa-v1.2',
    'signed_attestation' => true,
    'sbom_present' => true,
    'vex_status' => 'fixed',
]);
expectCycle123($unsafeBuilder['state'] === 'blocked' && in_array('builder_identity', $unsafeBuilder['missing'], true), 'Builder identity must remain an opaque non-URL reference.');

echo "PASS: cycle123 clean provenance/VEX review; no new repository defect found\n";
