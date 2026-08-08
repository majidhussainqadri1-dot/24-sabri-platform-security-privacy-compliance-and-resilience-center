<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

use Sabri\Platform\Security\Support\Sanitizer;

final class ArtifactProvenanceVerifier
{
    /** @param array<string,mixed> $attestation
     *  @return array<string,mixed>
     */
    public function verify(array $attestation): array
    {
        $source = strtolower(trim((string) ($attestation['source_commit'] ?? '')));
        $artifact = strtolower(trim((string) ($attestation['artifact_sha256'] ?? '')));
        $builder = Sanitizer::opaqueReference($attestation['builder_identity'] ?? '');
        $provenance = Sanitizer::text($attestation['provenance_version'] ?? '', 40);
        $vexStatus = Sanitizer::key($attestation['vex_status'] ?? '', 40);
        $missing = [];
        if (preg_match('/^[0-9a-f]{40}$/', $source) !== 1) $missing[] = 'source_commit';
        if (preg_match('/^[0-9a-f]{64}$/', $artifact) !== 1) $missing[] = 'artifact_sha256';
        if ($builder === '') $missing[] = 'builder_identity';
        if ($provenance === '') $missing[] = 'provenance_version';
        if (! Sanitizer::boolean($attestation['signed_attestation'] ?? false)) $missing[] = 'signed_attestation';
        if (! Sanitizer::boolean($attestation['sbom_present'] ?? false)) $missing[] = 'sbom_present';
        if (! in_array($vexStatus, ['affected','not_affected','fixed','under_investigation'], true)) $missing[] = 'vex_status';
        return ['state' => $missing === [] ? 'verified' : 'blocked', 'missing' => $missing, 'source_commit' => $source, 'artifact_sha256' => $artifact, 'builder_identity' => $builder];
    }
}
