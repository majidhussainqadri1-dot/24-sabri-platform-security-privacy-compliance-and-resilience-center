# File 24 0.99.0 — Review and Correction Round 1

## Review scope

Requirements traceability, canonical ownership, PHP 8.0 compatibility, registry persistence, audit semantics, plugin boot, scheduling, REST/admin surfaces, version/SBOM/docs and package closure.

## Defects found and corrected

- same-origin URL validation had been coupled to generic sensitive-material detection and could reject legitimate HTTPS URLs; URL validation was separated and normalized;
- governed artifact and incident mutations emitted arbitrary business states as audit results; audit results were normalized to accepted audit semantics;
- isolated activation tests could load without optional new scheduler classes; class guards preserve non-fatal test/runtime degradation;
- the test WordPress compatibility layer lacked REST, nonce, admin and error-data behaviors required by new controls; the harness was corrected;
- incident optimistic-concurrency predicates were absent in the fake database harness; stale updates now fail closed;
- release identity and supporting documents were harmonized to 0.99.0.

All corrections require complete regression retesting before release.
