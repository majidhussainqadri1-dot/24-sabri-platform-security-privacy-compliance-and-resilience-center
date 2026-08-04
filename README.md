# File 24 — Sabri Platform Security, Privacy, Compliance and Resilience Center

File 24 is the cross-platform security-governance and assurance plane for the Sabri Social Homeopathy Platform. Native modules retain their own authentication, authorization, data, safety and business truth.

## Current release identity

- Runtime: **0.99.0 — Repository Code-Complete Candidate**
- Schema: **0.25.5**
- Production target: **1.0.0**, only after the full external Definition of Done
- Requirements: **F24-R001–F24-R100 repository-implemented**

This status means the approved repository-coding scope is implemented, reviewed, testable and packageable. It does **not** mean Hostinger staging acceptance, independent certification, penetration-test acceptance, restore-drill acceptance, live deployment or operational acceptance.

## Implemented repository scope

- module manifests, security states and Files 00–25 integration contracts;
- control, risk, finding, vulnerability, incident, governance and assurance registries;
- versioned policy hierarchy, exceptions and release gates;
- File 00 membership and File 02 credential-authentication assurance without alternate identity ownership;
- REST/AJAX/webhook authorization, same-origin/SSRF policy, rate limiting, idempotency and replay protection;
- upload quarantine/scanner contracts and short-lived one-time private-delivery grants;
- privacy requests, verification, recovery, data inventory, processing activities, consent, legal holds, international-transfer metadata and deletion replay;
- vendor/compliance/backup evidence, BIA, recovery objectives, continuity plans and drill findings;
- detection alerts, remote-evidence queue, performance measurements, incident command and evidence-gated Trust Center data;
- capability-protected wp-admin fallback, private REST APIs, security headers and truthful seven-status reporting;
- public-safe architecture, RTM, schema/threat/integration manifests, manuals, SBOM, license inventory, checksums and deterministic build tooling.

## Public/private boundary

This public repository must never contain production secrets, key inventory, detailed vulnerabilities, risk or incident evidence, vendor contracts, backup locations, private playbooks, patient records, messages, identity documents or production logs. Repository records use bounded metadata and opaque references to a separately protected operations store.

## Build and complete repository QA

```bash
find plugin tests -type f -name '*.php' -print0 | xargs -0 -n1 php -l
while IFS= read -r -d '' test_file; do
  php "$test_file"
done < <(find tests -maxdepth 1 -type f -name '*.php' ! -name 'bootstrap.php' -print0 | sort -z)
sha256sum -c CHECKSUMS.sha256
./tools/build-release.sh
```

The build creates an installable ZIP and SHA-256 receipt under `build/`.

## External gates deliberately deferred

Real Hostinger WordPress/MySQL activation and upgrade, live companion contracts, providers, backup restore, rollback rehearsal, browser/RTL/accessibility acceptance, independent penetration testing, legal applicability, Founder staging acceptance, production deployment and operational SLOs remain separate evidence-gated work.
