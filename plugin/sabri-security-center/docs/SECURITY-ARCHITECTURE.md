# File 24 0.99.0 — Security Architecture

## Three planes

1. **Institutional governance:** policy, risk, exceptions, incidents, privacy and continuity decisions.
2. **WordPress control plane:** manifests, security states, events, registries, adapters, dashboards and orchestration.
3. **External infrastructure:** WAF, DNS, SMTP/SMS, remote logs, backup/object storage, scanners, TURN/SFU, AI/provider services and independent testing.

File 24 records bounded assurance metadata and never silently assumes that an external control exists. Unknown or unavailable evidence is not reported as secure.

## Native ownership

Files 00–25 retain canonical data/actions. File 24 consumes versioned contracts and emits assurance recommendations/evidence. File 20 renders security states; native modules enforce them. File 24 failure does not disable native restrictions.

## Trust boundaries

WordPress requests, REST/AJAX/webhooks, native module adapters, provider callbacks, uploads/private delivery, wp-admin, remote-evidence delivery and public Trust Center publication are separately authorized and fail closed.
