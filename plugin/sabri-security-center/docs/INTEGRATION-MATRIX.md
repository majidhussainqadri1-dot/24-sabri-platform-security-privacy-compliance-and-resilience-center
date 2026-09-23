# File 24 0.99.0 — Files 00–26 Integration Matrix

File 24 is the canonical assurance/governance plane, not a duplicate native backend. The runtime matrix contains exactly 27 permanent numbered entries (00–26). Every returned matrix row carries a versioned fail-safe contract with: contract version, failure mode, degraded behavior, user message, alert owner, recovery owner and exit criteria.

| File | Native truth | File 24 assurance | Failure behavior |
|---:|---|---|---|
| 00 | membership, identity assurance, guardian, roles, suspension | identity, guardian, retention | privileged writes fail closed |
| 01 | product constitution, owner registry, runtime-safe bootstrap | source hierarchy, contract registry, environment evidence | changes remain blocked |
| 02 | credentials, OAuth, recovery, session-entry UX | authentication, session, recovery-abuse assurance | privileged writes fail closed |
| 03 | profile master fields and visibility | leakage, cache, index assurance | profile assurance unknown |
| 04 | legacy publishing data pending controlled cutover | duplicate-owner and migration assurance | legacy writes disabled |
| 05 | lessons, curriculum, progress | minor, entitlement, assessment integrity | education assurance unavailable |
| 06 | knowledge/disease entries, sources, corrections | source integrity and correction assurance | knowledge assurance unavailable |
| 07 | verified doctor discovery | impersonation, scraping, contact and ranking-fairness assurance | directory assurance unavailable |
| 08 | clinic and appointment truth | clinical privacy, emergency and access assurance | clinical actions gated |
| 09 | professional evidence and reviewer decisions | private evidence, separation and expiry assurance | verification actions gated |
| 10 | recorded/live media, stream keys, replay | upload, rights, live-key and provider assurance | live/high-risk actions gated |
| 11 | reel entity, discovery, watch history | duration, abuse and patient-privacy assurance | reels assurance unavailable |
| 12 | restricted PDF objects, reader access, eligibility | private delivery, entitlement, download and purge assurance | restricted delivery gated |
| 13 | historical Welcome compatibility only | duplicate-owner detection, safe suppression, migration assurance | legacy intro remains disabled |
| 14 | approved clinic value proposition | claim substantiation and privacy-safe analytics | claim status unknown |
| 15 | Radar research rubric, saved studies, trends | no-diagnosis, provenance and private-study assurance | private/clinical-like actions gated |
| 16 | source-linked educational AI / institutional AI Teacher | identity, disclosure, corpus ACL, citation, prompt-injection, budget/provider assurance | AI generation/publication gated |
| 17 | relationships, messages, media, calls and transfer orchestration | identity, IDOR, one-GiB transfer, storage, TURN/SFU and retention assurance | private communication/transfers gated |
| 18 | listings, offers/deals, disputes | fraud, prohibited goods, zero-commission and contact assurance | transactions/contact gated |
| 19 | notification center and delivery adapters | spoofing, sensitive preview and provider-retry assurance | delivery degraded |
| 20 | global shell, routes, Safe Mode, Welcome invocation/frequency | state rendering, 30-day suppression and reversible repair | wp-admin fallback; Welcome never blocks site |
| 21 | social/news publishing and corrections | publishing, source/retraction and cache assurance | publishing gated |
| 22 | create/draft/upload/submit orchestration | authorization, privacy scan and idempotency assurance | create/submit gated |
| 23 | private publishing operations | role, delegation, adapter and export assurance | write actions gated |
| 24 | governance and assurance | canonical assurance owner | native controls continue |
| 25 | public profiles, timelines, visual presentation, Welcome visual/RTL/accessibility | leakage, cache, trust and visual assurance | safe presentation fallback |
| 26 | federated search, derivative indexes, ranking, recommendations, taxonomy and owner-sourced KG projections | leakage, deletion reconciliation, fairness, consent and experiment assurance | ranking/recommendation experiments and privileged discovery writes gated |

## Conditional integrations

CF-01 through CF-04 remain planning/conditional identifiers, not permanent numbered files. In addition, Traffic Analytics and Disease Intelligence remain separately governed conditional plans. File 24 may encode assurance contracts for these plans but must not claim activation or native ownership. See `CONDITIONAL-INTEGRATION-CONTRACTS.md`.
