# File 24 0.99.0 — Files 00–25 Integration Matrix

File 24 is the canonical assurance owner, not a duplicate native backend. Each integration must provide a versioned manifest, evidence source and degraded behavior.

| File | Native truth | File 24 assurance | Failure behavior |
|---:|---|---|---|
| 0 — Sabri Membership Core | membership, identity assurance, guardian, roles and suspension | identity, guardian and retention assurance | privileged writes fail closed |
| 1 — Platform Foundation and Master Governance | product constitution, owner registry and runtime-safe bootstrap | source hierarchy, contract registry and environment evidence | changes remain blocked |
| 2 — Authentication and Accounts | credentials, OAuth, recovery and session-entry UX | authentication, session and recovery abuse assurance | privileged writes fail closed |
| 3 — Profiles and Doctors | profile master fields and visibility | field leakage, cache and index assurance | profile assurance unknown |
| 4 — Legacy News Feed | legacy publishing data pending controlled cutover | duplicate owner and migration assurance | legacy write disabled |
| 5 — Learn | lessons, curriculum and progress | minor, entitlement and assessment integrity | education assurance unavailable |
| 6 — Encyclopedia | knowledge entries, sources and corrections | source integrity and correction assurance | knowledge assurance unavailable |
| 7 — Doctors Directory | verified doctor discovery | impersonation, scraping and contact safety | directory assurance unavailable |
| 8 — Worldwide Clinic and Appointments | clinic and appointment truth | clinical privacy, emergency and access assurance | clinical actions gated |
| 9 — Doctor Onboarding and Verification | professional evidence and reviewer decisions | private evidence, reviewer separation and expiry assurance | verification actions gated |
| 10 — Video Wall and Live Broadcasting | recorded/live media, stream keys and replay | upload, rights, live-key and provider assurance | live/high-risk actions gated |
| 11 — Reels | reel entity, discovery and watch history | duration, abuse and patient privacy assurance | reels assurance unavailable |
| 12 — PDF Library | restricted PDF objects and reader access | private delivery, entitlement and purge assurance | restricted delivery gated |
| 13 — Welcome Intro | session-aware accessible intro | privacy, accessibility and route-suppression assurance | intro assurance unavailable |
| 14 — Global Clinic USP | approved clinic value proposition | claim substantiation and privacy-safe analytics | claim status unknown |
| 15 — Radar and Trends | research rubric, saved studies and trends | no-diagnosis, provenance and private study assurance | private/clinical-like actions gated |
| 16 — Sabri Classical Homeopathy AI | source-linked educational AI | corpus ACL, citation, prompt-injection and provider assurance | AI actions gated |
| 17 — Communication Network | relationships, messages, media and calls | identity, IDOR, storage, TURN/SFU and retention assurance | private communications gated |
| 18 — Marketplace | listings, offers/deals and disputes | fraud, prohibited goods, zero commission and contact assurance | transactions/contact gated |
| 19 — Unified Notifications | notification center and delivery adapters | spoofing, sensitive preview and provider retry assurance | delivery degraded |
| 20 — Unified Application Shell | global shell, routes and Safe Mode presentation | security-state rendering and reversible repair | File 24 admin falls back to wp-admin |
| 21 — Home and News Feed | social/news publishing and corrections | publishing, source/retraction and cache assurance | publishing actions gated |
| 22 — Universal Post Composer | create/draft/upload/submit orchestration | authorization, privacy scan and idempotency assurance | create/submit gated |
| 23 — Publishing Dashboard | private publishing operations | role, delegation, adapter and export assurance | write actions gated |
| 24 — Security, Privacy, Compliance and Resilience Center | governance and assurance | canonical assurance owner | native controls continue |
| 25 — Public UI, Profile Timeline and Visual Experience | public profiles, timelines and visual presentation | public leakage, cache, trust and accessibility assurance | public presentation uses safe fallback |
