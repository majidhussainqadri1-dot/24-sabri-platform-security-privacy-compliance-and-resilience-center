#!/usr/bin/env python3
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]

def replace_once(path: str, old: str, new: str) -> None:
    p = ROOT / path
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one replacement target, found {count}: {old[:80]!r}")
    p.write_text(text.replace(old, new, 1))

# Privacy request identity parsing.
p = 'plugin/sabri-security-center/src/Privacy/PrivacyRequestPolicy.php'
replace_once(p, "$requesterUserId = absint($request['requester_user_id'] ?? 0);\n        if ($requesterUserId < 1 || ! get_userdata($requesterUserId)) {", "$requesterUserId = Sanitizer::strictInteger($request['requester_user_id'] ?? null, 1, PHP_INT_MAX);\n        if ($requesterUserId === null || ! get_userdata($requesterUserId)) {")
replace_once(p, "$assignedUserId = absint($request['assigned_user_id'] ?? get_current_user_id());\n        if ($assignedUserId < 1 || ! get_userdata($assignedUserId)) {", "$assignedUserId = Sanitizer::strictInteger($request['assigned_user_id'] ?? get_current_user_id(), 1, PHP_INT_MAX);\n        if ($assignedUserId === null || ! get_userdata($assignedUserId)) {")
replace_once(p, "if ($assignedUserId < 1 || ! get_userdata($assignedUserId)) {\n            return new \\WP_Error('spcrc_privacy_retry_assignee_invalid'", "if ($assignedUserId === null || ! get_userdata($assignedUserId)) {\n            return new \\WP_Error('spcrc_privacy_retry_assignee_invalid'")
replace_once(p, "$verifiedBy = absint($request['verified_by_user_id'] ?? 0);", "$verifiedBy = Sanitizer::strictInteger($request['verified_by_user_id'] ?? null, 1, PHP_INT_MAX);")
replace_once(p, "if ($verifiedBy < 1 || ! get_userdata($verifiedBy)) {\n            return new \\WP_Error('spcrc_privacy_verifier_invalid'", "if ($verifiedBy === null || ! get_userdata($verifiedBy)) {\n            return new \\WP_Error('spcrc_privacy_verifier_invalid'")

# Governed artifact completeness / version integrity.
p = 'plugin/sabri-security-center/src/Registry/GovernedArtifactRegistry.php'
replace_once(p, "if (++$listCount > 50) {\n                            break;\n                        }", "if (++$listCount > 50) {\n                            return new \\WP_Error('spcrc_artifact_payload_list_exceeded', 'Artifact payload list exceeds the bounded maximum and was not truncated.');\n                        }")
replace_once(p, "'deletion-ledger' => ['reconciled', 'failed', 'closed'],", "'deletion-ledger' => ['reconciled', 'closed'],")
replace_once(p, "'version' => max(1, absint($record['version'] ?? 1)),", "'version' => Sanitizer::strictInteger($record['version'] ?? null, 1, PHP_INT_MAX) ?? 0,")

# Module manifest completeness.
p = 'plugin/sabri-security-center/src/Registry/ModuleRegistry.php'
replace_once(p, "        $safe = [];\n        foreach (array_slice($routes, 0, 50) as $route) {", "        if (count($routes) > 50) {\n            return new \\WP_Error('spcrc_manifest_route_limit', 'Manifest route list exceeds the bounded maximum and was not truncated.');\n        }\n        $safe = [];\n        foreach ($routes as $route) {")
replace_once(p, "        $safe = [];\n        foreach (array_slice($values, 0, max(0, $maxItems)) as $value) {", "        if ($maxItems < 0 || count($values) > $maxItems) {\n            return new \\WP_Error('spcrc_manifest_list_limit', sprintf('Manifest field %s exceeds its bounded maximum and was not truncated.', $field));\n        }\n        $safe = [];\n        foreach ($values as $value) {")

# Security-state actor / TTL / persisted chronology integrity.
p = 'plugin/sabri-security-center/src/Registry/SecurityStateRegistry.php'
replace_once(p, "$serviceActor = absint($context['actor_user_id'] ?? 0);", "$serviceActor = Sanitizer::strictInteger($context['actor_user_id'] ?? null, 1, PHP_INT_MAX) ?? 0;")
replace_once(p, "            $ttl = (int) apply_filters('spcrc/security_state_default_ttl', HOUR_IN_SECONDS, $moduleKey, $state);\n            $expiresAt = gmdate('c', $now + max(300, min($ttl, self::MAX_TTL)));", "            $ttl = Sanitizer::strictInteger(\n                apply_filters('spcrc/security_state_default_ttl', HOUR_IN_SECONDS, $moduleKey, $state),\n                300,\n                self::MAX_TTL\n            );\n            if ($ttl === null) {\n                return false;\n            }\n            $expiresAt = gmdate('c', $now + $ttl);")
replace_once(p, "$requestedBy = absint($request['requested_by'] ?? 0);", "$requestedBy = Sanitizer::strictInteger($request['requested_by'] ?? null, 1, PHP_INT_MAX) ?? 0;")
replace_once(p, "$requestedBy = absint($request['requested_by'] ?? 0);", "$requestedBy = Sanitizer::strictInteger($request['requested_by'] ?? null, 1, PHP_INT_MAX) ?? 0;")
replace_once(p, "                || $requestedBy < 1\n            ) {", "                || $requestedBy < 1\n                || ($requestedTimestamp = strtotime($requestedAt)) === false\n                || ($expiresTimestamp = strtotime($expiresAt)) === false\n                || $requestedTimestamp > time() + 300\n                || $expiresTimestamp <= $requestedTimestamp\n                || $expiresTimestamp > time() + self::MAX_TTL\n            ) {")

# Assurance owner / review freshness / declared scope completeness.
p = 'plugin/sabri-security-center/src/Storage/AssuranceRepository.php'
replace_once(p, "$ownerUserId = absint($data['owner_user_id'] ?? get_current_user_id());\n        if ($ownerUserId < 1 || ! get_userdata($ownerUserId)) {", "$ownerUserId = Sanitizer::strictInteger($data['owner_user_id'] ?? get_current_user_id(), 1, PHP_INT_MAX);\n        if ($ownerUserId === null || ! get_userdata($ownerUserId)) {")
replace_once(p, "        if ($timeBoundDetermination && $nextReviewAt === null) {\n            return new \\WP_Error('spcrc_assurance_next_review_missing', 'Current compliance and vendor determinations require a future review date.');\n        }", "        if ($timeBoundDetermination && $nextReviewAt === null) {\n            return new \\WP_Error('spcrc_assurance_next_review_missing', 'Current compliance and vendor determinations require a future review date.');\n        }\n        if ($timeBoundDetermination && $nextReviewAt !== null && strtotime($nextReviewAt . ' UTC') <= time()) {\n            return new \\WP_Error('spcrc_assurance_next_review_expired', 'Current compliance and vendor determinations require an unexpired future review date.');\n        }")
replace_once(p, "        $dataClasses = Sanitizer::textList($data['data_classes'] ?? [], 20, 80);", "        $rawDataClasses = $data['data_classes'] ?? [];\n        if (! is_array($rawDataClasses) || count($rawDataClasses) > 20) {\n            return new \\WP_Error('spcrc_assurance_data_classes_invalid', 'Assurance data classes must be an explicit bounded list of at most 20 entries.');\n        }\n        $dataClasses = Sanitizer::textList($rawDataClasses, 20, 80);\n        if (count($dataClasses) !== count(array_unique($rawDataClasses, SORT_REGULAR))) {\n            return new \\WP_Error('spcrc_assurance_data_classes_invalid', 'Assurance data classes contain empty, malformed, duplicate or unsupported list values.');\n        }")
replace_once(p, "'owner_user_id' => absint($row['owner_user_id'] ?? 0),", "'owner_user_id' => Sanitizer::strictInteger($row['owner_user_id'] ?? null, 1, PHP_INT_MAX) ?? 0,")
replace_once(p, "'owner_user_id' => absint($record['owner_user_id'] ?? 0),", "'owner_user_id' => Sanitizer::strictInteger($record['owner_user_id'] ?? null, 1, PHP_INT_MAX) ?? 0,")

# Governance requester / explicit expiry / optimistic-lock integrity.
p = 'plugin/sabri-security-center/src/Storage/GovernanceRepository.php'
replace_once(p, "$requester = absint($data['requester_user_id'] ?? get_current_user_id());", "$requester = Sanitizer::strictInteger($data['requester_user_id'] ?? get_current_user_id(), 1, PHP_INT_MAX);")
replace_once(p, "if ($requester < 1 || $requester !== get_current_user_id() || ! get_userdata($requester)) {", "if ($requester === null || $requester !== get_current_user_id() || ! get_userdata($requester)) {")
replace_once(p, "        $requestedAt = current_time('mysql', true);\n        $expiry = Sanitizer::isoTime($data['expires_at'] ?? '');\n        $expiryTs = $expiry === '' ? time() + (7 * DAY_IN_SECONDS) : (int) strtotime($expiry);", "        $requestedAt = current_time('mysql', true);\n        $rawExpiry = is_scalar($data['expires_at'] ?? null) ? trim((string) ($data['expires_at'] ?? '')) : '';\n        $expiry = Sanitizer::isoTime($data['expires_at'] ?? '');\n        if ($rawExpiry !== '' && $expiry === '') {\n            return new \\WP_Error('spcrc_governance_expiry_invalid', 'Decision expiry must be an absolute ISO-8601 timestamp.');\n        }\n        $expiryTs = $rawExpiry === '' ? time() + (7 * DAY_IN_SECONDS) : (int) strtotime($expiry);")
replace_once(p, "        $expectedLock = absint($context['expected_lock_version'] ?? -1);\n        if ($expectedLock !== (int) ($row['lock_version'] ?? 0)) {", "        $expectedLock = Sanitizer::strictInteger($context['expected_lock_version'] ?? null, 0, PHP_INT_MAX);\n        if ($expectedLock === null) {\n            return new \\WP_Error('spcrc_governance_expected_lock_version_invalid', 'A non-negative whole expected lock version is required.');\n        }\n        if ($expectedLock !== (int) ($row['lock_version'] ?? 0)) {")

# Code-complete summary truth statement.
p = 'docs/CODE-COMPLETE-SUMMARY-0.99.0.md'
replace_once(p, "**Repository coding result:** 100% of the identified current governing File-24 coding scope plus the approved Future Security & Privacy Superset is represented and gated, with zero known unresolved repository defect after the latest ten fresh review/correction rounds (126–135). Later staging/live/operational statuses remain unclaimed until independently evidenced.", "**Repository coding result:** 100% of the identified current governing File-24 coding scope plus the approved Future Security & Privacy Superset is represented and gated, with zero known unresolved repository-correctable defect after the latest ten fresh review/correction rounds (185–194), the post-request Cycle 195 QA correction, and two clean closure reviews (196–197). Later staging/live/operational statuses remain unclaimed until independently evidenced.")

# CI ranges, floors, permanent review gates and snapshot identity.
p = '.github/workflows/ci.yml'
replace_once(p, 'test "$count" -ge 276', 'test "$count" -ge 289')
replace_once(p, 'test "$count" -ge 189', 'test "$count" -ge 202')
replace_once(p, 'for cycle in $(seq 116 184); do', 'for cycle in $(seq 116 197); do')
replace_once(p, '          test -f docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-168-177.md\n', '          test -f docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-168-177.md\n          test -f docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-185-194.md\n')
anchor = '          test -f tests/cycle184-second-clean-final-closure-review.php\n'
block = anchor + """          grep -Fq 'Defect-bearing requested cycles | **185, 186, 187, 188, 189, 190, 191, 192, 193, 194**' docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-185-194.md
          grep -Fq 'Additional post-request defect-bearing cycles | **195**' docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-185-194.md
          grep -Fq '**Consecutive clean final closing cycles: 196, 197.**' docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-185-194.md
          grep -Fq 'Known unresolved repository-correctable defects after fixes/retests | **0**' docs/REVIEW-AND-CORRECTION-FUTURE-SECURITY-CYCLES-185-194.md
          test -f tests/cycle185-rate-limit-persisted-state-integrity-review.php
          test -f tests/cycle186-privacy-verification-identity-freshness-review.php
          test -f tests/cycle187-external-adapter-exception-containment-review.php
          test -f tests/cycle188-security-state-strict-integrity-review.php
          test -f tests/cycle189-future-security-strict-numeric-contract-review.php
          test -f tests/cycle190-module-manifest-completeness-limit-review.php
          test -f tests/cycle191-governed-artifact-payload-version-integrity-review.php
          test -f tests/cycle192-governance-strict-request-version-expiry-review.php
          test -f tests/cycle193-assurance-owner-freshness-completeness-review.php
          test -f tests/cycle194-core-record-owner-integrity-review.php
          test -f tests/cycle195-php80-regression-compatibility-review.php
          test -f tests/cycle196-first-clean-post-fix-review.php
          test -f tests/cycle197-second-clean-final-closure-review.php
          grep -q 'spcrc_rate_limit_state_invalid' plugin/sabri-security-center/src/Security/RateLimiter.php
          grep -q 'spcrc_manifest_route_limit' plugin/sabri-security-center/src/Registry/ModuleRegistry.php
          grep -q 'spcrc_artifact_payload_list_exceeded' plugin/sabri-security-center/src/Registry/GovernedArtifactRegistry.php
          grep -q 'spcrc_governance_expected_lock_version_invalid' plugin/sabri-security-center/src/Storage/GovernanceRepository.php
          grep -q 'spcrc_assurance_next_review_expired' plugin/sabri-security-center/src/Storage/AssuranceRepository.php
"""
replace_once(p, anchor, block)
replace_once(p, '/tmp/file24-source-snapshot-cycle184.zip', '/tmp/file24-source-snapshot-cycle197.zip')
replace_once(p, '/tmp/file24-source-snapshot-cycle184.zip', '/tmp/file24-source-snapshot-cycle197.zip')
replace_once(p, 'file-24-sanitized-source-snapshot-cycle184', 'file-24-sanitized-source-snapshot-cycle197')
replace_once(p, '/tmp/file24-source-snapshot-cycle184.zip', '/tmp/file24-source-snapshot-cycle197.zip')

expected = {
    '.github/workflows/ci.yml': '9e1eec5c3509587d2228255700aa530e213d63d7493f2d8bd0e564548418de68',
    'docs/CODE-COMPLETE-SUMMARY-0.99.0.md': 'b78a024adc46c34ccd38488cacd3162d38139cab83a1c7515a9172ec8cd304b6',
    'plugin/sabri-security-center/src/Privacy/PrivacyRequestPolicy.php': '5bfb6125e16e453ba7e92cbf264a7dd72564a3fec699cdcf0cc0a2b4288909c4',
    'plugin/sabri-security-center/src/Registry/GovernedArtifactRegistry.php': '45a9594400282e8057c4525cf60ac8a9338d110175062e461cc95ca7a13bab61',
    'plugin/sabri-security-center/src/Registry/ModuleRegistry.php': 'c2f5a17d2a2349318c57067c1aecf83d3259836c1cf06ca8c1b90056c050ee63',
    'plugin/sabri-security-center/src/Registry/SecurityStateRegistry.php': 'e279ccccd3dd8865e2369bdf6eb0fc6abdb072640f9e5d786b4c2ba7c6d12b38',
    'plugin/sabri-security-center/src/Storage/AssuranceRepository.php': 'ae3378e84324a0ad3af9b400384536d8338cc00b19e2a9d774ff2b98cb83b739',
    'plugin/sabri-security-center/src/Storage/GovernanceRepository.php': '1a8990588f3e24d9d86f644ed0b0bd48210ad798bcdbac30a8c6d82492357f4c',
}
for path, digest in expected.items():
    actual = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    if actual != digest:
        raise SystemExit(f'{path}: final digest mismatch: {actual} != {digest}')

# Remove temporary bootstrap artifacts before the workflow commits the final source.
(ROOT / 'tools/apply-cycle185-194-final-patches.py').unlink(missing_ok=True)
(ROOT / '.github/workflows/cycle185-194-bootstrap.yml').unlink(missing_ok=True)
print('Cycle 185-194 remaining patches applied and exact expected digests verified.')
