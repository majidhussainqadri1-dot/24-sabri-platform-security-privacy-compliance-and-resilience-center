<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Policy\AIHomeopathyTeacherAssurance;

function c130(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$now = strtotime('2026-08-08T10:00:00Z');
$controls = ['institutional_ai_identity','visible_ai_disclosure','corpus_allowlist','retrieval_acl','source_citations','prompt_injection_defense','medical_review','shariah_review','budget_cap','provider_failure_fallback','deletion_propagation','file26_classification_contract'];
$base = ['controls'=>$controls,'identity_type'=>'institutional-ai','human_review_enabled'=>true,'daily_post_cap'=>4,'evidence_ref'=>'evidence:ai-130'];
$future = AIHomeopathyTeacherAssurance::evaluate($base + ['launch_at'=>'2099-01-01T00:00:00Z','tested_at'=>gmdate('c',$now)], $now);
c130(empty($future['publication_allowed']) && empty($future['launch_valid']), 'Future launch date must not authorize current AI publication.');
$stale = AIHomeopathyTeacherAssurance::evaluate($base + ['launch_at'=>'2026-08-01T00:00:00Z','tested_at'=>'2020-01-01T00:00:00Z'], $now);
c130(empty($stale['publication_allowed']) && empty($stale['evidence_fresh']), 'Stale AI safety evidence must not authorize publication.');
$fresh = AIHomeopathyTeacherAssurance::evaluate($base + ['launch_at'=>'2026-08-01T00:00:00Z','tested_at'=>gmdate('c',$now-DAY_IN_SECONDS)], $now);
c130(($fresh['state'] ?? '') === 'verified' && ! empty($fresh['publication_allowed']), 'Fresh bounded AI launch with initial human review must verify.');

echo "PASS: cycle130 AI launch/evidence freshness defects fixed and retested\n";
