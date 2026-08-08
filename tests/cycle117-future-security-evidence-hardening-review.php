<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\FutureSecurityAssurance;

function expectCycle117(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$base = [
    'domain_inventory' => ['example.test'],
    'endpoint_inventory' => ['endpoint:public-api'],
    'certificate_inventory' => ['certificate:primary'],
    'orphan_detection' => ['state' => 'clear'],
    'ownership' => ['owner' => 'security-team'],
    'evidence_ref' => 'evidence:future-117',
    'reviewed_at' => gmdate('c'),
];
$ok = FutureSecurityAssurance::evaluate('F24-FUT-006', $base);
expectCycle117($ok['state'] === 'verified' && $ok['write_allowed'], 'Safe structured evidence must verify.');

$secret = $base;
$secret['domain_inventory'] = ['api_key=supersecret'];
$secretResult = FutureSecurityAssurance::evaluate('F24-FUT-006', $secret);
expectCycle117($secretResult['state'] === 'incomplete' && in_array('domain_inventory', $secretResult['missing_controls'], true), 'Nested sensitive material must invalidate a required evidence control.');

$emptyNested = $base;
$emptyNested['ownership'] = [[]];
$emptyResult = FutureSecurityAssurance::evaluate('F24-FUT-006', $emptyNested);
expectCycle117($emptyResult['state'] === 'incomplete' && in_array('ownership', $emptyResult['missing_controls'], true), 'Structurally empty nested evidence must not count as meaningful.');

$nonFinite = $base;
$nonFinite['ownership'] = INF;
$finiteResult = FutureSecurityAssurance::evaluate('F24-FUT-006', $nonFinite);
expectCycle117($finiteResult['state'] === 'incomplete' && in_array('ownership', $finiteResult['missing_controls'], true), 'Non-finite numeric evidence must fail closed.');

echo "PASS: cycle117 evidence validation defects fixed and retested\n";
