<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\PolicyAsCodeEngine;

function expectCycle120(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$engine = new PolicyAsCodeEngine();
$typeConfusion = $engine->evaluate(['version' => '1.1', 'effect' => 'allow', 'rules' => [['field' => 'approved', 'operator' => 'equals', 'value' => '']]], ['approved' => false]);
expectCycle120($typeConfusion['decision'] === 'deny' && ! $typeConfusion['matched'], 'Boolean false must not equal an empty string through scalar coercion.');

$truthyConfusion = $engine->evaluate(['version' => '1.1', 'effect' => 'allow', 'rules' => [['field' => 'approved', 'operator' => 'equals', 'value' => '1']]], ['approved' => true]);
expectCycle120($truthyConfusion['decision'] === 'deny', 'Boolean true must not equal string 1 through coercion.');

$strict = $engine->evaluate(['version' => '1.1', 'effect' => 'allow', 'rules' => [['field' => 'approved', 'operator' => 'equals', 'value' => true]]], ['approved' => true]);
expectCycle120($strict['decision'] === 'allow' && $strict['matched'], 'Strictly typed equality must continue to match identical values.');

$nonFinite = $engine->evaluate(['version' => '1.1', 'effect' => 'allow', 'rules' => [['field' => 'risk', 'operator' => 'gte', 'value' => 10]]], ['risk' => INF]);
expectCycle120($nonFinite['decision'] === 'deny', 'Non-finite numeric context must never satisfy gte/lte policy rules.');

echo "PASS: cycle120 policy type-confusion defects fixed and retested\n";
