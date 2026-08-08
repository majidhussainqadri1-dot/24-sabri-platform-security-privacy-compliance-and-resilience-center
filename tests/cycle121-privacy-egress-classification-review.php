<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Future\PrivacyEgressGuard;

function expectCycle121(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$guard = new PrivacyEgressGuard();
$common = ['destination_class' => 'approved-clean-room', 'purpose' => 'research', 'consent_or_lawful_basis' => true, 'native_authorized' => true];

$missing = $guard->evaluate($common + ['minimum_necessary' => true]);
expectCycle121($missing['decision'] === 'block' && in_array('data_classification_missing', $missing['reasons'], true), 'Egress without a data classification must fail closed.');

$unknown = $guard->evaluate($common + ['data_classes' => ['C9'], 'minimum_necessary' => true]);
expectCycle121($unknown['decision'] === 'block' && in_array('unknown_data_class', $unknown['reasons'], true), 'Unknown data classes must fail closed.');

$excessive = $guard->evaluate($common + ['data_classes' => ['C5'], 'detected_categories' => ['identity'], 'minimum_necessary' => false]);
expectCycle121($excessive['decision'] === 'block' && in_array('minimum_necessary_not_proven', $excessive['reasons'], true), 'Sensitive clean-room egress still requires minimum-necessary proof.');

$bounded = $guard->evaluate($common + ['data_classes' => ['C5'], 'detected_categories' => ['identity'], 'minimum_necessary' => true]);
expectCycle121($bounded['decision'] === 'allow' && $bounded['sensitive'], 'Classified, authorized and minimum-necessary sensitive egress may pass the assurance gate.');

echo "PASS: cycle121 DLP/egress defects fixed and retested\n";
