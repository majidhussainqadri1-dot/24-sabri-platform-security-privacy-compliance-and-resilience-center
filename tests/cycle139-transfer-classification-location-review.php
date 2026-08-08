<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use Sabri\Platform\Security\Privacy\DataGovernanceRegistry;
use Sabri\Platform\Security\Registry\GovernedArtifactRegistry;
use Sabri\Platform\Security\Storage\AuditLogger;

function c139(bool $condition, string $message): void { if (! $condition) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); } }

$data = new DataGovernanceRegistry(new GovernedArtifactRegistry(new AuditLogger()));

$c4Unknown = $data->recordTransfer([
    'transfer_key' => 'cycle139-c4', 'origin_region' => 'PK', 'destination_region' => 'unknown',
    'vendor_ref' => 'vendor:cycle139', 'data_classes' => ['C4'], 'location_assurance' => 'unknown',
]);
c139(is_wp_error($c4Unknown) && $c4Unknown->get_error_code() === 'spcrc_transfer_restricted_location_unknown', 'C4, like C5, must not leave for an unverified provider location.');

$unknownClass = $data->recordTransfer([
    'transfer_key' => 'cycle139-c9', 'origin_region' => 'PK', 'destination_region' => 'US',
    'vendor_ref' => 'vendor:cycle139', 'data_classes' => ['C9'], 'location_assurance' => 'verified',
]);
c139(is_wp_error($unknownClass) && $unknownClass->get_error_code() === 'spcrc_transfer_data_class_invalid', 'Unrecognized data classifications must fail closed.');

$c3 = $data->recordTransfer([
    'transfer_key' => 'cycle139-c3', 'origin_region' => 'PK', 'destination_region' => 'US',
    'vendor_ref' => 'vendor:cycle139', 'data_classes' => ['c3'], 'location_assurance' => 'documented',
]);
c139(is_string($c3), 'Recognized C3 transfer may proceed to assessment without the C4/C5 location hard block.');

echo "PASS: cycle139 international-transfer classification/location defect fixed and retested\n";
