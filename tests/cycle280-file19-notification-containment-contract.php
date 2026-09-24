<?php
declare(strict_types=1);
/** File 24 -> File 19 containment bridge must derive only from canonical security-state evidence. */
$plugin = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Plugin.php');
$matrix = (string) file_get_contents(__DIR__ . '/../plugin/sabri-security-center/src/Registry/PlatformIntegrationMatrix.php');
foreach ([
    "add_filter('sun_file24_notification_containment_active'",
    "apply_filters('spcrc/security_state_requests', [])",
    "'incident-containment'",
    "'platform-read-only'",
] as $needle) {
    if (strpos($plugin, $needle) === false) {
        fwrite(STDERR, "Missing File 19 containment bridge invariant: {$needle}\n");
        exit(1);
    }
}
if (strpos($matrix, "'contract_filter' => 'spcrc/file19_contract_state'") === false) {
    fwrite(STDERR, "File 19 assurance matrix contract is missing.\n");
    exit(1);
}
echo "Cycle 280 File19 notification containment contract PASS\n";
