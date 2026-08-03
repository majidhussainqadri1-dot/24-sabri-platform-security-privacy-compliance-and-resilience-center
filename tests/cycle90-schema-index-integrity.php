<?php

declare(strict_types=1);

require __DIR__ . '/support/cycle57-96.php';


use Sabri\Platform\Security\Storage\Schema;
cycleReviewAssert(Schema::verify()===true,'Complete required table, column and index set must verify.');
$GLOBALS['wpdb']->missingIndexes['spcrc_security_events']=['event_uuid'];
$result=Schema::verify();
cycleReviewAssert(is_wp_error($result)&&$result->get_error_code()==='spcrc_schema_integrity_failed','Missing unique event identity index must fail schema integrity.');

cycleReviewPass(90, 'schema-index-integrity');
