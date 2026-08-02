<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

final class Schema
{
    public const VERSION = '0.25.5';

    /** @return bool|\WP_Error */
    public static function install(): bool|\WP_Error
    {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        $tables = self::tables();

        dbDelta("CREATE TABLE {$tables['events']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            event_uuid char(36) NOT NULL,
            event_type varchar(120) NOT NULL,
            module_key varchar(120) NOT NULL DEFAULT '',
            actor_user_id bigint unsigned NULL,
            result varchar(40) NOT NULL DEFAULT 'recorded',
            risk_level varchar(20) NOT NULL DEFAULT 'low',
            correlation_id varchar(80) NOT NULL DEFAULT '',
            context_json longtext NULL,
            created_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY event_uuid (event_uuid),
            KEY event_type_created (event_type, created_at),
            KEY module_created (module_key, created_at),
            KEY risk_created (risk_level, created_at)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['incidents']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            incident_uuid char(36) NOT NULL,
            title varchar(200) NOT NULL,
            severity varchar(20) NOT NULL DEFAULT 'sev4',
            status varchar(40) NOT NULL DEFAULT 'open',
            owner_user_id bigint unsigned NULL,
            summary text NULL,
            evidence_ref varchar(255) NOT NULL DEFAULT '',
            opened_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            closed_at datetime NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY incident_uuid (incident_uuid),
            KEY status_severity (status, severity),
            KEY updated_at (updated_at),
            KEY incident_evidence (evidence_ref)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['findings']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            finding_uuid char(36) NOT NULL,
            module_key varchar(120) NOT NULL DEFAULT '',
            title varchar(200) NOT NULL,
            severity varchar(20) NOT NULL DEFAULT 'medium',
            status varchar(40) NOT NULL DEFAULT 'open',
            owner_user_id bigint unsigned NULL,
            due_at datetime NULL,
            evidence_ref varchar(255) NOT NULL DEFAULT '',
            governance_decision_uuid char(36) NULL,
            acceptance_expires_at datetime NULL,
            created_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY finding_uuid (finding_uuid),
            KEY status_severity (status, severity),
            KEY module_status (module_key, status),
            KEY finding_governance (governance_decision_uuid),
            KEY finding_acceptance_expiry (acceptance_expires_at)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['risks']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            risk_uuid char(36) NOT NULL,
            module_key varchar(120) NOT NULL DEFAULT '',
            title varchar(200) NOT NULL,
            likelihood tinyint unsigned NOT NULL DEFAULT 1,
            impact tinyint unsigned NOT NULL DEFAULT 1,
            inherent_score smallint unsigned NOT NULL DEFAULT 1,
            status varchar(40) NOT NULL DEFAULT 'open',
            treatment varchar(30) NOT NULL DEFAULT 'mitigate',
            owner_user_id bigint unsigned NULL,
            due_at datetime NULL,
            governance_decision_uuid char(36) NULL,
            accepted_by_user_id bigint unsigned NULL,
            accepted_at datetime NULL,
            acceptance_expires_at datetime NULL,
            created_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY risk_uuid (risk_uuid),
            KEY status_score (status, inherent_score),
            KEY module_status (module_key, status),
            KEY due_at (due_at),
            KEY governance_decision (governance_decision_uuid),
            KEY accepted_at (accepted_at),
            KEY risk_acceptance_expiry (acceptance_expires_at)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['controls']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            control_key varchar(120) NOT NULL,
            title varchar(200) NOT NULL,
            framework varchar(120) NOT NULL DEFAULT '',
            status varchar(40) NOT NULL DEFAULT 'unassessed',
            owner_user_id bigint unsigned NULL,
            evidence_ref varchar(255) NOT NULL DEFAULT '',
            last_tested_at datetime NULL,
            created_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY control_key (control_key),
            KEY status (status),
            KEY framework (framework),
            KEY updated_at (updated_at)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['privacy']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            request_uuid char(36) NOT NULL,
            requester_user_id bigint unsigned NULL,
            request_type varchar(40) NOT NULL,
            status varchar(40) NOT NULL DEFAULT 'received',
            assigned_user_id bigint unsigned NULL,
            jurisdiction varchar(80) NOT NULL DEFAULT '',
            due_at datetime NULL,
            verification_method varchar(40) NOT NULL DEFAULT '',
            authority_basis varchar(40) NOT NULL DEFAULT '',
            verification_reference varchar(200) NOT NULL DEFAULT '',
            verified_by_user_id bigint unsigned NULL,
            verified_at datetime NULL,
            module_results_json longtext NULL,
            dispatch_attempts smallint unsigned NOT NULL DEFAULT 0,
            lock_version bigint unsigned NOT NULL DEFAULT 0,
            next_retry_at datetime NULL,
            last_error_code varchar(120) NOT NULL DEFAULT '',
            completed_at datetime NULL,
            created_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY request_uuid (request_uuid),
            KEY status_due (status, due_at),
            KEY status_retry (status, next_retry_at),
            KEY requester_type (requester_user_id, request_type),
            KEY verification_status (verification_method, status),
            KEY verified_by (verified_by_user_id, verified_at),
            KEY updated_status (updated_at, status)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['manifests']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            module_key varchar(120) NOT NULL,
            module_version varchar(60) NOT NULL DEFAULT '',
            manifest_hash char(64) NOT NULL,
            posture varchar(40) NOT NULL DEFAULT 'unassessed',
            manifest_json longtext NOT NULL,
            last_seen_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY module_key (module_key),
            KEY posture_seen (posture, last_seen_at)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['governance']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            decision_uuid char(36) NOT NULL,
            decision_type varchar(60) NOT NULL,
            subject_key varchar(120) NOT NULL,
            module_key varchar(120) NOT NULL DEFAULT 'file-24-security-center',
            status varchar(30) NOT NULL DEFAULT 'pending',
            requester_user_id bigint unsigned NOT NULL,
            approver_user_id bigint unsigned NULL,
            evidence_ref varchar(255) NOT NULL,
            rationale_hash char(64) NOT NULL,
            requested_at datetime NOT NULL,
            expires_at datetime NOT NULL,
            decided_at datetime NULL,
            revoked_at datetime NULL,
            lock_version bigint unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            UNIQUE KEY decision_uuid (decision_uuid),
            KEY type_subject (decision_type, subject_key),
            KEY status_expiry (status, expires_at),
            KEY requester_status (requester_user_id, status),
            KEY approver_decided (approver_user_id, decided_at)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['assurance']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            record_uuid char(36) NOT NULL,
            record_type varchar(40) NOT NULL,
            record_key varchar(120) NOT NULL,
            title varchar(200) NOT NULL,
            status varchar(40) NOT NULL DEFAULT 'unassessed',
            owner_user_id bigint unsigned NULL,
            jurisdiction varchar(80) NOT NULL DEFAULT '',
            data_classes_json text NULL,
            evidence_ref varchar(255) NOT NULL DEFAULT '',
            notes text NULL,
            reviewed_at datetime NULL,
            next_review_at datetime NULL,
            backup_completed_at datetime NULL,
            restore_tested_at datetime NULL,
            created_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY record_uuid (record_uuid),
            UNIQUE KEY type_record (record_type, record_key),
            KEY type_status (record_type, status),
            KEY next_review (next_review_at),
            KEY backup_restore (backup_completed_at, restore_tested_at),
            KEY updated_at (updated_at)
        ) {$charset};");

        return self::verify();
    }

    /** @return bool|\WP_Error */
    public static function verify(): bool|\WP_Error
    {
        global $wpdb;

        $tables = self::tables();

        foreach (self::tables() as $key => $table) {
            $found = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table)));
            if ($found !== $table) {
                return new \WP_Error(
                    'spcrc_schema_integrity_failed',
                    sprintf('Required File 24 table is unavailable: %s', $key)
                );
            }
        }

        if (method_exists($wpdb, 'get_col')) {
            $required = [
                'risks' => ['governance_decision_uuid', 'accepted_by_user_id', 'accepted_at', 'acceptance_expires_at'],
                'findings' => ['governance_decision_uuid', 'acceptance_expires_at'],
                'incidents' => ['evidence_ref'],
                'governance' => ['decision_uuid', 'decision_type', 'subject_key', 'status', 'requester_user_id', 'approver_user_id', 'evidence_ref', 'lock_version'],
            ];
            foreach ($required as $tableKey => $columns) {
                $foundColumns = $wpdb->get_col("SHOW COLUMNS FROM {$tables[$tableKey]}", 0);
                if (! is_array($foundColumns)) {
                    return new \WP_Error('spcrc_schema_column_check_failed', sprintf('File 24 columns could not be inspected: %s', $tableKey));
                }
                foreach ($columns as $column) {
                    if (! in_array($column, $foundColumns, true)) {
                        return new \WP_Error('spcrc_schema_integrity_failed', sprintf('Required File 24 column is unavailable: %s.%s', $tableKey, $column));
                    }
                }
            }
        }

        return true;
    }

    /** @return array<string,string> */
    public static function tables(): array
    {
        global $wpdb;

        return [
            'events' => $wpdb->prefix . 'spcrc_security_events',
            'incidents' => $wpdb->prefix . 'spcrc_incidents',
            'findings' => $wpdb->prefix . 'spcrc_findings',
            'risks' => $wpdb->prefix . 'spcrc_risks',
            'controls' => $wpdb->prefix . 'spcrc_controls',
            'privacy' => $wpdb->prefix . 'spcrc_privacy_requests',
            'manifests' => $wpdb->prefix . 'spcrc_module_manifests',
            'assurance' => $wpdb->prefix . 'spcrc_assurance_records',
            'governance' => $wpdb->prefix . 'spcrc_governance_decisions',
        ];
    }
}
