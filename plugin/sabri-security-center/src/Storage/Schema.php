<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

final class Schema
{
    public const VERSION = '0.25.1';

    /** @return array<string,string> */
    public static function tables(): array
    {
        global $wpdb;

        return [
            'events' => $wpdb->prefix . 'spcrc_security_events',
            'incidents' => $wpdb->prefix . 'spcrc_incidents',
            'findings' => $wpdb->prefix . 'spcrc_findings',
            'privacy' => $wpdb->prefix . 'spcrc_privacy_requests',
            'manifests' => $wpdb->prefix . 'spcrc_module_manifests',
            'state_requests' => $wpdb->prefix . 'spcrc_security_state_requests',
        ];
    }

    public static function install(): bool
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
            environment varchar(20) NOT NULL DEFAULT 'production',
            actor_user_id bigint unsigned NOT NULL DEFAULT 0,
            result varchar(40) NOT NULL DEFAULT 'recorded',
            risk_level varchar(20) NOT NULL DEFAULT 'low',
            correlation_id varchar(80) NOT NULL DEFAULT '',
            context_json longtext NULL,
            created_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY event_uuid (event_uuid),
            KEY event_type_created (event_type, created_at),
            KEY module_created (module_key, created_at),
            KEY risk_created (risk_level, created_at),
            KEY environment_created (environment, created_at)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['incidents']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            incident_uuid char(36) NOT NULL,
            title varchar(200) NOT NULL,
            severity varchar(20) NOT NULL DEFAULT 'sev4',
            status varchar(40) NOT NULL DEFAULT 'open',
            owner_user_id bigint unsigned NULL,
            summary text NULL,
            opened_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            closed_at datetime NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY incident_uuid (incident_uuid),
            KEY status_severity (status, severity),
            KEY updated_at (updated_at)
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
            created_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY finding_uuid (finding_uuid),
            KEY status_severity (status, severity),
            KEY module_status (module_key, status)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['privacy']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            request_uuid char(36) NOT NULL,
            requester_user_id bigint unsigned NOT NULL DEFAULT 0,
            request_type varchar(40) NOT NULL,
            status varchar(40) NOT NULL DEFAULT 'received',
            assigned_user_id bigint unsigned NOT NULL DEFAULT 0,
            jurisdiction varchar(80) NOT NULL DEFAULT '',
            due_at datetime NULL,
            created_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY request_uuid (request_uuid),
            KEY status_due (status, due_at),
            KEY requester_type (requester_user_id, request_type)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['manifests']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            module_key varchar(120) NOT NULL,
            module_version varchar(60) NOT NULL DEFAULT '',
            manifest_hash char(64) NOT NULL,
            posture varchar(40) NOT NULL DEFAULT 'unassessed',
            manifest_json longtext NOT NULL,
            first_seen_at datetime NULL,
            last_seen_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY module_key (module_key),
            KEY posture_seen (posture, last_seen_at)
        ) {$charset};");

        dbDelta("CREATE TABLE {$tables['state_requests']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            request_uuid char(36) NOT NULL,
            module_key varchar(120) NOT NULL,
            requested_state varchar(40) NOT NULL,
            reason varchar(500) NOT NULL DEFAULT '',
            status varchar(40) NOT NULL DEFAULT 'open',
            requested_by bigint unsigned NOT NULL DEFAULT 0,
            requested_at datetime NOT NULL,
            expires_at datetime NOT NULL,
            resolved_at datetime NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY request_uuid (request_uuid),
            KEY module_status (module_key, status),
            KEY status_expiry (status, expires_at)
        ) {$charset};");

        return self::missingTables() === [] && self::missingColumns() === [];
    }


    /** @return array<string,string[]> */
    public static function requiredColumns(): array
    {
        return [
            'events' => ['event_uuid', 'event_type', 'module_key', 'environment', 'actor_user_id', 'result', 'risk_level', 'correlation_id', 'context_json', 'created_at'],
            'incidents' => ['incident_uuid', 'title', 'severity', 'status', 'owner_user_id', 'summary', 'opened_at', 'updated_at', 'closed_at'],
            'findings' => ['finding_uuid', 'module_key', 'title', 'severity', 'status', 'owner_user_id', 'due_at', 'evidence_ref', 'created_at', 'updated_at'],
            'privacy' => ['request_uuid', 'requester_user_id', 'request_type', 'status', 'assigned_user_id', 'jurisdiction', 'due_at', 'created_at', 'updated_at'],
            'manifests' => ['module_key', 'module_version', 'manifest_hash', 'posture', 'manifest_json', 'first_seen_at', 'last_seen_at'],
            'state_requests' => ['request_uuid', 'module_key', 'requested_state', 'reason', 'status', 'requested_by', 'requested_at', 'expires_at', 'resolved_at'],
        ];
    }

    /** @return string[] */
    public static function missingColumns(): array
    {
        global $wpdb;
        $missing = [];
        $tables = self::tables();

        foreach (self::requiredColumns() as $tableKey => $columns) {
            $table = $tables[$tableKey];
            foreach ($columns as $column) {
                $found = $wpdb->get_var($wpdb->prepare("SHOW COLUMNS FROM {$table} LIKE %s", $column));
                if ((string) $found !== $column) {
                    $missing[] = $table . '.' . $column;
                }
            }
        }

        return $missing;
    }

    /** @return string[] */
    public static function missingTables(): array
    {
        global $wpdb;
        $missing = [];

        foreach (self::tables() as $table) {
            $found = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table)));
            if ((string) $found !== $table) {
                $missing[] = $table;
            }
        }

        return $missing;
    }
}
