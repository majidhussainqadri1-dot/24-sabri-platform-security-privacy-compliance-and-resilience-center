<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Storage;

final class Schema
{
    public const VERSION = '0.25.0';

    public static function install(): void
    {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();

        $events = $wpdb->prefix . 'spcrc_security_events';
        $incidents = $wpdb->prefix . 'spcrc_incidents';
        $findings = $wpdb->prefix . 'spcrc_findings';
        $privacy = $wpdb->prefix . 'spcrc_privacy_requests';
        $manifests = $wpdb->prefix . 'spcrc_module_manifests';

        dbDelta("CREATE TABLE {$events} (
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

        dbDelta("CREATE TABLE {$incidents} (
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

        dbDelta("CREATE TABLE {$findings} (
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

        dbDelta("CREATE TABLE {$privacy} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            request_uuid char(36) NOT NULL,
            requester_user_id bigint unsigned NULL,
            request_type varchar(40) NOT NULL,
            status varchar(40) NOT NULL DEFAULT 'received',
            assigned_user_id bigint unsigned NULL,
            jurisdiction varchar(80) NOT NULL DEFAULT '',
            due_at datetime NULL,
            created_at datetime NOT NULL,
            updated_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY request_uuid (request_uuid),
            KEY status_due (status, due_at),
            KEY requester_type (requester_user_id, request_type)
        ) {$charset};");

        dbDelta("CREATE TABLE {$manifests} (
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
    }
}
