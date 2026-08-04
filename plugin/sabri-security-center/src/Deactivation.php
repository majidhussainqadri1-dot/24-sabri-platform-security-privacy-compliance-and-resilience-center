<?php

declare(strict_types=1);

namespace Sabri\Platform\Security;

use Sabri\Platform\Security\Monitoring\RemoteEvidenceQueue;
use Sabri\Platform\Security\Privacy\DeletionReplayManager;
use Sabri\Platform\Security\Privacy\RecoveryManager;
use Sabri\Platform\Security\Resilience\ResilienceCoordinator;
use Sabri\Platform\Security\Retention\RetentionManager;

final class Deactivation
{
    public static function deactivate(): void
    {
        RetentionManager::unschedule();
        RecoveryManager::unschedule();
        if (class_exists(DeletionReplayManager::class)) { DeletionReplayManager::unschedule(); }
        if (class_exists(RemoteEvidenceQueue::class)) { RemoteEvidenceQueue::unschedule(); }
        if (class_exists(ResilienceCoordinator::class)) { ResilienceCoordinator::unschedule(); }
        update_option('spcrc_last_deactivated_at', gmdate('c'), false);

        // Preserve evidence and schema. Native modules must remain secure without File 24.
        do_action('spcrc/deactivated');
    }
}
