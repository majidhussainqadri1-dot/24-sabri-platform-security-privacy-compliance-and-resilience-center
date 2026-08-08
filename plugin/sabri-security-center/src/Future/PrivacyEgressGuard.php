<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Future;

use Sabri\Platform\Security\Support\Sanitizer;

final class PrivacyEgressGuard
{
    private const DATA_CLASSES = ['C0','C1','C2','C3','C4','C5'];

    /** @param array<string,mixed> $request
     *  @return array<string,mixed>
     */
    public function evaluate(array $request): array
    {
        $classes = array_values(array_unique(array_map('strtoupper', Sanitizer::textList($request['data_classes'] ?? [], 10, 10))));
        $categories = array_values(array_unique(array_map('strtolower', Sanitizer::textList($request['detected_categories'] ?? [], 20, 40))));
        $destination = Sanitizer::key($request['destination_class'] ?? '', 40);
        $purpose = Sanitizer::key($request['purpose'] ?? '', 80);
        $consent = Sanitizer::boolean($request['consent_or_lawful_basis'] ?? false);
        $nativeAuthorized = Sanitizer::boolean($request['native_authorized'] ?? false);
        $minimumNecessary = Sanitizer::boolean($request['minimum_necessary'] ?? false);
        $approvedDestinations = ['same-platform', 'approved-processor', 'approved-clean-room'];
        $unknownClasses = array_values(array_diff($classes, self::DATA_CLASSES));
        $sensitive = array_intersect($classes, ['C3','C4','C5']) !== [] || array_intersect($categories, ['secret','identity','clinical','payment','credential']) !== [];

        $reasons = [];
        if ($classes === []) $reasons[] = 'data_classification_missing';
        if ($unknownClasses !== []) $reasons[] = 'unknown_data_class';
        if ($destination === '' || ! in_array($destination, $approvedDestinations, true)) $reasons[] = 'destination_not_approved';
        if ($purpose === '') $reasons[] = 'purpose_missing';
        if (! $consent) $reasons[] = 'lawful_basis_missing';
        if (! $nativeAuthorized) $reasons[] = 'native_authorization_missing';
        if ($sensitive && ! $minimumNecessary) $reasons[] = 'minimum_necessary_not_proven';

        return [
            'decision' => $reasons === [] ? 'allow' : 'block',
            'sensitive' => $sensitive,
            'reasons' => array_values(array_unique($reasons)),
            'unknown_data_classes' => $unknownClasses,
            'native_enforcement_required' => true,
        ];
    }
}
