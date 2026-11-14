<?php

declare(strict_types=1);

// Source-claim QA only. Not a legal applicability assessment or legal advice.
function v123LegalAssert(bool $ok, string $message): void
{
    if (! $ok) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$text = file_get_contents(__DIR__ . '/../docs/V123-LEGAL-JURISDICTION-DESK-REVIEW-2026-11-14.md');
v123LegalAssert(is_string($text) && $text !== '', 'Legal issue register must exist.');
preg_match_all('/^\|\s*(LEG-[0-9]{2})\s*\|/m', $text, $matches);
$ids = $matches[1] ?? [];
$expected = [];
for ($i = 1; $i <= 10; ++$i) {
    $expected[] = 'LEG-' . str_pad((string) $i, 2, '0', STR_PAD_LEFT);
}
sort($ids);
sort($expected);
v123LegalAssert($ids === $expected, 'Exact ten legal questions must exist, once each.');
v123LegalAssert(
    str_contains($text, 'Personal Data Protection Bill May 2023 – Draft'),
    'Pakistan law status must name the May 2023 draft as a draft, not enacted.'
);
v123LegalAssert(
    str_contains($text, 'Act No. II of 2025')
        && str_contains($text, '29 January 2025'),
    'PECA enacted amendment must include source-act identity and Gazette date.'
);
v123LegalAssert(
    str_contains($text, 'Unani, Ayurvedic and Homoeopathic Practitioners Act, 1965')
        && str_contains($text, 'National Council for Homoeopathy'),
    'Practitioner verification must map to the actual statutory council.'
);
v123LegalAssert(
    str_contains($text, 'Articles 3 (territorial scope), 8 (children')
        && str_contains($text, '9 (special categories'),
    'GDPR Article 3, 8, 9 applicability conditions must stay explicit.'
);
foreach (['legal advice', 'NOT DETERMINED', 'COUNSEL REVIEW PENDING', 'BLOCKED', 'UNVERIFIED'] as $caution) {
    v123LegalAssert(
        stripos($text, $caution) !== false,
        'Legal source note must retain qualified unknown/blocked marker: ' . $caution
    );
}
echo "PASS: V12.3 legal issues are sourced, draft-aware, conditional and not certified\n";
