<?php

declare(strict_types=1);

const SPCRC_PLUGIN_URL = 'https://example.test/wp-content/plugins/sabri-security-center/';
const SPCRC_VERSION = '0.99.0';
$GLOBALS['shortcodes'] = [];
$GLOBALS['actions'] = [];
$GLOBALS['styles'] = [];
$GLOBALS['menus'] = [];
$GLOBALS['allowed'] = true;
$GLOBALS['post_text'] = '[sabri_security_guidance]';

function add_shortcode(string $tag, callable $callback): void { $GLOBALS['shortcodes'][$tag] = $callback; }
function add_action(string $tag, callable $callback): void { $GLOBALS['actions'][$tag][] = $callback; }
function wp_enqueue_style(string $handle, string $url, array $deps, string $ver): void { $GLOBALS['styles'][$handle] = $url; }
function is_singular(): bool { return true; }
function get_post(): object { return (object) ['post_content' => $GLOBALS['post_text']]; }
function has_shortcode(string $content, string $tag): bool { return str_contains($content, '[' . $tag . ']'); }
function __(string $value, string $domain): string { return $value; }
function esc_html(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
function esc_html__(string $value, string $domain): string { return esc_html($value); }
function esc_attr(string $value): string { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
function current_user_can(string $cap): bool { return $cap === 'spcrc_view_overview' && $GLOBALS['allowed']; }
function wp_die(string $message): void { throw new RuntimeException($message); }
function add_submenu_page(string $parent, string $page, string $menu, string $cap, string $slug, callable $callback): void
{
    $GLOBALS['menus'][$slug] = ['parent' => $parent, 'cap' => $cap, 'callback' => $callback];
}
function assertTrue(bool $passed, string $message): void
{
    if (! $passed) { fwrite(STDERR, "FAIL: {$message}\n"); exit(1); }
}

require_once __DIR__ . '/../plugin/sabri-security-center/src/Guidance/SecurityGuidance.php';
use Sabri\Platform\Security\Guidance\SecurityGuidance;

$guide = new SecurityGuidance();
$guide->registerHooks();
assertTrue(isset($GLOBALS['shortcodes'][SecurityGuidance::SHORTCODE]), 'Public shortcode registered.');
assertTrue(isset($GLOBALS['actions']['admin_menu']), 'Operator menu hooked.');
$page = $guide->renderPublic();
assertTrue(str_contains($page, 'عام صارفین اور فالوورز') && str_contains($page, 'مریضوں اور ڈاکٹروں'), 'Public audiences covered.');
assertTrue(str_contains($page, 'OTP') && str_contains($page, 'پاس ورڈ'), 'Credential/phishing advice present.');
assertTrue(str_contains($page, 'Support/Report'), 'No fabricated report destination.');
assertTrue(! str_contains($page, 'سات لازمی حفاظتی ذمہ داریاں') && ! str_contains($page, 'Cloudflare'), 'Private operator controls excluded from public output.');
assertTrue(! str_contains($page, '100% secure'), 'No total-security guarantee.');
$guide->enqueuePublicAssets();
assertTrue(isset($GLOBALS['styles']['spcrc-security-guidance']), 'Scoped CSS loaded for shortcode.');
$GLOBALS['styles'] = [];
$GLOBALS['post_text'] = 'No shortcode';
$guide->enqueuePublicAssets();
assertTrue(isset($GLOBALS['styles']['spcrc-security-guidance']), 'Dynamic shortcode or template CSS loaded before rendering, even when raw post content lacks shortcode.');
$secondPage = $guide->renderPublic();
preg_match_all('/\\bid="([^"]+)"/', $page . $secondPage, $ids);
preg_match_all('/\\baria-labelledby="([^"]+)"/', $page . $secondPage, $refs);
assertTrue(count($ids[1]) === 8 && count($ids[1]) === count(array_unique($ids[1])), 'Each repeated shortcode instance has distinct heading and section ids.');
assertTrue(count($refs[1]) === 8 && ! array_diff($refs[1], $ids[1]), 'Every section ARIA reference targets an existing unique id.');
$guide->registerAdminMenu();
assertTrue(($GLOBALS['menus']['sabri-security-guidance']['cap'] ?? '') === 'spcrc_view_overview', 'Admin capability guard.');
ob_start();
$guide->renderAdmin();
$admin = (string) ob_get_clean();
assertTrue(str_contains($admin, 'Cloudflare') && str_contains($admin, '[sabri_security_guidance]'), 'Operator checklist and publication guidance present.');
$GLOBALS['allowed'] = false;
try {
    $guide->renderAdmin();
    assertTrue(false, 'Unauthorized access must fail.');
} catch (RuntimeException $e) {
    assertTrue(str_contains($e->getMessage(), 'not allowed'), 'Unauthorized denial.');
}
echo "PASS: security guidance registration, public privacy boundary, assets and admin authorization\n";
