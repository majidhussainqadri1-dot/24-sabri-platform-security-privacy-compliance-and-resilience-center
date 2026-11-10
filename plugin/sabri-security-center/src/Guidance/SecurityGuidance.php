<?php

declare(strict_types=1);

namespace Sabri\Platform\Security\Guidance;

/**
 * Public security education and a separate operator checklist.
 * This class does not change authentication, WAF, backups, or clinical access.
 */
final class SecurityGuidance
{
    public const SHORTCODE = 'sabri_security_guidance';

    public function registerHooks(): void
    {
        if (function_exists('add_shortcode')) {
            add_shortcode(self::SHORTCODE, [$this, 'renderPublic']);
        }
        add_action('admin_menu', [$this, 'registerAdminMenu']);
        add_action('wp_enqueue_scripts', [$this, 'enqueuePublicAssets']);
        add_action('admin_enqueue_scripts', [$this, 'enqueueAdminAssets']);
    }

    public function enqueuePublicAssets(): void
    {
        if (! is_singular()) {
            return;
        }

        $post = get_post();
        if (! $post || ! has_shortcode((string) $post->post_content, self::SHORTCODE)) {
            return;
        }

        wp_enqueue_style('spcrc-security-guidance', SPCRC_PLUGIN_URL . 'assets/security-guidance.css', [], SPCRC_VERSION);
    }

    public function enqueueAdminAssets(string $hook): void
    {
        if ($hook === 'security-center_page_sabri-security-guidance') {
            wp_enqueue_style('spcrc-admin', SPCRC_PLUGIN_URL . 'assets/admin.css', [], SPCRC_VERSION);
        }
    }

    public function registerAdminMenu(): void
    {
        add_submenu_page(
            'sabri-security-center',
            __('Security guidance', 'sabri-security-center'),
            __('Security guidance', 'sabri-security-center'),
            'spcrc_view_overview',
            'sabri-security-guidance',
            [$this, 'renderAdmin']
        );
    }

    /** Public-safe guidance only: no runtime posture, risk register or secrets. */
    public function renderPublic(): string
    {
        $general = [
            'اپنے اکاؤنٹ کے لیے منفرد اور مضبوط پاس ورڈ رکھیں؛ دستیاب ہو تو پاس کی یا دو مرحلہ تصدیق استعمال کریں۔',
            'پاس ورڈ، OTP، پاس کی، ریکوری کوڈ یا تصدیقی لنک کسی شخص کو نہ دیں؛ پلیٹ فارم کا منتظم بھی یہ معلومات نہیں مانگتا۔',
            'جعلی پیغامات سے بچیں: ویب پتے کی املا اور اصل ڈومین دیکھیں؛ مشتبہ لنک اور منسلکہ فائل نہ کھولیں۔',
            'فون، براؤزر اور حفاظتی سافٹ ویئر کو تازہ رکھیں؛ مشترکہ آلے پر استعمال کے بعد لاگ آؤٹ کریں۔',
            'صرف اپنی معلومات اور تصاویر شیئر کریں؛ دوسرے شخص کا نجی ڈیٹا اس کی اجازت کے بغیر شائع نہ کریں۔',
            'اگر کوئی آپ کو فوری رقم، خفیہ کوڈ یا اکاؤنٹ تک رسائی دینے پر مجبور کرے تو کارروائی روک دیں اور تصدیق کریں۔',
            'مشتبہ اکاؤنٹ، جعلی ڈاکٹر، دھوکے یا غیر مجاز رسائی کی شکایت پلیٹ فارم کے دستیاب Support/Report راستے سے کریں۔',
        ];
        $patients = [
            'مریض اپنی رپورٹس، تصاویر اور کیس ہسٹری صرف مجاز نجی کلینک یا محفوظ فارم میں جمع کرائیں؛ عوامی تبصروں میں نہیں۔',
            'ڈاکٹر کی تصدیق اور مجاز تعلق جانچیں؛ تصدیقی نشان علاج کے نتیجے کی ضمانت نہیں ہے۔',
            'کسی مشتبہ رابطے کو مریض کی دستاویز یا اکاؤنٹ کوڈ نہ بھیجیں، چاہے وہ خود کو معاون ظاہر کرے۔',
        ];
        $incident = [
            'اگر اکاؤنٹ مشتبہ ہو تو محفوظ آلے سے پاس ورڈ تبدیل کریں، فعال سیشنز بند کریں اور MFA کی حالت جانچیں۔',
            'نقصان یا مشتبہ پیغام کے ثبوت محفوظ رکھیں، مگر پاس ورڈ، OTP یا نجی مریض ریکارڈ کسی عوامی رپورٹ میں نہ لکھیں۔',
            'واقعے کی فوری اطلاع پلیٹ فارم کے دستیاب Support/Report راستے اور، ضرورت ہو تو، متعلقہ خدمت فراہم کنندہ کو دیں۔',
        ];

        ob_start();
        ?>
        <section class="spcrc-public-guidance" dir="rtl" lang="ur" aria-labelledby="spcrc-public-guidance-heading">
            <header class="spcrc-public-guidance__header">
                <p class="spcrc-public-guidance__eyebrow"><?php echo esc_html('Sabri Social Homeopathy Platform'); ?></p>
                <h2 id="spcrc-public-guidance-heading"><?php echo esc_html('حفاظتی مرکز: آپ کا اکاؤنٹ، آپ کی رازداری'); ?></h2>
                <p><?php echo esc_html('آن لائن حفاظت ایک مشترک ذمہ داری ہے۔ یہ رہنمائی خطرات کم کرنے کے لیے ہے؛ کسی نظام کے ناقابلِ حملہ ہونے کا دعویٰ نہیں۔'); ?></p>
            </header>
            <?php $this->renderList('عام صارفین اور فالوورز کے لیے', $general); ?>
            <?php $this->renderList('مریضوں اور ڈاکٹروں کے لیے', $patients); ?>
            <?php $this->renderList('مشتبہ داخلے یا دھوکے کی صورت میں', $incident); ?>
            <p class="spcrc-public-guidance__footnote"><?php echo esc_html('اہم: اس صفحے پر عمومی احتیاطی تدابیر دی گئی ہیں؛ یہ کسی خاص حفاظتی کنٹرول کے فعال ہونے کی تصدیق نہیں۔'); ?></p>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    public function renderAdmin(): void
    {
        if (! current_user_can('spcrc_view_overview')) {
            wp_die(esc_html__('You are not allowed to view security guidance.', 'sabri-security-center'));
        }

        $checks = [
            'منتظم، ہوسٹنگ، رجسٹرار اور بحالی ای میل کے MFA یا پاس کی نفاذ اور ریکوری کوڈ کے محفوظ الگ ذخیرے کا ثبوت جانچیں۔',
            'WordPress، پلگ اِن، تھیم، سرور اور dependencies کی تازہ حفاظتی اپ ڈیٹس و غیر ضروری سافٹ ویئر کی فہرست دیکھیں۔',
            'فائل اور ڈیٹابیس کے بیک اپ، الگ رمز بند نقل، بحالی آزمائش اور قابلِ ثبوت RPO/RTO کی تصدیق کریں۔',
            'اصل ہوسٹ پر WAF، DDoS دفاع، لاگ اِن rate limiting، TLS، اور Cloudflare ہو تو Full (strict) کی اصل ترتیب جانچیں۔',
            'بندش، نامعلوم منتظم، فائلوں/ڈیٹابیس کی مشتبہ تبدیلی اور حساس واقعات کے انتباہات کا عملی امتحان کریں۔',
            'مریضوں کی فائلیں نجی ذخیرے میں رکھیں؛ ہر view/download پر سرور سے object-level authorization اور محفوظ اپ لوڈ اسکیننگ جانچیں۔',
            'واقعے میں رسائی محدود کریں، ناقابلِ تبدیل ثبوت/لاگز محفوظ کریں، credentials منسوخ کریں، اصل سبب دور اور بحالی کا دوبارہ امتحان کریں۔',
        ];
        ?>
        <div class="wrap spcrc-wrap" dir="rtl" lang="ur">
            <h1><?php echo esc_html('صابری حفاظتی مرکز — بانی و منتظم کے لیے عملی ہدایات'); ?></h1>
            <p><?php echo esc_html('یہ پڑھنے کی چیک لسٹ ہے، خودکار سکیورٹی اسکین یا مکمل نفاذ کا سرٹیفکیٹ نہیں۔ ہر شق کا ثبوت اصل تعینات نظام سے حاصل کریں۔'); ?></p>
            <section class="spcrc-panel" aria-labelledby="spcrc-operator-checks">
                <h2 id="spcrc-operator-checks"><?php echo esc_html('سات لازمی حفاظتی ذمہ داریاں'); ?></h2>
                <?php $this->renderListItems($checks); ?>
            </section>
            <section class="spcrc-panel" aria-labelledby="spcrc-operator-deploy">
                <h2 id="spcrc-operator-deploy"><?php echo esc_html('نفاذ اور ثبوت کا اصول'); ?></h2>
                <p><?php echo esc_html('Live، staging اور GitHub تین الگ حالتیں ہیں۔ Repository HEAD، تعینات پلگ اِن ورژن، ڈیٹابیس ورژن، migration اور live retest الگ ریکارڈ کریں۔ غیر مصدقہ کنٹرول کو فعال یا کامیاب ظاہر نہ کریں۔'); ?></p>
                <p><?php echo esc_html('عوامی رہنمائی شائع کرنے کے لیے منظور شدہ WordPress صفحے میں یہ shortcode درج کریں:'); ?> <code>[sabri_security_guidance]</code></p>
                <p><?php echo esc_html('اس صفحے کا تعلق File 24 سے ہے؛ عوامی مینو میں اس کا راستہ File 20 کی منظوری سے شامل کریں۔'); ?></p>
            </section>
        </div>
        <?php
    }

    /** @param array<int,string> $items */
    private function renderList(string $heading, array $items): void
    {
        $id = 'spcrc-guidance-' . substr(hash('sha256', $heading), 0, 10);
        ?>
        <section class="spcrc-public-guidance__section" aria-labelledby="<?php echo esc_attr($id); ?>">
            <h3 id="<?php echo esc_attr($id); ?>"><?php echo esc_html($heading); ?></h3>
            <?php $this->renderListItems($items); ?>
        </section>
        <?php
    }

    /** @param array<int,string> $items */
    private function renderListItems(array $items): void
    {
        echo '<ul>';
        foreach ($items as $item) {
            echo '<li>' . esc_html($item) . '</li>';
        }
        echo '</ul>';
    }
}
