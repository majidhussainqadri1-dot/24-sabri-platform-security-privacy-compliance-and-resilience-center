# صابری سوشل ہومیوپیتھی پلیٹ فارم — مستقل سائبر تحفظ، عوامی رہنمائی اور انتظامی ذمہ داری

**حیثیت:** File 24 repository/source candidate؛ live deployment غیر مصدقہ۔

## ۱۔ مرکزی فیصلہ اور ذمہ داری
- File 24 سلامتی، رازداری، incident evidence اور assurance کا مرکزی مالک ہے۔
- File 00 شناخت و کردار؛ File 02 login/MFA/sessions؛ File 20 عوامی menu؛ File 19/CF02 alerts/support؛ CF01/CF04 مریض و میڈیا کی رازداری۔
- File 24، اصل authentication، host WAF، backup یا native clinical authorization کا متبادل نہیں۔
- عوامی مواد میں secrets، خطرات کی نجی تفصیل، patient charts، backup location، incident logs اور credential information ظاہر نہ ہو۔

## ۲۔ سات مستقل حفاظتی ضوابط
1. انتظامی رسائی: ہوسٹنگ، WordPress، رجسٹرار اور recovery email پر MFA؛ passkeys جہاں دستیاب؛ least privilege اور محفوظ recovery codes۔
2. اپ ڈیٹس: WordPress، تھیم، پلگ اِنز، سرور اور dependencies کی بروقت حفاظتی اصلاح؛ غیر ضروری components ختم۔
3. بیک اپ: فائل + database؛ روزانہ حساس کاروباری تبدیلیوں پر روزانہ؛ الگ encrypted copy؛ isolated restore drill۔
4. ویب تحفظ: WAF، DDoS، login rate limiting، TLS؛ Cloudflare ہو تو Full (strict) اور valid origin certificate؛ رجسٹریشن اور اپائنٹمنٹ retest۔
5. نگرانی: بندش، نامعلوم administrator، مشتبہ فائل/DB تبدیلی اور alerts کی تحقیق۔
6. مریض کی رازداری: وصولی سے private storage؛ ہر view/download پر server-side object access؛ authorized doctor only؛ upload validation and malware scanning۔
7. مشتبہ حملہ: containment، host notice، log preservation، revoked credentials، root cause، clean verified restore اور live retest۔

## ۳۔ اصل coded interfaces
- عوامی WordPress صفحے میں shortcode: [sabri_security_guidance]۔ File 20 سے منظور شدہ مرکزی مینو link دیجیے۔
- Public content: OTP/passkeys، phishing، device safety، patient privacy، suspicious-account response اور Support/Report guidance۔
- Admin: File 24 Security Center کے اندر capability-gated، read-only operator checklist۔
- جامد رہنمائی کو MFA، WAF یا restore کے حقیقی نفاذ کا ثبوت نہیں کہا جائے گا۔

## ۴۔ قبولیت اور Live-First
- Source syntax، registration، public/privacy boundary اور admin authorization tests الگ چلیں۔
- Staging پر WP/PHP version، RTL/mobile/keyboard/400% zoom، page publication، menu integration، File 02 login اور incident-report journey تصدیق ہو۔
- Live، staging اور GitHub الگ؛ exact deployed plugin/code، DB/schema، migrations اور package checksum سے parity ثابت کی جائے۔
- ہر رپورٹ میں defects found/fixed/retested/unresolved/blocked الگ؛ live re-test کے بغیر Resolved نہیں۔
- یہ code change real infrastructure WAF، backup، email-MFA یا independent pen-test activate نہیں کرتا۔

## ۵۔ ماخذ
- صارف کی فراہم کردہ «صابری سوشل ہومیوپیتھی پلیٹ فارم کا مستقل حفاظتی ضابطہ»، ۱۰ نومبر ۲۰۲۶، سات شقیں۔
- «صابری ویب سائٹ کا جامع منصوبہ»، ایڈیشن ۱۲، ابواب ۳، ۵، ۸ اور ۹۔
