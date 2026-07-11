# 🔧 گزارش رفع باگ‌های اتصال + IP detection

این نسخه فورک شده از [`jajajajajahahahhaha/AI-fixed-xray`](https://github.com/jajajajajahahahhaha/AI-fixed-xray) با **۹ فیکس عمیق** روی مشکلات:
- ❌ قطع/وصل شدن مداوم اتصال کاربران
- ❌ IP سیستم بعضی وقتا نشون داده میشد بعضی وقتا نه
- ❌ Xray Race condition + کرش

---

## 🐛 باگ ۱ — `is_xray_core_running()` false positive میداد
**قبل:** `pgrep xray` روی هر پروسه‌ای که اسمش شامل "xray" بود match میکرد (مثل `xray-checker`، حتی خود دستور `pgrep`).  
**نتیجه:** watchdog فکر میکرد Xray زنده‌ست ولی نبود → پنل و کانال تلگرام Xray فعال نشون میدادن ولی کاربران وصل نمیشدن.

**فیکس:** `pgrep -f 'xray -config'` که فقط پروسه‌ی واقعی xray رو match میکنه + validation بر PID عددی.

---

## 🐛 باگ ۲ (بزرگترین!) — چرخه‌ی قطع/وصل از `check_expiration_and_limits`
**قبل:** این تابع هر ۵ ثانیه از لوپ اصلی صدا میشد. اگه یه کاربر برای یه لحظه `live_ips_count > max_ips` میشد (که در NAT، mobile data، یا نویز sniffer معمولاً پیش میاد)، `active=False` میشد و **بلافاصله `sync_xray_core()` صدا میشد که کل Xray رو ریستارت میکنه**. ۲ ثانیه بعد که `speed_and_ip_cleaner` اون IP رو تمیز میکرد، دوباره `active=True` → دوباره `sync_xray_core()`.

**نتیجه:** هر ~۵-۱۰ ثانیه کل Xray ریستارت → **همه‌ی کاربرا** قطع/وصل میشدن.

**فیکس:**
1. **Debounce ۲۰ ثانیه‌ای**: کاربر باید ۲۰ ثانیه پیوسته بیشتر از `max_ips` داشته باشه تا واقعا بلاک بشه.
2. **جدا کردن heavy/light change**: فقط EXPIRED (منقضی شدن حجم یا زمان) `sync_xray_core` رو صدا میزنه. `IP_LIMIT_EXCEEDED` فقط `save_database()` میکنه و از طریق sniffer که ترافیک کاربر بلاک شده رو نادیده میگیره اثر میذاره — **بدون restart Xray**.

**تست شده:** سناریوی flicker (IP لحظه‌ای زیاد بعد کاهش) دیگه کاربر رو بلاک نمی‌کنه، `sync_xray_core` صدا نمیشه. ✅

---

## 🐛 باگ ۳ — Race condition و disk thrashing روی `PANEL_DATABASE`
**قبل:**
- `xray_live_log_sniffer` روی **هر خط لاگ** یه بار `save_database()` صدا میزد. با ۱۰ کاربر فعال میتونست هزاران write در ثانیه بشه.
- هیچ قفلی روی `PANEL_DATABASE` نبود — sniffer، cleaner، expiration checker، و HTTP handlers همه از چند thread میخوندن/مینوشتن.

**نتیجه:** disk thrashing، فایل db گاهی corrupt، پنل کند.

**فیکس:**
- `save_database()` در sniffer فقط **هر ۳ ثانیه یا هر ۲۰۰ خط** صدا زده میشه (throttle).
- کل فراخوانی‌های `PANEL_DATABASE` mutation در `check_expiration_and_limits` با `DB_LOCK` محافظت شده.
- اگه sniffer در حالت idle باشه، dirty flag رو flush میکنه.

---

## 🐛 باگ ۴ — IP detection شکسته و ناقص
**قبل:**
```python
IP_REGEX = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+')
```
- بدون word boundary → توی UUID و target path هم match میشد.
- IP loopback (`127.0.0.1`) و LAN (`10.x`, `192.168.x`, `172.16-31`) و CGNAT و multicast همه به عنوان "IP کاربر" ثبت میشدن.
- بین **IP کاربر** (source) و **IP مقصد** (destination) فرقی نمیذاشت.

**نتیجه:**
- "بعضی وقتا نشون میده، بعضی وقتا نه" — به‌خصوص وقتی لاگ ترتیب IP‌ها فرق میکرد.
- تعداد "IP کاربر" مصنوعی زیاد میشد → کاربر false-positive بلاک میشد (که باگ ۲ رو ترکیب میکرد).

**فیکس:**
- Regex اصلی حالا الگوی `from tcp:X.X.X.X:port` رو target میکنه (استاندارد لاگ Xray).
- Regex fallback برای وقتی لاگ format متفاوت داره.
- تابع `_is_private_or_local_ip()` که همه‌ی رنج‌های RFC1918 + loopback + multicast + CGNAT رو reject میکنه.

**تست شده:** ۹ حالت مختلف لاگ (loopback، private، UUID داخل لاگ، ...) درست کار میکنه. ✅

---

## 🐛 باگ ۵ — تنظیمات policy نامناسب برای شبکه ایران
**قبل:**
- `handshake: 8` ثانیه → برای TLS handshake ایرانی که با DPI مواجه میشه خیلی کمه → reset.
- `connIdle: 900` → کش سشن پر از zombie.
- `uplinkOnly: 5`, `downlinkOnly: 10` → half-close گاهی زودتر از خاتمه واقعی بسته میشد.

**فیکس:** مقادیر تیون شده:
- `handshake: 20` (فرصت TLS handshake روی شبکه سنگین)
- `connIdle: 300` (پاکسازی سریع‌تر زامبی)
- `uplinkOnly: 10`, `downlinkOnly: 30`
- `bufferSize: 10`
- `tcpKeepAlive` از 15/45 → 10/30 (تشخیص سریع‌تر قطعی، جلوگیری از half-open)
- حذف `mark: 0` (بی‌فایده) و `domainStrategy` از داخل sockopt (در Xray جدید unrecognized).

---

## 🐛 باگ ۶ — log rotate باعث ناپدید شدن IP میشد
**قبل:** `xray_live_log_sniffer` یه بار فایل رو باز میکرد و برای همیشه از EOF میخوند. اگه Xray restart میشد یا لاگ rotate → sniffer روی inode قدیمی گیر میکرد و دیگه هیچ IP جدیدی ثبت نمی‌شد.

**نتیجه:** بعد از یه ریستارت Xray (و ما داشتیم زیاد ریستارت میدادیم — باگ ۲!) پنل "بعضی وقتا IP نشون میده بعضی وقتا نه".

**فیکس:** هر ۳ ثانیه inode فایل چک میشه؛ اگه فرق کرد فایل دوباره باز میشه از ابتدا.

---

## 🐛 باگ ۷ — `fuser -k` روی پورت‌ها Xray قدیمی رو hard-kill میکرد
**قبل:** هر بار `sync_xray_core` صدا میشد، `fuser -k 8085/tcp` تمام سوکت‌های اون پورت (شامل WS connections کاربران) رو با SIGKILL می‌کشت.

**فیکس:**
1. اول `pkill -TERM` (graceful shutdown، xray فرصت داره خودش connection ها رو ببنده).
2. ۲ ثانیه صبر.
3. اگه هنوز زنده بود → `pkill -KILL`.
4. `fuser -k` فقط اگه پورت هنوز busy باشه (fallback) — با `ss` چک میشه.

---

## 🐛 باگ ۸ — watchdog خیلی تهاجمی
**قبل:** فقط با ۱ چک داون شدن (`consecutive_down >= 1`) بلافاصله restart میکرد. اگه `sync_xray_core` در حال restart بود، watchdog دوباره میکشتش.

**فیکس:**
- حداقل ۲ چک پیوسته داون شدن (~۱۲ ثانیه) لازمه.
- rate limit: بین دو restart متوالی حداقل ۱۵ ثانیه فاصله.

---

## 🐛 باگ ۹ — SESSION_TOKEN بعد از ریستارت پنل reset میشد
**قبل:** `SESSION_TOKEN = secrets.token_hex(16)` در بارگذاری ماژول → هر بار پنل restart میشد همه‌ی sessionها باطل میشدن.

**فیکس:** توکن در `.panel_session_token` (chmod 600) ذخیره میشه و در startup لود میشه.

---

## ✅ تست‌های خودکار

فایل `test_fixes.py` و `test_integration.py` شامل ۴۰+ تست:
- ✅ IP detection: ۹ سناریوی مختلف
- ✅ debounce IP_LIMIT: کاربر flicker بلاک نمیشه، متخلف واقعی بعد hold بلاک میشه، هیچ کدوم Xray restart نمیخواد
- ✅ atomic_json_write با ۸ thread × ۳۰ write همزمان: فایل معتبر میمونه
- ✅ private/local IP detection: ۱۶ حالت
- ✅ is_xray_core_running: دیگه false positive نمیده
- ✅ integration test: کل چرخه sniffer + expiration + IP limit

**اجرای تست:**
```bash
python3 test_fixes.py
python3 test_integration.py
```

## 🚀 UI و DB و APIها همه دست‌نخورده

هیچ تغییری در ظاهر پنل، ساختار `panel_db.json`، endpoint های HTTP، یا behavior تلگرام بات ایجاد نشده. فقط منطق داخلی fix شده.

## 📊 خلاصه‌ی تاثیر

| مشکل قبل                                    | نتیجه بعد                          |
| ------------------------------------------- | ---------------------------------- |
| کاربران هر ~۵-۱۰ ثانیه قطع/وصل میشدن        | اتصال پایدار                       |
| flicker یه IP، همه کاربرا رو قطع میکرد      | debounce ۲۰s جلوش رو میگیره         |
| IP کاربر گاهی نشون داده نمیشد               | تشخیص دقیق source از لاگ Xray       |
| بعد ریستارت پنل همه لاگ‌اوت میشدن          | session persistent                 |
| بعد rotate لاگ، IP دیگه ثبت نمیشد          | auto-detect و re-open              |
| Xray watchdog باعث restart-loop میشد        | rate limit + threshold             |
