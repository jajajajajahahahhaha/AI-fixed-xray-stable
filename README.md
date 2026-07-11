# 🔧 AI-fixed-xray — Stable Connection Edition

پنل مدیریت Xray با **۹ فیکس عمیق** برای رفع مشکلات:
- ❌ قطع/وصل شدن مداوم کاربران
- ❌ تشخیص ناپایدار IP سیستم
- ❌ Race conditions و disk thrashing

فورک شده از [`jajajajajahahahhaha/AI-fixed-xray`](https://github.com/jajajajajahahahhaha/AI-fixed-xray).

جزئیات کامل تغییرات در [`BUGFIX_NOTES.md`](./BUGFIX_NOTES.md).

## 🧪 اجرای تست‌ها

```bash
python3 test_fixes.py        # ۴۰+ unit test
python3 test_integration.py  # end-to-end scenarios
```

هر دو باید ✅ همه‌ی تست‌ها موفق نشون بدن.

## 🚀 اجرا

مثل نسخه‌ی اصلی:

```bash
python3 analytics_worker.py
```

نیازمندی‌ها: Python 3.7+، `xray-core` نصب شده، `cloudflared` (اختیاری).

## 📋 خلاصه فیکس‌ها

| # | باگ | راه‌حل |
|---|-----|--------|
| 1 | `pgrep xray` false positive | `pgrep -f 'xray -config'` |
| 2 | **قطع/وصل چرخه‌ای** ← `sync_xray_core` هر ۵s | Debounce ۲۰s + جدایی heavy/light change |
| 3 | disk thrashing + no lock | throttle save + DB_LOCK |
| 4 | IP detection شکسته | regex `from ...` + reject private/CGNAT |
| 5 | policy نامناسب برای ایران | handshake ۲۰s، connIdle ۳۰۰s، keepalive ۱۰/۳۰ |
| 6 | log rotate → IP گم میشد | auto reopen on inode change |
| 7 | `fuser -k` کاربر رو میکشت | TERM → KILL escalation |
| 8 | watchdog restart-loop | ۲ چک + ۱۵s rate-limit |
| 9 | SESSION_TOKEN reset بعد restart | persistent file |

## ⚠️ نکته

این فورک UI، ساختار DB، endpoint‌های HTTP، و رفتار بات تلگرام رو **دست‌نخورده** نگه داشته. فقط منطق داخلی تعمیر شده.
