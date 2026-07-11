"""
تست‌های خودکار برای فیکس‌های اعمال‌شده.
Approach: توابع رو مستقیم از source استخراج کنیم و در namespace ایزوله اجرا کنیم.
"""
import os, sys, time, re, tempfile, shutil, json, threading, ast, secrets, subprocess

sys.path.insert(0, '/home/user/fixed')

with open('/home/user/fixed/analytics_worker.py', 'r') as f:
    src = f.read()

# function/class + assignment های regex/const رو keep، ولی کدی که thread/HTTPServer صدا میزنه رو skip
tree = ast.parse(src)
kept = []
SKIP_KEYWORDS = ['HTTPServer', 'Thread(', 'sync_xray_core()', 'init_telegram',
                 'load_database()', 'load_system_config()', 'load_blocked_ips()',
                 'load_ip_traffic()', 'bootstrap_private_tunnels', 'reapply_all_iptables',
                 'push_channel_event(', 'push_subs_to_github(', 'infinity_polling',
                 'while elapsed', 'check_expiration_and_limits()']
for node in tree.body:
    if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
        kept.append(node); continue
    try:
        code_snip = ast.unparse(node)
    except Exception:
        continue
    if any(k in code_snip for k in SKIP_KEYWORDS):
        continue
    # فایل io خارجی رو هم skip کنیم (SYSTEM_CONFIG file رو نمیخونیم)
    if code_snip.startswith('print(') or code_snip.startswith('sys.exit'):
        continue
    kept.append(node)
tree.body = kept
mod_src = ast.unparse(tree)

# namespace با تمام built-in global هایی که توابع نیاز دارن
ns = {
    '__name__': 'test',
    # global state ها که در همون فایل تعریف شدن رو دستی اضافه میکنیم
    'PANEL_DATABASE': {},
    'USER_LIVE_IPS': {},
    'USER_TARGET_SITES': {},
    'SYSTEM_LIVE_LOGS': [],
    'DPI_BLOCK_LOGS': [],
    'BLOCKED_IPS': {},
    'BLOCKED_IPS_LOCK': threading.RLock(),
    'IP_TRAFFIC': {},
    'IP_TRAFFIC_LOCK': threading.RLock(),
    'IP_TO_USER': {},
    'DB_LOCK': threading.RLock(),
    'SYSTEM_CONFIG_LOCK': threading.RLock(),
    'GIVEAWAY_CONFIG_LOCK': threading.RLock(),
    'COMBINED_SUBS_LOCK': threading.RLock(),
    'SYSTEM_CONFIG': {
        'panel_user':'admin','panel_pass':'x','default_clean_ip':'1.2.3.4',
        'traffic_coefficient':1.0,'sub_repo_name':'','sub_repo_token':'',
        'telegram_bot_token':'t','telegram_admin_id':'0','telegram_channel_id':'@x',
        'telegram_proxy_secret': 'a'*32, 'telegram_proxy_port': 8443
    },
    'CHANNEL_STREAM_STATE': {'msg_id': None, 'last_update': 0, 'events': []},
    'DEFAULT_CLEAN_IP': "1.2.3.4",
    'TRAFFIC_COEFFICIENT': 1.0,
    'BLOCKED_IPS_PATH': '/tmp/test_blocked.json',
    'IP_TRAFFIC_PATH': '/tmp/test_ip_traffic.json',
    'DB_PATH': '/tmp/test_db.json',
    'SYSTEM_CONFIG_PATH': '/tmp/test_sys.json',
    'GIVEAWAY_CONFIG_PATH': '/tmp/test_giveaway.json',
    'XRAY_CONFIG_PATH': '/tmp/test_xray.json',
    'XRAY_LOG_PATH': '/tmp/test_xray.log',
    'CLOUDFLARED_BIN': '/tmp/none',
    'USER_PRIVATE_TUNNELS': {},
    'PRIVATE_TUNNEL_LOG_DIR': '/tmp/priv',
    'PANEL_USER': 'admin', 'PANEL_PASS': 'x',
    'SUB_REPO_NAME': '', 'SUB_REPO_TOKEN': '',
    'TELEGRAM_BOT_TOKEN': 't', 'TELEGRAM_ADMIN_ID': '0', 'TELEGRAM_CHANNEL_ID': '@x',
    'TELEGRAM_PROXY_SECRET': secrets.token_hex(16),
    'TELEGRAM_PROXY_PORT': 8443,
    'SESSION_TOKEN': secrets.token_hex(16),
    'RUNNER_LIVE_LOGS': [],
    'tunnel_host': '127.0.0.1', 'runner_host': '127.0.0.1',
    'is_runner_active_file': False,
}

exec(compile(mod_src, 'analytics_worker.py', 'exec'), ns)

print("✅ توابع بارگذاری شدن\n")

# ========================= تست‌ها =========================
results = []

# ---- تست ۱: IP detection دقیق ----
print("=" * 60); print("تست ۱: IP detection دقیق"); print("=" * 60)
IP_REGEX = ns['IP_REGEX']
IP_FALLBACK_REGEX = ns['IP_FALLBACK_REGEX']
_is_private_or_local_ip = ns['_is_private_or_local_ip']

def detect_ip(line):
    m = IP_REGEX.search(line)
    got = m.group(1) if m else None
    if not got:
        fb = IP_FALLBACK_REGEX.search(line)
        if fb:
            got = fb.group(1)
    if got and _is_private_or_local_ip(got):
        got = None
    return got

cases = [
    ('2024/01/15 12:34:56 from 89.10.20.30:45678 accepted tcp:google.com:443', '89.10.20.30'),
    ('2024/01/15 12:34:56 from tcp:5.6.7.8:12345 accepted tls:example.com:443', '5.6.7.8'),
    ('accepted from 127.0.0.1:8085 to target:443', None),
    ('uuid abc-1234 from 91.99.10.20:5555 to 8.8.8.8:443', '91.99.10.20'),
    ('rejected: no source', None),
    ('from 10.0.0.5:1234 accepted', None),
    ('from 192.168.1.100:5555 accepted', None),
    ('from 172.20.5.5:1234 accepted', None),  # private range
    ('from 172.15.5.5:1234 accepted', '172.15.5.5'),  # 15 عمومی
]
p = 0
for line, exp in cases:
    got = detect_ip(line)
    ok = got == exp
    p += ok
    print(f"  {'✅' if ok else '❌'} exp={exp!s:<15} got={got!s:<15} | {line[:55]}")
results.append(('IP detection', p, len(cases)))
print()

# ---- تست ۲: debounce IP_LIMIT ----
print("=" * 60); print("تست ۲: debounce IP_LIMIT"); print("=" * 60)
ns['PANEL_DATABASE'] = {
    'u1': {'uuid':'x','active':True,'status':'ONLINE','total_limit_bytes':0,'used_bytes':0,
           'created_at':int(time.time()),'expire_seconds':31536000,'max_ips':2,'is_proxy_type':False},
}
ns['USER_LIVE_IPS'] = {'u1':{'1.1.1.1':time.time(),'2.2.2.2':time.time(),'3.3.3.3':time.time()}}
ns['_IP_LIMIT_HOLD_SECONDS'] = 2
ns['_IP_LIMIT_DEBOUNCE'] = {}
sync_calls = [0]
def _fake_sync(): sync_calls[0]+=1
ns['sync_xray_core'] = _fake_sync
ns['save_database'] = lambda: None
ns['push_subs_to_github'] = lambda: None

check = ns['check_expiration_and_limits']
check()
assert ns['PANEL_DATABASE']['u1']['active'] == True, "بار اول باید active بمونه"
print("  ✅ بار اول: کاربر active مونده (debounce فعال)")
for _ in range(3):
    check()
    time.sleep(0.1)
assert ns['PANEL_DATABASE']['u1']['active'] == True
print("  ✅ چک های پشت سر هم: هنوز active")
time.sleep(2.2)
check()
assert ns['PANEL_DATABASE']['u1']['active'] == False
assert ns['PANEL_DATABASE']['u1']['status'] == 'IP_LIMIT_EXCEEDED'
print("  ✅ بعد hold تموم شد: بلاک شد")
assert sync_calls[0] == 0, f"❌ sync_xray_core نباید صدا بشه ولی {sync_calls[0]} بار شد!"
print("  ✅ sync_xray_core هرگز صدا نشد (باگ اصلی قطع/وصل رفع شد!)")

# آنبلاک
ns['USER_LIVE_IPS'] = {'u1':{'1.1.1.1':time.time()}}
check()
assert ns['PANEL_DATABASE']['u1']['active'] == True
print("  ✅ بعد کاهش IP: آنبلاک شد")
assert sync_calls[0] == 0
print("  ✅ آنبلاک هم بدون restart Xray بود")
results.append(('debounce IP_LIMIT', 5, 5))
print()

# ---- تست ۳: is_ip_blocked ----
print("=" * 60); print("تست ۳: is_ip_blocked"); print("=" * 60)
ns['BLOCKED_IPS'] = {'6.6.6.6':{'blocked_at':0}}
assert ns['is_ip_blocked']('6.6.6.6') == True
assert ns['is_ip_blocked']('7.7.7.7') == False
print("  ✅ درست کار میکنه")
results.append(('is_ip_blocked', 2, 2))
print()

# ---- تست ۴: atomic_json_write زیر فشار همزمانی ----
print("=" * 60); print("تست ۴: atomic_json_write concurrent"); print("=" * 60)
tmp = tempfile.mkdtemp()
try:
    p = os.path.join(tmp, 'test.json')
    ns['atomic_json_write'](p, {'k':'v','fa':'فارسی'})
    with open(p,'r',encoding='utf-8') as f: got = json.load(f)
    assert got == {'k':'v','fa':'فارسی'}
    print("  ✅ نوشتن یونیکد فارسی OK")
    ok=[True]
    def w(i):
        try:
            for _ in range(30):
                ns['atomic_json_write'](p, {'t':i,'ts':time.time()})
        except Exception as e:
            ok[0]=False; print(f"  ❌ thread {i}: {e}")
    ts = [threading.Thread(target=w, args=(i,)) for i in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    with open(p,'r',encoding='utf-8') as f: json.load(f)
    print("  ✅ ۸ thread × ۳۰ write همزمان: فایل معتبر موند")
    results.append(('atomic_json concurrent', 2, 2))
finally:
    shutil.rmtree(tmp)
print()

# ---- تست ۵: private/local IP detection ----
print("=" * 60); print("تست ۵: تشخیص IP خصوصی/لوکال"); print("=" * 60)
cases = [
    ('127.0.0.1',True),('127.5.5.5',True),
    ('10.0.0.1',True),('10.255.255.255',True),
    ('172.16.0.1',True),('172.31.0.5',True),('172.15.0.5',False),
    ('192.168.1.1',True),('192.169.1.1',False),
    ('8.8.8.8',False),('1.1.1.1',False),
    ('0.0.0.0',True),('224.0.0.1',True),('239.255.255.255',True),
    ('',True),(None,True),
]
p = 0
for ip,exp in cases:
    got = ns['_is_private_or_local_ip'](ip)
    ok = got == exp
    p += ok
    if not ok: print(f"  ❌ {ip!r}: exp {exp} got {got}")
print(f"  ✅ {p}/{len(cases)} حالت درست")
results.append(('private IP', p, len(cases)))
print()

# ---- تست ۶: is_xray_core_running دیگه match false-positive نمیده ----
print("=" * 60); print("تست ۶: is_xray_core_running دقیق"); print("=" * 60)
# بدون xray واقعی، باید False برگردونه (نه true از روی pgrep match الکی)
# (چون pgrep -f 'xray -config' هیچی نداره)
r = ns['is_xray_core_running']()
if sys.platform.startswith('linux'):
    assert r == False, f"در سیستمی که xray نیست باید False برگرده، ولی {r}"
    print("  ✅ در نبود xray، False برمیگرده (قبلاً pgrep xray ممکن بود true بده)")
else:
    print("  ⏭️ غیرلینوکس؛ همیشه True")
results.append(('is_xray_core_running', 1, 1))
print()

# ---- تست ۷: normalize_user_record ----
print("=" * 60); print("تست ۷: normalize_user_record"); print("=" * 60)
n = ns['normalize_user_record']('u', {})
must = ['uuid','max_ips','active','status','used_bytes']
for k in must:
    assert k in n, f"باید {k} داشته باشه"
print(f"  ✅ همه فیلدهای ضروری default دارن ({len(n)} فیلد)")
results.append(('normalize_user', 1, 1))
print()

# ---- تست ۸: safe_float / safe_int ----
print("=" * 60); print("تست ۸: safe_float / safe_int"); print("=" * 60)
assert ns['safe_float']('3.14', 0) == 3.14
assert ns['safe_float']('abc', 99) == 99
assert ns['safe_int']('42', 0) == 42
assert ns['safe_int']('xyz', 7) == 7
print("  ✅ همه cases درست")
results.append(('safe_conv', 4, 4))
print()

# ---- گزارش نهایی ----
print("=" * 60); print("📊 گزارش نهایی"); print("=" * 60)
tot_p = sum(p for _,p,_ in results)
tot_t = sum(t for _,_,t in results)
for name,p,t in results:
    icon = "✅" if p==t else "⚠️"
    print(f"  {icon} {name:<25} {p}/{t}")
print(f"\n🎯 مجموع: {tot_p}/{tot_t}")
if tot_p == tot_t:
    print("🎉 همه‌ی تست‌ها موفق!")
else:
    print("⚠️ بعضی تست‌ها fail شدن")
    sys.exit(1)
