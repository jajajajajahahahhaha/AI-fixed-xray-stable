"""
Integration test: شبیه‌سازی یه سناریوی واقعی
- ۲ کاربر با max_ips=2
- لاگ های Xray واقعی
- بررسی که آیا کاربر با flicker (IP لحظه‌ای زیاد) بلاک میشه یا نه
"""
import os, sys, time, tempfile, threading, ast, secrets, json

with open('/home/user/fixed/analytics_worker.py', 'r') as f:
    src = f.read()

tree = ast.parse(src)
SKIP = ['HTTPServer','Thread(','sync_xray_core()','init_telegram',
        'load_database()','load_system_config()','load_blocked_ips()',
        'load_ip_traffic()','bootstrap_private_tunnels','reapply_all_iptables',
        'push_channel_event(','push_subs_to_github(','infinity_polling',
        'while elapsed','check_expiration_and_limits()']
kept=[]
for n in tree.body:
    if isinstance(n,(ast.FunctionDef,ast.ClassDef,ast.Import,ast.ImportFrom)):
        kept.append(n); continue
    try: s = ast.unparse(n)
    except: continue
    if any(k in s for k in SKIP): continue
    if s.startswith('print(') or s.startswith('sys.exit'): continue
    kept.append(n)
tree.body = kept
mod_src = ast.unparse(tree)

ns = {
    '__name__':'test','PANEL_DATABASE':{},'USER_LIVE_IPS':{},'USER_TARGET_SITES':{},
    'SYSTEM_LIVE_LOGS':[],'DPI_BLOCK_LOGS':[],'BLOCKED_IPS':{},
    'BLOCKED_IPS_LOCK':threading.RLock(),'IP_TRAFFIC':{},'IP_TRAFFIC_LOCK':threading.RLock(),
    'IP_TO_USER':{},'DB_LOCK':threading.RLock(),'SYSTEM_CONFIG_LOCK':threading.RLock(),
    'GIVEAWAY_CONFIG_LOCK':threading.RLock(),'COMBINED_SUBS_LOCK':threading.RLock(),
    'SYSTEM_CONFIG':{'panel_user':'admin','panel_pass':'x','default_clean_ip':'1.2.3.4',
        'traffic_coefficient':1.0,'sub_repo_name':'','sub_repo_token':'',
        'telegram_bot_token':'t','telegram_admin_id':'0','telegram_channel_id':'@x',
        'telegram_proxy_secret':'a'*32,'telegram_proxy_port':8443},
    'CHANNEL_STREAM_STATE':{'msg_id':None,'last_update':0,'events':[]},
    'DEFAULT_CLEAN_IP':'1.2.3.4','TRAFFIC_COEFFICIENT':1.0,
    'BLOCKED_IPS_PATH':'/tmp/tb.json','IP_TRAFFIC_PATH':'/tmp/tt.json',
    'DB_PATH':'/tmp/tdb.json','SYSTEM_CONFIG_PATH':'/tmp/tsys.json',
    'GIVEAWAY_CONFIG_PATH':'/tmp/tg.json','XRAY_CONFIG_PATH':'/tmp/txc.json',
    'XRAY_LOG_PATH':'/tmp/txr.log','CLOUDFLARED_BIN':'/tmp/none',
    'USER_PRIVATE_TUNNELS':{},'PRIVATE_TUNNEL_LOG_DIR':'/tmp/priv',
    'PANEL_USER':'admin','PANEL_PASS':'x','SUB_REPO_NAME':'','SUB_REPO_TOKEN':'',
    'TELEGRAM_BOT_TOKEN':'t','TELEGRAM_ADMIN_ID':'0','TELEGRAM_CHANNEL_ID':'@x',
    'TELEGRAM_PROXY_SECRET':'a'*32,'TELEGRAM_PROXY_PORT':8443,
    'SESSION_TOKEN':secrets.token_hex(16),'RUNNER_LIVE_LOGS':[],
    'tunnel_host':'127.0.0.1','runner_host':'127.0.0.1','is_runner_active_file':False,
}
exec(compile(mod_src,'analytics_worker.py','exec'), ns)

# سناریو
ns['PANEL_DATABASE'] = {
    'ali': {'uuid':'11111111-1111-1111-1111-111111111111','active':True,'status':'ONLINE',
            'total_limit_bytes':100*1024*1024*1024,'used_bytes':0,
            'created_at':int(time.time()),'expire_seconds':2592000,
            'max_ips':2,'is_proxy_type':False,'real_traffic':True,'coefficient':1.0,
            'last_active_time':0,'down_speed':0,'up_speed':0},
    'reza': {'uuid':'22222222-2222-2222-2222-222222222222','active':True,'status':'OFFLINE',
             'total_limit_bytes':10*1024*1024*1024,'used_bytes':0,
             'created_at':int(time.time()),'expire_seconds':2592000,
             'max_ips':3,'is_proxy_type':False,'real_traffic':False,'coefficient':1.5,
             'last_active_time':0,'down_speed':0,'up_speed':0},
}
ns['_IP_LIMIT_HOLD_SECONDS'] = 3
sync_calls=[0]
ns['sync_xray_core'] = lambda: sync_calls.__setitem__(0, sync_calls[0]+1)
ns['save_database'] = lambda: None
ns['push_subs_to_github'] = lambda: None

check = ns['check_expiration_and_limits']

print("=" * 60)
print("سناریو ۱: کاربر ali با flicker (IP لحظه‌ای زیاد)")
print("=" * 60)
# ali فقط ۱ ثانیه ۳ تا IP دارد بعد برمیگرده به ۲
ns['USER_LIVE_IPS'] = {'ali':{'1.1.1.1':time.time(),'2.2.2.2':time.time(),'3.3.3.3':time.time()}}
check()
print(f"  T=0: active={ns['PANEL_DATABASE']['ali']['active']}  sync_calls={sync_calls[0]}")
time.sleep(1)
ns['USER_LIVE_IPS'] = {'ali':{'1.1.1.1':time.time(),'2.2.2.2':time.time()}}
check()
print(f"  T=1 (کاهش IP): active={ns['PANEL_DATABASE']['ali']['active']}  sync_calls={sync_calls[0]}")
assert ns['PANEL_DATABASE']['ali']['active'] == True
assert sync_calls[0] == 0
print("  ✅ Flicker نتوانست کاربر رو بلاک کنه (سناریوی مقصر اصلی قطع/وصل)")
print()

print("=" * 60)
print("سناریو ۲: کاربر ali مداوم ۳ IP (violation واقعی)")
print("=" * 60)
sync_calls[0] = 0
ns['USER_LIVE_IPS'] = {'ali':{'1.1.1.1':time.time(),'2.2.2.2':time.time(),'4.4.4.4':time.time()}}
ns['_IP_LIMIT_DEBOUNCE'] = {}
ns['PANEL_DATABASE']['ali']['active'] = True
ns['PANEL_DATABASE']['ali']['status'] = 'ONLINE'

t0 = time.time()
while time.time() - t0 < 4:
    check()
    time.sleep(0.5)
    # IP رو زنده نگه دار
    ns['USER_LIVE_IPS']['ali'] = {k:time.time() for k in ns['USER_LIVE_IPS']['ali']}

st = ns['PANEL_DATABASE']['ali']
print(f"  بعد ۴ ثانیه violation مداوم: active={st['active']}  status={st['status']}")
print(f"  sync_xray_core فراخوانی‌ها: {sync_calls[0]} (باید 0 باشه چون فقط IP_LIMIT است)")
assert st['active'] == False
assert st['status'] == 'IP_LIMIT_EXCEEDED'
assert sync_calls[0] == 0
print("  ✅ کاربر متخلف بلاک شد، بدون restart Xray (باقی کاربرا قطع نمیشن)")
print()

print("=" * 60)
print("سناریو ۳: انقضای واقعی (که باید Xray رو ریلود کنه)")
print("=" * 60)
sync_calls[0] = 0
ns['PANEL_DATABASE']['reza']['created_at'] = int(time.time()) - 10*24*3600
ns['PANEL_DATABASE']['reza']['expire_seconds'] = 5*24*3600  # منقضی شده
ns['PANEL_DATABASE']['reza']['active'] = True
ns['PANEL_DATABASE']['reza']['status'] = 'ONLINE'
check()
st = ns['PANEL_DATABASE']['reza']
print(f"  reza: active={st['active']}  status={st['status']}  sync_calls={sync_calls[0]}")
assert st['status'] == 'EXPIRED'
assert sync_calls[0] == 1
print("  ✅ انقضا واقعا Xray رو reload میکنه (heavy change)")
print()

print("=" * 60)
print("سناریو ۴: sniffer با خط لاگ واقعی")
print("=" * 60)
# شبیه‌سازی خط لاگ واقعی
log_line = "2024/01/15 12:34:56 [Info] [1234567] proxy/vless/inbound: firstLen = 517 from 91.99.10.20:45678 accepted tcp:google.com:443 [inbound-vless-8085] uplink: 1024 bytes downlink: 4096 bytes"
IP_REGEX = ns['IP_REGEX']; IP_FALLBACK = ns['IP_FALLBACK_REGEX']
_priv = ns['_is_private_or_local_ip']
DOMAIN = ns['DOMAIN_REGEX']
TRAF = ns['REAL_TRAFFIC_REGEX']

m = IP_REGEX.search(log_line)
ip = m.group(1) if m else None
if not ip:
    fb = IP_FALLBACK.search(log_line)
    ip = fb.group(1) if fb else None
if ip and _priv(ip): ip = None
print(f"  IP کاربر: {ip}")
assert ip == '91.99.10.20'

d = DOMAIN.search(log_line)
domain = d.group(1) or d.group(2) if d else None
print(f"  Domain: {domain}")
assert domain == 'google.com'

t = TRAF.search(log_line)
up = int(t.group(1) or 0); dn = int(t.group(2) or 0)
print(f"  Traffic: uplink={up}  downlink={dn}")
assert up == 1024 and dn == 4096
print("  ✅ کل پارس لاگ Xray درست کار میکنه")
print()

print("=" * 60)
print("سناریو ۵: تست UUID های داخل لاگ به IP اشتباه match نمیشن")
print("=" * 60)
# UUID شامل عدد و '-' هست، regex نباید توش IP ببینه
uuid_log = "accepted user email:11111111-1111-1111-1111-111111111111 destination 8.8.8.8:443"
m = IP_REGEX.search(uuid_log)
ip = m.group(1) if m else None
if not ip:
    fb = IP_FALLBACK.search(uuid_log)
    ip = fb.group(1) if fb else None
if ip and _priv(ip): ip = None
print(f"  فقط IP مقصد (8.8.8.8) به عنوان fallback میاد: {ip}")
# نکته: پترن اصلی from ندیده پس fallback میاد. اینجا 8.8.8.8:443 هست
assert ip == '8.8.8.8'
print("  ✅ اگه پترن 'from' نباشه fallback میره سراغ IP قابل مشاهده (نه UUID hex)")
print()

print("=" * 60)
print("🎉 همه سناریوهای integration pass شدن!")
print("=" * 60)
