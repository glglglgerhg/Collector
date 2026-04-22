#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Configs Collector & Proxy - РАБОЧАЯ ВЕРСИЯ
- /sub/СЕКРЕТ — тандем двух серверов
- /whitelist — жесткая проверка VLESS (TCP + TLS + VLESS handshake)
"""

from flask import Flask, Response, request, abort
import requests
import base64
import re
import time
import logging
import sys
import json
import socket
import ssl
import threading
import struct
import sqlite3
import os
from queue import Queue, Empty
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict
from functools import wraps
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ==================== НАСТРОЙКИ ====================
WORK_DIR = Path(__file__).parent
DATA_DIR = WORK_DIR / "vpn_data"
DATA_DIR.mkdir(exist_ok=True)

TANDEM_SERVERS = [
    {"url": "https://2.27.86.119:2096/sub/{secret}", "name": "Germany", "flag": "🇩🇪", "type": "general"},   
    {"url": "https://195.133.9.107:2096/sub/{secret}", "name": "Netherlands", "flag": "🇳🇱", "type": "reserve"},
]

WHITELIST_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/vless.txt",
    "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/mix.txt",
]

MAX_WHITELIST_CONFIGS = 325
WHITELIST_OUTPUT = DATA_DIR / "whitelist_checked.txt"
WHITELIST_STATUS = DATA_DIR / "whitelist_status.json"
DB_PATH = DATA_DIR / "data.db"

# Настройки проверки
MAX_WORKERS = 350
TCP_TIMEOUT = 3
TLS_TIMEOUT = 3
HTTP_TIMEOUT = 2

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler(DATA_DIR / "collector.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

PANEL_USER = os.getenv("PANEL_USER", "admin")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD", "change-me")
LOG_QUEUE_MAXSIZE = 5000
_log_queue = Queue(maxsize=LOG_QUEUE_MAXSIZE)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS subscription_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                secret TEXT,
                requested_url TEXT NOT NULL,
                client_ip TEXT,
                hwid TEXT,
                device TEXT,
                os TEXT,
                user_agent TEXT,
                country TEXT,
                region_name TEXT,
                city TEXT,
                lat REAL,
                lon REAL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_subscription_logs_ts ON subscription_logs(ts)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_subscription_logs_ip ON subscription_logs(client_ip)")


def panel_auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != PANEL_USER or auth.password != PANEL_PASSWORD:
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="Collector Panel"'}
            )
        return fn(*args, **kwargs)
    return wrapper


def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return (request.headers.get("X-Real-IP") or request.remote_addr or "").strip()


def get_client_geo(ip):
    if not ip or ip in ("127.0.0.1", "::1"):
        return {}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,lat,lon"},
            timeout=2
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "region_name": data.get("regionName"),
                    "city": data.get("city"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                }
    except Exception:
        pass
    return {}


def get_time_from_filter(period):
    now = int(time.time())
    if period == "day":
        return now - 24 * 60 * 60
    if period == "week":
        return now - 7 * 24 * 60 * 60
    return now - 30 * 24 * 60 * 60


def log_subscription_access(secret):
    client_ip = get_client_ip()
    geo = get_client_geo(client_ip)
    hwid = request.args.get("hwid") or request.headers.get("X-HWID", "")
    device = request.args.get("device") or request.headers.get("X-Device", "")
    os_name = request.args.get("os") or request.headers.get("X-OS", "")
    user_agent = request.headers.get("User-Agent", "")
    requested_url = request.full_path[:-1] if request.full_path.endswith("?") else request.full_path

    with get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO subscription_logs (
                ts, secret, requested_url, client_ip, hwid, device, os, user_agent,
                country, region_name, city, lat, lon
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(time.time()),
                secret,
                requested_url,
                client_ip,
                hwid,
                device,
                os_name,
                user_agent,
                geo.get("country"),
                geo.get("region_name"),
                geo.get("city"),
                geo.get("lat"),
                geo.get("lon"),
            )
        )


init_db()


# ==================== ФУНКЦИИ ДЛЯ ТАНДЕМА ====================

def decode_subscription(content):
    try:
        content = content.strip()
        if not content.startswith(('vless://', 'vmess://', 'ss://', 'trojan://')):
            decoded = base64.b64decode(content).decode('utf-8')
            return decoded
        return content
    except Exception as e:
        logger.error(f"Decode error: {e}")
        return None


def extract_configs(text):
    configs = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(('vless://', 'vmess://', 'ss://', 'trojan://', 'hysteria2://')):
            configs.append(line)
    return configs


def extract_name_from_config(config):
    match = re.search(r'#([^#]+)$', config)
    if match:
        name = match.group(1).strip()
        name = re.split(r'[-_\s]', name)[0]
        name = re.sub(r'[^\w]', '', name)
        if name:
            return name
    return None


def fetch_tandem_server(server, secret):
    try:
        url = server["url"].format(secret=secret)
        logger.info(f"Fetching from {server['name']}: {url}")
        
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, verify=False, timeout=10)
        
        if response.status_code != 200:
def write_subscription_log(payload):
    client_ip = payload.get("client_ip", "")
                country, region_name, city, lat, lon, geo_source
                payload.get("ts", int(time.time())),
                payload.get("secret", ""),
                payload.get("requested_url", ""),
                payload.get("hwid", ""),
                payload.get("device", ""),
                payload.get("os_name", ""),
                payload.get("user_agent", ""),
def enqueue_subscription_access(secret):
    payload = {
        "ts": int(time.time()),
        "secret": secret,
        "requested_url": request.full_path[:-1] if request.full_path.endswith("?") else request.full_path,
        "client_ip": get_client_ip(),
        "hwid": request.args.get("hwid") or request.headers.get("X-HWID", ""),
        "device": request.args.get("device") or request.headers.get("X-Device", ""),
        "os_name": request.args.get("os") or request.headers.get("X-OS", ""),
        "user_agent": request.headers.get("User-Agent", ""),
    }
    try:
        _log_queue.put_nowait(payload)
    except Exception:
        logger.warning("Log queue is full; skipping one subscription log entry")


def start_log_worker():
    def worker():
        while True:
            try:
                payload = _log_queue.get(timeout=1)
            except Empty:
                continue
            try:
                write_subscription_log(payload)
            except Exception as e:
                logger.error(f"Failed to write subscription log: {e}")
            finally:
                _log_queue.task_done()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    logger.info("🧾 Log worker started")


start_log_worker()
            cfg = re.sub(r'#.*$', '', cfg)
            fixed_configs.append(f"{cfg}#{new_name}")
        
        return fixed_configs
        
    except Exception as e:
        logger.error(f"Error from {server['name']}: {e}")
        return []


# ==================== ПАРСИНГ VLESS ====================

def parse_vless_config(config):
    """Парсит VLESS конфиг"""
    match = re.match(r'vless://([a-f0-9\-]+)@([^:]+):(\d+)(\?[^#]*)?#?(.*)?', config)
    if not match:
        return None
    
    uuid, host, port, params, name = match.groups()
    port = int(port)
    params = params or ''
    
    parsed = {
        'uuid': uuid,
        'host': host,
        'port': port,
        'name': name or '',
        'security': 'tls',
        'sni': host,
        'raw': config,
        'flow': ''
    }
    
    if params and params.startswith('?'):
        for param in params[1:].split('&'):
            if '=' in param:
                k, v = param.split('=', 1)
                if k == 'security':
                    parsed['security'] = v
                elif k == 'sni':
                    parsed['sni'] = v
                elif k == 'flow':
                    parsed['flow'] = v
    
    try:
        parsed['resolved_ip'] = socket.gethostbyname(host)
    except:
        parsed['resolved_ip'] = host
    
    return parsed


# ==================== ЖЕСТКАЯ ПРОВЕРКА ====================

def test_vless_full(parsed):
    """
    Полная проверка VLESS:
    1. TCP connect (реальный пинг)
    2. TLS handshake
    3. HTTP запрос (проверка что прокси работает)
    """
    result = {
        'working': False,
        'ping': None,
        'tcp_ms': None,
        'tls_ms': None,
        'http_ok': False,
        'error': None,
        'parsed': parsed
    }
    
    # 1. TCP connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        start_tcp = time.time()
        sock.connect((parsed['resolved_ip'], parsed['port']))
        tcp_time = (time.time() - start_tcp) * 1000
        result['tcp_ms'] = round(tcp_time, 1)
        result['ping'] = round(tcp_time, 1)
    except Exception as e:
        result['error'] = f"TCP: {str(e)[:30]}"
        return result
    
    # 2. TLS handshake (если security=tls)
    if parsed['security'] == 'tls':
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            start_tls = time.time()
            sock_tls = context.wrap_socket(sock, server_hostname=parsed['sni'])
            sock_tls.do_handshake()
            tls_time = (time.time() - start_tls) * 1000
            result['tls_ms'] = round(tls_time, 1)
            
            # 3. HTTP запрос (простейшая проверка)
            try:
                http_request = f"GET / HTTP/1.1\r\nHost: {parsed['sni']}\r\nConnection: close\r\n\r\n"
                sock_tls.send(http_request.encode())
                sock_tls.settimeout(HTTP_TIMEOUT)
                response = sock_tls.recv(256)
                if response and (b'HTTP/' in response or b'200' in response or b'301' in response or b'302' in response):
                    result['http_ok'] = True
            except:
                pass
            
            sock_tls.close()
            result['working'] = True
            
        except Exception as e:
            result['error'] = f"TLS: {str(e)[:30]}"
            sock.close()
    else:
        sock.close()
        result['working'] = True
    
    return result


# ==================== СБОР КОНФИГОВ ====================

def fetch_vless_configs():
    """Собирает VLESS конфиги из всех источников"""
    logger.info("=" * 60)
    logger.info("📡 СБОР VLESS КОНФИГОВ")
    logger.info("=" * 60)
    
    all_configs = []
    seen = set()
    
    for url in WHITELIST_SOURCES:
        try:
            logger.info(f"  Загрузка: {url.split('/')[-1][:40]}...")
            response = requests.get(url, timeout=30, verify=False)
            
            if response.status_code != 200:
                logger.warning(f"    ❌ HTTP {response.status_code}")
                continue
            
            added = 0
            for line in response.text.splitlines():
                line = line.strip()
                if line.startswith('vless://'):
                    if line not in seen:
                        seen.add(line)
                        all_configs.append(line)
                        added += 1
            
            logger.info(f"    ✅ Добавлено {added} VLESS конфигов")
            
        except Exception as e:
            logger.error(f"    ❌ Ошибка: {e}")
    
    logger.info(f"\n📊 Всего уникальных VLESS конфигов: {len(all_configs)}")
    return all_configs


# ==================== ОСНОВНАЯ ПРОВЕРКА ====================

def run_whitelist_check():
    """Основная функция проверки"""
    logger.info("=" * 60)
    logger.info("🚀 ЖЕСТКАЯ ПРОВЕРКА WHITELIST (TCP + TLS + HTTP)")
    logger.info("=" * 60)
    
    start_time = time.time()
    
    # 1. Собираем конфиги
    all_configs = fetch_vless_configs()
    if not all_configs:
        logger.warning("❌ Нет VLESS конфигов для проверки")
        return
    
    # 2. Парсим
    logger.info("🔍 Парсинг конфигов...")
    parsed_configs = []
    for cfg in all_configs:
        p = parse_vless_config(cfg)
        if p:
            parsed_configs.append(p)
    
    logger.info(f"✅ Распарсено: {len(parsed_configs)}/{len(all_configs)}")
    
    if not parsed_configs:
        logger.warning("❌ Нет валидных конфигов")
        return
    
    # 3. Проверяем
    logger.info(f"⚡ Проверка {len(parsed_configs)} серверов ({MAX_WORKERS} потоков)...")
    
    valid_results = []
    stats = {'total': len(parsed_configs), 'tcp_ok': 0, 'http_ok': 0}
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_vless_full, p): p for p in parsed_configs}
        
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            
            if result['working']:
                stats['tcp_ok'] += 1
                if result.get('http_ok'):
                    stats['http_ok'] += 1
                valid_results.append(result)
            
            # Показываем прогресс
            if i % 100 == 0:
                logger.info(f"  Прогресс: {i}/{stats['total']}, найдено: {len(valid_results)}")
    
    # 4. Сортируем по пингу
    valid_results.sort(key=lambda x: x['ping'])
    
    # 5. Ограничиваем количество
    if len(valid_results) > MAX_WHITELIST_CONFIGS:
        valid_results = valid_results[:MAX_WHITELIST_CONFIGS]
        logger.info(f"✂️ Ограничено до {MAX_WHITELIST_CONFIGS} конфигов")
    
    # 6. Сохраняем
    with open(WHITELIST_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(f"# profile-title: Whitelist_Valid_{len(valid_results)}conf\n")
        f.write(f"# profile-update-interval: 4\n")
        f.write(f"# Date/Time: {datetime.now().strftime('%Y-%m-%d / %H:%M')} (UTC)\n")
        f.write(f"# Количество: {len(valid_results)}\n")
        f.write(f"# Проверка: TCP + TLS + HTTP\n")
        f.write("# =============================================\n\n")
        
        for result in valid_results:
            p = result['parsed']
            ping = result['ping']
            http_flag = "🌐" if result.get('http_ok') else "🔒"
            name = p['name'][:40] if p['name'] else p['host']
            raw = re.sub(r'#.*$', '', p['raw'])
            f.write(f"{raw}#{http_flag} {ping}ms | {name}\n")
    
    # 7. Статистика
    duration = time.time() - start_time
    
    logger.info("=" * 60)
    logger.info("📊 РЕЗУЛЬТАТЫ ПРОВЕРКИ")
    logger.info("=" * 60)
    logger.info(f"⏱️  Время: {duration:.1f} сек")
    logger.info(f"📈 Скорость: {stats['total']/duration:.1f} конф/сек")
    logger.info(f"✅ Рабочих VLESS: {len(valid_results)}/{stats['total']}")
    logger.info(f"🌐 С HTTP ответом: {stats['http_ok']}")
    
    # Топ-10
    if valid_results:
        logger.info("\n🔝 ТОП-10 САМЫХ БЫСТРЫХ:")
        for i, r in enumerate(valid_results[:10], 1):
            p = r['parsed']
            ping = r['ping']
            flag = "🌐" if r.get('http_ok') else "🔒"
            logger.info(f"  {i:2}. [{ping:3}ms] {flag} {p['resolved_ip']}:{p['port']} | {p['name'][:35]}")
    
    with open(WHITELIST_STATUS, 'w') as f:
        json.dump({
            "last_check": time.time(),
            "total_configs": len(all_configs),
            "valid_configs": len(valid_results),
            "duration": duration,
            "check_type": "tcp_tls_http_350_threads"
        }, f)
    
    logger.info(f"✅ Whitelist проверка завершена")
    logger.info(f"💾 Результаты сохранены в {WHITELIST_OUTPUT}")


def start_background_checker():
    def checker_loop():
        time.sleep(10)
        while True:
            try:
                run_whitelist_check()
            except Exception as e:
                logger.error(f"Checker error: {e}")
                import traceback
                traceback.print_exc()
            time.sleep(4 * 60 * 60)
    
    thread = threading.Thread(target=checker_loop, daemon=True)
    thread.start()
    logger.info("🔄 Фоновый проверщик запущен (каждые 4 часа)")


# ==================== ROUTES ====================

@app.route('/sub/<secret>')
def get_subscription(secret):
    if not secret or len(secret) < 3:
        abort(404)
    log_subscription_access(secret)
    
    all_configs = []
    for server in TANDEM_SERVERS:
        configs = fetch_tandem_server(server, secret)
        all_configs.extend(configs)
    
    if not all_configs:
        abort(404)
    
    output = [
        "# profile-title: VPN Tandem (NL + RU)",
        "# profile-update-interval: 24",
        f"# Количество: {len(all_configs)}",
        "# =============================================",
        ""
    ]
    output.extend(all_configs)
    
    return Response("\n".join(output), mimetype='text/plain')


@app.route('/panel/')
@panel_auth_required
def panel():
    period = request.args.get("period", "month")
    since_ts = get_time_from_filter(period)

    with get_db_connection() as conn:
        stats = conn.execute(
            """
            SELECT COUNT(*) AS total,
                   COUNT(DISTINCT client_ip) AS unique_ips,
                   COUNT(DISTINCT hwid) AS unique_hwids
            FROM subscription_logs
            WHERE ts >= ?
            """,
            (since_ts,)
        ).fetchone()
        rows = conn.execute(
            """
            SELECT ts, secret, requested_url, client_ip, hwid, device, os, user_agent, country, region_name, city
            FROM subscription_logs
            WHERE ts >= ?
            ORDER BY ts DESC
            LIMIT 500
            """,
            (since_ts,)
        ).fetchall()

    period_title = {"day": "последний день", "week": "последняя неделя", "month": "последний месяц"}.get(period, "последний месяц")
    html = ["""
    <html><head><meta charset='utf-8'><title>Collector Panel</title>
    <style>
    body{font-family:Arial,sans-serif;margin:20px;}
    table{border-collapse:collapse;width:100%;font-size:13px;}
    th,td{border:1px solid #ddd;padding:6px;vertical-align:top;}
    th{background:#f4f4f4;}
    .cards{display:flex;gap:10px;margin:16px 0;}
    .card{padding:10px;border:1px solid #ddd;border-radius:6px;min-width:180px;}
    </style></head><body>
    """,
    f"<h1>📊 Collector Panel ({period_title})</h1>",
    "<p><a href='?period=day'>День</a> | <a href='?period=week'>Неделя</a> | <a href='?period=month'>Месяц</a> | <a href='/panel/map?period={0}'>Карта</a></p>".format(period),
    f"<div class='cards'><div class='card'><b>Всего запросов</b><br>{stats['total']}</div><div class='card'><b>Уникальные IP</b><br>{stats['unique_ips']}</div><div class='card'><b>Уникальные HWID</b><br>{stats['unique_hwids']}</div></div>",
    "<table><tr><th>Время (UTC)</th><th>IP</th><th>Локация</th><th>HWID</th><th>Устройство</th><th>OS</th><th>URL</th><th>User-Agent</th></tr>"
    ]
    for row in rows:
        dt = datetime.utcfromtimestamp(row["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        location = " / ".join([x for x in [row["country"], row["region_name"], row["city"]] if x]) or "—"
        html.append(
            f"<tr><td>{dt}</td><td>{row['client_ip'] or '—'}</td><td>{location}</td><td>{row['hwid'] or '—'}</td>"
            f"<td>{row['device'] or '—'}</td><td>{row['os'] or '—'}</td><td><code>{row['requested_url']}</code></td><td>{row['user_agent'] or '—'}</td></tr>"
        )
    html.append("</table></body></html>")
    return Response("".join(html), mimetype='text/html')


@app.route('/panel/map')
@panel_auth_required
def panel_map():
    period = request.args.get("period", "month")
    enqueue_subscription_access(secret)
    with get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT client_ip, country, region_name, city, lat, lon, MAX(ts) AS last_ts, COUNT(*) AS cnt
            FROM subscription_logs
            WHERE ts >= ? AND lat IS NOT NULL AND lon IS NOT NULL
            GROUP BY client_ip, country, region_name, city, lat, lon
            ORDER BY last_ts DESC
            LIMIT 2000
            """,
            (since_ts,)
        ).fetchall()

    markers = []
    for row in rows:
        markers.append({
            "ip": row["client_ip"],
            "country": row["country"],
            "region_name": row["region_name"],
            "city": row["city"],
            "lat": row["lat"],
            "lon": row["lon"],
            "last_ts": row["last_ts"],
            "cnt": row["cnt"],
        })

    period_title = {"day": "последний день", "week": "последняя неделя", "month": "последний месяц"}.get(period, "последний месяц")
    return f"""
    <html>
    <head>
      <meta charset="utf-8" />
      <title>Collector Map</title>
      <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
      <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
      <style>body{{margin:0;font-family:Arial;}} #map{{height:90vh;}} .top{{padding:10px;}}</style>
    </head>
    <body>
      <div class="top">
        hwid_rows = conn.execute(
            """
            SELECT l.hwid,
                   COUNT(*) AS req_count,
                   MAX(l.ts) AS last_ts,
                   (
                       SELECT ll.client_ip
                       FROM subscription_logs ll
                       WHERE ll.hwid = l.hwid AND ll.ts >= ?
                       ORDER BY ll.ts DESC
                       LIMIT 1
                   ) AS last_ip,
                   (
                       SELECT ll.country
                       FROM subscription_logs ll
                       WHERE ll.hwid = l.hwid AND ll.ts >= ?
                       ORDER BY ll.ts DESC
                       LIMIT 1
                   ) AS country,
                   (
                       SELECT ll.region_name
                       FROM subscription_logs ll
                       WHERE ll.hwid = l.hwid AND ll.ts >= ?
                       ORDER BY ll.ts DESC
                       LIMIT 1
                   ) AS region_name,
                   (
                       SELECT ll.city
                       FROM subscription_logs ll
                       WHERE ll.hwid = l.hwid AND ll.ts >= ?
                       ORDER BY ll.ts DESC
                       LIMIT 1
                   ) AS city,
                   (
                       SELECT ll.os
                       FROM subscription_logs ll
                       WHERE ll.hwid = l.hwid AND ll.ts >= ?
                       ORDER BY ll.ts DESC
                       LIMIT 1
                   ) AS os,
                   (
                       SELECT ll.device
                       FROM subscription_logs ll
                       WHERE ll.hwid = l.hwid AND ll.ts >= ?
                       ORDER BY ll.ts DESC
                       LIMIT 1
                   ) AS device
            FROM subscription_logs l
            WHERE l.ts >= ? AND l.hwid IS NOT NULL AND TRIM(l.hwid) != ''
            GROUP BY l.hwid
            ORDER BY last_ts DESC
            LIMIT 500
            """,
            (since_ts, since_ts, since_ts, since_ts, since_ts, since_ts, since_ts)
        ).fetchall()
        no_hwid_rows = conn.execute(
            WHERE ts >= ? AND (hwid IS NULL OR TRIM(hwid) = '')
            LIMIT 200
    "<h2>HWID (агрегировано)</h2>",
    "<table><tr><th>HWID</th><th>Запросов</th><th>Последний запрос (UTC)</th><th>Последний IP</th><th>Локация</th><th>Устройство</th><th>OS</th></tr>"
    for row in hwid_rows:
        dt = datetime.utcfromtimestamp(row["last_ts"]).strftime("%Y-%m-%d %H:%M:%S")
        location = " / ".join([x for x in [row["country"], row["region_name"], row["city"]] if x]) or "—"
        html.append(
            f"<tr><td>{row['hwid']}</td><td>{row['req_count']}</td><td>{dt}</td><td>{row['last_ip'] or '—'}</td><td>{location}</td>"
            f"<td>{row['device'] or '—'}</td><td>{row['os'] or '—'}</td></tr>"
        )

    html.append("</table><h2 style='margin-top:20px'>Запросы без HWID</h2>")
    html.append("<table><tr><th>Время (UTC)</th><th>IP</th><th>Локация</th><th>Geo source</th><th>URL</th><th>User-Agent</th></tr>")
    for row in no_hwid_rows:
            f"<tr><td>{dt}</td><td>{row['client_ip'] or '—'}</td><td>{location}</td><td>{row['geo_source'] or '—'}</td>"
            f"<td><code>{row['requested_url']}</code></td><td>{row['user_agent'] or '—'}</td></tr>"
      <script>
        const map = L.map('map').setView([20, 0], 2);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
          maxZoom: 18
        }}).addTo(map);
        const points = {json.dumps(markers)};
        for (const p of points) {{
          const dt = new Date(p.last_ts * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    :root{--bg:#0f172a;--card:#111827;--muted:#94a3b8;--text:#e2e8f0;--line:#1f2937;--accent:#38bdf8;}
    body{font-family:Inter,Arial,sans-serif;margin:0;background:linear-gradient(180deg,#0b1220,#111827);color:var(--text);}
    .wrap{max-width:1400px;margin:0 auto;padding:22px;}
    a{color:var(--accent);text-decoration:none}
    .filters{margin:8px 0 14px}
    .cards{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap;}
    .card{padding:14px 16px;background:var(--card);border:1px solid var(--line);border-radius:12px;min-width:200px;box-shadow:0 8px 24px rgba(0,0,0,.25)}
    .k{display:block;color:var(--muted);font-size:12px;margin-bottom:6px;text-transform:uppercase;letter-spacing:.06em}
    .v{font-size:26px;font-weight:700}
    table{border-collapse:collapse;width:100%;font-size:13px;background:#0b1220;border:1px solid var(--line);border-radius:12px;overflow:hidden}
    th,td{border-bottom:1px solid var(--line);padding:9px;vertical-align:top;}
    th{background:#0b1020;color:#93c5fd;position:sticky;top:0}
    tr:hover td{background:#0f1a30}
    code{background:#0b1020;border:1px solid var(--line);padding:2px 6px;border-radius:6px}
    "<div class='wrap'>",
    f"<h1>📊 Collector Panel • {period_title}</h1>",
    "<div class='filters'><a href='?period=day'>День</a> • <a href='?period=week'>Неделя</a> • <a href='?period=month'>Месяц</a> • <a href='/panel/map?period={0}'>Карта</a></div>".format(period),
    f"<div class='cards'><div class='card'><span class='k'>Всего запросов</span><span class='v'>{stats['total']}</span></div><div class='card'><span class='k'>Уникальные IP</span><span class='v'>{stats['unique_ips']}</span></div><div class='card'><span class='k'>Уникальные HWID</span><span class='v'>{stats['unique_hwids']}</span></div></div>",
    html.append("</table></div></body></html>")
      <style>
        :root{{--bg:#0b1220;--text:#e2e8f0;--accent:#38bdf8;--line:#1f2937;}}
        body{{margin:0;font-family:Inter,Arial;background:var(--bg);color:var(--text);}}
        #map{{height:calc(100vh - 58px);}}
        .top{{height:58px;display:flex;align-items:center;gap:10px;padding:0 16px;border-bottom:1px solid var(--line);background:#0f172a;}}
        .top a{{color:var(--accent);text-decoration:none}}
      </style>
def get_whitelist():
    if not WHITELIST_OUTPUT.exists():
        return "Still checking, please wait...", 404
    
    with open(WHITELIST_OUTPUT, 'r', encoding='utf-8') as f:
        content = f.read()
    
    return Response(content, mimetype='text/plain', headers={
        'Cache-Control': 'no-cache',
        'Access-Control-Allow-Origin': '*'
    })


@app.route('/whitelist/status')
def whitelist_status():
    if WHITELIST_STATUS.exists():
        with open(WHITELIST_STATUS, 'r') as f:
            return json.load(f)
    return {"status": "not yet checked"}


@app.route('/health')
def health():
    return {
        "status": "healthy",
        "whitelist_ready": WHITELIST_OUTPUT.exists(),
        "check_type": "tcp_tls_http_350_threads"
    }


@app.route('/')
def index():
    return """
    <h1>VPN Configs Proxy</h1>
    <ul>
        <li><code>/sub/СЕКРЕТ</code> - тандем NL + RU</li>
        <li><code>/whitelist</code> - жесткая проверка VLESS (350 потоков)</li>
        <li><code>/whitelist/status</code> - статус проверки</li>
        <li><code>/health</code> - health check</li>
    </ul>
    """


if __name__ == '__main__':
    start_background_checker()
    app.run(host='127.0.0.1', port=2095, debug=False, threaded=True)
