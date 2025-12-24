#!/usr/bin/env python3
"""
HTTP/HTTPS Proxy Checker Pro - проверка прокси серверов
Многоуровневая проверка: TCP → HTTP Connect → IP → Download → Latency
"""

import os
import base64
import asyncio
import json
import time
import re
from urllib.parse import urlparse
from typing import Optional, Tuple
from dataclasses import dataclass
import aiohttp

# ============== НАСТРОЙКИ ==============
TIMEOUT_TCP = 5          # Таймаут TCP пинга
TIMEOUT_PROXY = 15       # Таймаут проверки через прокси
MAX_CONCURRENT = 100     # Параллельных проверок
MAX_LATENCY_MS = 5000    # Максимальный пинг (мс)
MIN_SPEED_KBPS = 10      # Минимальная скорость (KB/s)

# Тестовые URL
TEST_FILE_URL = "https://www.google.com/favicon.ico"
IP_CHECK_URLS = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://icanhazip.com"
]
CONNECTIVITY_URLS = [
    "https://www.google.com/generate_204",
    "https://httpbin.org/ip",
    "https://cp.cloudflare.com/"
]


@dataclass
class ProxyResult:
    """Результат проверки прокси"""
    proxy: str
    host: str
    port: int
    protocol: str  # http, https, socks5
    working: bool
    tcp_ok: bool = False
    http_ok: bool = False
    https_ok: bool = False
    anonymous: bool = False
    latency_ms: int = 0
    speed_kbps: float = 0
    exit_ip: str = ""
    country: str = ""
    country_code: str = ""
    isp: str = ""
    error: str = ""


# Флаги стран
COUNTRY_FLAGS = {
    "RU": "🇷🇺", "DE": "🇩🇪", "NL": "🇳🇱", "US": "🇺🇸", "GB": "🇬🇧",
    "FR": "🇫🇷", "FI": "🇫🇮", "SE": "🇸🇪", "NO": "🇳🇴", "PL": "🇵🇱",
    "UA": "🇺🇦", "KZ": "🇰🇿", "BY": "🇧🇾", "LT": "🇱🇹", "LV": "🇱🇻",
    "EE": "🇪🇪", "CZ": "🇨🇿", "AT": "🇦🇹", "CH": "🇨🇭", "IT": "🇮🇹",
    "ES": "🇪🇸", "PT": "🇵🇹", "GR": "🇬🇷", "TR": "🇹🇷", "IL": "🇮🇱",
    "AE": "🇦🇪", "SG": "🇸🇬", "JP": "🇯🇵", "KR": "🇰🇷", "HK": "🇭🇰",
    "TW": "🇹🇼", "AU": "🇦🇺", "CA": "🇨🇦", "BR": "🇧🇷", "IN": "🇮🇳",
    "AM": "🇦🇲", "GE": "🇬🇪", "MD": "🇲🇩", "RO": "🇷🇴", "BG": "🇧🇬",
    "HU": "🇭🇺", "SK": "🇸🇰", "RS": "🇷🇸", "HR": "🇭🇷", "SI": "🇸🇮",
    "IE": "🇮🇪", "BE": "🇧🇪", "LU": "🇱🇺", "DK": "🇩🇰", "IS": "🇮🇸",
    "CN": "🇨🇳", "ID": "🇮🇩", "TH": "🇹🇭", "VN": "🇻🇳", "PH": "🇵🇭",
    "MY": "🇲🇾", "MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴",
}

COUNTRY_PRIORITY = {
    "RU": 0, "KZ": 1, "BY": 2, "UA": 3, "AM": 4, "GE": 5, "MD": 6,
    "DE": 10, "NL": 11, "FI": 12, "SE": 13, "NO": 14, "PL": 15, "FR": 16, "GB": 17,
    "LT": 20, "LV": 21, "EE": 22,
    "US": 30, "CA": 31,
    "JP": 40, "KR": 41, "SG": 42, "HK": 43,
}


def parse_proxy(line: str) -> Optional[Tuple[str, int, str, str, str]]:
    """
    Парсит прокси из строки
    Форматы: 
    - ip:port
    - ip:port:user:pass
    - http://ip:port
    - http://user:pass@ip:port
    - protocol://ip:port
    Возвращает: (host, port, protocol, user, password)
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    protocol = 'http'
    user = ''
    password = ''
    
    # Проверяем URL формат
    if '://' in line:
        try:
            parsed = urlparse(line)
            protocol = parsed.scheme or 'http'
            host = parsed.hostname
            port = parsed.port or 8080
            user = parsed.username or ''
            password = parsed.password or ''
            if host and port:
                return (host, port, protocol, user, password)
        except:
            pass
    
    # Формат ip:port или ip:port:user:pass
    parts = line.split(':')
    if len(parts) >= 2:
        try:
            host = parts[0]
            port = int(parts[1])
            if len(parts) >= 4:
                user = parts[2]
                password = parts[3]
            return (host, port, protocol, user, password)
        except:
            pass
    
    return None


def parse_proxy_list(content: str) -> list:
    """Парсит список прокси из текста"""
    proxies = []
    seen = set()
    
    for line in content.split('\n'):
        parsed = parse_proxy(line)
        if parsed:
            host, port, protocol, user, password = parsed
            key = f"{host}:{port}"
            if key not in seen:
                seen.add(key)
                proxies.append({
                    'host': host,
                    'port': port,
                    'protocol': protocol,
                    'user': user,
                    'password': password
                })
    
    return proxies


async def check_tcp(host: str, port: int) -> Tuple[bool, int]:
    """TCP проверка + измерение latency"""
    start = time.time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TIMEOUT_TCP
        )
        latency = int((time.time() - start) * 1000)
        writer.close()
        await writer.wait_closed()
        return True, latency
    except:
        return False, 0


async def get_ip_info(session: aiohttp.ClientSession, ip: str) -> Tuple[str, str, str]:
    """Получает информацию об IP"""
    try:
        async with session.get(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode,isp,org",
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                country = data.get('country', 'Unknown')
                code = data.get('countryCode', 'XX')
                isp = data.get('isp', '') or data.get('org', 'Unknown')
                isp = isp.replace('LLC', '').replace('Ltd', '').replace('Limited', '')
                isp = isp.replace('Corporation', '').replace('Inc.', '').strip()
                if len(isp) > 25:
                    isp = isp[:22] + "..."
                return country, code, isp
    except:
        pass
    return "Unknown", "XX", "Unknown"


async def check_proxy_full(
    proxy_data: dict,
    semaphore: asyncio.Semaphore,
    counter: list,
    total: int,
    my_ip: str
) -> ProxyResult:
    """Полная проверка прокси"""
    
    async with semaphore:
        counter[0] += 1
        num = counter[0]
        
        host = proxy_data['host']
        port = proxy_data['port']
        protocol = proxy_data['protocol']
        user = proxy_data['user']
        password = proxy_data['password']
        
        proxy_str = f"{host}:{port}"
        result = ProxyResult(
            proxy=proxy_str,
            host=host,
            port=port,
            protocol=protocol,
            working=False
        )
        
        print(f"[{num}/{total}] {proxy_str}", flush=True)
        
        # === ЭТАП 1: TCP Ping ===
        tcp_ok, latency = await check_tcp(host, port)
        result.tcp_ok = tcp_ok
        result.latency_ms = latency
        
        if not tcp_ok:
            print(f"  ✗ TCP: недоступен", flush=True)
            return result
        
        if latency > MAX_LATENCY_MS:
            print(f"  ✗ TCP: пинг слишком высокий ({latency}ms)", flush=True)
            return result
        
        print(f"  ✓ TCP: {latency}ms", flush=True)
        
        # === ЭТАП 2: HTTP/HTTPS проверка ===
        if user and password:
            proxy_url = f"http://{user}:{password}@{host}:{port}"
        else:
            proxy_url = f"http://{host}:{port}"
        
        timeout = aiohttp.ClientTimeout(total=TIMEOUT_PROXY, connect=10)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Проверка HTTP
                try:
                    async with session.get(
                        "http://httpbin.org/ip",
                        proxy=proxy_url,
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            result.http_ok = True
                            print(f"  ✓ HTTP: работает", flush=True)
                except Exception as e:
                    print(f"  ✗ HTTP: {type(e).__name__}", flush=True)
                
                # Проверка HTTPS
                try:
                    async with session.get(
                        "https://api.ipify.org?format=json",
                        proxy=proxy_url
                    ) as resp:
                        if resp.status == 200:
                            result.https_ok = True
                            data = await resp.json()
                            result.exit_ip = data.get('ip', '')
                            print(f"  ✓ HTTPS: работает", flush=True)
                except Exception as e:
                    print(f"  ✗ HTTPS: {type(e).__name__}", flush=True)
                
                if not result.http_ok and not result.https_ok:
                    result.error = "no_connectivity"
                    return result
                
                # === ЭТАП 3: Проверка анонимности ===
                if result.exit_ip and result.exit_ip != my_ip:
                    result.anonymous = True
                    # Получаем гео-данные
                    country, code, isp = await get_ip_info(session, result.exit_ip)
                    result.country = country
                    result.country_code = code
                    result.isp = isp
                    flag = COUNTRY_FLAGS.get(code, "🌍")
                    print(f"  ✓ IP: {result.exit_ip} | {flag} {country}", flush=True)
                
                # === ЭТАП 4: Тест скорости ===
                try:
                    start = time.time()
                    async with session.get(
                        TEST_FILE_URL,
                        proxy=proxy_url
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.read()
                            elapsed = time.time() - start
                            if len(data) > 0 and elapsed > 0:
                                result.speed_kbps = (len(data) / 1024) / elapsed
                                print(f"  ✓ Speed: {result.speed_kbps:.1f} KB/s", flush=True)
                except:
                    pass
                
                # === ИТОГ ===
                result.working = (result.http_ok or result.https_ok)
                
                if result.working:
                    print(f"  ★ РАБОЧИЙ!", flush=True)
                
                return result
                
        except Exception as e:
            print(f"  ✗ Error: {e}", flush=True)
            result.error = str(e)
            return result


async def get_my_ip() -> str:
    """Получает текущий IP"""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.get("https://api.ipify.org") as resp:
                return (await resp.text()).strip()
    except:
        return ""


async def fetch_proxy_list(url: str) -> str:
    """Загружает список прокси"""
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    return await resp.text()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
    return ""


async def main():
    print("=" * 60)
    print("HTTP/HTTPS Proxy Checker Pro")
    print("=" * 60)
    
    # Получаем свой IP
    print("\nПолучаю текущий IP...")
    my_ip = await get_my_ip()
    if my_ip:
        print(f"Мой IP: {my_ip}")
    else:
        print("Не удалось получить IP")
    
    # Загружаем источники прокси
    proxy_sources = os.environ.get('PROXY_SOURCES', '')
    
    if not proxy_sources:
        if os.path.exists('proxy_sources.txt'):
            with open('proxy_sources.txt', 'r') as f:
                proxy_sources = f.read()
    
    urls = [url.strip() for url in proxy_sources.split('\n') 
            if url.strip() and not url.strip().startswith('#')]
    
    if not urls:
        print("No proxy sources found!")
        return
    
    all_proxies = []
    print(f"\nЗагружаю {len(urls)} источников...")
    
    for url in urls:
        print(f"  {url[:60]}...")
        content = await fetch_proxy_list(url)
        if content:
            proxies = parse_proxy_list(content)
            print(f"    Найдено {len(proxies)} прокси")
            all_proxies.extend(proxies)
    
    # Убираем дубликаты
    seen = set()
    unique_proxies = []
    for p in all_proxies:
        key = f"{p['host']}:{p['port']}"
        if key not in seen:
            seen.add(key)
            unique_proxies.append(p)
    
    print(f"\nВсего уникальных прокси: {len(unique_proxies)}")
    
    if not unique_proxies:
        print("Прокси не найдены!")
        return
    
    # Проверяем
    print(f"\n{'=' * 60}")
    print("НАЧИНАЮ ПРОВЕРКУ")
    print(f"{'=' * 60}")
    
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    counter = [0]
    total = len(unique_proxies)
    
    tasks = [check_proxy_full(p, semaphore, counter, total, my_ip) for p in unique_proxies]
    results = await asyncio.gather(*tasks)
    
    # Фильтруем рабочие
    working = [r for r in results if r.working]
    
    # Сортируем по качеству
    working.sort(key=lambda r: (r.latency_ms, -r.speed_kbps))
    
    # Статистика
    print(f"\n{'=' * 60}")
    print("РЕЗУЛЬТАТЫ")
    print(f"{'=' * 60}")
    print(f"Всего проверено: {len(results)}")
    print(f"TCP доступны: {sum(1 for r in results if r.tcp_ok)}")
    print(f"HTTP работает: {sum(1 for r in results if r.http_ok)}")
    print(f"HTTPS работает: {sum(1 for r in results if r.https_ok)}")
    print(f"Анонимные: {sum(1 for r in results if r.anonymous)}")
    print(f"\n★ РАБОЧИХ ПРОКСИ: {len(working)}")
    
    if working:
        # Сортируем по стране и пингу
        def sort_key(r):
            priority = COUNTRY_PRIORITY.get(r.country_code, 99)
            return (priority, r.latency_ms)
        
        working.sort(key=sort_key)
        
        # Топ-5
        print(f"\nТоп-5 по качеству:")
        for i, r in enumerate(working[:5], 1):
            flag = COUNTRY_FLAGS.get(r.country_code, "🌍")
            proto = "HTTPS" if r.https_ok else "HTTP"
            anon = "🔒" if r.anonymous else "👁"
            print(f"  {i}. {flag} {r.country} | {r.latency_ms}ms | {proto} | {anon}")
        
        # === Сохраняем результаты ===
        
        # 1. Простой список ip:port
        with open('proxies.txt', 'w') as f:
            f.write('\n'.join([f"{r.host}:{r.port}" for r in working]))
        
        # 2. HTTP формат
        http_proxies = [r for r in working if r.http_ok]
        with open('proxies_http.txt', 'w') as f:
            f.write('\n'.join([f"http://{r.host}:{r.port}" for r in http_proxies]))
        
        # 3. HTTPS формат
        https_proxies = [r for r in working if r.https_ok]
        with open('proxies_https.txt', 'w') as f:
            f.write('\n'.join([f"http://{r.host}:{r.port}" for r in https_proxies]))
        
        # 4. Только анонимные
        anon_proxies = [r for r in working if r.anonymous]
        with open('proxies_anonymous.txt', 'w') as f:
            f.write('\n'.join([f"{r.host}:{r.port}" for r in anon_proxies]))
        
        # 5. JSON отчёт
        report = {
            "total_checked": len(results),
            "working_count": len(working),
            "http_count": len(http_proxies),
            "https_count": len(https_proxies),
            "anonymous_count": len(anon_proxies),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "countries": {},
            "proxies": []
        }
        
        for r in working:
            code = r.country_code or "XX"
            if code not in report["countries"]:
                report["countries"][code] = {
                    "name": r.country,
                    "flag": COUNTRY_FLAGS.get(code, "🌍"),
                    "count": 0
                }
            report["countries"][code]["count"] += 1
            
            report["proxies"].append({
                "host": r.host,
                "port": r.port,
                "proxy": f"{r.host}:{r.port}",
                "protocol": "https" if r.https_ok else "http",
                "anonymous": r.anonymous,
                "country": r.country,
                "country_code": r.country_code,
                "flag": COUNTRY_FLAGS.get(r.country_code, "🌍"),
                "isp": r.isp,
                "latency_ms": r.latency_ms,
                "speed_kbps": round(r.speed_kbps, 1),
                "exit_ip": r.exit_ip
            })
        
        with open('proxy_report.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # 6. Папка по странам
        countries_dir = 'countries'
        if not os.path.exists(countries_dir):
            os.makedirs(countries_dir)
        
        country_proxies = {}
        for r in working:
            code = r.country_code or "XX"
            if code not in country_proxies:
                country_proxies[code] = []
            country_proxies[code].append(r)
        
        for code, proxies in country_proxies.items():
            country_name = proxies[0].country or "Unknown"
            filename = f"{country_name.lower().replace(' ', '_')}.txt"
            filepath = os.path.join(countries_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write('\n'.join([f"{r.host}:{r.port}" for r in proxies]))
        
        print(f"\n{'=' * 60}")
        print("СОХРАНЕНО:")
        print(f"{'=' * 60}")
        print(f"  📄 proxies.txt - {len(working)} прокси (ip:port)")
        print(f"  📄 proxies_http.txt - {len(http_proxies)} HTTP прокси")
        print(f"  📄 proxies_https.txt - {len(https_proxies)} HTTPS прокси")
        print(f"  🔒 proxies_anonymous.txt - {len(anon_proxies)} анонимных")
        print(f"  📊 proxy_report.json - детальный отчёт")
        print(f"  📁 countries/ - {len(country_proxies)} файлов по странам")
        
    else:
        print("\nРабочих прокси не найдено!")
        for f in ['proxies.txt', 'proxies_http.txt', 'proxies_https.txt', 
                  'proxies_anonymous.txt', 'proxy_report.json']:
            with open(f, 'w') as file:
                file.write('')


if __name__ == '__main__':
    asyncio.run(main())
