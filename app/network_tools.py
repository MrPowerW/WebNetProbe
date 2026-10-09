# -*- coding: utf-8 -*-
"""
网络诊断工具集：ping / traceroute / DNS 查询 / 端口扫描 / 服务识别
仅提供内网授权的网络诊断能力，参数严格校验、以参数列表方式执行，杜绝注入。
"""
import os
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

_HOST_RE = re.compile(r'^[A-Za-z0-9.\-_]{1,253}$')
_PORT_RE = re.compile(r'^(\d{1,5})(-\d{1,5})?$')

# 常见服务端口名
SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    80: 'HTTP', 110: 'POP3', 123: 'NTP', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 500: 'ISAKMP', 554: 'RTSP', 636: 'LDAPS', 993: 'IMAPS',
    995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9000: 'PHP-FPM', 9090: 'HTTP-Alt', 27017: 'MongoDB'
}


def validate_host(host):
    """校验目标主机：IP 或合法主机名"""
    host = (host or '').strip()
    if not host or len(host) > 253 or not _HOST_RE.match(host):
        return None
    return host


def _run(args, timeout):
    try:
        proc = subprocess.run(
            args, capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        out = (proc.stdout or b'').decode('gbk', errors='replace')
        err = (proc.stderr or b'').decode('gbk', errors='replace')
        return (out + '\n' + err).strip()
    except subprocess.TimeoutExpired:
        return f'[超时] 命令执行超过 {timeout}s 已中止'
    except Exception as e:
        return f'[错误] {e}'


def ping(host, count=4):
    """ICMP Ping：Windows ping -n"""
    host = validate_host(host)
    if not host:
        return '错误：目标主机不合法'
    count = max(1, min(int(count or 4), 20))
    lines = _run(['ping', '-n', str(count), host], timeout=count * 3 + 10).split('\n')
    keep = [ln for ln in lines if any(k in ln.lower() for k in
            ('回复', '来自', '时间=', 'ttl', 'timed out', '无法访问', '丢失', 'packets', 'lost', '统计', '平均', 'minimum', 'maximum', 'average', 'reply from', 'bytes='))]
    return '\n'.join(keep) if keep else '\n'.join(lines)


def traceroute(host, max_hops=15):
    """路由追踪：Windows tracert -d（不解析域名，更快）"""
    host = validate_host(host)
    if not host:
        return '错误：目标主机不合法'
    max_hops = max(3, min(int(max_hops or 15), 30))
    out = _run(['tracert', '-d', '-h', str(max_hops), '-w', '1000', host], timeout=90)
    return out if 'tracert' in out.lower() or 'route' in out.lower() or out.startswith('通过') or 'trace' in out.lower() else out


def dns_lookup(host):
    """DNS 查询：A/AAAA 记录 + 反向解析"""
    host = validate_host(host)
    if not host:
        return '错误：目标主机不合法'
    try:
        infos = socket.getaddrinfo(host, None)
        results = set()
        for info in infos:
            results.add(info[4][0])
        lines = [f'正向解析 {host} ->']
        for ip in sorted(results):
            try:
                rev = socket.gethostbyaddr(ip)[0]
            except Exception:
                rev = ''
            lines.append(f'  {ip}' + (f'  (反向: {rev})' if rev else ''))
        return '\n'.join(lines)
    except socket.gaierror:
        return f'解析失败：{host} 不存在（NXDOMAIN）'
    except Exception as e:
        return f'解析错误：{e}'


def _parse_ports(port_spec, cap=200):
    """解析 '22,80,8000-9000' 端口列表，返回去重排序列表；超限返回 None"""
    ports = set()
    for part in (port_spec or '').replace(' ', '').split(','):
        if not part:
            continue
        if '-' in part:
            lo_s, hi_s = part.split('-', 1)
            if not _PORT_RE.match(part):
                return None
            lo, hi = int(lo_s), int(hi_s)
            if not (1 <= lo <= hi <= 65535):
                return None
            ports.update(range(lo, hi + 1))
        else:
            if not part.isdigit() or not (1 <= int(part) <= 65535):
                return None
            ports.add(int(part))
    if not ports:
        return None
    if len(ports) > cap:
        return None
    return sorted(ports)


def _scan_one(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except Exception:
        return None


def port_scan(host, port_spec, timeout=0.8, concurrency=60):
    """TCP 连接扫描：返回开放端口与服务名"""
    host = validate_host(host)
    if not host:
        return {'error': '目标主机不合法'}
    ports = _parse_ports(port_spec)
    if ports is None:
        return {'error': '端口格式不合法（如 22,80,8000-9000）或数量超过 200 个'}
    timeout = max(0.2, min(float(timeout or 0.8), 3.0))
    open_ports = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(_scan_one, host, p, timeout): p for p in ports}
        for fut in futures:
            p = fut.result()
            if p:
                open_ports.append(p)
    open_ports.sort()
    result = {
        'target': host,
        'scanned': len(ports),
        'open': open_ports,
        'detail': [{'port': p, 'service': SERVICES.get(p, 'unknown')} for p in open_ports]
    }
    return result


def service_detect(host, port, timeout=3):
    """基础服务识别：HTTP 抓取 Server/Title，其余读 TCP banner"""
    host = validate_host(host)
    if not host:
        return {'error': '目标主机不合法'}
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            return {'error': '端口不合法'}
    except (TypeError, ValueError):
        return {'error': '端口不合法'}
    if port in (80, 443, 8080, 8443, 8888, 9090):
        scheme = 'https' if port in (443, 8443) else 'http'
        try:
            import ssl
            import http.client
            ctx = ssl.create_default_context() if scheme == 'https' else None
            conn = (http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
                    if scheme == 'https' else http.client.HTTPConnection(host, port, timeout=timeout))
            conn.request('HEAD', '/', headers={'User-Agent': 'WebNetProbe/2.2'})
            resp = conn.getresponse()
            server = resp.getheader('Server', '')
            body = resp.read(2048).decode('utf-8', errors='ignore') if port in (80,) else ''
            conn.close()
            title = ''
            m = re.search(r'<title[^>]*>(.*?)</title>', body, re.I | re.S)
            if m:
                title = m.group(1).strip()[:120]
            return {'port': port, 'service': SERVICES.get(port, 'http'), 'status': resp.status,
                    'server': server, 'title': title}
        except Exception as e:
            return {'port': port, 'service': SERVICES.get(port, 'http'), 'error': str(e)[:120]}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()[:200]
            return {'port': port, 'service': SERVICES.get(port, 'unknown'), 'banner': banner}
    except Exception as e:
        return {'port': port, 'service': SERVICES.get(port, 'unknown'), 'error': str(e)[:120]}


# ==================== 长期 Ping 监控（不间断 + 自动本地保存） ====================
import threading
import datetime

PING_LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'ping_logs')
# 多目标持续Ping：host -> {proc, host, log_path, start_ts, lines, error}
_ping_monitors = {}
_ping_lock = threading.Lock()


def _now_str():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def ping_monitor_status(tail=50):
    """多目标持续Ping 状态 + 日志尾部（兼容旧字段 host/lines/tail）"""
    with _ping_lock:
        items = {}
        for h, m in list(_ping_monitors.items()):
            d = dict(m)
            d['running'] = (m['proc'] is not None and m['proc'].poll() is None)
            d.pop('proc', None)
            items[h] = d
    hosts = list(items.keys())
    running_any = any(d.get('running') for d in items.values())
    # 主目标 = 第一个运行中或第一个
    main_host = ''
    for h in hosts:
        if items[h].get('running'):
            main_host = h
            break
    if not main_host and hosts:
        main_host = hosts[0]
    total_lines = 0
    merged_tail = []
    for h, d in items.items():
        lp = d.get('log_path')
        if not (lp and os.path.exists(lp)):
            continue
        try:
            with open(lp, 'r', encoding='utf-8', errors='replace') as f:
                all_lines = f.readlines()
            d['total_lines'] = len(all_lines)
            total_lines += len(all_lines)
            if h == main_host or len(hosts) == 1:
                merged_tail = [ln.rstrip('\n') for ln in all_lines[-int(tail):]]
        except Exception as e:
            d['error'] = str(e)
    st = {
        'running': running_any,
        'host': main_host,
        'hosts': hosts,
        'lines': total_lines,
        'total_lines': total_lines,
        'tail': merged_tail,
        'monitors': items,
        'error': ''
    }
    return st


def start_ping_monitor(host):
    """启动不间断 ping -t（支持逗号/换行分隔多目标，各自独立日志线程）"""
    hosts = [h.strip() for h in re.split(r'[,;\n\r]+', host or '') if h.strip()]
    if not hosts:
        return False, '目标主机不合法', None
    started = []
    errors = []
    with _ping_lock:
        os.makedirs(PING_LOG_DIR, exist_ok=True)
        for h in hosts:
            h = validate_host(h)
            if not h:
                errors.append(h + ': 目标不合法')
                continue
            if h in _ping_monitors and _ping_monitors[h]['proc'] is not None and _ping_monitors[h]['proc'].poll() is None:
                errors.append(h + ': 已在运行')
                continue
            log_path = os.path.join(PING_LOG_DIR, h.replace('.', '_') + '.log')
            try:
                proc = subprocess.Popen(
                    ['ping', '-t', h],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                )
            except Exception as e:
                errors.append(h + ': 启动失败 ' + str(e))
                continue
            _ping_monitors[h] = {'proc': proc, 'host': h, 'log_path': log_path,
                                 'start_ts': time.time(), 'lines': 0, 'error': ''}
            threading.Thread(target=_ping_reader, args=(proc, log_path, h), daemon=True).start()
            started.append(h)
    if not started:
        return False, ('启动失败: ' + '; '.join(errors)) if errors else '没有可启动的目标', None
    msg = '已启动 ' + str(len(started)) + ' 个目标: ' + ', '.join(started)
    if errors:
        msg += '；' + '; '.join(errors[:5])
    return True, msg, os.path.join(PING_LOG_DIR, started[0].replace('.', '_') + '.log')


def _ping_reader(proc, log_path, host):
    """后台读取 ping 输出并带时间戳落盘"""
    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f'\n===== 持续Ping 启动 {_now_str()} 目标={host} =====\n')
            f.flush()
            while True:
                raw = proc.stdout.readline()
                if not raw:
                    break
                text = raw.decode('gbk', errors='replace').strip()
                if not text:
                    continue
                f.write(f'[{_now_str()}] {text}\n')
                f.flush()
                with _ping_lock:
                    if host in _ping_monitors:
                        _ping_monitors[host]['lines'] += 1
            f.write(f'===== 持续Ping 结束 {_now_str()} =====\n')
    except Exception:
        pass
    finally:
        with _ping_lock:
            if host in _ping_monitors:
                _ping_monitors[host]['proc'] = None


def stop_ping_monitor(target=''):
    """停止持续Ping（target 为空停全部；否则停指定目标）"""
    tgt = (target or '').strip()
    stopped = []
    with _ping_lock:
        targets = [tgt] if tgt else list(_ping_monitors.keys())
        for h in targets:
            m = _ping_monitors.get(h)
            if not m:
                continue
            proc = m.get('proc')
            try:
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                stopped.append(h)
            except Exception:
                continue
    if not stopped:
        return False, '当前没有运行中的持续Ping' if not tgt else ('目标未在运行: ' + tgt)
    return True, ('持续Ping已停止: ' + ', '.join(stopped)) if len(stopped) > 1 else ('持续Ping已停止（' + stopped[0] + '）')