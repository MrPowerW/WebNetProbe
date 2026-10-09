# -*- coding: utf-8 -*-
"""
设备识别层：读取本机 ARP 表获取内网设备 MAC 地址，
与扫描结果合并，写入 SQLite 设备注册表（含厂商 OUI 识别、IP-MAC 绑定检测）。
"""
import datetime
import platform
import re
import subprocess
import threading

from . import db, oui

_arp_lock = threading.Lock()


def _normalize_mac(mac):
    """统一 MAC 格式为小写冒号分隔"""
    mac = (mac or '').strip().replace('-', ':').lower()
    parts = mac.split(':')
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        return mac
    # 兼容单字符段（如 a:b:...）
    if len(parts) == 6:
        return ':'.join(p.zfill(2) for p in parts)
    return ''


def _is_ignorable_mac(mac):
    """过滤广播/组播/无效 MAC"""
    if not mac:
        return True
    if mac in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
        return True
    if mac.startswith('01:00:5e') or mac.startswith('33:33:'):
        return True
    return False


def read_arp_table():
    """读取本机 ARP 表，返回 [{ip, mac}]（MAC 已标准化）"""
    system = platform.system()
    try:
        if system == 'Windows':
            out = subprocess.check_output('arp -a', shell=True, timeout=5).decode('gbk', errors='ignore')
        elif system == 'Linux':
            out = subprocess.check_output(['ip', 'neigh', 'show'], timeout=5).decode('utf-8', errors='ignore')
        elif system == 'Darwin':
            out = subprocess.check_output(['arp', '-an'], timeout=5).decode('utf-8', errors='ignore')
        else:
            return []
    except Exception:
        return []

    entries = {}
    # 通用匹配：IP 后跟 MAC（兼容 Windows 'xx-xx'、Linux/macOS 'xx:xx' 及'('ip')' 形式）
    for m in re.finditer(r'(\d{1,3}(?:\.\d{1,3}){3})[^\n]{0,50}?([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})', out):
        ip = m.group(1)
        mac = _normalize_mac(m.group(2))
        if ip and mac and not _is_ignorable_mac(mac):
            entries[ip] = mac
    return [{'ip': ip, 'mac': mac} for ip, mac in entries.items()]


def ip_mac_map():
    """ARP 表 -> {ip: mac}"""
    return {e['ip']: e['mac'] for e in read_arp_table()}


def sync_devices(scan_hosts=None):
    """
    设备注册表同步：
    1) 扫描结果（含本机/网关）合并进注册表，并尝试补全 MAC；
    2) ARP 表中额外出现的设备（不响应 Ping 的隐藏设备）也纳入注册表；
    3) 检测 IP-MAC 绑定变化（地址冲突/欺骗）。
    """
    with _arp_lock:
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        arp = ip_mac_map()
        seen_ips = {}

        # 第一步：合并扫描结果
        for h in scan_hosts or []:
            ip = h.get('ip', '')
            mac = _normalize_mac(h.get('mac', ''))
            if not mac:
                mac = arp.get(ip, '')  # 用 ARP 表补全 MAC
            if not mac:
                continue
            dev = {
                'mac': mac, 'ip': ip,
                'hostname': h.get('hostname', ''),
                'os_guess': h.get('os', ''),
                'status': 'online' if h.get('status') == 'online' else h.get('status', 'online'),
                'last_seen': ts,
                'vendor': oui.lookup_vendor(mac),
            }
            db.upsert_device(dev)
            seen_ips[ip] = mac

        # 第二步：ARP 表独有设备（扫描没发现但 L2 层活跃）
        for e in arp.items():
            ip, mac = e
            if ip in seen_ips:
                continue
            hostname = ''
            try:
                hostname = socket_get_hostname(ip)
            except Exception:
                pass
            db.upsert_device({
                'mac': mac, 'ip': ip, 'hostname': hostname or '',
                'status': 'online', 'last_seen': ts, 'vendor': oui.lookup_vendor(mac),
            })
            seen_ips[ip] = mac

        # 第三步：IP-MAC 绑定变化检测（同一 IP 对应不同 MAC）
        _detect_binding_conflicts(arp)


def socket_get_hostname(ip):
    import socket
    import threading as _t
    result = ['']
    def _do():
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            result[0] = ''
    t = _t.Thread(target=_do, daemon=True)
    t.start()
    t.join(1.0)
    return result[0]


def _detect_binding_conflicts(arp):
    """检测 IP 被多个 MAC 占用（地址冲突/ARP 欺骗迹象）"""
    db_devices = {d['ip']: d for d in db.list_devices() if d['ip']}
    for ip, mac in arp.items():
        old = db_devices.get(ip)
        if old and old['mac'] != mac and old['status'] == 'online':
            db.audit(
                'binding_conflict',
                f"IP {ip} 的 MAC 发生变化: {old['mac']} -> {mac}（可能为地址冲突或ARP欺骗）"
            )
            # 记录新绑定，旧设备保留历史
            db.execute("UPDATE devices SET is_bound=0 WHERE mac=?", (old['mac'],))
