#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebNetProbe 内网流量探针平台 - v2.5 软件识别版
- 真实获取本地网络信息 + 设备 MAC 注册表（ARP 采集 + IEEE OUI 厂商识别）
- 精细流控策略引擎（设备/MAC/IP/IP段/分组 × 端口/协议/时段 × 上下行限速/优先级）
- 策略冲突检测、设备生效策略评估、审计日志（SQLite 持久化）
- 数据实时同步，前后端联动；历史数据持久化，支持导出下载
"""

import json
import os
import socket
import struct
import threading
try:
    import faulthandler
    _thd = open(r'C:\Users\Administrator\Desktop\WebNetProbe\data\threads_dump.log', 'w', encoding='utf-8')
    faulthandler.dump_traceback_later(45, repeat=False, file=_thd)
except Exception:
    pass
import time
START_TIME = time.time()  # v2.11.3 服务启动时间（关于系统运行时长）
VERSION = 'v2.21.15'  # v2.21.15 版本号固化单一来源（/api/version 与 /api/admin/info 均引用此常量，同步更新）
import datetime
import platform
import subprocess
import re
import csv
import io
import sys
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

# 保证从任意目录启动都能导入 app 包
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import db, oui, arp, policies, firewall, network_tools, compliance, auth, notify

# ==================== 配置 ====================
HOST = '0.0.0.0'
PORT = 8090
STATIC_DIR = 'static'
DATA_DIR = 'data'
SCAN_INTERVAL = 300  # 5分钟自动扫描一次网段
PING_TIMEOUT = 800  # Ping超时ms
PING_THREADS = 50  # 并发扫描线程
SESSIONS_MAX = 50000  # 会话历史上限
ALERTS_MAX = 20000  # 告警历史上限
alert_seq_counter = [0]  # 告警全局序号（用于删除/多选）
WHITELIST_FILE = os.path.join(DATA_DIR, 'whitelist.json')
ATTACK_WHITELIST = {}  # key(ip/域名) -> {'type','reason','added'}
CUSTOM_APP_NAMES = {}  # 软件 label -> 自定义显示名
CUSTOM_APP_FILE = os.path.join(DATA_DIR, 'custom_app_names.json')

def _load_json_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

def _save_json_file(path, data):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

def _load_whitelist():
    global ATTACK_WHITELIST
    try:
        ATTACK_WHITELIST = _load_json_file(WHITELIST_FILE)
    except Exception:
        ATTACK_WHITELIST = {}

def _save_whitelist():
    return _save_json_file(WHITELIST_FILE, ATTACK_WHITELIST)

def _load_custom_app_names():
    global CUSTOM_APP_NAMES
    try:
        CUSTOM_APP_NAMES = _load_json_file(CUSTOM_APP_FILE)
    except Exception:
        CUSTOM_APP_NAMES = {}

def _save_custom_app_names():
    return _save_json_file(CUSTOM_APP_FILE, CUSTOM_APP_NAMES)

def _is_whitelisted(ip_or_host):
    key = str(ip_or_host or '').strip()
    return bool(key) and (key in ATTACK_WHITELIST)

DOMAIN_PLATFORMS = [
    (('baidu.com', 'baidu.cn', 'bdstatic.com', 'bcebos.com'), '百度'),
    (('qq.com', 'tencent.com', 'weixin.qq.com', 'qpic.cn', 'qlogo.cn', 'gtimg.cn', 'qcloud.com'), '腾讯'),
    (('taobao.com', 'tmall.com', 'alicdn.com', 'aliyuncs.com', 'alibaba.com', '1688.com'), '阿里巴巴'),
    (('jd.com', 'jdcloud.com', '360buyimg.com'), '京东'),
    (('163.com', 'netease.com', '126.com', '163yun.com'), '网易'),
    (('sina.com.cn', 'sina.cn', 'weibo.com', 'sinajs.cn'), '新浪微博'),
    (('zhihu.com', 'zhimg.com'), '知乎'),
    (('bilibili.com', 'hdslb.com'), '哔哩哔哩'),
    (('douyin.com', 'bytedance.com', 'byteimg.com', 'toutiao.com', 'feishu.cn', 'larksuite.com', 'doubao.com', 'volcengine.com', 'snssdk.com'), '字节跳动'),
    (('feishu.cn', 'larksuite.com', 'doubao.com'), '飞书/豆包'),
    (('csdn.net', 'csdnimg.cn'), 'CSDN'),
    (('kuaishou.com', 'gifshow.com'), '快手'),
    (('meituan.com', 'dianping.com', 'meituan.net'), '美团'),
    (('pinduoduo.com', 'yangkeduo.com', 'pddpic.com'), '拼多多'),
    (('huawei.com', 'hicloud.com', 'vmall.com'), '华为'),
    (('xiaomi.com', 'mi.com', 'xiaomi.net'), '小米'),
    (('google.com', 'googleapis.com', 'gstatic.com', 'googlevideo.com', 'google.cn'), '谷歌'),
    (('facebook.com', 'fbcdn.net', 'instagram.com'), 'Meta/脸书'),
    (('microsoft.com', 'live.com', 'office.com', 'windows.net', 'msn.com', 'bing.com'), '微软'),
    (('apple.com', 'icloud.com', 'mzstatic.com'), '苹果'),
    (('amazon.com', 'amazonaws.com', 'awsstatic.com'), '亚马逊 AWS'),
    (('cloudflare.com', 'cloudflare.net'), 'Cloudflare'),
    (('github.com', 'githubusercontent.com', 'github.io'), 'GitHub'),
    (('youtube.com', 'ytimg.com'), 'YouTube'),
    (('twitter.com', 'x.com', 'twimg.com'), 'Twitter/X'),
    (('openai.com', 'oaistatic.com', 'chatgpt.com'), 'OpenAI'),
    (('steam.com', 'steamstatic.com', 'steampowered.com'), 'Steam'),
]

def _domain_platform(host):
    h = (host or '').lower().strip()
    for names, label in DOMAIN_PLATFORMS:
        for nm in names:
            if h == nm or h.endswith('.' + nm):
                return label
    return ''

GEO_RULES = [
    ('100.64.0.0/10', '运营商CGNAT', '保留共享地址段'),
    ('8.8.8.0/24', '美国 Google', 'Google Public DNS'),
    ('8.8.4.0/24', '美国 Google', 'Google Public DNS'),
    ('1.1.1.0/24', '美国 Cloudflare', 'Cloudflare DNS'),
    ('1.0.0.0/24', '美国 Cloudflare', 'Cloudflare DNS'),
    ('13.0.0.0/8', '美国 亚马逊AWS', 'AWS 全球'),
    ('20.0.0.0/8', '美国 微软Azure', 'Microsoft Azure'),
    ('40.0.0.0/8', '美国 微软Azure', 'Microsoft Azure'),
    ('52.0.0.0/8', '美国 微软Azure', 'Microsoft Azure'),
    ('23.0.0.0/8', '美国 Cloudflare', 'Cloudflare 网络'),
    ('104.0.0.0/8', '美国 Cloudflare', 'Cloudflare 网络'),
    ('172.64.0.0/13', '美国 Cloudflare', 'Cloudflare 网络'),
    ('34.0.0.0/8', '美国 Google Cloud', 'GCP'),
    ('35.0.0.0/8', '美国 Google Cloud', 'GCP'),
    ('39.0.0.0/8', '中国 云厂商', '阿里云/腾讯云（近似）'),
    ('47.0.0.0/8', '中国 阿里云', '阿里云（近似）'),
    ('144.0.0.0/8', '中国 运营商', '中国运营商段（近似）'),
    ('223.0.0.0/8', '中国 运营商', '中国运营商段（近似）'),
    ('58.0.0.0/8', '中国 运营商', '中国运营商段（近似）'),
    ('60.0.0.0/8', '中国 运营商', '中国运营商段（近似）'),
    ('103.0.0.0/8', '中国/亚太', '多国分配段（近似）'),
]
CN_RANGES = ['1.', '2.', '14.', '27.', '36.', '42.', '49.', '59.', '61.', '101.', '106.', '110.', '111.',
             '112.', '113.', '114.', '115.', '116.', '117.', '118.', '119.', '120.', '121.', '122.', '123.',
             '124.', '125.', '139.', '140.', '150.', '153.', '163.', '171.', '175.', '180.', '182.', '183.',
             '202.', '203.', '210.', '211.', '218.', '219.', '220.', '221.', '222.']

def _geo_guess(ip):
    import ipaddress as _ipa
    try:
        a = _ipa.ip_address(ip)
        if a.version != 4:
            return None
        for cidr, region, note in GEO_RULES:
            if a in _ipa.ip_network(cidr):
                return {'region': region, 'note': note}
        for pre in CN_RANGES:
            if ip.startswith(pre):
                return {'region': '中国（近似）', 'note': '运营商/云厂商段（内置精简库，非官方 GeoIP）'}
        return {'region': '未知（未内置）', 'note': '内置精简库未收录，可到威胁情报平台核实'}
    except Exception:
        return None

def _reverse_host(ip):
    import socket as _s
    try:
        _s.setdefaulttimeout(1.5)
        return _s.gethostbyaddr(ip)[0]
    except Exception:
        return ''
    finally:
        try:
            _s.setdefaulttimeout(None)
        except Exception:
            pass

def _resolve_domain(host):
    import socket as _s
    ips = []
    try:
        for r in _s.getaddrinfo(host, None)[:8]:
            ip = r[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips, _domain_platform(host)
SAVE_INTERVAL = 60  # 数据自动保存间隔（秒）
STATE_FILE = os.path.join(DATA_DIR, 'state.json')
FLOW_WINDOW_SEC = 60  # 每终端流量估算窗口（秒）
FLOW_ALERT_INTERVAL = 300  # 同一终端超限告警去重间隔（秒）
LEGACY_POLICY_FILE = os.path.join(DATA_DIR, 'flow_policy.json')  # 旧版策略文件（启动时迁移）

# 确保目录存在
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ==================== 全局数据存储 ====================
network_info = {
    'interfaces': [],
    'gateways': [],
    'public_ip': '',
    'local_subnets': [],
    'local_ip': '',
    'detected_at': ''
}

hosts_data = []  # 存活主机
hosts_lock = threading.Lock()
stats_lock = threading.Lock()  # 保护 current_stats 的并发累加
scan_lock = threading.Lock()  # 同一时间只允许一个扫描任务
last_scan_time = 0

# 历史数据存储
bandwidth_history = deque(maxlen=3600*24*7)  # 保存7天秒级数据
daily_usage = {}          # date -> {'down': 字节, 'up': 字节}（内存每日累计）
usage_lock = threading.Lock()
usage_last_persist = [0.0]
usage_last_day = [time.strftime('%Y-%m-%d')]
sessions_history = []  # 所有会话历史
alerts_history = []  # 告警历史
history_lock = threading.Lock()

# 实时会话
active_sessions = deque(maxlen=500)
session_id_counter = 0

# 终端流量估算（软流控数据源：会话上报）
flow_tracker = defaultdict(lambda: deque(maxlen=240))  # src_ip -> [(ts, bytes_in)]
flow_alert_last = {}  # mac -> 上次超限告警时间

# 实时统计
current_stats = {
    'down_bw': 0,
    'up_bw': 0,
    'total_packets': 0,
    'tcp_count': 0,
    'udp_count': 0,
    'http_count': 0,
    'https_count': 0,
    'dns_count': 0,
    'icmp_count': 0,
    'other_count': 0,
    'established': 0,
    'time_wait': 0,
    'close_wait': 0,
    'total_down_bytes': 0,
    'total_up_bytes': 0,
    'total_sessions': 0,
    'alert_count': 0
}

# ==================== 网络信息获取增强 ====================
def get_all_network_info():
    """获取所有网卡真实信息"""
    info = {
        'interfaces': [],
        'gateways': [],
        'public_ip': '',
        'local_subnets': [],
        'local_ip': '',
        'detected_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'os_info': f"{platform.system()} {platform.release()}"
    }
    
    system = platform.system()
    
    if system == 'Linux':
        info['interfaces'] = _get_linux_interfaces()
        info['gateways'] = _get_linux_gateways()
    elif system == 'Windows':
        info['interfaces'] = _get_windows_interfaces()
        info['gateways'] = _get_windows_gateways()
    elif system == 'Darwin':
        info['interfaces'] = _get_mac_interfaces()
        info['gateways'] = _get_mac_gateways()
    
    # 如果上述方法失败，使用回退方式
    if not info['interfaces']:
        info['interfaces'] = _fallback_get_interfaces()
    
    # 提取本地子网和本机IP
    subnets = []
    for iface in info['interfaces']:
        if iface['inet'] and iface['netmask'] and not iface['inet'].startswith('127.'):
            info['local_ip'] = iface['inet']  # 取第一个非回环IP作为本机IP
            try:
                mask_parts = list(map(int, iface['netmask'].split('.')))
                cidr = sum(bin(x).count('1') for x in mask_parts)
                # 修复/32掩码问题，云服务器环境自动修正为合理网段
                if cidr >= 31:
                    # /31或/32时，使用/16网段（大内网）
                    cidr = 16
                    mask_parts = [255, 255, 0, 0]
                    iface['netmask'] = '255.255.0.0'
                ip_parts = list(map(int, iface['inet'].split('.')))
                net_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
                network = '.'.join(map(str, net_parts))
                subnet = f"{network}/{cidr}"
                if subnet not in subnets:
                    subnets.append(subnet)
                    iface['subnet'] = subnet
            except:
                iface['subnet'] = ''
    
    for subnet in subnets:
        if _is_private_subnet(subnet):
            info['local_subnets'].append(subnet)
    
    # 如果没有获取到网段，给默认值
    if not info['local_subnets'] and info['local_ip']:
        parts = info['local_ip'].split('.')
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        info['local_subnets'].append(subnet)
    
    # 获取公网IP
    def get_public_ip():
        try:
            import urllib.request
            apis = [
                'https://api.ipify.org?format=json',
                'https://ifconfig.me/ip',
                'https://api.myip.com'
            ]
            for api in apis:
                try:
                    resp = urllib.request.urlopen(api, timeout=3)
                    data = resp.read().decode('utf-8').strip()
                    if data.startswith('{'):
                        j = json.loads(data)
                        ip = j.get('ip', '')
                        if ip:
                            info['public_ip'] = ip
                            return
                    else:
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', data):
                            info['public_ip'] = data
                            return
                except:
                    continue
        except:
            pass
    
    threading.Thread(target=get_public_ip, daemon=True).start()
    
    return info

def _is_private_subnet(subnet):
    """判断是否为内网网段"""
    try:
        net = subnet.split('/')[0]
        parts = list(map(int, net.split('.')))
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
    except:
        pass
    return False

def _get_linux_interfaces():
    """Linux下获取网卡信息"""
    interfaces = []
    try:
        output = subprocess.check_output(['ip', '-j', 'addr'], timeout=5).decode('utf-8')
        data = json.loads(output)
        for iface in data:
            ifname = iface.get('ifname', '')
            if ifname == 'lo' or 'docker' in ifname or 'veth' in ifname or 'br-' in ifname:
                continue
            mac = ''
            inet = ''
            netmask = ''
            for addr in iface.get('addr_info', []):
                if addr.get('family') == 'inet':
                    inet = addr.get('local', '')
                    prefix = addr.get('prefixlen', 24)
                    netmask = _prefix_to_netmask(prefix)
                    break
            if 'address' in iface:
                mac = iface['address']
            rx_bytes = 0
            tx_bytes = 0
            try:
                with open(f'/sys/class/net/{ifname}/statistics/rx_bytes') as f:
                    rx_bytes = int(f.read())
                with open(f'/sys/class/net/{ifname}/statistics/tx_bytes') as f:
                    tx_bytes = int(f.read())
            except:
                pass
            
            interfaces.append({
                'name': ifname,
                'mac': mac,
                'inet': inet,
                'netmask': netmask,
                'rx_bytes': rx_bytes,
                'tx_bytes': tx_bytes,
                'status': 'up' if iface.get('operstate') == 'UP' else 'down'
            })
    except Exception as e:
        print(f"获取Linux网卡信息失败: {e}")
        interfaces = _fallback_get_interfaces()
    return interfaces

def _get_linux_gateways():
    """Linux获取网关"""
    gateways = []
    try:
        output = subprocess.check_output(['ip', 'route', 'show', 'default'], timeout=3).decode('utf-8')
        for line in output.split('\n'):
            match = re.search(r'default via ([\d.]+) dev (\S+)', line)
            if match:
                gateways.append({
                    'ip': match.group(1),
                    'interface': match.group(2)
                })
    except:
        try:
            with open('/proc/net/route') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if parts[1] == '00000000':
                        ip = socket.inet_ntoa(struct.pack('<L', int(parts[2], 16)))
                        gateways.append({'ip': ip, 'interface': parts[0]})
        except:
            pass
    return gateways

def _get_windows_interfaces():
    """Windows下获取网卡信息"""
    interfaces = []
    try:
        output = subprocess.check_output('ipconfig /all', shell=True, timeout=5).decode('gbk', errors='ignore')
        blocks = output.split('\n\n')
        for block in blocks:
            if '适配器' not in block and 'adapter' not in block.lower():
                continue
            name_match = re.search(r'(?:适配器|adapter)\s+([^:]+):', block)
            if not name_match:
                continue
            name = name_match.group(1).strip()
            mac_match = re.search(r'(?:物理地址|Physical Address)[^:]+:\s*([0-9A-Fa-f-]+)', block)
            ip_match = re.search(r'(?:IPv4 地址|IPv4 Address)[^:]+:\s*([\d.]+)', block)
            mask_match = re.search(r'(?:子网掩码|Subnet Mask)[^:]+:\s*([\d.]+)', block)
            mac = mac_match.group(1).replace('-', ':') if mac_match else ''
            inet = ip_match.group(1) if ip_match else ''
            netmask = mask_match.group(1) if mask_match else ''
            if inet and not inet.startswith('127.'):
                interfaces.append({
                    'name': name,
                    'mac': mac,
                    'inet': inet,
                    'netmask': netmask,
                    'rx_bytes': 0,
                    'tx_bytes': 0,
                    'status': 'up'
                })
    except Exception as e:
        print(f"获取Windows网卡信息失败: {e}")
        interfaces = _fallback_get_interfaces()
    return interfaces

def _get_windows_gateways():
    """Windows获取网关"""
    gateways = []
    try:
        output = subprocess.check_output('ipconfig', shell=True, timeout=3).decode('gbk', errors='ignore')
        matches = re.findall(r'(?:默认网关|Default Gateway)[^:]+:\s*([\d.]+)', output)
        for gw in matches:
            if gw and gw != '0.0.0.0':
                gateways.append({'ip': gw, 'interface': ''})
    except:
        pass
    return gateways

def _get_mac_interfaces():
    """macOS获取网卡信息"""
    interfaces = []
    try:
        output = subprocess.check_output(['ifconfig'], timeout=5).decode('utf-8')
        blocks = output.split('\n\n')
        for block in blocks:
            name_match = re.match(r'^(\S+):', block)
            if not name_match:
                continue
            name = name_match.group(1)
            if name == 'lo0':
                continue
            mac_match = re.search(r'ether\s+([0-9a-f:]+)', block)
            ip_match = re.search(r'inet\s+([\d.]+)\s+netmask\s+([0-9a-fx]+)', block)
            inet = ''
            netmask = ''
            if ip_match:
                inet = ip_match.group(1)
                mask_hex = ip_match.group(2)
                if mask_hex.startswith('0x'):
                    mask_int = int(mask_hex, 16)
                    netmask = f"{mask_int>>24&255}.{mask_int>>16&255}.{mask_int>>8&255}.{mask_int&255}"
            mac = mac_match.group(1) if mac_match else ''
            if inet and not inet.startswith('127.'):
                interfaces.append({
                    'name': name,
                    'mac': mac,
                    'inet': inet,
                    'netmask': netmask,
                    'rx_bytes': 0,
                    'tx_bytes': 0,
                    'status': 'up'
                })
    except Exception as e:
        print(f"获取macOS网卡信息失败: {e}")
        interfaces = _fallback_get_interfaces()
    return interfaces

def _get_mac_gateways():
    """macOS获取网关"""
    gateways = []
    try:
        output = subprocess.check_output(['route', '-n', 'get', 'default'], timeout=3).decode('utf-8')
        match = re.search(r'gateway:\s*([\d.]+)', output)
        if match:
            gateways.append({'ip': match.group(1), 'interface': ''})
    except:
        pass
    return gateways

def _fallback_get_interfaces():
    """回退方法获取IP"""
    interfaces = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('114.114.114.114', 53))
            ip = s.getsockname()[0]
            interfaces.append({
                'name': '默认网卡',
                'mac': '',
                'inet': ip,
                'netmask': '255.255.255.0',
                'rx_bytes': 0,
                'tx_bytes': 0,
                'status': 'up'
            })
        except:
            hostname = socket.gethostname()
            try:
                ip = socket.gethostbyname(hostname)
                if not ip.startswith('127.'):
                    interfaces.append({
                        'name': hostname,
                        'mac': '',
                        'inet': ip,
                        'netmask': '255.255.255.0',
                        'rx_bytes': 0,
                        'tx_bytes': 0,
                        'status': 'up'
                    })
            except:
                interfaces.append({
                    'name': 'localhost',
                    'mac': '',
                    'inet': '127.0.0.1',
                    'netmask': '255.0.0.0',
                    'rx_bytes': 0,
                    'tx_bytes': 0,
                    'status': 'up'
                })
        finally:
            s.close()
    except:
        pass
    return interfaces

def _prefix_to_netmask(prefix):
    """CIDR前缀转子网掩码"""
    mask = 0xffffffff << (32 - prefix) & 0xffffffff
    return f"{mask>>24&255}.{mask>>16&255}.{mask>>8&255}.{mask&255}"

# ==================== 终端MAC采集 ====================
_arp_cache = {}
_arp_cache_time = 0

def _normalize_mac(mac):
    """统一MAC格式为 AA:BB:CC:DD:EE:FF，非法输入返回空串"""
    if not mac:
        return ''
    hex_chars = re.sub(r'[^0-9a-fA-F]', '', mac)
    if len(hex_chars) != 12:
        return ''
    return ':'.join(hex_chars[i:i+2] for i in range(0, 12, 2)).upper()

def _get_arp_table(force=False):
    """跨平台读取系统ARP表，返回 {ip: normalized_mac}（带短缓存避免频繁调子进程）"""
    global _arp_cache, _arp_cache_time
    now = time.time()
    if not force and _arp_cache and now - _arp_cache_time < 10:
        return _arp_cache

    table = {}
    system = platform.system()
    try:
        if system == 'Windows':
            output = subprocess.check_output('arp -a', shell=True, timeout=5).decode('gbk', errors='ignore')
            for m in re.finditer(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{1,2}[-:][0-9a-fA-F-:]{14,17})', output):
                mac = _normalize_mac(m.group(2))
                if mac:
                    table[m.group(1)] = mac
        elif system == 'Linux':
            try:
                output = subprocess.check_output(['ip', 'neigh'], timeout=5).decode('utf-8', errors='ignore')
                for line in output.split('\n'):
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})', line)
                    if m:
                        mac = _normalize_mac(m.group(2))
                        if mac:
                            table[m.group(1)] = mac
            except:
                output = subprocess.check_output(['arp', '-n'], timeout=5).decode('utf-8', errors='ignore')
                for line in output.split('\n'):
                    m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})', line)
                    if m:
                        mac = _normalize_mac(m.group(2))
                        if mac:
                            table[m.group(1)] = mac
        elif system == 'Darwin':
            output = subprocess.check_output(['arp', '-a'], timeout=5).decode('utf-8', errors='ignore')
            for line in output.split('\n'):
                m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})', line)
                if m:
                    mac = _normalize_mac(m.group(2))
                    if mac:
                        table[m.group(1)] = mac
    except:
        pass

    _arp_cache = table
    _arp_cache_time = now
    return table

def _ip_to_mac(ip):
    """在ARP表与已知主机中查找IP对应的MAC"""
    arp = _get_arp_table()
    mac = arp.get(ip, '')
    if mac:
        return mac
    with hosts_lock:
        for h in hosts_data:
            if h.get('ip') == ip and h.get('mac'):
                return h['mac']
    return ''

def _mac_vendor(mac):
    """根据MAC前3字节识别厂商（IEEE OUI 官方库，3.4万条），未收录返回'未知设备'"""
    vendor = oui.lookup_vendor(mac)
    return vendor or '未知设备'

# ==================== 网段存活扫描 ====================
def ping_host(ip):
    """Ping单个主机"""
    system = platform.system()
    try:
        if system == 'Windows':
            cmd = ['ping', '-n', '1', '-w', str(PING_TIMEOUT), ip]
        else:
            cmd = ['ping', '-c', '1', '-W', str(PING_TIMEOUT/1000), ip]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return result.returncode == 0
    except:
        return False

def _resolve_hostname(ip, timeout=1.0):
    """带超时的主机名反解，避免 DNS 查询拖慢整个扫描"""
    result = [None]
    def _do():
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except:
            result[0] = None
    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout)
    return result[0]

def scan_subnet(subnet):
    """扫描单个网段内所有存活主机（同一时间只允许一个扫描任务）"""
    global hosts_data, last_scan_time
    if not scan_lock.acquire(blocking=False):
        print(f"[跳过] 已有扫描任务在进行，忽略 {subnet}")
        return
    
    try:
        net_part = subnet.split('/')[0]
        cidr = int(subnet.split('/')[1]) if '/' in subnet else 24
        ip_parts = list(map(int, net_part.split('.')))
        
        # 根据CIDR计算扫描范围
        if cidr >= 24:
            start = 1
            end = 254
            network_prefix = '.'.join(map(str, ip_parts[:3]))
        elif cidr == 16:
            # /16 网段太大，只扫描本机所在 C 段及下一段（最多510个IP）
            network_prefix = '.'.join(map(str, ip_parts[:2]))
            start = 1
            end = 510
        else:
            network_prefix = '.'.join(map(str, ip_parts[:3]))
            start = 1
            end = 254
        
        found_hosts = []
        existing_ips = set()
        arp_table = _get_arp_table()  # 本次扫描的IP->MAC映射
        
        print(f"开始扫描网段 {subnet} ...")
        
        # 先加入已知网关和本机
        for gw in network_info['gateways']:
            if gw['ip']:
                host = {
                    'ip': gw['ip'],
                    'mac': arp_table.get(gw['ip'], ''),
                    'hostname': '默认网关',
                    'type': 'gateway',
                    'os': '网络设备',
                    'status': 'online',
                    'first_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'rx_bytes': 0,
                    'tx_bytes': 0,
                    'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                found_hosts.append(host)
                existing_ips.add(gw['ip'])
        
        for iface in network_info['interfaces']:
            if iface['inet'] and iface['inet'] not in existing_ips:
                host = {
                    'ip': iface['inet'],
                    'mac': iface['mac'],
                    'hostname': '本机',
                    'type': 'localhost',
                    'os': network_info['os_info'],
                    'status': 'online',
                    'first_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'rx_bytes': iface['rx_bytes'],
                    'tx_bytes': iface['tx_bytes'],
                    'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                found_hosts.append(host)
                existing_ips.add(iface['inet'])
        
        # 构造待扫描IP列表（排除已知主机）
        if cidr >= 24:
            ips_to_scan = [f"{network_prefix}.{i}" for i in range(start, end+1) if f"{network_prefix}.{i}" not in existing_ips]
        elif cidr == 16:
            ips_to_scan = []
            for c in range(ip_parts[2], ip_parts[2]+2):
                if c > 255:
                    break
                for i in range(1, 255):
                    ip = f"{network_prefix}.{c}.{i}"
                    if ip not in existing_ips:
                        ips_to_scan.append(ip)
        else:
            ips_to_scan = []
        
        ips_to_scan = ips_to_scan[:510]  # 单轮最多扫描510个IP
        
        with ThreadPoolExecutor(max_workers=PING_THREADS) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in ips_to_scan}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result(timeout=2):
                        last_octet = int(ip.split('.')[-1])
                        host_type = 'terminal'
                        hostname = '终端设备'
                        os_guess = ''
                        mac = arp_table.get(ip, '')  # 从ARP表读取MAC（跨平台）
                        
                        hostname = _resolve_hostname(ip) or f"设备-{last_octet}"
                        
                        if last_octet in [2,3,4,5,6,7,8,9,10]:
                            host_type = 'server'
                            hostname = f"服务器-{last_octet}"
                            os_guess = 'Linux/Windows Server'
                        elif last_octet in [20,21,22,23,24,25]:
                            host_type = 'camera'
                            hostname = f"摄像头-{last_octet}"
                            os_guess = 'IoT设备'
                        elif last_octet in [100,101,102]:
                            host_type = 'printer'
                            hostname = f"打印机-{last_octet}"
                            os_guess = '打印设备'
                        elif last_octet in [253,254]:
                            host_type = 'switch'
                            hostname = '交换机/AP'
                            os_guess = '网络设备'
                        else:
                            host_type = 'terminal'
                        
                        host = {
                            'ip': ip,
                            'mac': mac,
                            'hostname': hostname,
                            'type': host_type,
                            'os': os_guess,
                            'status': 'online',
                            'first_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'rx_bytes': 0,
                            'tx_bytes': 0,
                            'last_seen': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                        found_hosts.append(host)
                except:
                    pass
        
        with hosts_lock:
            # 合并之前的主机
            current_ips = {h['ip'] for h in found_hosts}
            for old_host in hosts_data:
                if old_host['ip'] not in current_ips:
                    if (datetime.datetime.now() - datetime.datetime.strptime(old_host['last_seen'], '%Y-%m-%d %H:%M:%S')).total_seconds() < 600:
                        old_host['status'] = 'online'
                    else:
                        old_host['status'] = 'offline'
                    if not old_host.get('mac'):
                        old_host['mac'] = arp_table.get(old_host['ip'], '')  # 补MAC
                    found_hosts.append(old_host)
            # IP排序
            def ip_to_int(ip):
                parts = list(map(int, ip.split('.')))
                return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
            hosts_data = sorted(found_hosts, key=lambda x: ip_to_int(x['ip']))
        
        last_scan_time = time.time()
        online_count = len([h for h in hosts_data if h['status']=='online'])
        print(f"扫描完成，网段 {subnet} 发现 {online_count} 台在线主机")
        # 同步设备注册表（MAC/厂商识别/绑定冲突检测）
        try:
            arp.sync_devices(hosts_data)
        except Exception as e:
            print(f"[!] 设备注册表同步失败: {e}")
    except Exception as e:
        print(f"扫描出错: {e}")
        import traceback
        traceback.print_exc()
    finally:
        scan_lock.release()

def scheduled_scan():
    """定期扫描所有网段"""
    time.sleep(3)  # 启动后等待3秒再开始第一次扫描
    while True:
        for subnet in network_info['local_subnets']:
            scan_subnet(subnet)
        time.sleep(SCAN_INTERVAL)

# ==================== 带宽统计 ====================
last_rx_bytes = 0
last_tx_bytes = 0
last_bw_time = 0

# Windows 网卡计数缓存（处理 32 位计数器回绕）
_windows_prev = {}  # ifindex -> (in, out)
_windows_acc = {}   # ifindex -> (in累计, out累计)

def _get_windows_if_octets():
    """通过 iphlpapi.GetIfTable 读取 Windows 各接口流量计数"""
    import ctypes
    from ctypes import wintypes
    try:
        class MIB_IFROW(ctypes.Structure):
            _fields_ = [
                ('wszName', ctypes.c_wchar * 256),
                ('dwIndex', ctypes.c_ulong),
                ('dwType', ctypes.c_ulong),
                ('dwMtu', ctypes.c_ulong),
                ('dwSpeed', ctypes.c_ulong),
                ('dwPhysAddrLen', ctypes.c_ulong),
                ('bPhysAddr', ctypes.c_ubyte * 8),
                ('dwAdminStatus', ctypes.c_ulong),
                ('dwOperStatus', ctypes.c_ulong),
                ('dwLastChange', ctypes.c_ulong),
                ('dwInOctets', ctypes.c_ulong),
                ('dwInUcastPkts', ctypes.c_ulong),
                ('dwInNUcastPkts', ctypes.c_ulong),
                ('dwInDiscards', ctypes.c_ulong),
                ('dwInErrors', ctypes.c_ulong),
                ('dwInUnknownProtos', ctypes.c_ulong),
                ('dwOutOctets', ctypes.c_ulong),
                ('dwOutUcastPkts', ctypes.c_ulong),
                ('dwOutNUcastPkts', ctypes.c_ulong),
                ('dwOutDiscards', ctypes.c_ulong),
                ('dwOutErrors', ctypes.c_ulong),
                ('dwOutQLen', ctypes.c_ulong),
                ('dwDescrLen', ctypes.c_ulong),
                ('bDescr', ctypes.c_ubyte * 256),
            ]

        class MIB_IFTABLE(ctypes.Structure):
            _fields_ = [
                ('dwNumEntries', ctypes.c_ulong),
                ('table', MIB_IFROW * 1),
            ]

        GetIfTable = ctypes.windll.iphlpapi.GetIfTable
        GetIfTable.restype = ctypes.c_ulong
        GetIfTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), wintypes.BOOL]

        ERROR_INSUFFICIENT_BUFFER = 122
        dw_size = ctypes.c_ulong(0)
        ret = GetIfTable(None, ctypes.byref(dw_size), False)
        if ret != ERROR_INSUFFICIENT_BUFFER:
            return None
        buf = ctypes.create_string_buffer(dw_size.value)
        ret = GetIfTable(buf, ctypes.byref(dw_size), False)
        if ret != 0:
            return None
        table = ctypes.cast(buf, ctypes.POINTER(MIB_IFTABLE)).contents
        row_size = ctypes.sizeof(MIB_IFROW)
        entries = []
        for i in range(table.dwNumEntries):
            row = ctypes.cast(ctypes.addressof(table.table[0]) + i * row_size, ctypes.POINTER(MIB_IFROW)).contents
            if row.dwType == 24:  # 跳过回环接口
                continue
            entries.append((row.dwIndex, row.dwInOctets, row.dwOutOctets))
        return entries
    except Exception:
        return None

def _windows_cumulative_bytes():
    """Windows 全网卡累计字节数（按接口分别处理 32 位计数回绕）"""
    global _windows_prev, _windows_acc
    try:
        entries = _get_windows_if_octets()
        if not entries:
            return None
        for idx, cur_in, cur_out in entries:
            prev = _windows_prev.get(idx)
            if prev is None:
                _windows_prev[idx] = (cur_in, cur_out)
            else:
                p_in, p_out = prev
                delta_in = (cur_in - p_in) & 0xFFFFFFFF
                delta_out = (cur_out - p_out) & 0xFFFFFFFF
                a_in, a_out = _windows_acc.get(idx, (0, 0))
                _windows_acc[idx] = (a_in + delta_in, a_out + delta_out)
                _windows_prev[idx] = (cur_in, cur_out)
        rx = sum(v[0] for v in _windows_acc.values())
        tx = sum(v[1] for v in _windows_acc.values())
        return rx, tx
    except Exception:
        return None

def _get_mac_total_bytes():
    """macOS 通过 netstat -ib 读取流量计数"""
    try:
        output = subprocess.check_output(['netstat', '-ib'], timeout=3).decode('utf-8', errors='ignore')
        rx = 0
        tx = 0
        for line in output.split('\n'):
            parts = line.split()
            if len(parts) >= 10 and '<Link#' in line:
                try:
                    rx += int(parts[6])
                    tx += int(parts[9])
                except:
                    pass
        return (rx, tx) if (rx or tx) else None
    except:
        return None

def _read_total_bytes():
    """按平台读取全网卡累计字节数 (rx, tx)，失败返回 None"""
    system = platform.system()
    if system == 'Linux':
        total_rx = 0
        total_tx = 0
        ok = False
        for iface in network_info['interfaces']:
            try:
                name = iface['name']
                with open(f'/sys/class/net/{name}/statistics/rx_bytes') as f:
                    rx = int(f.read())
                with open(f'/sys/class/net/{name}/statistics/tx_bytes') as f:
                    tx = int(f.read())
                total_rx += rx
                total_tx += tx
                ok = True
            except:
                pass
        return (total_rx, total_tx) if ok else None
    elif system == 'Windows':
        return _windows_cumulative_bytes()
    elif system == 'Darwin':
        return _get_mac_total_bytes()
    return None

def update_bandwidth_stats():
    """更新带宽统计（真实网卡计数，Linux / Windows / macOS 均支持）"""
    global last_rx_bytes, last_tx_bytes, last_bw_time
    
    # 初始读取一次，作为基准
    time.sleep(1)
    initial = _read_total_bytes()
    if initial is None:
        last_rx_bytes = 0
        last_tx_bytes = 0
    else:
        last_rx_bytes, last_tx_bytes = initial
    last_bw_time = time.time()
    
    while True:
        total = _read_total_bytes()
        now = time.time()
        if total is not None:
            total_rx, total_tx = total
            interval = now - last_bw_time
            if interval > 0.5:  # 最小间隔0.5秒
                d_rx = total_rx - last_rx_bytes
                d_tx = total_tx - last_tx_bytes
                # 校准：接口重置/计数回绕导致 delta 异常（>10Gbps*间隔）时忽略本轮，防虚高
                if d_rx < 0 or d_tx < 0 or d_rx > 10 * 1024 ** 3 * interval or d_tx > 10 * 1024 ** 3 * interval:
                    last_rx_bytes = total_rx
                    last_tx_bytes = total_tx
                    last_bw_time = now
                    time.sleep(1)
                    continue
                down_speed = d_rx / interval
                up_speed = d_tx / interval
                
                # 平滑处理
                alpha = 0.3
                if current_stats['down_bw'] > 0:
                    current_stats['down_bw'] = current_stats['down_bw'] * (1-alpha) + down_speed * alpha
                    current_stats['up_bw'] = current_stats['up_bw'] * (1-alpha) + up_speed * alpha
                else:
                    current_stats['down_bw'] = down_speed
                    current_stats['up_bw'] = up_speed
                
                current_stats['total_down_bytes'] += d_rx
                current_stats['total_up_bytes'] += d_tx

                # 每日累计（按日期0点自动切日+动态清零），每60秒落库一次；跨日立即强刷昨日
                ddate = time.strftime('%Y-%m-%d')
                with usage_lock:
                    if ddate != usage_last_day[0]:
                        old = usage_last_day[0]
                        if old and old in daily_usage:
                            db.upsert_usage(old, daily_usage[old]['down'], daily_usage[old]['up'])
                        usage_last_day[0] = ddate
                    du = daily_usage.setdefault(ddate, {'down': 0, 'up': 0})
                    du['down'] += d_rx
                    du['up'] += d_tx
                    now_t = time.time()
                    if now_t - usage_last_persist[0] >= 60:
                        usage_last_persist[0] = now_t
                        for dk, dv in list(daily_usage.items()):
                            db.upsert_usage(dk, dv['down'], dv['up'])
                
                # 保存到历史记录
                with history_lock:
                    point = {
                        'time': now * 1000,
                        'down': current_stats['down_bw'],
                        'up': current_stats['up_bw'],
                        'sessions': len(active_sessions),
                        'total_hosts': len([h for h in hosts_data if h['status']=='online'])
                    }
                    bandwidth_history.append(point)
            
            last_rx_bytes = total_rx
            last_tx_bytes = total_tx
            last_bw_time = now
        else:
            # 计数读取失败：本轮不做计算，仅更新时间基准
            last_bw_time = now
        
        time.sleep(1)

# 本机实时连接缓存（Windows netstat 采集）
CONN_CACHE = {'data': [], 'counts': {}, 'ts': 0}
CONN_LOCK = threading.Lock()

# ==================== 态势感知（攻击检测/封禁/风险） ====================
ATTACK_EVENTS = deque(maxlen=500)   # 攻击事件
ATTACK_LOCK = threading.Lock()
ATTACK_BLOCKS = {}                  # ip -> {time, reason, type, rule_id, status}
AUTO_BLOCK_ATTACKS = {'enabled': False}  # 默认关闭自动封禁：攻击源改为高亮提示（可在态势感知页手动封禁/手动开启）
_attack_debounce = {}               # (ip,type) -> last_ts
_ATTACK_SENSITIVE_PORTS = (3389, 22, 23, 445, 3306)
# ==================== 进程识别（PID → 进程名 → 软件分类） ====================
PROC_CACHE = {'map': {}, 'ts': 0}
PROC_LOCK = threading.Lock()
PROC_TTL = 30  # 进程表缓存秒数（tasklist 全量开销大）

# 常见软件进程名 → 软件分类
APP_RULES = [
    (('chrome', 'msedge', 'firefox', '360chrome', '360se', 'iexplore', 'sogouexplorer',
      'qqbrowser', 'opera', 'brave', 'vivaldi'), '浏览器'),
    (('feishu', 'lark', 'larkd'), '飞书'),
    (('wechat', 'weixin', 'wechatappex', 'wechatweb', 'wechatmini'), '微信'),
    (('wxwork', 'wework'), '企业微信'),
    (('qq.exe', 'qq', 'tim.exe', 'qdownloader'), 'QQ'),
    (('wemeetapp', 'wemeet', 'voovmeeting'), '腾讯会议'),
    (('dingtalk', 'dingtalklite'), '钉钉'),
    (('outlook', 'msimn'), '邮件客户端'),
    (('thunder', 'xunlei', 'xlservice'), '下载工具'),
    (('python', 'pythonw', 'node', 'java', 'javaw', 'dotnet', 'nginx', 'httpd', 'mysqld', 'postgres'), '开发/服务进程'),
    (('svchost', 'services', 'lsass', 'wininit', 'csrss', 'smss', 'winlogon', 'dwm', 'explorer',
      'taskhostw', 'spoolsv', 'wudfhost', 'conhost', 'runtimebroker', 'sihost', 'fontdrvhost',
      'system', 'registry', 'secure system', '360tray', '360safe'), '系统进程'),
    (('doubaowork', 'doubao'), '豆包工作台'),
    (('wechatdevtools', 'vscode', 'code.exe', 'idea64', 'pycharm64', 'adb'), '开发工具'),
    (('qqmusic', 'cloudmusic', 'wpscloudsvr', 'kugou'), '影音办公'),
]
APP_OTHER = '其他'


def _get_process_map():
    """获取 PID→进程名 映射（Windows tasklist，缓存 30 秒）"""
    with PROC_LOCK:
        now = time.time()
        if PROC_CACHE['map'] and now - PROC_CACHE['ts'] < PROC_TTL:
            return PROC_CACHE['map']
    pmap = {}
    try:
        if platform.system() == 'Windows':
            out = subprocess.check_output(['tasklist', '/FO', 'CSV', '/NH'], timeout=8,
                                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            for line in out.decode('gbk', errors='replace').splitlines():
                # CSV: "映像名称","PID","会话名","会话#","内存使用"
                parts = line.split('","')
                if len(parts) >= 2:
                    name = parts[0].strip('"').strip()
                    try:
                        pid = int(parts[1].strip('"').strip())
                    except ValueError:
                        continue
                    if pid > 0 and name:
                        pmap[pid] = name
    except Exception:
        pmap = {}
    with PROC_LOCK:
        PROC_CACHE['map'] = pmap
        PROC_CACHE['ts'] = time.time()
    return pmap


def _classify_app(proc):
    """进程名 → 软件分类"""
    p = (proc or '').lower()
    if not p:
        return APP_OTHER
    for names, label in APP_RULES:
        for n in names:
            if n.endswith('.exe'):
                if p == n:
                    return label
            elif n in p:
                return label
    return APP_OTHER


def _app_analysis():
    """软件树弹性分析：按 软件→进程→连接 聚合，估算流量占比 + 异常分析"""
    with CONN_LOCK:
        details = [dict(c) for c in CONN_CACHE.get('data', [])]
    pmap = _get_process_map()
    for c in details:
        c['process'] = pmap.get(int(c.get('pid') or 0), '')
        c['app'] = _classify_app(c.get('process', ''))
    # 软件聚合
    apps = {}
    for c in details:
        app = c.get('app') or APP_OTHER
        proc = c.get('process') or '-'
        a = apps.setdefault(app, {'connections': [], 'processes': {}})
        a['connections'].append(c)
        p = a['processes'].setdefault(proc, [])
        p.append(c)
    # 流量估算：本机实时上下行带宽 × 该软件连接数占比（估算口径）
    with stats_lock:
        down_bw = current_stats.get('down_bw', 0)
        up_bw = current_stats.get('up_bw', 0)
    total = len(details) or 1
    tree = []
    for app, a in sorted(apps.items(), key=lambda kv: -len(kv[1]['connections'])):
        conns = a['connections']
        share = len(conns) / total
        tree.append({
            'app': CUSTOM_APP_NAMES.get(app, app),
            '_key': app,
            'connections': len(conns),
            'share': round(share * 100, 1),
            'est_down_bps': round(down_bw * share, 0),
            'est_up_bps': round(up_bw * share, 0),
            'states': {},
            'processes': sorted(
                [{'name': pn, 'connections': len(pl),
                  'pids': sorted({int(x.get('pid') or 0) for x in pl if x.get('pid')})} for pn, pl in a['processes'].items()],
                key=lambda x: -x['connections'])
        })
        for c in conns:
            st = c.get('state') or '-'
            tree[-1]['states'][st] = tree[-1]['states'].get(st, 0) + 1
    # 异常分析（规则引擎）
    anomalies = []
    for t in tree:
        if t['connections'] >= 50:
            anomalies.append({'level': 'high', 'app': t['app'], 'type': '连接数偏高',
                              'msg': f"{t['app']} 当前 {t['connections']} 条连接，高于阈值 50"})
        ext = [c for c in apps[t['app']]['connections'] if _is_public_ip(_conn_remote_ip(c.get('remote', '')))]
        if len(ext) >= 20:
            anomalies.append({'level': 'medium', 'app': t['app'], 'type': '公网连接偏多',
                              'msg': f"{t['app']} 存在 {len(ext)} 条公网地址连接，请关注是否有异常外联"})
        sens = [c for c in apps[t['app']]['connections'] if _is_sensitive_port(c.get('remote', ''))]
        if sens:
            anomalies.append({'level': 'medium', 'app': t['app'], 'type': '敏感端口',
                              'msg': f"{t['app']} 命中敏感端口连接 {len(sens)} 条（如 3389/4444/5555 等）"})
    # 排序后的树
    return {'tree': tree, 'total_connections': total,
            'down_bw': round(down_bw, 0), 'up_bw': round(up_bw, 0),
            'anomalies': anomalies, 'generated_at': datetime.datetime.now().strftime('%H:%M:%S')}


def _is_public_ip(ip):
    """粗略判断公网 IP（非私有/环回/链路本地）"""
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved)
    except Exception:
        return False


def _is_sensitive_port(remote):
    """远端地址是否命中敏感端口"""
    r = (remote or '').strip()
    if r.startswith('['):
        port = r.split(']')[-1].lstrip(':')
    elif ':' in r:
        port = r.rsplit(':', 1)[-1]
    else:
        port = ''
    try:
        return int(port) in (23, 3389, 4444, 5555, 5900, 6379, 27017, 3306, 1433, 9200)
    except Exception:
        return False



def _conn_remote_ip(remote):
    """从远端地址提取 IP（兼容 IPv4 / [IPv6]）"""
    remote = (remote or '').strip()
    if remote.startswith('['):
        return remote[1:].split(']')[0]
    if ':' in remote:
        return remote.rsplit(':', 1)[0]
    return remote


def collect_local_connections():
    """采集本机实时连接：Windows netstat -ano；返回 (counts, details)"""
    try:
        if platform.system() == 'Windows':
            out = subprocess.check_output(['netstat', '-ano'], timeout=5).decode('gbk', errors='replace')
        elif platform.system() == 'Linux':
            out = ''
            lines = []
            try:
                with open('/proc/net/tcp') as f:
                    lines.extend(f.readlines()[1:])
            except Exception:
                lines = []
            out = '\n'.join(lines)
        else:
            return None, []
        counts = {'total': 0, 'tcp': 0, 'udp': 0, 'established': 0, 'time_wait': 0, 'close_wait': 0}
        details = []
        for line in out.splitlines():
            if platform.system() == 'Windows':
                parts = line.split()
                if len(parts) < 4:
                    continue
                proto = parts[0].upper()
                if proto == 'TCP' and len(parts) >= 5:
                    local, remote, state, pid = parts[1], parts[2], parts[3], parts[4]
                elif proto == 'UDP' and len(parts) >= 4:
                    local, remote, state, pid = parts[1], parts[2], '-', parts[3]
                else:
                    continue
            else:
                # Linux /proc/net/tcp：loc rem st ...；十六进制 IP:PORT
                parts = line.split()
                if len(parts) < 4:
                    continue
                proto = 'TCP'
                try:
                    local_hex, remote_hex, state_hex = parts[1], parts[2], parts[3]
                    local_ip = '.'.join(str(int(local_hex[i:i+2], 16)) for i in (6, 4, 2, 0))
                    remote_ip = '.'.join(str(int(remote_hex[i:i+2], 16)) for i in (6, 4, 2, 0))
                    local_port = int(local_hex.split(':')[1], 16) if ':' in local_hex else int(local_hex[-4:], 16)
                    remote_port = int(remote_hex.split(':')[1], 16) if ':' in remote_hex else int(remote_hex[-4:], 16)
                    local = f'{local_ip}:{local_port}'
                    remote = f'{remote_ip}:{remote_port}'
                    state = {'01': 'ESTABLISHED', '02': 'SYN_SENT', '06': 'TIME_WAIT',
                             '08': 'CLOSE_WAIT', '0A': 'LISTEN'}.get(state_hex, state_hex)
                except Exception:
                    continue
                pid = ''
            counts['total'] += 1
            if proto == 'TCP':
                counts['tcp'] += 1
            else:
                counts['udp'] += 1
            if state == 'ESTABLISHED':
                counts['established'] += 1
            elif state == 'TIME_WAIT':
                counts['time_wait'] += 1
            elif state == 'CLOSE_WAIT':
                counts['close_wait'] += 1
            if len(details) < 300:
                details.append({'proto': proto, 'local': local, 'remote': remote,
                                'state': state, 'pid': pid})
        return counts, details
    except Exception:
        return None, []

# ==================== 连接统计 ====================
def update_connection_stats():
    """更新连接状态统计"""
    while True:
        if platform.system() == 'Linux':
            try:
                established = 0
                time_wait = 0
                close_wait = 0
                tcp_count = 0
                udp_count = 0
                
                with open('/proc/net/tcp') as f:
                    for line in f.readlines()[1:]:
                        tcp_count += 1
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            state = parts[3]
                            if state == '01':
                                established += 1
                            elif state == '06':
                                time_wait += 1
                            elif state == '08':
                                close_wait += 1
                
                try:
                    with open('/proc/net/udp') as f:
                        udp_count = len(f.readlines()) - 1
                except:
                    udp_count = 0
                
                with stats_lock:
                    current_stats['tcp_count'] = tcp_count
                    current_stats['udp_count'] = udp_count
                    current_stats['established'] = established
                    current_stats['time_wait'] = time_wait
                    current_stats['close_wait'] = close_wait
            except:
                pass
        elif platform.system() == 'Windows':
            # Windows：netstat -ano 真实连接表
            counts, details = collect_local_connections()
            if counts is not None:
                with stats_lock:
                    current_stats['tcp_count'] = counts['tcp']
                    current_stats['udp_count'] = counts['udp']
                    current_stats['established'] = counts['established']
                    current_stats['time_wait'] = counts['time_wait']
                    current_stats['close_wait'] = counts['close_wait']
                    current_stats['session_count'] = counts['total']
                with CONN_LOCK:
                    CONN_CACHE['data'] = details
                    CONN_CACHE['counts'] = counts
                    CONN_CACHE['ts'] = time.time()
        else:
            # 其他系统按会话估算
            with stats_lock:
                current_stats['tcp_count'] = current_stats['http_count'] + current_stats['https_count']
                current_stats['udp_count'] = current_stats['dns_count']
                current_stats['established'] = len(active_sessions)
        
        time.sleep(2)

def _safe_int(value, default):
    """安全解析整数参数，非法值返回默认值"""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default

# ==================== HTTP请求处理 ====================
class ProbeHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)
    
    _load_whitelist()
    _load_custom_app_names()

    def end_headers(self):
        # 静态资源禁用缓存：浏览器始终获取最新版本（防止旧 JS 导致功能"未生效"）；带 query 的 URL 也命中
        p = urlparse(self.path).path
        if p == '/' or p.endswith('.html') or p.endswith('.js') or p.endswith('.css'):
            try:
                self.send_header('Cache-Control', 'no-store')
            except Exception:
                pass
        try:
            super().end_headers()
        except Exception:
            pass

    def send_head(self):
        """静态文件响应：强制 no-cache / no-store，防止浏览器旧缓存导致页面不更新"""
        path = self.translate_path(self.path)
        # v2.21.4：logo.png 不存在时回退 favicon.svg（消除默认 logo 404；上传后仍返回真实 PNG）
        if urlparse(self.path).path in ('/logo.png',) and not os.path.isfile(path):
            path = self.translate_path('/favicon.svg')
        f = None
        if os.path.isdir(path):
            for _idx in ('index.html', 'index.htm'):
                _p = os.path.join(path, _idx)
                if os.path.isfile(_p):
                    path = _p
                    break
            else:
                self.send_error(404, 'File not found')
                return None
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(404, 'File not found')
            return None
        try:
            fs = os.fstat(f.fileno())
            try:
                self.send_response(200)
                ctype = self.guess_type(path)
                self.send_header('Content-type', ctype)
                self.send_header('Content-Length', str(fs[6]))
                self.send_header('Last-Modified', self.date_time_string(fs.st_mtime))
                self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                self.end_headers()
                return f
            except Exception:
                f.close()
                raise
        except Exception:
            try:
                f.close()
            except Exception:
                pass
            raise

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path

            # v2.11 访问控制：所有 /api/* 需登录（公开：/api/auth/check）；viewer 敏感前缀拒绝
            if path.startswith('/api/') and path not in ('/api/auth/check', '/api/version'):
                user = self._require_auth()
                if not user:
                    return
                if user['role'] == 'viewer' and not auth.can_view_full(user, path):
                    self._json_response({'error': '权限不足：该功能未向只读访客开放'}, status=403)
                    return
                # v2.11.2 细粒度模块权限（admin 分发查看模块）
                module = auth.path_module(path)
                if module and not auth.module_allowed(user, module, 'view'):
                    self._json_response({'error': '权限不足：该用户未被授权查看此模块'}, status=403)
                    return
                # v2.11.2 敏感查看留痕审计（管理/敏感类数据查看；轮询类不记避免刷屏）
                if user['role'] != 'admin':
                    _AUDIT_VIEW_PATHS = ('/api/users', '/api/audit', '/api/export/', '/api/compliance',
                                         '/api/notify/config', '/api/admin/', '/api/settings/logo')
                    if any(path.startswith(p) for p in _AUDIT_VIEW_PATHS):
                        db.audit('view_' + (module or 'data'), '查看数据(' + path + '): ' + user['username'])

            if path == '/':
                self.path = '/index.html'
                return super().do_GET()
        
            # API接口
            if path == '/api/auth/check':
                tok = self._auth_token()
                user, perms = auth.user_by_token(tok)
                if not user:
                    return self._json_response({'auth': False})
                return self._json_response({'auth': True, 'user': auth.public_view(user)})

            elif path == '/api/version':
                # v2.16 版本号公开接口（动态更新页面标题/副标题）
                return self._json_response({'version': VERSION})

            elif path == '/api/users':
                return self._json_response({'users': auth.list_users()})

            elif path == '/api/admin/session_timeout':
                # v2.14 会话超时配置（admin-only）
                if not self._require_auth(admin=True):
                    return
                return self._json_response({'minutes': auth.get_session_timeout(), 'options': list(auth.SESSION_TIMEOUT_OPTIONS)})
            elif path == '/api/admin/info':
                # v2.11.3 关于系统：版本/运行/数据库状态（admin-only，读操作）
                if not self._require_auth(admin=True):
                    return
                import os as _os, time as _time, platform as _platform
                info = {
                    'name': 'WebNetProbe 内网流量探针平台',
                    'version': VERSION,
                    'python': _platform.python_version(),
                    'db_path': db.get_db_path() if hasattr(db, 'get_db_path') else db.DB_PATH,
                }
                try:
                    info['db_size_mb'] = round(_os.path.getsize(info['db_path']) / 1048576, 2)
                except Exception:
                    info['db_size_mb'] = 0
                try:
                    import sqlite3 as _sq
                    c = _sq.connect(info['db_path'], timeout=5)
                    info['tables'] = {}
                    for t in ('users', 'devices', 'policies', 'audit', 'sessions', 'usage_daily', 'attacks', 'whitelist', 'firewall_rules', 'apps_usage'):
                        try:
                            info['tables'][t] = c.execute('SELECT COUNT(*) FROM ' + t).fetchone()[0]
                        except Exception:
                            info['tables'][t] = 0
                    c.close()
                except Exception:
                    info['tables'] = {}
                info['uptime_sec'] = int(_time.time() - START_TIME)
                return self._json_response(info)

            elif path == '/api/users/view_password':
                # admin 查看用户密码明文（Fernet 可逆解密）
                user = self._require_auth(admin=True)
                if not user:
                    return
                q = parse_qs(urlparse(self.path).query)
                uname = (q.get('username') or [''])[0]
                r = auth.view_password(uname)
                if r.get('ok'):
                    db.audit('user_view_pwd', '查看密码: ' + uname)
                return self._json_response(r)

            elif path == '/api/notify/config':
                return self._json_response({'channels': notify.list_configs()})

            if path == '/api/network_info':
                return self._json_response(network_info)
        
            elif path == '/api/scan':
                for subnet in network_info['local_subnets']:
                    threading.Thread(target=scan_subnet, args=(subnet,), daemon=True).start()
                return self._json_response({'status': 'started'})
        
            elif path == '/api/hosts':
                with hosts_lock:
                    return self._json_response([dict(h, vendor=_mac_vendor(h.get('mac', ''))) for h in hosts_data])
        
            elif path == '/api/realtime':
                # 实时数据 - 返回最新60秒带宽历史
                with history_lock:
                    bw_hist = list(bandwidth_history)[-60:]
                    sessions_list = list(active_sessions)[-30:]
                    stats_copy = dict(current_stats)
                    stats_copy['alert_count'] = len(alerts_history)
                    stats_copy['total_sessions'] = len(sessions_history)
                with hosts_lock:
                    online_hosts = len([h for h in hosts_data if h['status']=='online'])
                    total_hosts = len(hosts_data)
                return self._json_response({
                    'stats': stats_copy,
                    'sessions': sessions_list,
                    'bandwidth_history': bw_hist,
                    'last_scan': last_scan_time,
                    'online_hosts': online_hosts,
                    'total_hosts': total_hosts
                })
        
            elif path == '/api/history':
                # 时间段选择 + 秒级精度；超 6 小时自动聚合为分钟级
                params = parse_qs(parsed.query)
                now = time.time()
                start_sec = _safe_int(params.get('start', [''])[0] or '0', 0)
                end_sec = _safe_int(params.get('end', [''])[0] or '0', 0)
                if start_sec <= 0 or end_sec <= 0 or end_sec <= start_sec:
                    # 兼容旧参数 hours
                    hours = _safe_int(params.get('hours', ['1'])[0], 1)
                    hours = max(1, min(hours, 168))
                    start_sec = now - hours * 3600
                    end_sec = now
                if end_sec - start_sec > 6 * 3600:
                    precision = 'minute'
                else:
                    precision = 'second'
                with history_lock:
                    history = [p for p in bandwidth_history if start_sec <= p['time']/1000 <= end_sec]
                    alerts = [a for a in alerts_history if a['timestamp']/1000 >= start_sec]
                    sessions_count = len(sessions_history)
                    if precision == 'minute':
                        bucket = defaultdict(lambda: {'down':0, 'up':0, 'count':0})
                        for p in history:
                            m = int(p['time']/1000/60)*60*1000
                            bucket[m]['down'] += p['down']
                            bucket[m]['up'] += p['up']
                            bucket[m]['count'] += 1
                        points = []
                        for m in sorted(bucket.keys()):
                            cnt = bucket[m]['count']
                            points.append({'time': m, 'down': bucket[m]['down']/cnt, 'up': bucket[m]['up']/cnt})
                    else:
                        points = [{'time': p['time'], 'down': p['down'], 'up': p['up']} for p in history]
                # 数据一致性核对：样本数 / 覆盖时长 / 时间戳缺口
                _pts = points
                gaps = 0
                for i in range(1, len(_pts)):
                    if _pts[i]['time'] - _pts[i-1]['time'] > 3000:
                        gaps += 1
                return self._json_response({
                    'bandwidth': points,
                    'precision': precision,
                    'start': start_sec,
                    'end': end_sec,
                    'sessions_count': sessions_count,
                    'alerts_count': len(alerts),
                    'alerts': alerts[-100:],
                    'stats': {
                        'points': len(points),
                        'coverage_sec': int(max(0, (end_sec - start_sec))),
                        'gaps': gaps,
                        'consistent': gaps == 0
                    }
                })
        
            elif path == '/api/usage/stat':
                return self._json_response(_usage_stat())

            elif path == '/api/usage/months':
                return self._json_response(_usage_months())

            elif path == '/api/usage/month':
                params = parse_qs(parsed.query)
                return self._json_response(_usage_month(params.get('ym', [''])[0]))

            elif path == '/api/situational':
                return self._json_response(_situational())

            elif path == '/api/attacks':
                params = parse_qs(parsed.query)
                limit = _safe_int(params.get('limit', ['50'])[0], 50)
                with ATTACK_LOCK:
                    return self._json_response({'attacks': list(reversed(list(ATTACK_EVENTS)[-limit:]))})

            elif path == '/api/ip/lookup':
                params = parse_qs(parsed.query)
                return self._json_response(_ip_lookup(params.get('ip', [''])[0]))

            elif path == '/api/whitelist':
                return self._json_response({'items': [dict(key=k, **v) for k, v in ATTACK_WHITELIST.items()]})

            elif path == '/api/apps/names':
                return self._json_response({'names': CUSTOM_APP_NAMES})

            elif path == '/api/ping/export':
                # 长期Ping 日志导出 CSV（解析 RTT，精确到秒）
                params = parse_qs(parsed.query)
                target = (params.get('target') or [''])[0].strip()
                if not target:
                    target = network_tools.ping_monitor_status(1).get('host', '')
                target = re.sub(r'[^0-9a-zA-Z.\-]', '', target)
                if not target:
                    return self._json_response({'error': '未指定目标（请先启动持续Ping）'})
                log_path = os.path.join(network_tools.PING_LOG_DIR, target.replace('.', '_') + '.log')
                if not os.path.exists(log_path):
                    return self._json_response({'error': '未找到该目标的持续Ping日志：' + target})
                rows = []
                with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        m = re.match(r'\[([0-9\-]+ [0-9:]+)\] (.*)', line)
                        if not m:
                            continue
                        ts, body = m.group(1), m.group(2)
                        rm = re.search(r'时间=(\d+)ms', body) or re.search(r'time[=<](\d+)', body)
                        if rm:
                            rows.append([ts, target, rm.group(1), 'success'])
                        elif '超时' in body or 'timed out' in body.lower():
                            rows.append([ts, target, '', 'timeout'])
                        elif '无法访问' in body or 'unreachable' in body.lower():
                            rows.append([ts, target, '', 'unreachable'])
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(['Time', 'Target', 'RTT(ms)', 'Status'])
                w.writerows(rows)
                content = '\ufeff' + buf.getvalue()
                cb = content.encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv; charset=utf-8')
                self.send_header('Content-Length', str(len(cb)))
                self.send_header('Content-Disposition', 'attachment; filename="ping_' + target + '_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + '.csv"')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(cb)
                return None

            elif path == '/api/ping/export/multi':
                # 多目标合并导出 CSV（targets 逗号分隔；缺省取所有运行中目标）
                params = parse_qs(parsed.query)
                raw = (params.get('targets') or [''])[0]
                targets = [t.strip() for t in re.split(r'[,;\n]+', raw) if t.strip()]
                if not targets:
                    targets = list((network_tools.ping_monitor_status(1).get('hosts') or []))
                if not targets:
                    return self._json_response({'error': '未指定目标（请先输入目标或启动持续Ping）'})
                rows = []
                missing = []
                for tg in targets:
                    tg2 = re.sub(r'[^0-9a-zA-Z.\-]', '', tg)
                    if not tg2:
                        continue
                    lp = os.path.join(network_tools.PING_LOG_DIR, tg2.replace('.', '_') + '.log')
                    if not os.path.exists(lp):
                        missing.append(tg2)
                        continue
                    with open(lp, 'r', encoding='utf-8', errors='replace') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            m = re.match(r'\[([0-9\-]+ [0-9:]+)\] (.*)', line)
                            if not m:
                                continue
                            ts, body = m.group(1), m.group(2)
                            rm = re.search(r'时间=(\d+)ms', body) or re.search(r'time[=<](\d+)', body)
                            if rm:
                                rows.append([ts, tg2, rm.group(1), 'success'])
                            elif '超时' in body or 'timed out' in body.lower():
                                rows.append([ts, tg2, '', 'timeout'])
                            elif '无法访问' in body or 'unreachable' in body.lower():
                                rows.append([ts, tg2, '', 'unreachable'])
                if not rows:
                    return self._json_response({'error': '所选目标均无已收集样本' + ('（未找到日志: ' + ','.join(missing) + '）' if missing else '')})
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(['Time', 'Target', 'RTT(ms)', 'Status'])
                w.writerows(rows)
                content = '\ufeff' + buf.getvalue()
                cb = content.encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv; charset=utf-8')
                self.send_header('Content-Length', str(len(cb)))
                self.send_header('Content-Disposition', 'attachment; filename="ping_multi_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + '.csv"')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(cb)
                return None

            elif path == '/api/jitter':
                # 网络抖动实时：读取持续Ping日志尾部 RTT 序列计算抖动
                params = parse_qs(parsed.query)
                target = (params.get('target') or [''])[0].strip()
                if not target:
                    target = network_tools.ping_monitor_status(1).get('host', '')
                target = re.sub(r'[^0-9a-zA-Z.\-]', '', target)
                if not target:
                    return self._json_response({'error': '未指定目标（请先启动持续Ping）'})
                log_path = os.path.join(network_tools.PING_LOG_DIR, target.replace('.', '_') + '.log')
                rtts = []
                if os.path.exists(log_path):
                    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                        for line in f:
                            rm = re.search(r'时间=(\d+)ms', line) or re.search(r'time[=<](\d+)', line)
                            if rm:
                                rtts.append(int(rm.group(1)))
                rtts = rtts[-60:]
                if len(rtts) < 2:
                    return self._json_response({'target': target, 'samples': len(rtts),
                                                'note': '样本不足（需至少 2 个 RTT 样本，请先运行持续Ping 后再查看抖动）'})
                mn, mx = min(rtts), max(rtts)
                avg = sum(rtts) / len(rtts)
                jitter = sum(abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))) / (len(rtts) - 1)
                sd = (sum((x - avg) ** 2 for x in rtts) / len(rtts)) ** 0.5
                return self._json_response({'target': target, 'samples': len(rtts), 'min': mn,
                                            'avg': round(avg, 1), 'max': mx,
                                            'jitter': round(jitter, 1), 'stddev': round(sd, 1)})

            elif path == '/api/usage/days':
                params = parse_qs(parsed.query)
                days_n = _safe_int(params.get('days', ['31'])[0], 31)
                days_n = max(2, min(days_n, 366))
                base = db.get_usage_days(days_n)
                with usage_lock:
                    for d, v in daily_usage.items():
                        base[d] = {'down': v['down'], 'up': v['up']}
                today = time.strftime('%Y-%m-%d')
                day0 = time.mktime(time.strptime(today, '%Y-%m-%d')) - (days_n - 1) * 86400
                out = []
                for i in range(days_n):
                    dstr = time.strftime('%Y-%m-%d', time.localtime(day0 + i * 86400))
                    v = base.get(dstr, {'down': 0, 'up': 0})
                    out.append({'date': dstr, 'down': v['down'], 'up': v['up'], 'total': v['down'] + v['up']})
                return self._json_response({'days': out})

            elif self.path == '/api/settings/logo' and self.command == 'POST':
                return self._handle_logo_upload()

            elif path == '/api/sessions':
                params = parse_qs(parsed.query)
                limit = _safe_int(params.get('limit', ['200'])[0], 200)
                limit = max(1, min(limit, 5000))
                with history_lock:
                    return self._json_response(list(reversed(sessions_history[-limit:])))
        
            elif path == '/api/alerts':
                params = parse_qs(parsed.query)
                limit = _safe_int(params.get('limit', ['200'])[0], 200)
                limit = max(1, min(limit, 5000))
                with history_lock:
                    return self._json_response(list(reversed(alerts_history[-limit:])))
        

            elif path == '/api/flow_policy/export':
                return self._export_flow_script_response()
        
            elif path == '/api/devices':
                _devs = db.list_devices()
                for _d in _devs:
                    if _d.get('mac'):
                        _d['vendor'] = _mac_vendor(_d['mac'])
                return self._json_response({'devices': _devs})
        
            elif path == '/api/devices/sync':
                try:
                    arp.sync_devices(hosts_data)
                    return self._json_response({'status': 'ok', 'count': len(db.list_devices())})
                except Exception as e:
                    return self._json_response({'status': 'error', 'msg': str(e)})
        
            elif path == '/api/policies':
                return self._json_response({'policies': db.list_policies()})
        
            elif path == '/api/policies/check':
                return self._json_response({
                    'conflicts': policies.find_conflicts(),
                    'evaluation': policies.evaluate_devices()
                })
        
            elif path == '/api/audit':
                # v2.16 审计日志：admin / 审计员默认可看；其他角色需被授权 audit 模块查看权限
                _tok = self._auth_token()
                _u, _ = auth.user_by_token(_tok)
                if not _u or (_u['role'] not in ('admin', 'audit') and not auth.module_allowed(_u, 'audit', 'view')):
                    return self._json_response({'error': '权限不足：审计日志仅 admin / 审计员或已授权用户可见'}, status=403)
                params = parse_qs(parsed.query)
                limit = _safe_int(params.get('limit', ['200'])[0], 200)
                _rows = db.list_audit(limit)
                # v2.17 审计时间段过滤（ts 为 YYYY-MM-DD HH:MM:SS，字典序即时间序）
                _st = (params.get('start') or [''])[0]
                _en = (params.get('end') or [''])[0]
                if _st:
                    _rows = [a for a in _rows if (a.get('ts') or '') >= _st]
                if _en:
                    _rows = [a for a in _rows if (a.get('ts') or '') <= _en]
                return self._json_response({'audit': _rows})
        
            elif path == '/api/connections':
                # 本机实时连接明细
                dev_map = {}
                for d in db.list_devices():
                    ip = (d.get('ip') or '').strip()
                    if ip and ip not in dev_map:
                        if d.get('mac'):
                            d['vendor'] = _mac_vendor(d['mac'])
                        dev_map[ip] = d
                with CONN_LOCK:
                    details = list(CONN_CACHE.get('data', []))
                    counts = dict(CONN_CACHE.get('counts', {}))
                    ts = CONN_CACHE.get('ts', 0)
                pmap = _get_process_map()
                for c in details:
                    rip = _conn_remote_ip(c.get('remote', ''))
                    d = dev_map.get(rip)
                    if d:
                        c['device'] = (d.get('hostname') or d.get('mac') or '-')
                        c['vendor'] = (d.get('vendor') or '')
                    c['process'] = pmap.get(int(c.get('pid') or 0), '')
                    c['app'] = _classify_app(c.get('process', ''))
                with history_lock:
                    online_sessions = len(active_sessions)
                return self._json_response({
                    'counts': counts, 'connections': details, 'ts': ts,
                    'online_sessions': online_sessions,
                    'devices': len(dev_map)
                })
        
            elif path == '/api/apps/analysis':
                return self._json_response(_app_analysis())

            elif path == '/api/compliance/sources':
                return self._json_response({'sources': compliance.data_sources()})
        
            elif path == '/api/compliance/checks':
                with hosts_lock:
                    hd = list(hosts_data)
                with history_lock:
                    sess = list(active_sessions)[-200:]
                try:
                    _users = auth.list_users()
                    _nch = notify.list_configs()
                except Exception:
                    _users, _nch = None, None
                checks = compliance.run_checks(hd, db.list_devices(), db.list_policies(), sess, _users, _nch)
                # 合规告警同步：warn/fail 项写入告警流（同规则 10 分钟去重，避免轮询刷屏）
                try:
                    _sync_compliance_alerts(checks)
                except Exception:
                    pass
                return self._json_response({
                    'checks': checks,
                    'generated_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
        
            elif path == '/api/compliance/sop':
                return self._json_response({'sop': compliance.sop()})

            elif path == '/api/compliance/matrix':
                return self._json_response({
                    'iso': compliance.iso27001_matrix(),
                    'djbh': compliance.djbh_matrix()
                })
        
            elif path == '/api/firewall':
                return self._json_response({'rules': firewall.list_rules()})
        
            elif path == '/api/tools/ping/status':
                params = parse_qs(parsed.query)
                tail = _safe_int(params.get('tail', ['50'])[0], 50)
                return self._json_response(network_tools.ping_monitor_status(tail))

            elif path == '/api/tools/dns':
                params = parse_qs(parsed.query)
                host = params.get('host', [''])[0]
                return self._json_response({'output': network_tools.dns_lookup(host)})
        
            elif path.startswith('/api/export/'):
                export_type = path.split('/')[-1]
                return self._export_data(export_type)
        
            elif path == '/api/report_session':
                self.send_error(405, 'Method Not Allowed')  # 上报仅允许POST
        
            else:
                return super().do_GET()
    
        except Exception as _ee:
            try:
                import traceback as _tb2
                with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'get_error.log'), 'a', encoding='utf-8') as _lf:
                    _lf.write('[' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '] do_GET ERROR: ' + repr(_ee) + '\n')
                    _tb2.print_exc(file=_lf)
            except Exception:
                pass
            try:
                self.send_error(500, 'Internal Error: ' + repr(_ee))
            except Exception:
                pass

    def _export_flow_script_response(self):
        """导出网关限速脚本"""
        filename, content = _export_flow_script()
        if filename is None:
            return self._json_response({'status': 'error', 'msg': content})
        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        elif isinstance(content, (bytes, bytearray)):
            content_bytes = bytes(content)
        else:
            content_bytes = str(content).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(content_bytes)))
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(content_bytes)
    
    def do_POST(self):
        # v2.11 访问控制：公开（login/report_session）；自身操作（logout/change_password）仅需登录；
        # 写操作 operator+；admin-only 前缀要求 admin
        if self.path.startswith('/api/'):
            if self.path in ('/api/auth/login', '/api/report_session'):
                pass
            elif self.path.startswith('/api/auth/'):
                if self.path in ('/api/auth/logout', '/api/auth/change_password'):
                    if not self._require_auth():
                        return
                else:
                    if not self._require_auth(admin=True):
                        return
            else:
                admin_only = any(self.path.startswith(p) for p in auth.ADMIN_ONLY_PREFIXES)
                user = self._require_auth(write=True, admin=admin_only)
                if not user:
                    return
                # v2.11.2 细粒度模块权限（admin 分发修改模块）
                module = auth.path_module(self.path)
                if module and not auth.module_allowed(user, module, 'write'):
                    self._json_response({'error': '权限不足：该用户未被授权修改此模块'}, status=403)
                    return
        if self.path == '/api/auth/login':
            return self._handle_auth_login()
        elif self.path == '/api/auth/logout':
            tok = self._auth_token()
            u, _ = auth.user_by_token(tok) if tok else (None, None)
            if tok:
                auth.revoke_token(tok)
            if u:
                db.audit('logout', '退出登录: ' + u['username'])
            return self._json_response({'ok': True, 'msg': '已退出登录'})
        elif self.path == '/api/audit/event':
            # v2.20 页面/模块访问留痕（进入画面/来回切换）
            _u = self._require_auth()
            if not _u:
                return
            data = self._read_json_body()
            _md = (data.get('module') or 'unknown').strip()
            _nm = (data.get('name') or _md).strip()
            _act = (data.get('action') or 'view_module').strip()
            if _act == 'user_click':
                db.audit('user_click', '点击: ' + _nm + ' by ' + _u['username'])
            else:
                db.audit('view_module', '进入画面: ' + _nm + ' by ' + _u['username'])
            return self._json_response({'status': 'ok'})
        elif self.path == '/api/auth/change_password':
            return self._handle_change_password()
        elif self.path == '/api/admin/session_timeout':
            # v2.14 会话超时设置（admin-only）
            if not self._require_auth(admin=True):
                return
            data = self._read_json_body()
            r = auth.set_session_timeout(data.get('minutes'))
            if r.get('ok'):
                db.audit('policy_session_timeout', '会话超时设置: ' + str(data.get('minutes')) + ' 分钟')
            return self._json_response(r)
        elif self.path == '/api/auth/reset_password':
            return self._handle_reset_password()
        elif self.path == '/api/users/create':
            return self._handle_user_create()
        elif self.path == '/api/users/permissions':
            # v2.11.2 admin 分发某用户的 查看/修改 模块权限
            data = self._read_json_body()
            uname = (data.get('username') or '').strip()
            r = auth.set_user_modules(uname,
                                      perm_view=data.get('perm_view'),
                                      perm_write=data.get('perm_write'))
            if r.get('ok'):
                db.audit('user_perm', '分发权限: ' + uname + ' 查看=' + ','.join(data.get('perm_view') or []) + ' 修改=' + ','.join(data.get('perm_write') or []))
            return self._json_response(r)
        elif self.path == '/api/users/update':
            return self._handle_user_update()
        elif self.path == '/api/users/delete':
            return self._handle_user_delete()
        elif self.path == '/api/notify/config':
            return self._handle_notify_config()
        elif self.path == '/api/notify/test':
            return self._handle_notify_test()
        elif self.path == '/api/notify/send':
            return self._handle_notify_send()
        if self.path == '/api/settings/logo':
            return self._handle_logo_upload()
        elif self.path == '/api/report_session':
            return self._handle_report_session()
        elif self.path == '/api/devices/update':
            return self._handle_device_update()
        elif self.path == '/api/policies/create':
            return self._handle_policy_create()
        elif self.path == '/api/policies/update':
            return self._handle_policy_update()
        elif self.path == '/api/policies/delete':
            return self._handle_policy_delete()
        elif self.path == '/api/firewall/create':
            return self._handle_firewall_create()
        elif self.path == '/api/firewall/delete':
            return self._handle_firewall_delete()
        elif self.path == '/api/attacks/block':
            return self._handle_attack_block()
        elif self.path == '/api/attacks/unblock':
            return self._handle_attack_unblock()
        elif self.path == '/api/attacks/auto_block':
            return self._handle_attack_auto_block()
        elif self.path == '/api/alerts/delete':
            return self._handle_alerts_delete()
        elif self.path == '/api/alerts/clear':
            return self._handle_alerts_clear()
        elif self.path == '/api/admin/reset':
            return self._handle_admin_reset()
        elif self.path == '/api/whitelist/add':
            return self._handle_whitelist_add()
        elif self.path == '/api/whitelist/remove':
            return self._handle_whitelist_remove()
        elif self.path == '/api/apps/names':
            return self._handle_app_name_save()
        elif self.path == '/api/tools/ping':
            return self._handle_tool_ping()
        elif self.path == '/api/tools/traceroute':
            return self._handle_tool_traceroute()
        elif self.path == '/api/tools/portscan':
            return self._handle_tool_portscan()
        elif self.path == '/api/tools/service':
            return self._handle_tool_service()
        elif self.path == '/api/tools/ping/start':
            return self._handle_ping_start()
        elif self.path == '/api/tools/ping/stop':
            return self._handle_ping_stop()
        else:
            self.send_error(404)
    
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def _read_json_body(self, max_len=1024*1024):
        """读取 JSON 请求体，超限返回 413"""
        try:
            length = int(self.headers.get('Content-Length', 0))
        except (TypeError, ValueError):
            length = 0
        if length > max_len:
            self.send_error(413)
            return None
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode('utf-8'))
        except Exception:
            return {}
    
    def _handle_device_update(self):
        """更新设备的可编辑字段（类型/分组/备注）"""
        try:
            data = self._read_json_body()
            if data is None:
                return
            mac = (data.get('mac') or '').strip().lower()
            if not mac:
                return self._json_response({'status': 'error', 'msg': '缺少MAC地址'})
            if not db.update_device(mac, data):
                return self._json_response({'status': 'error', 'msg': '设备不存在或无可更新字段'})
            db.audit('device_update',
                     f"更新设备 {mac}: 类型={data.get('type','-')} 分组={data.get('group_name','-')} 备注={data.get('note','-')}")
            return self._json_response({'status': 'ok'})
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})
    
    def _handle_policy_create(self):
        """创建流控策略"""
        try:
            data = self._read_json_body()
            if data is None:
                return
            ok, msg = policies.validate_policy(data)
            if not ok:
                return self._json_response({'status': 'error', 'msg': msg})
            pid = db.create_policy(data)
            db.audit('policy_create',
                     f"创建策略[{pid}] 「{data.get('name')}」 {data.get('target_type')}:{data.get('target_value')} "
                     f"下行={data.get('down_limit')}bps 上行={data.get('up_limit')}bps 优先级={data.get('priority')}")
            return self._json_response({'status': 'ok', 'id': pid})
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})
    
    def _handle_policy_update(self):
        """更新流控策略"""
        try:
            data = self._read_json_body()
            if data is None:
                return
            pid = int(data.get('id', 0) or 0)
            if pid <= 0:
                return self._json_response({'status': 'error', 'msg': '缺少策略ID'})
            ok, msg = policies.validate_policy({k: v for k, v in data.items() if k != 'id'})
            if not ok:
                return self._json_response({'status': 'error', 'msg': msg})
            if not db.update_policy(pid, data):
                return self._json_response({'status': 'error', 'msg': '策略不存在'})
            db.audit('policy_update', f"更新策略[{pid}]「{data.get('name') or ''}」")
            return self._json_response({'status': 'ok'})
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})
    
    def _handle_policy_delete(self):
        """删除流控策略"""
        try:
            data = self._read_json_body()
            if data is None:
                return
            pid = int(data.get('id', 0) or 0)
            if pid <= 0:
                return self._json_response({'status': 'error', 'msg': '缺少策略ID'})
            db.delete_policy(pid)
            db.audit('policy_delete', f"删除策略[{pid}]")
            return self._json_response({'status': 'ok'})
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})
    
    def _handle_firewall_create(self):
        """创建端口封禁规则（Windows 高级防火墙）"""
        try:
            data = self._read_json_body()
            if data is None:
                return
            ok, msg, rec = firewall.create_rule(
                data.get('name', ''), data.get('direction', 'in'),
                data.get('protocol', 'TCP'), data.get('port', 0),
                data.get('remote_ip', ''), data.get('note', ''))
            resp = {'status': 'ok' if ok else 'error', 'msg': msg}
            if rec:
                resp.update(rec)
            return self._json_response(resp)
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})

    def _handle_attack_block(self):
        """手动封禁 IP（攻击封禁）"""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
        except Exception:
            return self._json_response({'status': 'error', 'msg': '请求体错误'})
        ip = str(body.get('ip', '')).strip()
        reason = str(body.get('reason', '手动封禁'))[:100]
        if not ip:
            return self._json_response({'status': 'error', 'msg': '缺少 IP'})
        if ip in ATTACK_BLOCKS:
            return self._json_response({'status': 'ok', 'msg': '该 IP 已在攻击封禁列表', 'ip': ip})
        name = 'attack_' + ip.replace('.', '_') + '_' + str(int(time.time()) % 100000)
        try:
            ok, msg, rec = firewall.create_rule(name, 'in', 'tcp', 0, ip, note='手动攻击封禁')
        except Exception as e:
            ok, msg, rec = False, str(e), None
        ATTACK_BLOCKS[ip] = {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'reason': reason, 'type': '手动封禁',
            'rule_id': rec.get('id') if rec else None,
            'status': 'blocked' if ok else ('failed:' + str(msg)[:80])
        }
        return self._json_response({'status': 'ok' if ok else 'error', 'msg': msg, 'ip': ip})

    def _handle_attack_unblock(self):
        """手动解除攻击封禁"""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
        except Exception:
            return self._json_response({'status': 'error', 'msg': '请求体错误'})
        ip = str(body.get('ip', '')).strip()
        if not ip:
            return self._json_response({'status': 'error', 'msg': '缺少 IP'})
        msgs = []
        rec = ATTACK_BLOCKS.pop(ip, None)
        if rec and rec.get('rule_id'):
            try:
                ok, msg = firewall.delete_rule(rec['rule_id'])
                msgs.append('防火墙规则: ' + msg)
            except Exception as e:
                msgs.append('防火墙规则删除异常: ' + str(e))
        # 兜底：按 remote_ip 清理匹配的本平台规则
        try:
            for r in db.list_firewall_rules():
                if r.get('remote_ip') == ip and r.get('rule_name', '').startswith('WNP-attack_'):
                    db.delete_firewall_rule(r['id'])
        except Exception:
            pass
        return self._json_response({'status': 'ok', 'msg': '; '.join(msgs) if msgs else '已解除（无防火墙规则）', 'ip': ip})

    def _handle_whitelist_add(self):
        """白名单添加（IP 或域名；域名需可解析）"""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
        except Exception:
            return self._json_response({'status': 'error', 'msg': '请求体错误'})
        key = str(body.get('key') or '').strip()
        if not key:
            return self._json_response({'status': 'error', 'msg': '请输入 IP 或域名'})
        if key in ATTACK_WHITELIST:
            return self._json_response({'status': 'ok', 'msg': '已存在于白名单', 'count': len(ATTACK_WHITELIST)})
        is_ip = re.match(r'^[0-9.]+$', key)
        if not is_ip:
            ips, _ = _resolve_domain(key)
            if not ips:
                return self._json_response({'status': 'error', 'msg': '域名无法解析（DNS 无记录），不能加入白名单'})
        ATTACK_WHITELIST[key] = {'type': 'ip' if is_ip else 'domain',
                                 'reason': str(body.get('reason') or ''), 'added': time.strftime('%Y-%m-%d %H:%M:%S')}
        _save_whitelist()
        return self._json_response({'status': 'ok', 'msg': '已加入白名单', 'count': len(ATTACK_WHITELIST)})

    def _handle_whitelist_remove(self):
        """白名单移除"""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
        except Exception:
            return self._json_response({'status': 'error', 'msg': '请求体错误'})
        key = str(body.get('key') or '').strip()
        if key in ATTACK_WHITELIST:
            del ATTACK_WHITELIST[key]
            _save_whitelist()
        return self._json_response({'status': 'ok', 'count': len(ATTACK_WHITELIST)})

    def _handle_app_name_save(self):
        """软件显示名手动更改（key=原始软件名，name 为空则恢复默认）"""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
        except Exception:
            return self._json_response({'status': 'error', 'msg': '请求体错误'})
        key = str(body.get('key') or '').strip()
        if not key:
            return self._json_response({'status': 'error', 'msg': '缺少软件标识'})
        name = str(body.get('name') or '').strip()
        if name:
            CUSTOM_APP_NAMES[key] = name
        else:
            CUSTOM_APP_NAMES.pop(key, None)
        _save_custom_app_names()
        return self._json_response({'status': 'ok', 'names': CUSTOM_APP_NAMES})

    def _handle_alerts_delete(self):
        """删除指定告警（按 seq 单条或多选）"""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
        except Exception:
            return self._json_response({'status': 'error', 'msg': '请求体错误'})
        seqs = body.get('seqs') or []
        if not isinstance(seqs, list):
            return self._json_response({'status': 'error', 'msg': '参数错误'})
        seqs = set(int(x) for x in seqs if str(x).isdigit())
        with history_lock:
            keep = [a for a in alerts_history if a.get('seq') not in seqs]
            del alerts_history[:]
            alerts_history.extend(keep)
        with stats_lock:
            current_stats['alert_count'] = len(alerts_history)
        return self._json_response({'status': 'ok', 'deleted': len(seqs), 'remain': len(alerts_history)})

    def _handle_alerts_clear(self):
        """清空全部告警（重置）"""
        _clear_alerts()
        return self._json_response({'status': 'ok', 'remain': 0})

    def _handle_admin_reset(self):
        """模块重置：alerts / sessions / attacks / usage_today / all"""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
        except Exception:
            return self._json_response({'status': 'error', 'msg': '请求体错误'})
        module = str(body.get('module', ''))
        if module not in ('alerts', 'sessions', 'attacks', 'usage_today', 'all'):
            return self._json_response({'status': 'error', 'msg': '不支持的重置模块'})
        _reset_module(module)
        return self._json_response({'status': 'ok', 'module': module})

    def _handle_attack_auto_block(self):
        """自动封禁开关"""
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
        except Exception:
            return self._json_response({'status': 'error', 'msg': '请求体错误'})
        AUTO_BLOCK_ATTACKS['enabled'] = bool(body.get('enabled', True))
        return self._json_response({'status': 'ok', 'enabled': AUTO_BLOCK_ATTACKS['enabled']})

    def _handle_firewall_delete(self):
        """删除端口封禁规则"""
        try:
            data = self._read_json_body()
            if data is None:
                return
            rid = int(data.get('id', 0) or 0)
            if rid <= 0:
                return self._json_response({'status': 'error', 'msg': '缺少规则ID'})
            ok, msg = firewall.delete_rule(rid)
            return self._json_response({'status': 'ok' if ok else 'error', 'msg': msg})
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})

    def _handle_tool_ping(self):
        try:
            data = self._read_json_body()
            if data is None:
                return
            out = network_tools.ping(data.get('host', ''), data.get('count', 4))
            db.audit('tool_ping', f"ping {data.get('host','')}")
            return self._json_response({'output': out})
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})

    def _handle_tool_traceroute(self):
        try:
            data = self._read_json_body()
            if data is None:
                return
            out = network_tools.traceroute(data.get('host', ''), data.get('max_hops', 15))
            db.audit('tool_traceroute', f"tracert {data.get('host','')}")
            return self._json_response({'output': out})
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})

    def _handle_tool_portscan(self):
        try:
            data = self._read_json_body()
            if data is None:
                return
            res = network_tools.port_scan(data.get('host', ''), data.get('ports', ''),
                                          data.get('timeout', 0.8))
            db.audit('tool_portscan', f"端口扫描 {data.get('host','')} [{data.get('ports','')}]")
            return self._json_response(res)
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})

    def _handle_tool_service(self):
        try:
            data = self._read_json_body()
            if data is None:
                return
            res = network_tools.service_detect(data.get('host', ''), data.get('port', 0))
            return self._json_response(res)
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})
    def _handle_ping_start(self):
        """启动长期不间断 Ping（输出自动保存本地）"""
        try:
            data = self._read_json_body()
            if data is None:
                return
            ok, msg, log_path = network_tools.start_ping_monitor(data.get('host', ''))
            db.audit('tool_ping_start', f"持续Ping 启动 {data.get('host','')} -> {log_path or msg}")
            resp = {'status': 'ok' if ok else 'error', 'msg': msg}
            if log_path:
                resp['log'] = log_path
            return self._json_response(resp)
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})

    def _handle_ping_stop(self):
        """停止长期 Ping（body.target 为空 = 停止全部）"""
        try:
            body = self._read_json_body()
            target = (body or {}).get('target', '') if body else ''
            ok, msg = network_tools.stop_ping_monitor(target)
            db.audit('tool_ping_stop', msg)
            return self._json_response({'status': 'ok' if ok else 'error', 'msg': msg})
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})

    # ============ v2.11 认证/用户/通知处理器 ============
    def _handle_auth_login(self):
        data = self._read_json_body()
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        if not username or not password:
            return self._json_response({'ok': False, 'msg': '请输入用户名与密码'})
        _lip = self.client_address[0] if self.client_address and self.client_address[0] else ''
        _st, _u, _extra = auth.verify_password(username, password, _lip)
        if _st == 'ok':
            tok = auth.create_token(username)
            db.audit('auth_login', '登录成功: ' + username + (' 来源 ' + _lip if _lip else ''))
            return self._json_response({'ok': True, 'token': tok, 'user': auth.public_view(_u)})
        if _st == 'locked':
            _m = '账户已锁定，请约 %d 分钟后重试（连续 5 次失败触发）' % _extra if _extra else '账户已锁定，请 30 分钟后重试'
            return self._json_response({'ok': False, 'msg': _m})
        if _st == 'disabled':
            return self._json_response({'ok': False, 'msg': '账户已停用（连续 3 次锁定），请联系管理员启用'})
        return self._json_response({'ok': False, 'msg': '用户名或密码错误'})

    def _handle_change_password(self):
        data = self._read_json_body()
        tok = self._auth_token()
        user = self._require_auth()
        if not user:
            return
        r = auth.change_password(user['username'], data.get('old_password') or '', data.get('new_password') or '', tok or '')
        if r.get('ok'):
            db.audit('user_change_pwd', '修改密码: ' + user['username'])
        return self._json_response(r)

    def _handle_reset_password(self):
        data = self._read_json_body()
        uname = (data.get('username') or '').strip()
        r = auth.reset_password(uname, data.get('new_password') or '')
        if r.get('ok'):
            db.audit('user_reset_pwd', '重置用户密码: ' + uname)
        return self._json_response(r)

    def _handle_user_create(self):
        data = self._read_json_body()
        r = auth.create_user(data.get('username'), data.get('password'), data.get('role') or 'viewer',
                             data.get('display_name') or '', data.get('email') or '',
                             perm_view=data.get('perm_view'), perm_write=data.get('perm_write'))
        if r.get('ok'):
            db.audit('user_create', '创建用户: ' + (data.get('username') or ''))
        return self._json_response(r)

    def _handle_user_update(self):
        data = self._read_json_body()
        uid = data.get('id')
        if uid is None:
            return self._json_response({'ok': False, 'msg': '缺少用户 ID'})
        r = auth.update_user(uid, role=data.get('role'), display_name=data.get('display_name'),
                             email=data.get('email'), status=data.get('status'))
        if r.get('ok'):
            db.audit('user_update', '更新用户 #' + str(uid))
        return self._json_response(r)

    def _handle_user_delete(self):
        data = self._read_json_body()
        uname = (data.get('username') or '').strip()
        r = auth.delete_user(uname)
        if r.get('ok'):
            db.audit('user_delete', '删除用户: ' + uname)
        return self._json_response(r)

    def _handle_notify_config(self):
        data = self._read_json_body()
        channel = (data.get('channel') or '').strip()
        r = notify.save_config(channel, bool(data.get('enabled')), data.get('config') or {})
        if r.get('ok'):
            db.audit('notify_config', '更新通知渠道: ' + channel)
        return self._json_response(r)

    def _handle_notify_test(self):
        data = self._read_json_body()
        channel = (data.get('channel') or '').strip()
        r = notify.test_channel(channel)
        return self._json_response({'ok': r['ok'], 'result': r})

    def _handle_notify_send(self):
        data = self._read_json_body()
        channel = (data.get('channel') or '').strip()
        title = data.get('title') or 'WebNetProbe 消息'
        content = data.get('content') or ''
        if channel and channel != 'all':
            r = notify.send(channel, title, content)
            return self._json_response({'ok': r['ok'], 'results': [r]})
        results = notify.send_all(title, content)
        return self._json_response({'ok': any(r['ok'] for r in results), 'results': results})

    def _handle_logo_upload(self):
        """接收 base64 图片并保存为 static/logo.png（仅限 png/jpeg/svg）"""
        import base64 as _b64
        try:
            body = self._read_json_body()
            if body is None:
                return
            data = body.get('image') or ''
            if not data.startswith('data:image/'):
                return self._json_response({'status': 'error', 'msg': '仅支持图片数据(data:image/...)'})
            m = re.match(r'^data:image/(png|jpe?g|svg\+xml);base64,(.+)$', data, re.S)
            if not m:
                return self._json_response({'status': 'error', 'msg': '图片格式仅支持 PNG/JPG/SVG'})
            raw = _b64.b64decode(m.group(2))
            if len(raw) > 3 * 1024 * 1024:
                return self._json_response({'status': 'error', 'msg': '图片超过 3MB 限制'})
            static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
            ext = 'png' if m.group(1).startswith('png') else ('svg' if 'svg' in m.group(1) else 'jpg')
            target = os.path.join(static_dir, 'logo.' + ext)
            # 清理旧的其它扩展名 logo，避免多个 logo 文件并存
            for old_ext in ('png', 'jpg', 'jpeg', 'svg'):
                oldf = os.path.join(static_dir, 'logo.' + old_ext)
                if oldf != target and os.path.exists(oldf):
                    try:
                        os.remove(oldf)
                    except Exception:
                        pass
            with open(target, 'wb') as f:
                f.write(raw)
            db.audit('settings_logo', '更新平台 logo -> ' + os.path.basename(target))
            return self._json_response({'status': 'ok', 'url': '/' + os.path.basename(target)})
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})

    # ============ v2.11 认证与分权 ============
    def _auth_token(self):
        tok = (self.headers.get('X-Auth-Token') or '').strip()
        if not tok:
            q = parse_qs(urlparse(self.path).query)
            tok = (q.get('token') or [''])[0]
        return tok

    def _require_auth(self, write=False, admin=False):
        """返回 user；未登录 401，权限不足 403"""
        tok = self._auth_token()
        user, perms = auth.user_by_token(tok)
        if not user:
            self._json_response({'error': '未登录或会话已过期，请重新登录'}, status=401)
            return None
        if admin and not auth.can_admin(user):
            self._json_response({'error': '权限不足：该操作仅限超级管理员'}, status=403)
            return None
        if write and not auth.can_write(user):
            self._json_response({'error': '权限不足：该操作需要运维操作员及以上角色'}, status=403)
            return None
        return user

    def _json_response(self, data, status=200):
        response = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(response)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(response)
    
    def _handle_report_session(self):
        """处理前端上报的会话数据"""
        global session_id_counter
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length > 1024*1024:  # 限制1MB
                self.send_error(413)
                return
            body = self.rfile.read(length).decode('utf-8')
            data = json.loads(body)
            
            session_id_counter += 1
            now = datetime.datetime.now()
            
            # 获取客户端IP
            client_ip = self.client_address[0]
            
            protocol = data.get('protocol', 'HTTPS').upper()
            dst_ip = data.get('dst_ip', '')
            # 尝试解析目标域名
            dst_host = data.get('dst_host', '')
            if not dst_ip and dst_host:
                try:
                    dst_ip = socket.gethostbyname(dst_host)
                except:
                    dst_ip = dst_host
            
            session = {
                'id': session_id_counter,
                'time': now.strftime('%Y-%m-%d %H:%M:%S'),
                'timestamp': now.timestamp() * 1000,
                'src_ip': client_ip,
                'src_port': self.client_address[1],
                'dst_ip': dst_ip,
                'dst_host': dst_host,
                'dst_port': data.get('dst_port', 443),
                'protocol': protocol,
                'method': data.get('method', 'GET'),
                'url': data.get('url', ''),
                'status': data.get('status', 200),
                'bytes_in': data.get('bytes_in', 0),
                'bytes_out': data.get('bytes_out', 0),
                'type': data.get('type', 'request'),
                'duration': data.get('duration', 0),
                'client_ip': client_ip
            }
            
            # 更新协议统计（加锁防止多线程并发累加丢失）
            with stats_lock:
                if 'HTTPS' in protocol:
                    current_stats['https_count'] += 1
                elif 'HTTP' in protocol:
                    current_stats['http_count'] += 1
                elif 'DNS' in protocol:
                    current_stats['dns_count'] += 1
                elif 'UDP' in protocol:
                    current_stats['udp_count'] += 1
                elif 'TCP' in protocol:
                    current_stats['tcp_count'] += 1
                elif 'ICMP' in protocol:
                    current_stats['icmp_count'] += 1
                else:
                    current_stats['other_count'] += 1
                
                current_stats['total_packets'] += 1
                # 统计流量
                current_stats['total_down_bytes'] += data.get('bytes_in', 0)
                current_stats['total_up_bytes'] += data.get('bytes_out', 0)
            
            active_sessions.append(session)
            
            with history_lock:
                sessions_history.append(session)
                current_stats['total_sessions'] = len(sessions_history)
                if len(sessions_history) > SESSIONS_MAX:
                    del sessions_history[:len(sessions_history) - SESSIONS_MAX]
            
            # 异常检测 + 基于MAC的流控超限检测
            alerts = _detect_anomalies(session)
            flow_alert = _check_flow_limit(session)
            if flow_alert:
                alerts.append(flow_alert)
            for alert in alerts:
                _append_alert(alert)
            
            return self._json_response({'status': 'ok', 'id': session_id_counter})
        except Exception as e:
            return self._json_response({'status': 'error', 'msg': str(e)})
    
    def _export_data(self, export_type):
        """导出数据 - 使用英文文件名避免编码问题；支持 ?start=&end= 时间段过滤（秒级）"""
        # v2.19 导出即留痕：任何导出动作写入审计日志
        try:
            _eu, _ = auth.user_by_token(self._auth_token())
            if _eu:
                _q2 = parse_qs(urlparse(self.path).query)
                _det = '导出[' + export_type + ']'
                if _q2.get('start') or _q2.get('end'):
                    _det += ' 时间段 ' + ((_q2.get('start') or [''])[0] or '全部') + ' ~ ' + ((_q2.get('end') or [''])[0] or '全部')
                if _q2.get('format'):
                    _det += ' 格式 ' + (_q2.get('format') or [''])[0]
                db.audit('export_' + export_type, _det + ' by ' + _eu['username'])
        except Exception:
            pass
        buf = io.StringIO()
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        # 时间段过滤：start/end 支持 秒时间戳 或 YYYY-MM-DD HH:MM:SS / ISO
        try:
            q = urlparse(self.path).query
            params = parse_qs(q)
            def _parse_ts(v):
                if not v:
                    return None
                v = v.strip()
                if v.isdigit():
                    return float(v)
                for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d'):
                    try:
                        return datetime.datetime.strptime(v, fmt).timestamp()
                    except Exception:
                        continue
                return None
            start_ts = _parse_ts((params.get('start') or [''])[0])
            end_ts = _parse_ts((params.get('end') or [''])[0])
        except Exception:
            start_ts = end_ts = None
        if start_ts and end_ts and end_ts <= start_ts:
            start_ts = end_ts = None
        
        if export_type == 'csv':
            writer = csv.writer(buf)
            writer.writerow(['Time', 'SrcIP', 'DstHost', 'DstIP', 'DstPort', 'Protocol', 'Method', 'URL', 'StatusCode', 'BytesIn', 'BytesOut'])
            with history_lock:
                _src = sessions_history
                if start_ts is not None and end_ts is not None:
                    _src = [s for s in _src if start_ts <= s.get('timestamp', 0) / 1000 <= end_ts]
                for s in _src:
                    writer.writerow([
                        s['time'], s['src_ip'], s['dst_host'], s['dst_ip'], s['dst_port'],
                        s['protocol'], s['method'], s['url'], s['status'], s['bytes_in'], s['bytes_out']
                    ])
            content_type = 'text/csv; charset=utf-8'
            filename = f"sessions_{timestamp}.csv"
            content = '\ufeff' + buf.getvalue()
        
        elif export_type == 'json':
            with history_lock:
                _ss = sessions_history
                _aa = alerts_history
                if start_ts is not None and end_ts is not None:
                    _ss = [s for s in _ss if start_ts <= s.get('timestamp', 0) / 1000 <= end_ts]
                    _aa = [a for a in _aa if start_ts <= a.get('timestamp', 0) / 1000 <= end_ts]
                export_data = {
                    'network_info': network_info,
                    'hosts': hosts_data,
                    'sessions': _ss,
                    'alerts': _aa,
                    'range': {'start': start_ts, 'end': end_ts} if start_ts is not None else None,
                    'export_time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
            content_type = 'application/json; charset=utf-8'
            filename = f"full_data_{timestamp}.json"
            content = json.dumps(export_data, ensure_ascii=False, indent=2)
        
        elif export_type == 'hosts':
            writer = csv.writer(buf)
            writer.writerow(['IP', 'MAC', 'Hostname', 'Type', 'OS', 'Status', 'FirstSeen', 'LastSeen'])
            with hosts_lock:
                for h in hosts_data:
                    writer.writerow([
                        h['ip'], h['mac'], h['hostname'], h['type'], h['os'], h['status'],
                        h['first_seen'], h['last_seen']
                    ])
            content_type = 'text/csv; charset=utf-8'
            filename = f"hosts_{timestamp}.csv"
            content = '\ufeff' + buf.getvalue()

        elif export_type == 'audit':
            # v2.17 审计日志导出 CSV（start/end 时间段过滤，默认全部）
            writer = csv.writer(buf)
            writer.writerow(['#', '时间', '动作', '详情'])
            _arows = db.list_audit(100000)
            def _in_range(row_ts, s0, e0):
                try:
                    _t = datetime.datetime.strptime(row_ts, '%Y-%m-%d %H:%M:%S').timestamp()
                except Exception:
                    return True
                return (s0 is None or _t >= s0) and (e0 is None or _t <= e0)
            if start_ts is not None or end_ts is not None:
                _arows = [a for a in _arows if _in_range(a.get('ts') or '', start_ts, end_ts)]
            for _i, _a in enumerate(_arows):
                writer.writerow([_i + 1, _a.get('ts', ''), _a.get('action', ''), _a.get('detail', '')])
            content_type = 'text/csv; charset=utf-8'
            filename = f"audit_log_{timestamp}.csv"
            content = '\ufeff' + buf.getvalue()

        elif export_type == 'compliance':
            # v2.12 合规体检表（评分 + 优化建议）：重跑最新数据真实性校验并输出 CSV
            with hosts_lock:
                _hd = list(hosts_data)
            with history_lock:
                _sess = list(active_sessions)[-200:]
            try:
                _usr = auth.list_users()
                _nch = notify.list_configs()
            except Exception:
                _usr, _nch = None, None
            try:
                _checks = compliance.run_checks(_hd, db.list_devices(), db.list_policies(), _sess, _usr, _nch)
            except Exception as _e:
                _checks = []
            _advice = {
                'ip_mac_conflict': '核查冲突 IP 对应设备并更新设备注册表，避免地址冲突',
                'mac_dup': '区分多网卡/虚拟接口设备，必要时调整注册表 MAC-IP 绑定',
                'arp_scan_cross': '确认 ARP 独有设备在网并补充注册信息',
                'arp': '确认 ARP 采集线程运行正常，保障内网资产可见性',
                'scan': '确认扫描线程运行正常，周期性刷新存活资产',
                'oui': '及时更新 IEEE OUI 厂商库，保证厂商识别准确',
                'session': '确认浏览器探针上报链路正常，保证会话数据完整',
                'netstat': '确认本机连接统计采集正常',
                'dns': '确认 DNS 反向解析可用，完善域名归属性',
                'bw': '确认网卡带宽计量正常，保证流量统计准确',
            }
            _fmt = (params.get('format') or ['csv'])[0].lower()
            total = len(_checks)
            score = 0.0
            for ch in _checks:
                st = ch.get('status')
                score += 1.0 if st in ('pass', 'ok') else (0.5 if st == 'warn' else 0.0)
            _ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            def _advice_for(ch):
                st = ch.get('status')
                if st in ('pass', 'ok'):
                    return '无需处理'
                return _advice.get(ch.get('id'), '核查相关数据源并补充完善') if st == 'fail' else '建议关注并核查'
            if _fmt == 'json':
                export_obj = {
                    'report': 'WebNetProbe 合规体检表',
                    'generated_at': _ts,
                    'basis': 'ISO/IEC 27001:2022 Annex A · 等保 3.0（GB/T 22239 三级）',
                    'score': round(score, 1),
                    'max_score': total,
                    'percent': round(score / total * 100, 1) if total else 0,
                    'data_truthfulness': '基于最新一次数据真实性校验结果动态生成',
                    'checks': [
                        {'id': ch.get('id'), 'name': ch.get('name'), 'status': ch.get('status'),
                         'detail': ch.get('detail', ''), 'advice': _advice_for(ch)}
                        for ch in _checks
                    ],
                }
                content = json.dumps(export_obj, ensure_ascii=False, indent=2)
                content_type = 'application/json; charset=utf-8'
                filename = f"compliance_health_{timestamp}.json"
            elif _fmt == 'pdf':
                try:
                    from fpdf import FPDF
                    # v2.19 固化 PDF：深信服样式表格化（表头/列宽/自动分页/页脚），真实可打开
                    _CAT = {
                        'ip_mac_conflict': '安全计算环境-访问控制', 'mac_dup': '安全计算环境-访问控制',
                        'arp_scan_cross': '安全区域边界-入侵防范', 'oui_coverage': '安全计算环境-资产识别',
                        'arp': '安全区域边界-网络访问控制', 'scan': '安全区域边界-入侵防范',
                        'session': '安全通信网络-通信传输', 'netstat': '安全计算环境-安全审计',
                        'dns': '安全通信网络-通信传输', 'bw': '安全计算环境-资源控制',
                        'session_valid': '安全通信网络-通信传输', 'policy_valid': '安全区域边界-访问控制',
                        'freshness': '安全区域边界-入侵防范', 'access_control': '安全计算环境-访问控制',
                        'notify_ready': '安全管理中心-安全监测',
                    }
                    _ST = {'pass': '符合', 'ok': '符合', 'warn': '部分符合', 'fail': '不符合'}
                    _RISK = {'pass': '低', 'ok': '低', 'warn': '中', 'fail': '高'}
                    _W = (10, 32, 40, 55, 18, 15, 20)
                    class _CompliancePdf(FPDF):
                        def footer(self):
                            self.set_font('hei', '', 8)
                            self.set_y(-12)
                            self.cell(0, 8, 'WebNetProbe 合规体检报告 - 第 {} 页 / 共 {{nb}} 页'.format(self.page_no()), align='C', new_x='LMARGIN', new_y='NEXT')
                        def check_space(self, h):
                            if self.get_y() + h > 278:
                                self.add_page()
                        def row(self, cells):
                            _lines = []
                            for _i, _t in enumerate(cells):
                                self.set_font('hei', '', 8)
                                try:
                                    _parts = self.multi_cell(_W[_i], 5, str(_t), split_only=True)
                                    _nl = max(1, len(_parts)) if isinstance(_parts, (list, tuple)) else 1
                                except Exception:
                                    _nl = max(1, int(self.get_string_width(str(_t)) / (_W[_i] * 0.5)) + 1)
                                _lines.append(_nl)
                            _h = max(_lines) * 5 + 2
                            self.check_space(_h)
                            _y0 = self.get_y()
                            _x0 = 10
                            for _i, _t in enumerate(cells):
                                self.set_xy(_x0, _y0)
                                self.set_font('hei', '', 8)
                                self.multi_cell(_W[_i], 5, str(_t), border=1)
                                _x0 += _W[_i]
                            self.set_y(_y0 + _h)
                        def head_row(self, cells):
                            self.set_fill_color(23, 32, 61)
                            self.set_text_color(0, 212, 255)
                            self.set_font('hei', '', 9)
                            for _i, _t in enumerate(cells):
                                self.cell(_W[_i], 7, _t, border=1, fill=True, align='C')
                            self.ln()
                            self.set_text_color(0, 0, 0)
                    pdf = _CompliancePdf('P', 'mm', 'A4')
                    pdf.set_auto_page_break(auto=True, margin=16)
                    pdf.add_page()
                    _font_path = None
                    for _fp in (r'C:\Windows\Fonts\simhei.ttf', r'C:\Windows\Fonts\msyh.ttc', r'C:\Windows\Fonts\simsun.ttc'):
                        if os.path.exists(_fp):
                            _font_path = _fp
                            break
                    if not _font_path:
                        raise RuntimeError('未找到系统中文字体文件')
                    pdf.add_font('hei', '', _font_path)
                    pdf.set_font('hei', '', 16)
                    pdf.cell(190, 10, 'WebNetProbe 合规体检报告', align='C', new_x='LMARGIN', new_y='NEXT')
                    pdf.set_font('hei', '', 9)
                    pdf.cell(190, 6, '生成时间：' + _ts, align='C', new_x='LMARGIN', new_y='NEXT')
                    pdf.cell(190, 6, '评估依据：ISO/IEC 27001:2022 Annex A · 等保 3.0（GB/T 22239 三级）', align='C', new_x='LMARGIN', new_y='NEXT')
                    pdf.ln(4)
                    pdf.head_row(['序号', '检查类别', '检查项', '检查内容', '检查结果', '风险等级', '整改建议'])
                    for _i, ch in enumerate(_checks, 1):
                        _st = ch.get('status')
                        pdf.row([_i, _CAT.get(ch.get('id'), '安全管理中心-综合管理'), ch.get('name'),
                                 str(ch.get('detail', '')), _ST.get(_st, _st), _RISK.get(_st, '-'), _advice_for(ch)])
                    pdf.ln(4)
                    pdf.set_font('hei', '', 11)
                    pdf.cell(190, 8, '合规体检评分：{:.1f} 分 / 满分 {} 分（{:.0f}%）'.format(score, total, (score / total * 100) if total else 0), new_x='LMARGIN', new_y='NEXT')
                    pdf.cell(190, 8, '数据真实性：基于最新一次数据真实性校验结果动态生成', new_x='LMARGIN', new_y='NEXT')
                    content = pdf.output(dest='S')
                    content_type = 'application/pdf'
                    filename = f"compliance_health_{timestamp}.pdf"
                except Exception as _pe:
                    return self._json_response({'status': 'error', 'msg': 'PDF 生成失败: ' + str(_pe)})
            else:
                # v2.19 深信服合规体检表样式：序号/检查类别/检查项/检查内容/检查结果/风险等级/整改建议
                _CAT = {
                    'ip_mac_conflict': '安全计算环境-访问控制', 'mac_dup': '安全计算环境-访问控制',
                    'arp_scan_cross': '安全区域边界-入侵防范', 'oui_coverage': '安全计算环境-资产识别',
                    'arp': '安全区域边界-网络访问控制', 'scan': '安全区域边界-入侵防范',
                    'session': '安全通信网络-通信传输', 'netstat': '安全计算环境-安全审计',
                    'dns': '安全通信网络-通信传输', 'bw': '安全计算环境-资源控制',
                    'session_valid': '安全通信网络-通信传输', 'policy_valid': '安全区域边界-访问控制',
                    'freshness': '安全区域边界-入侵防范', 'access_control': '安全计算环境-访问控制',
                    'notify_ready': '安全管理中心-安全监测',
                }
                _ST = {'pass': '符合', 'ok': '符合', 'warn': '部分符合', 'fail': '不符合'}
                _RISK = {'pass': '低', 'ok': '低', 'warn': '中', 'fail': '高'}
                writer = csv.writer(buf)
                writer.writerow(['序号', '检查类别', '检查项', '检查内容', '检查结果', '风险等级', '整改建议'])
                for _i, ch in enumerate(_checks, 1):
                    _st = ch.get('status')
                    writer.writerow([
                        _i, _CAT.get(ch.get('id'), '安全管理中心-综合管理'), ch.get('name'),
                        str(ch.get('detail', '')), _ST.get(_st, _st), _RISK.get(_st, '-'), _advice_for(ch)
                    ])
                writer.writerow([])
                writer.writerow(['合规体检评分', '{:.1f} 分 / 满分 {} 分（{:.0f}%）'.format(score, total, (score / total * 100) if total else 0)])
                writer.writerow(['评估依据', 'ISO/IEC 27001:2022 Annex A · 等保 3.0（GB/T 22239 三级）'])
                writer.writerow(['生成时间', _ts])
                writer.writerow(['评估依据', 'ISO/IEC 27001:2022 Annex A · 等保 3.0（GB/T 22239 三级）'])
                writer.writerow(['数据真实性', '基于最新一次数据真实性校验结果动态生成'])
                content_type = 'text/csv; charset=utf-8'
                filename = f"compliance_health_{timestamp}.csv"
                content = '\ufeff' + buf.getvalue()
        
        elif export_type == 'devices':
            writer = csv.writer(buf)
            writer.writerow(['MAC', 'IP', 'Vendor', 'Hostname', 'Type', 'Group', 'Status', 'FirstSeen', 'LastSeen'])
            for d in db.list_devices():
                writer.writerow([
                    d['mac'], d['ip'], d['vendor'], d['hostname'], d['type'],
                    d['group_name'], d['status'], d['first_seen'], d['last_seen']
                ])
            content_type = 'text/csv; charset=utf-8'
            filename = f"devices_{timestamp}.csv"
            content = '\ufeff' + buf.getvalue()
        
        elif export_type == 'alerts':
            writer = csv.writer(buf)
            writer.writerow(['Time', 'Level', 'Type', 'SrcIP', 'DstIP', 'Message'])
            with history_lock:
                _aa = alerts_history
                if start_ts is not None and end_ts is not None:
                    _aa = [a for a in _aa if start_ts <= a.get('timestamp', 0) / 1000 <= end_ts]
                for a in _aa:
                    writer.writerow([
                        a['time'], a['level'], a['type'], a['src_ip'], a['dst_ip'], a['msg']
                    ])
            content_type = 'text/csv; charset=utf-8'
            filename = f"alerts_{timestamp}.csv"
            content = '\ufeff' + buf.getvalue()
        
        else:
            self.send_error(400, 'Unsupported export type')
            return
        
        if isinstance(content, str):
            content_bytes = content.encode('utf-8')
        elif isinstance(content, (bytes, bytearray)):
            content_bytes = bytes(content)
        else:
            content_bytes = str(content).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(content_bytes)))
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(content_bytes)
    
    def log_message(self, format, *args):
        """静默访问日志"""
        pass

def _append_alert(alert):
    """统一写入告警：分配 seq、上限裁剪、计数"""
    with history_lock:
        alert_seq_counter[0] += 1
        alert['seq'] = alert_seq_counter[0]
        alerts_history.append(alert)
        if len(alerts_history) > ALERTS_MAX:
            del alerts_history[:len(alerts_history) - ALERTS_MAX]
    with stats_lock:
        current_stats['alert_count'] = len(alerts_history)
    # v2.11 风险提示：告警异步推送到已启用渠道（10 分钟同 key 去重）
    try:
        _notify_alert(alert)
    except Exception:
        pass


_NOTIFY_DEDUP = {}
def _notify_alert(alert):
    """通知去重：同类型+同消息 10 分钟内只推一次"""
    key = (str(alert.get('type', '')) + '|' + str(alert.get('msg', ''))[:50])
    now = time.time()
    last = _NOTIFY_DEDUP.get(key, 0)
    if now - last < 600:
        return
    _NOTIFY_DEDUP[key] = now
    title = f"安全告警[{alert.get('level', 'info')}] {alert.get('type', '未知')}"
    content = f"时间：{alert.get('time', '')}\n类型：{alert.get('type', '')}\n等级：{alert.get('level', '')}\n来源：{alert.get('src_ip', '')} -> {alert.get('dst_ip', '')}\n详情：{alert.get('msg', '')}"
    notify.send_all_async(title, content)


def _clear_alerts():
    """清空全部告警（重置）"""
    with history_lock:
        alerts_history.clear()
    with stats_lock:
        current_stats['alert_count'] = 0
    db.audit('admin_reset', '清空安全告警（全部删除/重置）')


def _reset_module(module):
    """模块重置：alerts / sessions / attacks / usage_today / all"""
    global session_id_counter
    if module in ('alerts', 'all'):
        _clear_alerts()
    if module in ('sessions', 'all'):
        with history_lock:
            sessions_history.clear()
            active_sessions.clear()
        session_id_counter = 0
        with stats_lock:
            current_stats['total_sessions'] = 0
    if module in ('attacks', 'all'):
        with ATTACK_LOCK:
            ATTACK_EVENTS.clear()
            ATTACK_BLOCKS.clear()
            _attack_debounce.clear()
    if module in ('usage_today', 'all'):
        today = time.strftime('%Y-%m-%d')
        with usage_lock:
            daily_usage[today] = {'down': 0, 'up': 0}
            db.upsert_usage(today, 0, 0)
    db.audit('admin_reset', '模块重置: ' + module)
    return True


def _sync_compliance_alerts(checks):
    """将合规检查的 warn/fail 项写入告警流（同规则 10 分钟去重）"""
    # 修复：去重判断仅锁内短读，追加告警在锁外执行（_append_alert 内部会再取 history_lock，
    # 若此处持锁调用将造成普通 Lock 同线程二次 acquire 死锁，导致全系统相关接口永久超时）
    now = time.time()
    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    for ch in checks:
        st = ch.get('status')
        if st not in ('pass', 'ok', None):
            key = 'compliance:' + str(ch.get('id') or ch.get('name'))
            with history_lock:
                dup = any(a.get('rule_id') == key and now - a.get('timestamp', 0) / 1000 < 600 for a in alerts_history)
            if dup:
                continue
            _append_alert({
                'time': now_str,
                'timestamp': now * 1000,
                'level': 'high' if st == 'fail' else 'medium',
                'type': '合规检查',
                'src_ip': '-',
                'dst_ip': '-',
                'msg': ch.get('name', '') + '：' + str(ch.get('detail', '')),
                'rule_id': key
            })


def _conn_src_dst(conn):
    """连接记录拆分为 (local_ip, local_port), (remote_ip, remote_port)"""
    def split(addr):
        if not addr:
            return '', 0
        if addr.startswith('['):
            ipp = addr[1:].split(']')
            p = ipp[1].lstrip(':') if len(ipp) > 1 else ''
            return ipp[0], (int(p) if p.isdigit() else 0)
        if ':' in addr:
            ip, p = addr.rsplit(':', 1)
            return ip, (int(p) if p.isdigit() else 0)
        return addr, 0
    return split(conn.get('local', '')), split(conn.get('remote', ''))


def _block_attack_ip(ip, atype, reason):
    """自动封禁公网攻击源（复用防火墙模块，需管理员权限）"""
    if ip in ATTACK_BLOCKS:
        return
    name = 'attack_' + ip.replace('.', '_') + '_' + str(int(time.time()) % 100000)
    try:
        ok, msg, rec = firewall.create_rule(name, 'in', 'tcp', 0, ip, note='攻击自动封禁:' + atype)
    except Exception as e:
        ok, msg, rec = False, str(e), None
    ATTACK_BLOCKS[ip] = {
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'reason': reason, 'type': atype,
        'rule_id': rec.get('id') if rec else None,
        'status': 'blocked' if ok else ('failed:' + str(msg)[:80])
    }


def attack_monitor():
    """攻击检测线程：基于实时连接表（netstat）每 3 秒分析"""
    while True:
        time.sleep(3)
        try:
            with CONN_LOCK:
                conns = list(CONN_CACHE['data'])
        except Exception:
            conns = []
        if not conns:
            continue
        now = time.time()
        syn = sum(1 for c in conns if c.get('state') == 'SYN_SENT')
        by_src = {}   # src_ip -> {ports:set, count}
        by_dst = {}   # local_port -> {sources:set, count}
        for c in conns:
            (lip, lport), (rip, rport) = _conn_src_dst(c)
            if not rip or rip in ('0.0.0.0', '::', '127.0.0.1', '::1', '0:0:0:0:0:0:0:0'):
                continue
            s = by_src.setdefault(rip, {'ports': set(), 'count': 0})
            s['ports'].add(lport); s['count'] += 1
            d = by_dst.setdefault(lport, {'sources': set(), 'count': 0})
            d['sources'].add(rip); d['count'] += 1
        events = []
        if syn >= 30:
            events.append({'ip': '-', 'type': 'SYN洪泛', 'level': 'high',
                           'msg': 'SYN_SENT 状态连接 %d 条，疑似 SYN 洪泛攻击' % syn, 'ports': '-'})
        for p, info in by_dst.items():
            if info['count'] >= 60 and len(info['sources']) >= 10:
                for sip in info['sources']:
                    if _is_public_ip(sip):
                        events.append({'ip': sip, 'type': 'DDoS攻击', 'level': 'high',
                                       'msg': '对端口 %d 发起 %d 条连接（来源 %d 个），疑似 DDoS 攻击' % (p, info['count'], len(info['sources'])),
                                       'ports': str(p)})
        for sip, info in by_src.items():
            if len(info['ports']) >= 15 and _is_public_ip(sip):
                ports = ','.join(str(x) for x in sorted(info['ports'])[:8])
                events.append({'ip': sip, 'type': '端口扫描', 'level': 'high',
                               'msg': '来自 %s 的连接覆盖 %d 个不同端口，疑似端口扫描' % (sip, len(info['ports'])),
                               'ports': ports})
        for sip, info in by_src.items():
            sens = [p for p in info['ports'] if p in _ATTACK_SENSITIVE_PORTS]
            if len(sens) >= 20:
                events.append({'ip': sip, 'type': '暴力破解', 'level': 'high',
                               'msg': '来自 %s 对敏感端口 %s 的尝试 %d 次，疑似暴力破解' % (sip, ','.join(str(x) for x in sorted(set(sens))[:6]), len(sens)),
                               'ports': ','.join(str(x) for x in sorted(set(sens))[:6])})
        for sip, info in by_src.items():
            if info['count'] >= 40 and _is_public_ip(sip):
                events.append({'ip': sip, 'type': '异常外联', 'level': 'medium',
                               'msg': '本机对 %s 的连接数 %d，疑似异常外联' % (sip, info['count']), 'ports': '-'})
        for ev in events:
            if _is_whitelisted(ev['ip']):
                continue  # 白名单源不产生攻击告警
            key = (ev['ip'], ev['type'])
            if now - _attack_debounce.get(key, 0) < 60:
                continue
            _attack_debounce[key] = now
            ts = time.strftime('%Y-%m-%d %H:%M:%S')
            rec = {'time': ts, 'timestamp': now * 1000, 'level': ev['level'], 'type': ev['type'],
                   'src_ip': ev['ip'], 'dst_ip': '-', 'ports': str(ev['ports']), 'msg': ev['msg'],
                   'status': 'detected', 'highlight': True}
            with ATTACK_LOCK:
                ATTACK_EVENTS.append(rec)
            _append_alert(dict(rec, type='攻击检测:' + ev['type']))
            if AUTO_BLOCK_ATTACKS['enabled'] and ev['ip'] != '-' and _is_public_ip(ev['ip']):
                _block_attack_ip(ev['ip'], ev['type'], ev['msg'])


def _risk_score():
    """近 30 分钟攻击事件加权评分（时间衰减）"""
    now = time.time()
    score = 0.0
    with ATTACK_LOCK:
        events = list(ATTACK_EVENTS)
    for e in events[-120:]:
        age = (now - e.get('timestamp', 0) / 1000) / 60.0
        if age > 30:
            continue
        w = {'high': 10, 'medium': 5, 'low': 2}.get(e.get('level'), 2)
        score += w * (0.9 ** age)
    level = '低' if score < 5 else ('中' if score < 20 else '高')
    return round(score, 1), level


def _situational():
    with ATTACK_LOCK:
        attacks = list(reversed(list(ATTACK_EVENTS)[-50:]))
    blocks = []
    for ip, b in list(ATTACK_BLOCKS.items()):
        blocks.append(dict(ip=ip, **b))
    score, level = _risk_score()
    for a in attacks:
        a['blocked'] = a.get('src_ip', '-') in ATTACK_BLOCKS
    return {
        'attacks': attacks,
        'blocks': blocks,
        'stats': {
            'total_attacks': len(ATTACK_EVENTS),
            'blocked_count': len(ATTACK_BLOCKS),
            'risk_score': score,
            'risk_level': level,
            'auto_block': AUTO_BLOCK_ATTACKS['enabled']
        }
    }


def _usage_months():
    """最近 12 个自然月聚合（月度选择）"""
    days = db.get_usage_days(400)
    with usage_lock:
        for d, v in daily_usage.items():
            days[d] = {'down': v['down'], 'up': v['up']}
    months = {}
    for d, v in days.items():
        ym = d[:7]
        m = months.setdefault(ym, {'down': 0, 'up': 0})
        m['down'] += v['down']; m['up'] += v['up']
    out = []
    lt = time.localtime()
    for i in range(12):
        y = lt.tm_year; m = lt.tm_mon - i
        while m <= 0:
            m += 12; y -= 1
        ym = '%04d-%02d' % (y, m)
        v = months.get(ym, {'down': 0, 'up': 0})
        out.append({'ym': ym, 'down': v['down'], 'up': v['up'], 'total': v['down'] + v['up']})
    return {'months': out}


def _usage_month(ym):
    """指定月份每日累计明细"""
    import re
    if not re.match(r'^\d{4}-\d{2}$', ym or ''):
        return {'ym': ym or '', 'days': [], 'down': 0, 'up': 0, 'total': 0}
    days = db.get_usage_days(400)
    with usage_lock:
        for d, v in daily_usage.items():
            days[d] = {'down': v['down'], 'up': v['up']}
    out = []
    td = tu = 0
    for d in sorted(days.keys()):
        if d.startswith(ym):
            v = days[d]
            td += v['down']; tu += v['up']
            out.append({'date': d, 'down': v['down'], 'up': v['up'], 'total': v['down'] + v['up']})
    return {'ym': ym, 'days': out, 'down': td, 'up': tu, 'total': td + tu}


def _ip_lookup(query):
    """IP / 域名 查询：分类/归属/平台/端口统计/封禁状态/风险（支持域名反向解析）"""
    import ipaddress
    q = (query or '').strip()
    if not q:
        return {'error': '请输入 IP 或域名'}
    try:
        a = ipaddress.ip_address(q)
    except ValueError:
        ips, plat = _resolve_domain(q)
        if not ips:
            return {'error': '域名无法解析（DNS 查询失败或无 A 记录）'}
        ports = _session_ports(q, ips)
        risk = '高' if any(i in ATTACK_BLOCKS for i in ips) else '中'
        return {
            'ip': ips[0], 'ips': ips, 'domain': q, 'platform': plat or _domain_platform(q),
            'category': '域名解析', 'detail': '反向查询 ' + str(len(ips)) + ' 个 A 记录',
            'device': None, 'blocked': None, 'risk': risk, 'ports': ports,
            'whitelisted': _is_whitelisted(q),
            'threat_url': 'https://x.threatbook.com/v5/ip/' + ips[0],
            'is_public': True
        }
    ip = str(a)
    if a.is_private:
        cat, detail = '内网私网地址', 'RFC1918 私有地址'
    elif a.is_loopback:
        cat, detail = '本机回环地址', '127.0.0.0/8'
    elif a.is_link_local:
        cat, detail = '链路本地地址', '169.254.0.0/16'
    elif a.is_multicast:
        cat, detail = '组播地址', '224.0.0.0/4'
    elif a.is_reserved:
        cat, detail = '保留地址', 'IANA 保留段'
    elif a.version == 4 and str(a) == '255.255.255.255':
        cat, detail = '受限广播地址', 'IPv4 受限广播'
    else:
        cat, detail = '公网地址', '可访问互联网'
    dev = None
    try:
        for d in db.list_devices():
            if d.get('ip') == ip:
                dev = {'mac': d.get('mac', ''), 'hostname': d.get('hostname') or d.get('vendor') or '',
                       'vendor': d.get('vendor', ''), 'status': d.get('status', '')}
                break
    except Exception:
        pass
    blocked = None
    if ip in ATTACK_BLOCKS:
        blocked = dict(ATTACK_BLOCKS[ip])
    else:
        try:
            for r in firewall.list_rules():
                if r.get('remote_ip') == ip:
                    blocked = {'time': r.get('created_at', ''), 'reason': r.get('note', ''),
                               'status': 'blocked' if r.get('status') == 'active' else r.get('status', '')}
                    break
        except Exception:
            pass
    geo = _geo_guess(ip) if cat == '公网地址' else None
    hostname = _reverse_host(ip) if cat == '公网地址' else ''
    ports = _session_ports(ip, [ip])
    risk = '高' if blocked else ('中' if cat == '公网地址' else '低')
    return {
        'ip': ip, 'category': cat, 'detail': detail, 'device': dev,
        'blocked': blocked, 'risk': risk, 'geo': geo, 'hostname': hostname,
        'ports': ports, 'whitelisted': _is_whitelisted(ip),
        'threat_url': 'https://x.threatbook.com/v5/ip/' + ip,
        'is_public': cat == '公网地址'
    }


def _session_ports(host, ips):
    """会话中该目标（域名或 IP）出现的端口统计（取前 6）"""
    from collections import Counter
    cnt = Counter()
    try:
        with history_lock:
            for s in sessions_history:
                if s.get('dst_ip') in ips or (host and s.get('dst_host') == host):
                    cnt[s.get('dst_port')] += 1
    except Exception:
        pass
    return [{'port': k, 'count': v} for k, v in cnt.most_common(6)]


def _detect_anomalies(session):
    """简单异常检测（白名单目标跳过）"""
    if _is_whitelisted(session.get('dst_ip')) or _is_whitelisted(session.get('dst_host')):
        return []
    alerts = []
    now = datetime.datetime.now()
    time_str = now.strftime('%Y-%m-%d %H:%M:%S')
    
    # 明文HTTP传输
    if session['protocol'] == 'HTTP' and session['dst_port'] == 80:
        alerts.append({
            'time': time_str,
            'timestamp': now.timestamp()*1000,
            'level': 'medium',
            'type': 'Plaintext HTTP',
            'src_ip': session['src_ip'],
            'dst_ip': session['dst_ip'],
            'msg': f"明文HTTP访问: {session['dst_host']}{session['url'][:50]}"
        })
    
    # 敏感端口访问
    suspicious_ports = {
        22: 'SSH',
        23: 'Telnet',
        135: 'RPC',
        139: 'NetBIOS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5985: 'WinRM',
        6379: 'Redis'
    }
    if session['dst_port'] in suspicious_ports:
        alerts.append({
            'time': time_str,
            'timestamp': now.timestamp()*1000,
            'level': 'medium',
            'type': f'Sensitive Port',
            'src_ip': session['src_ip'],
            'dst_ip': session['dst_ip'],
            'msg': f"访问敏感端口 {session['dst_port']} ({suspicious_ports[session['dst_port']]}) -> {session['dst_host']}"
        })
    
    # 大流量下载
    if session['bytes_in'] > 5*1024*1024:
        alerts.append({
            'time': time_str,
            'timestamp': now.timestamp()*1000,
            'level': 'info',
            'type': 'Large Transfer',
            'src_ip': session['src_ip'],
            'dst_ip': session['dst_ip'],
            'msg': f"大流量下载: {session['bytes_in']/1024/1024:.2f}MB from {session['dst_host']}"
        })
    
    return alerts

# ==================== 基于策略引擎的终端流控 ====================
def _migrate_legacy_flow_policy():
    """将旧版 flow_policy.json（按MAC限速，Kbps）一次性迁移到新策略引擎"""
    if not os.path.exists(LEGACY_POLICY_FILE):
        return
    try:
        if db.query_one("SELECT COUNT(*) AS c FROM policies")['c'] > 0:
            return
        with open(LEGACY_POLICY_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        migrated = 0
        for mac, pol in data.items():
            if not isinstance(pol, dict) or not _normalize_mac(mac):
                continue
            db.create_policy({
                'name': (pol.get('remark') or f"旧版策略-{_normalize_mac(mac)}")[:50],
                'target_type': 'mac',
                'target_value': _normalize_mac(mac),
                'ports': '', 'protocols': '',
                'schedule_days': '1,2,3,4,5,6,7',
                'schedule_start': '00:00', 'schedule_end': '23:59',
                'down_limit': int(pol.get('down_limit', 0) or 0) * 1024,  # Kbps -> bps
                'up_limit': int(pol.get('up_limit', 0) or 0) * 1024,
                'priority': 0,
                'enabled': bool(pol.get('enabled', True)),
                'dynamic_mode': False,
            })
            migrated += 1
        if migrated:
            db.audit('policy_migrate', f"从旧版 flow_policy.json 迁移 {migrated} 条策略（Kbps→bps）")
        print(f"[+] 已迁移旧版流控策略: {migrated} 条")
    except Exception as e:
        print(f"[!] 旧版策略迁移失败(忽略): {e}")

def _track_flow(src_ip, bytes_in):
    """记录终端流量并返回最近60秒窗口的估算字节数（软流控数据源：会话上报）"""
    now = time.time()
    q = flow_tracker[src_ip]
    q.append((now, bytes_in))
    while q and now - q[0][0] > FLOW_WINDOW_SEC:
        q.popleft()
    return sum(b for t, b in q)

def _check_flow_limit(session):
    """基于会话估算的每终端流控检查（估算值，非真实抓包）。
    限速取自策略引擎：命中设备且时段内、优先级最高的启用策略。"""
    global flow_alert_last
    src_ip = session.get('src_ip', '')
    if not src_ip:
        return None
    mac = (_ip_to_mac(src_ip) or '').lower()
    if not mac:
        return None
    dev = db.query_one("SELECT * FROM devices WHERE mac=?", (mac,))
    dev_ctx = {'mac': mac, 'ip': src_ip, 'group_name': dev['group_name'] if dev else ''}
    down_limit = policies.effective_down_limit(dev_ctx)  # bps
    if down_limit <= 0:
        return None
    cur_bytes = _track_flow(src_ip, session.get('bytes_in', 0))
    cur_bps = cur_bytes * 8 / FLOW_WINDOW_SEC  # 60秒窗口估算速率(bps)
    if cur_bps > down_limit:
        now = time.time()
        if now - flow_alert_last.get(mac, 0) > FLOW_ALERT_INTERVAL:  # 去重，避免刷屏
            flow_alert_last[mac] = now
            now_dt = datetime.datetime.now()
            return {
                'time': now_dt.strftime('%Y-%m-%d %H:%M:%S'),
                'timestamp': now_dt.timestamp() * 1000,
                'level': 'medium',
                'type': 'Flow Limit',
                'src_ip': src_ip,
                'dst_ip': session.get('dst_ip', ''),
                'msg': f"终端 {mac} 超流控上限: 当前≈{cur_bps/1024:.0f}Kbps > 限制 {down_limit/1024:.0f}Kbps"
            }
    return None

def _export_flow_script():
    """生成基于MAC限速的部署脚本（Linux网关 / OpenWrt 通用，tc + iptables）"""
    items = []
    for p in db.list_policies():
        if p['enabled'] and p['target_type'] in ('mac', 'device') and p['down_limit'] > 0:
            items.append((p['target_value'].lower(), int(p['down_limit']), p['name']))
    if not items:
        return None, "请先配置至少一条启用的按MAC限速策略（目标类型=设备/MAC）"
    items.sort()
    lines = [
        '#!/bin/sh',
        '# WebNetProbe 按MAC限速脚本（Linux网关/OpenWrt通用）',
        '# 作用：在网关LAN口限制指定终端的下行带宽（路由器 -> 终端）',
        '# 用法：',
        '#   1. 修改下方 IFACE 为实际LAN接口（OpenWrt 一般为 br-lan，执行 ip link 查看）',
        '#   2. 需要 root 权限执行: sh flow_limit.sh',
        '#   3. 恢复不限速: sh flow_limit.sh clear',
        '',
        'IFACE=br-lan',
        'TOTAL_DOWN=100mbit   # 总下行带宽，按你的实际带宽修改',
        '',
        'clear_rules() {',
        '    tc qdisc del dev $IFACE root 2>/dev/null',
        '    iptables -t mangle -F WNP_MARK 2>/dev/null',
        '    iptables -t mangle -D FORWARD -j WNP_MARK 2>/dev/null',
        '    iptables -t mangle -X WNP_MARK 2>/dev/null',
        '    echo "[*] 限速规则已清除"',
        '}',
        '',
        'if [ "$1" = "clear" ]; then',
        '    clear_rules',
        '    exit 0',
        'fi',
        '',
        'echo "[*] 正在应用按MAC限速规则到 $IFACE ..."',
        'clear_rules',
        '',
        'tc qdisc add dev $IFACE root handle 1: htb default 9999',
        'tc class add dev $IFACE parent 1: classid 1:9999 htb rate $TOTAL_DOWN',
        '',
        '# 建立 iptables 标记链',
        'iptables -t mangle -N WNP_MARK',
        'iptables -t mangle -A FORWARD -j WNP_MARK',
        '',
    ]
    for i, (mac, bps, name) in enumerate(items, start=10):
        mbit = max(1, round(bps / 8 / 1000000, 3))
        lines.append(f"# [{name}]  {mac}  限速 {bps/1024:.0f} Kbps ({mbit} Mbit)")
        lines.append(f"tc class add dev $IFACE parent 1: classid 1:{i} htb rate {mbit}mbit ceil {mbit}mbit")
        lines.append(f"iptables -t mangle -A WNP_MARK -m mac --mac-source {mac} -j MARK --set-mark {i}")
        lines.append(f"tc filter add dev $IFACE parent 1: protocol ip prio {i} handle {i} fw classid 1:{i}")
        lines.append('')
    lines.append('echo "[*] 完成。共为 ' + str(len(items)) + ' 台终端应用限速。"')
    lines.append('echo "[*] 如需撤销: sh flow_limit.sh clear"')
    content = '\n'.join(lines)
    filename = 'flow_limit.sh'
    return filename, content

# ==================== 数据持久化 ====================
def _save_state():
    """将内存数据落盘保存（原子写入，避免半截文件）"""
    try:
        with history_lock, hosts_lock:
            data = {
                'saved_at': datetime.datetime.now().isoformat(),
                'sessions': sessions_history[-20000:],
                'alerts': alerts_history[-10000:],
                'hosts': hosts_data,
                'bandwidth': list(bandwidth_history)[-86400:],
            }
        tmp = STATE_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, STATE_FILE)
        print(f"[+] 数据已保存: {STATE_FILE} (会话{len(data['sessions'])}/告警{len(data['alerts'])}/主机{len(data['hosts'])})")
    except Exception as e:
        print(f"[!] 数据保存失败: {e}")

def _load_state():
    """启动时加载历史数据"""
    global hosts_data
    try:
        if not os.path.exists(STATE_FILE):
            return
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        with history_lock:
            if isinstance(data.get('sessions'), list):
                sessions_history.extend(data['sessions'])
                if len(sessions_history) > SESSIONS_MAX:
                    del sessions_history[:len(sessions_history) - SESSIONS_MAX]
            if isinstance(data.get('alerts'), list):
                alerts_history.extend(data['alerts'])
                if len(alerts_history) > ALERTS_MAX:
                    del alerts_history[:len(alerts_history) - ALERTS_MAX]
            for p in data.get('bandwidth', []):
                if isinstance(p, dict) and 'time' in p:
                    bandwidth_history.append(p)
        if isinstance(data.get('hosts'), list) and data['hosts']:
            with hosts_lock:
                hosts_data = data['hosts']
        print(f"[+] 已加载历史数据: 会话 {len(sessions_history)} 条, 告警 {len(alerts_history)} 条, 主机 {len(hosts_data)} 台")
    except Exception as e:
        print(f"[!] 历史数据加载失败(忽略): {e}")

def scheduled_save():
    """定期保存数据"""
    while True:
        time.sleep(SAVE_INTERVAL)
        _save_state()

# ==================== 启动 ====================
def _load_daily_usage():
    """启动时载入数据库中的今日累计，保证重启不丢"""
    global daily_usage
    today = time.strftime('%Y-%m-%d')
    row = db.get_usage_day(today)
    daily_usage = {today: {'down': row['down'], 'up': row['up']}}

def _persist_daily_usage():
    with usage_lock:
        for d, v in list(daily_usage.items()):
            db.upsert_usage(d, v['down'], v['up'])

def _usage_stat():
    """今日/本月/本年累计 + 今日峰值（基于带宽历史）"""
    now = time.time()
    today = time.strftime('%Y-%m-%d')
    days = db.get_usage_days(400)
    with usage_lock:
        for d, v in daily_usage.items():
            days[d] = {'down': v['down'], 'up': v['up']}
    tod = days.get(today, {'down': 0, 'up': 0})
    mp = time.strftime('%Y-%m-')
    yp = time.strftime('%Y-')
    month = {'down': 0, 'up': 0}; year = {'down': 0, 'up': 0}
    for d, v in days.items():
        if d.startswith(mp):
            month['down'] += v['down']; month['up'] += v['up']
        if d.startswith(yp):
            year['down'] += v['down']; year['up'] += v['up']
    # 今日峰值：自今日 0 点的带宽历史
    day0 = time.mktime(time.strptime(today, '%Y-%m-%d'))
    with history_lock:
        pts = [p for p in bandwidth_history if p['time']/1000 >= day0]
    peak = {'down': {'bps': 0, 'at': None}, 'up': {'bps': 0, 'at': None}}
    for p in pts:
        if p['down'] > peak['down']['bps']:
            peak['down'] = {'bps': p['down'], 'at': time.strftime('%H:%M:%S', time.localtime(p['time']/1000))}
        if p['up'] > peak['up']['bps']:
            peak['up'] = {'bps': p['up'], 'at': time.strftime('%H:%M:%S', time.localtime(p['time']/1000))}
    # 峰值动态核对：返回样本窗口（今日0点起实时样本数），前端可验证峰值口径
    peak['samples'] = len(pts)
    return {
        'today': {'date': today, 'down': tod['down'], 'up': tod['up'], 'total': tod['down'] + tod['up']},
        'month': {'down': month['down'], 'up': month['up'], 'total': month['down'] + month['up']},
        'year':  {'down': year['down'],  'up': year['up'],  'total': year['down'] + year['up']},
        'peak': peak
    }

def _rollback_on_corrupt():
    """v2.21.13 启动自检：数据库完整性异常时列出镜像，提示用户选择回滚版本（不自动恢复、不启动坏库）"""
    try:
        import os as _os, glob as _gl, sys as _sys, sqlite3 as _sq
        if not _os.path.exists(db.DB_PATH):
            return
        _ok = 'ok'
        try:
            _con = _sq.connect(db.DB_PATH)
            _ok = _con.execute('PRAGMA quick_check').fetchone()[0]
            _con.close()
        except Exception:
            _ok = 'malformed'   # 打开/检查异常 = 数据库损坏
        if _ok == 'ok':
            return
        _bks = sorted(_gl.glob(_os.path.join(_os.path.dirname(db.DB_PATH), 'backup', 'webnetprobe_*.db')), reverse=True)
        print('=' * 60)
        print('[!] 数据库完整性异常(%s)，已阻止启动（防止坏库运行）。' % _ok)
        if _bks:
            print('    可选回滚镜像:')
            for _i, _b in enumerate(_bks):
                print('    [%d] %s (%d bytes)' % (_i, _os.path.basename(_b), _os.path.getsize(_b)))
            print('    请运行: python rollback.py <序号>   选择回滚版本（回滚后自动重启服务）')
        else:
            print('    无备份镜像。请先运行: python backup_db.py 备份；或删除损坏的数据库文件后重启。')
        print('=' * 60)
        _sys.exit(1)
    except SystemExit:
        raise
    except Exception as _e:
        print('[!] 数据库启动自检跳过: %s' % _e)

def main():
    global network_info, hosts_data
    
    print("=" * 60)
    print("  WebNetProbe 内网流量探针平台 v2.6（态势感知版）")
    print("=" * 60)
    
    # v2.21.12 异常回滚机制：启动自检（数据库损坏自动恢复最近备份镜像）
    _rollback_on_corrupt()

    # 初始化数据层（SQLite）+ IEEE 厂商库
    db.get_conn()
    print(f"[+] 数据库就绪: {db.DB_PATH}")
    n_oui = oui.load_oui()
    print(f"[+] 厂商库已加载: {n_oui} 条（IEEE OUI MA-L 官方数据）")
    
    # 加载历史数据与旧版策略迁移
    _load_state()
    _migrate_legacy_flow_policy()
    
    # 设备注册表：上次会话的设备恢复进内存主机列表（状态待扫描刷新）
    try:
        saved_devs = db.list_devices()
        if saved_devs and not hosts_data:
            with hosts_lock:
                hosts_data = [{
                    'ip': d['ip'], 'mac': d['mac'],
                    'hostname': d['hostname'] or (d['vendor'] or f"设备-{d['mac'][-2:]}"),
                    'type': d['type'], 'os': d['os_guess'], 'status': d['status'],
                    'first_seen': d['first_seen'], 'last_seen': d['last_seen'],
                    'rx_bytes': 0, 'tx_bytes': 0
                } for d in saved_devs]
            print(f"[+] 已恢复设备注册表: {len(saved_devs)} 台")
    except Exception as e:
        print(f"[!] 设备注册表恢复失败(忽略): {e}")
    
    print("\n[+] 正在获取网络信息...")
    network_info = get_all_network_info()
    
    print(f"[+] 操作系统: {network_info['os_info']}")
    print(f"[+] 检测到 {len(network_info['interfaces'])} 张网卡:")
    for iface in network_info['interfaces']:
        print(f"    - {iface['name']}: {iface['inet']} / {iface['netmask']} (MAC: {iface['mac']}) [{iface['status']}]")
    
    print(f"[+] 默认网关: {', '.join(g['ip'] for g in network_info['gateways']) if network_info['gateways'] else '未检测到'}")
    print(f"[+] 本机IP: {network_info['local_ip']}")
    print(f"[+] 内网网段: {', '.join(network_info['local_subnets']) if network_info['local_subnets'] else '未检测到'}")
    if network_info['public_ip']:
        print(f"[+] 公网出口IP: {network_info['public_ip']}")
    
    _load_daily_usage()  # 载入今日累计（重启不丢）
    print("\n[+] 启动后台服务线程...")
    threading.Thread(target=update_bandwidth_stats, daemon=True).start()
    threading.Thread(target=update_connection_stats, daemon=True).start()
    threading.Thread(target=scheduled_scan, daemon=True).start()
    threading.Thread(target=scheduled_save, daemon=True).start()
    threading.Thread(target=attack_monitor, daemon=True).start()
    
    # 首次同步设备注册表（ARP 立即采集，不等首轮扫描）
    try:
        arp.sync_devices(hosts_data)
        print(f"[+] 设备注册表已同步: {len(db.list_devices())} 台")
    except Exception as e:
        print(f"[!] 设备注册表初始化失败: {e}")
    
    print(f"\n[+] Web服务已启动: http://0.0.0.0:{PORT}")
    print(f"[+] 请在浏览器访问 http://<本机IP>:{PORT}")
    print(f"[+] 按 Ctrl+C 停止服务\n")
    
    # v2.11 初始化认证与通知模块（建表 + 首次创建 admin）
    auth.init()
    notify.init()

    # v2.21.2 服务异常自动恢复：偶发句柄/线程/accept 异常不再导致服务退出
    while True:
        try:
            # ThreadingHTTPServer：并发处理请求，避免轮询/上报互相阻塞
            server = ThreadingHTTPServer((HOST, PORT), ProbeHandler)
            server.serve_forever()
            break
        except KeyboardInterrupt:
            print("\n[!] 服务已停止，保存数据...")
            _save_state()
            print("[!] 已安全退出")
            break
        except Exception as _se:
            try:
                import traceback as _tb3
                with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'server_error.log'), 'a', encoding='utf-8') as _lf:
                    _lf.write('[' + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '] serve_forever ERROR: ' + repr(_se) + '\n')
                    _tb3.print_exc(file=_lf)
            except Exception:
                pass
            print('[!] 服务监听异常，2 秒后自动重建: ' + repr(_se))
            try:
                server.server_close()
            except Exception:
                pass
            time.sleep(2)
            continue

if __name__ == '__main__':
    main()
