# -*- coding: utf-8 -*-
"""
流控策略引擎（精细流控定义层）
策略 = 目标(设备/MAC/IP/IP段/分组) × 匹配(端口/协议/时段) × 动作(上下行限速/优先级/动态)
本层负责：策略校验、CRUD、冲突检测、按设备评估生效策略与超限仿真。
执行层（OpenWrt tc / WinDivert 适配器）后续接入，本层与执行无关。
"""
import datetime
import ipaddress
import re

from . import db

TARGET_TYPES = ('device', 'mac', 'ip', 'ip_range', 'group')
PROTOCOLS = ('TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS')


# ==================== 校验 ====================
def validate_policy(data):
    """返回 (ok, msg)"""
    name = str(data.get('name', '')).strip()
    if not name:
        return False, '策略名称不能为空'
    if len(name) > 50:
        return False, '策略名称过长（≤50字）'

    ttype = data.get('target_type', '')
    if ttype not in TARGET_TYPES:
        return False, '目标类型不合法'
    tvalue = str(data.get('target_value', '')).strip()
    if not tvalue:
        return False, '目标值不能为空'
    if ttype == 'device':
        if not _valid_mac(tvalue):
            return False, '设备目标需填写 MAC 地址（如 aa:bb:cc:dd:ee:ff）'
    elif ttype == 'mac':
        if not _valid_mac(tvalue):
            return False, 'MAC 格式不合法'
    elif ttype == 'ip':
        if not _valid_ip(tvalue):
            return False, 'IP 格式不合法'
    elif ttype == 'ip_range':
        try:
            ipaddress.ip_network(tvalue, strict=False)
        except Exception:
            return False, 'IP 段格式不合法（如 192.168.1.0/24）'

    # 端口
    ports = str(data.get('ports', '')).strip()
    if ports:
        ok, msg = _validate_ports(ports)
        if not ok:
            return False, msg

    # 协议
    protocols = str(data.get('protocols', '')).strip().upper()
    if protocols:
        for p in protocols.split(','):
            if p not in PROTOCOLS:
                return False, f'协议 {p} 不支持（支持: {",".join(PROTOCOLS)}）'

    # 时段
    for f in ('schedule_start', 'schedule_end'):
        v = str(data.get(f, ''))
        if v and not re.match(r'^\d{2}:\d{2}$', v):
            return False, f'{f} 需为 HH:MM 格式'

    # 限速
    try:
        down = int(data.get('down_limit', 0))
        up = int(data.get('up_limit', 0))
    except (TypeError, ValueError):
        return False, '限速值需为数字'
    if down < 0 or up < 0 or down > 10 * 1024 * 1024 * 1024 or up > 10 * 1024 * 1024 * 1024:
        return False, '限速值超出范围（0 ~ 10Gbps）'

    return True, ''


def _valid_mac(mac):
    return bool(re.match(r'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$', mac.strip()))


def _valid_ip(ip):
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except Exception:
        return False


def _validate_ports(ports):
    """支持 80,443,8000-9000"""
    for part in ports.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                a, b = int(a), int(b)
                if not (1 <= a <= b <= 65535):
                    return False, f'端口段 {part} 不合法'
            except ValueError:
                return False, f'端口段 {part} 不合法'
        else:
            try:
                p = int(part)
                if not (1 <= p <= 65535):
                    return False, f'端口 {part} 超出范围'
            except ValueError:
                return False, f'端口 {part} 不合法'
    return True, ''


# ==================== 匹配 ====================
def _port_list(ports):
    """'80,443,8000-9000' -> [80,443,(8000,9000)]"""
    result = []
    for part in (ports or '').split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            result.append((int(a), int(b)))
        else:
            result.append(int(part))
    return result


def _time_matches(p):
    """检查当前时间是否落在策略时段内"""
    days = [int(x) for x in (p.get('schedule_days') or '').split(',') if x.strip().isdigit()]
    today = datetime.datetime.now().isoweekday()  # 1=周一
    if days and today not in days:
        return False
    start = p.get('schedule_start') or '00:00'
    end = p.get('schedule_end') or '23:59'
    if start == end:
        return True
    now = datetime.datetime.now().strftime('%H:%M')
    return start <= now <= end


def policy_matches_device(p, device):
    """策略目标是否命中设备（device: {mac, ip, group_name}）"""
    ttype = p.get('target_type')
    tvalue = (p.get('target_value') or '').strip().lower()
    if ttype == 'device' or ttype == 'mac':
        return (device.get('mac') or '').lower() == tvalue
    if ttype == 'ip':
        return (device.get('ip') or '') == (p.get('target_value') or '').strip()
    if ttype == 'ip_range':
        try:
            net = ipaddress.ip_network(p['target_value'], strict=False)
            return ipaddress.ip_address(device.get('ip') or '') in net
        except Exception:
            return False
    if ttype == 'group':
        return (device.get('group_name') or '') == (p.get('target_value') or '').strip()
    return False


def policy_matches_flow(p, flow):
    """策略是否命中具体流（含端口/协议匹配，供执行层适配器使用）"""
    if not policy_matches_device(p, flow):
        return False
    if not _time_matches(p):
        return False
    ports = _port_list(p.get('ports'))
    if ports and flow.get('dst_port'):
        dp = int(flow.get('dst_port') or 0)
        hit = any((isinstance(x, tuple) and x[0] <= dp <= x[1]) or (isinstance(x, int) and x == dp) for x in ports)
        if not hit:
            return False
    protocols = (p.get('protocols') or '').upper()
    if protocols and flow.get('protocol'):
        protos = [x.strip() for x in protocols.split(',')]
        if flow['protocol'].upper() not in protos:
            return False
    return True


# ==================== 冲突检测 ====================
def _targets_overlap(p1, p2):
    """两个策略目标集合是否有交集（精确/子网/分组重叠）"""
    t1, v1 = p1['target_type'], (p1['target_value'] or '').strip()
    t2, v2 = p2['target_type'], (p2['target_value'] or '').strip()
    if t1 in ('device', 'mac'):
        v1 = v1.lower()
    if t2 in ('device', 'mac'):
        v2 = v2.lower()

    def _target_set(t, v):
        if t in ('device', 'mac'):
            return {('mac', v.lower())}
        if t == 'ip':
            return {('ip', v)}
        if t == 'ip_range':
            try:
                return {('net', ipaddress.ip_network(v, strict=False))}
            except Exception:
                return set()
        if t == 'group':
            return {('group', v)}
        return set()

    s1, s2 = _target_set(t1, v1), _target_set(t2, v2)
    for k1, v1x in s1:
        for k2, v2x in s2:
            if k1 == k2 and v1x == v2x:
                return True
            if k1 == 'ip' and k2 == 'net' and ipaddress.ip_address(v1x) in v2x:
                return True
            if k2 == 'ip' and k1 == 'net' and ipaddress.ip_address(v2x) in v1x:
                return True
            if k1 == 'net' and k2 == 'net' and (v1x.overlaps(v2x)):
                return True
            if k1 == 'mac' and k2 == 'net' and v1x:
                # MAC 目标与网段目标无法确定重叠，保守按可能重叠提示
                return True
            if k2 == 'mac' and k1 == 'net' and v2x:
                return True
    return False


def _ports_overlap(p1, p2):
    p1l = _port_list(p1.get('ports'))
    p2l = _port_list(p2.get('ports'))
    if not p1l or not p2l:
        return True  # 空=全部端口
    for a in p1l:
        for b in p2l:
            if isinstance(a, tuple) and isinstance(b, tuple):
                if not (a[1] < b[0] or b[1] < a[0]):
                    return True
            elif isinstance(a, tuple):
                if a[0] <= b <= a[1]:
                    return True
            elif isinstance(b, tuple):
                if b[0] <= a <= b[1]:
                    return True
            elif a == b:
                return True
    return False


def _time_overlap(p1, p2):
    d1 = set(int(x) for x in (p1.get('schedule_days') or '').split(',') if x.strip().isdigit()) or set(range(1, 8))
    d2 = set(int(x) for x in (p2.get('schedule_days') or '').split(',') if x.strip().isdigit()) or set(range(1, 8))
    if not (d1 & d2):
        return False
    s1, e1 = p1.get('schedule_start'), p1.get('schedule_end')
    s2, e2 = p2.get('schedule_start'), p2.get('schedule_end')
    s1 = s1 or '00:00'; e1 = e1 or '23:59'
    s2 = s2 or '00:00'; e2 = e2 or '23:59'
    if s1 == e1 or s2 == e2:
        return True  # 全天
    return not (e1 <= s2 or e2 <= s1)


def find_conflicts(policies=None):
    """返回启用策略间的冲突列表 [{a, b, reason}]"""
    policies = policies or [p for p in db.list_policies() if p['enabled']]
    conflicts = []
    for i in range(len(policies)):
        for j in range(i + 1, len(policies)):
            p1, p2 = policies[i], policies[j]
            reasons = []
            if not _targets_overlap(p1, p2):
                continue
            if not _ports_overlap(p1, p2):
                continue
            if not _time_overlap(p1, p2):
                continue
            reasons.append('目标/端口/时段存在重叠')
            conflicts.append({
                'a': {'id': p1['id'], 'name': p1['name'], 'priority': p1['priority']},
                'b': {'id': p2['id'], 'name': p2['name'], 'priority': p2['priority']},
                'reason': '、'.join(reasons),
                'hint': f"优先级 {p1['priority']} vs {p2['priority']}，数值大者生效"
            })
    return conflicts


# ==================== 设备评估（仿真） ====================
def effective_down_limit(device):
    """取设备当前生效的下行限速（命中且时段内的启用策略按优先级取最高），无则 0"""
    policies_list = [p for p in db.list_policies() if p['enabled']]
    matched = [p for p in policies_list if policy_matches_device(p, device) and _time_matches(p)]
    if not matched:
        return 0
    matched.sort(key=lambda p: p['priority'], reverse=True)
    return int(matched[0]['down_limit'] or 0)


def evaluate_devices(devices=None):
    """
    为每个设备评估生效策略：
    - 命中且时段内的启用策略按优先级取最高者
    - 输出下行/上行生效限速、动态开关、命中策略列表
    - current_down/up 传入观测速率时可判断是否超限（C 路线下通常无设备级速率）
    """
    devices = devices or db.list_devices()
    policies = [p for p in db.list_policies() if p['enabled']]
    results = []
    for dev in devices:
        matched = []
        for p in policies:
            if policy_matches_device(p, dev) and _time_matches(p):
                matched.append(p)
        if not matched:
            results.append({
                'mac': dev['mac'], 'ip': dev['ip'], 'hostname': dev['hostname'],
                'matched': [], 'effective_down': 0, 'effective_up': 0,
                'dynamic': False, 'exceeded': False
            })
            continue
        matched.sort(key=lambda p: p['priority'], reverse=True)
        top = matched[0]
        results.append({
            'mac': dev['mac'], 'ip': dev['ip'], 'hostname': dev['hostname'],
            'matched': [{'id': p['id'], 'name': p['name'], 'priority': p['priority'],
                         'down_limit': p['down_limit'], 'up_limit': p['up_limit']} for p in matched],
            'effective_down': top['down_limit'], 'effective_up': top['up_limit'],
            'dynamic': bool(top['dynamic_mode']), 'exceeded': False
        })
    return results
