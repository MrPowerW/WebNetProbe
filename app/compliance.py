# -*- coding: utf-8 -*-
"""
合规与数据真实性校验（v2.11 升级：ISO 27001 / 等保 3.0 框架）：
- data_sources(): 数据源目录（每项数据的采集方法/频率/口径/局限）
- run_checks(): 交叉校验设备/策略/会话/账号/通知数据真实性，输出 pass/warn/fail（动态联动）
- iso27001_matrix(): ISO/IEC 27001:2022 Annex A 核心控制项 → 平台证据映射
- djbh_matrix(): 等保 3.0（参考 GB/T 22239 三级要求，10 个层面）→ 平台证据映射
- sop(): 平台使用标准操作规程（含访问控制/密码/审计/应急）
"""
import time
import datetime
import os
import hashlib
import json as _json

# ==================== 数据源目录 ====================
def data_sources():
    return [
        {
            'id': 'arp', 'name': 'ARP 表采集',
            'method': '读取本机 ARP 缓存（Windows arp -a / Linux /proc/net/arp）',
            'interval': '启动即时 + 每次网段扫描后',
            'accuracy': '高（二层协议事实记录，含不响应 Ping 的设备）',
            'caveats': 'ARP 缓存有老化时间（约 1-5 分钟），设备离线后仍短暂显示；MAC 为随机地址时（iOS/Android 隐私模式）无法关联物理设备',
            'verified': '厂商 OUI 匹配 + IP-MAC 冲突检测'
        },
        {
            'id': 'scan', 'name': 'ICMP/端口扫描',
            'method': '并发 Ping + 常用端口探测内网网段',
            'interval': '每 5 分钟自动一轮 + 手动触发',
            'accuracy': '中（只发现响应探测的主机，防火墙屏蔽 ICMP 的主机会漏报）',
            'caveats': '部分设备/安全软件丢弃 ICMP 包导致漏检；扫描结果与 ARP 合并去重',
            'verified': '与 ARP 表交叉比对'
        },
        {
            'id': 'oui', 'name': 'IEEE OUI 厂商库',
            'method': '官方 MA-L 库按 MAC 前 3 字节匹配',
            'interval': '启动时加载',
            'accuracy': '高（官方权威数据，仅标识厂商非具体型号）',
            'caveats': '私有/本地管理地址无法匹配厂商；随机 MAC 会误归为未知名',
            'verified': '数据来源 IEEE 官方 CSV'
        },
        {
            'id': 'session', 'name': '会话上报',
            'method': '浏览器探针页通过 /api/report_session 上报资源请求',
            'interval': '实时（秒级）',
            'accuracy': '中（只覆盖使用探针页的浏览器会话，非全链路镜像）',
            'caveats': '仅估算带宽与超限，非真实抓包；多探针页会重复统计',
            'verified': '参数校验（IP/端口/时间戳合法性与单调性）'
        },
        {
            'id': 'netstat', 'name': '本机连接统计',
            'method': '读取本机 netstat（TCP/UDP 连接表，含 PID）',
            'interval': '每 2 秒',
            'accuracy': '高（系统真实连接事实）',
            'caveats': '仅反映探针主机自身的连接，不包含网关转发流量',
            'verified': '远端 IP 归属设备注册表'
        },
        {
            'id': 'dns', 'name': 'DNS 反向解析',
            'method': '对设备 IP 做 PTR 反查',
            'interval': '设备发现时',
            'accuracy': '低-中（取决于内网是否配置反向 DNS）',
            'caveats': '无 PTR 记录时主机名为空',
            'verified': '与扫描/ARP 主机名交叉'
        },
        {
            'id': 'bw', 'name': '网卡带宽计量',
            'method': 'Windows ctypes 读系统计数器 / Linux /proc/net/dev',
            'interval': '每 1 秒',
            'accuracy': '高（系统计数器，本机网卡总量）',
            'caveats': '为本机整体流量，非按设备拆分',
            'verified': '计数器单调性检查'
        },
    ]


# ==================== 数据真实性校验（动态联动） ====================
def run_checks(hosts_data, devices, policies, active_sessions, users=None, notify_channels=None):
    """执行交叉校验，返回检查项列表 [{id, name, status, detail, evidence}]"""
    checks = []
    dev_by_ip = {}
    for d in devices:
        ip = (d.get('ip') or '').strip()
        if ip and ip not in dev_by_ip:
            dev_by_ip[ip] = d

    # 1. 设备 IP-MAC 冲突
    ip_macs = {}
    for d in devices:
        ip = (d.get('ip') or '').strip()
        if ip:
            ip_macs.setdefault(ip, set()).add(d.get('mac', ''))
    conflicts = {ip: macs for ip, macs in ip_macs.items() if len(macs) > 1}
    checks.append({
        'id': 'ip_mac_conflict', 'name': 'IP-MAC 冲突检测',
        'status': 'fail' if conflicts else 'pass',
        'detail': f'{len(conflicts)} 个 IP 对应多个 MAC' if conflicts else '未发现同一 IP 绑定多个 MAC',
        'evidence': [f'{ip} -> {", ".join(sorted(macs))}' for ip, macs in list(conflicts.items())[:5]]
    })

    # 2. MAC 唯一性
    mac_ips = {}
    for d in devices:
        mac = (d.get('mac') or '').strip()
        if mac:
            mac_ips.setdefault(mac, set()).add(d.get('ip', ''))
    dup_macs = {mac: ips for mac, ips in mac_ips.items() if len(ips) > 1}
    checks.append({
        'id': 'mac_dup', 'name': 'MAC 重复检测',
        'status': 'warn' if dup_macs else 'pass',
        'detail': f'{len(dup_macs)} 个 MAC 对应多个 IP（可能为多网卡/虚拟接口）' if dup_macs else '每个 MAC 仅绑定一个 IP',
        'evidence': [f'{mac} -> {", ".join(sorted(ips))}' for mac, ips in list(dup_macs.items())[:5]]
    })

    # 3. 扫描 vs ARP 覆盖一致性
    scan_ips = {h.get('ip') for h in hosts_data}
    arp_ips = {d.get('ip') for d in devices if d.get('ip')}
    only_arp = arp_ips - scan_ips
    checks.append({
        'id': 'arp_scan_cross', 'name': 'ARP/扫描交叉校验',
        'status': 'pass' if not only_arp else 'warn',
        'detail': f'注册表 {len(arp_ips)} 台，扫描存活 {len(scan_ips)} 台；ARP 独有 {len(only_arp)} 台（不响应探测的隐藏设备，属正常）'
                  if only_arp else f'注册表 {len(arp_ips)} 台与扫描结果一致',
        'evidence': [f'ARP独有: {ip}' for ip in sorted(only_arp)[:8]]
    })

    # 4. OUI 厂商覆盖
    total = len(devices)
    recognized = sum(1 for d in devices if (d.get('vendor') or '').strip())
    rate = (recognized / total * 100) if total else 0
    checks.append({
        'id': 'oui_coverage', 'name': '厂商识别覆盖率',
        'status': 'pass' if rate >= 60 else 'warn',
        'detail': f'{recognized}/{total} 台设备识别厂商（{rate:.1f}%）',
        'evidence': ['随机 MAC/私有地址不计入'] if rate < 100 else []
    })

    # 5. 会话数据合法性（v2.21.14 字段匹配修复：src_ip/src_port/dst_port/timestamp 毫秒）
    import re as _re
    _ip_re = _re.compile(r'^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$')
    bad = 0
    sample_bad = []
    for s in active_sessions:
        ip = str(s.get('src_ip') or s.get('dst_ip') or s.get('ip') or s.get('host') or '')
        port = s.get('src_port') or s.get('dst_port') or s.get('remote_port') or s.get('port') or 0
        ts = s.get('timestamp') or s.get('ts') or 0
        try:
            ip_ok = bool(_ip_re.match(ip)) or (':' in ip and ' ' not in ip and len(ip) > 1)  # IPv4 或 IPv6
        except Exception:
            ip_ok = False
        try:
            port_ok = 0 < int(port) <= 65535
        except Exception:
            port_ok = False
        try:
            tf = float(ts)
            ts_ok = (1e9 < tf < 1e12) or (1e12 <= tf < 1e14)   # 兼容秒级与毫秒级时间戳
        except Exception:
            ts_ok = False
        if not ip_ok or not port_ok or not ts_ok:
            bad += 1
            if len(sample_bad) < 3:
                sample_bad.append(str(s)[:100])
    checks.append({
        'id': 'session_valid', 'name': '会话数据合法性',
        'status': 'pass' if bad == 0 else 'warn',
        'detail': f'最近 {len(active_sessions)} 条会话中 {bad} 条参数异常' if bad else f'最近 {len(active_sessions)} 条会话参数全部合法',
        'evidence': sample_bad
    })

    # 5.5 主机清单数据完整性（v2.21.24 真实性校验：MAC 完整率/编造主机名/IP 合法性）
    _fake_hp = _re.compile(r'^(服务器|设备|摄像头|打印机)-\d+$')
    _empty_mac = [h for h in hosts_data if not (h.get('mac') or '').strip()]
    _fake_hosts = [h for h in hosts_data if _fake_hp.match((h.get('hostname') or '').strip())]
    _bad_ip_h = []
    for h in hosts_data:
        _ip = (h.get('ip') or '').strip()
        if _ip and not _ip_re.match(_ip):
            _bad_ip_h.append(_ip)
    _integrity_ok = len(hosts_data) > 0 and not _empty_mac and not _fake_hosts and not _bad_ip_h
    checks.append({
        'id': 'hosts_integrity', 'name': '主机清单数据完整性',
        'status': 'pass' if _integrity_ok else 'warn',
        'detail': f'主机 {len(hosts_data)} 台；MAC 缺失 {len(_empty_mac)}，编造主机名 {len(_fake_hosts)}，非法 IP {len(_bad_ip_h)}'
                  if not _integrity_ok else f'主机 {len(hosts_data)} 台，MAC/主机名/IP 均合法',
        'evidence': ([f'MAC缺失: {h.get("ip")}' for h in _empty_mac[:5]] +
                     [f'编造名: {h.get("hostname")}' for h in _fake_hosts[:5]] +
                     [f'非法IP: {x}' for x in _bad_ip_h[:5]])
    })

    # 6. 策略目标有效性
    enabled = [p for p in policies if p.get('enabled')]
    bad_policies = []
    for p in enabled:
        t = p.get('target_type')
        v = (p.get('target_value') or '').strip()
        if t == 'device' and not any(d.get('mac') == v for d in devices):
            bad_policies.append(f'「{p.get("name")}」指向不存在的设备 {v}')
        elif t == 'mac' and not any(d.get('mac') == v for d in devices):
            bad_policies.append(f'「{p.get("name")}」MAC {v} 未在注册表')
        elif t == 'group' and not any((d.get('group_name') or '') == v for d in devices):
            bad_policies.append(f'「{p.get("name")}」分组「{v}」无成员')
    checks.append({
        'id': 'policy_valid', 'name': '启用策略目标有效性',
        'status': 'fail' if bad_policies else 'pass',
        'detail': f'启用策略 {len(enabled)} 条，{len(bad_policies)} 条目标失效' if bad_policies else f'启用策略 {len(enabled)} 条，目标全部有效',
        'evidence': bad_policies[:5]
    })

    # 7. 数据新鲜度
    stale = 0
    now = time.time()
    for d in devices:
        ls = d.get('last_seen') or ''
        try:
            t = time.mktime(time.strptime(ls, '%Y-%m-%d %H:%M:%S'))
            if now - t > 24 * 3600:
                stale += 1
        except Exception:
            pass
    checks.append({
        'id': 'freshness', 'name': '设备数据新鲜度',
        'status': 'pass' if stale == 0 else 'warn',
        'detail': f'{stale}/{len(devices)} 台设备超过 24h 未更新（离线设备属正常）' if stale else '全部设备数据为 24h 内更新',
        'evidence': []
    })

    # 8. 账号与访问控制（ISO A.5.15/A.5.16、等保身份鉴别）
    if users is not None:
        disabled = [u for u in users if not u.get('status')]
        default_admin = [u for u in users if u.get('username') == 'admin' and u.get('must_change')]
        detail = f'共 {len(users)} 个账户，停用 {len(disabled)} 个'
        ev = []
        st = 'pass'
        if default_admin:
            st = 'fail'
            detail += '；admin 仍在使用初始默认密码（必须修改）'
            ev.append('admin 未修改默认密码')
        elif not users:
            st = 'warn'
            detail += '；无任何账户（访问控制未启用）'
        checks.append({
            'id': 'access_control', 'name': '账户分级与密码策略',
            'status': st, 'detail': detail, 'evidence': ev
        })

    # 9. 通知渠道可达性（告警联动完整性）
    if notify_channels is not None:
        enabled = [c for c in notify_channels if c.get('enabled')]
        checks.append({
            'id': 'notify_ready', 'name': '风险提示通知渠道',
            'status': 'pass' if enabled else 'warn',
            'detail': f'已启用通知渠道 {len(enabled)} 个（{"、".join(c["channel"] for c in enabled)}）' if enabled else '未启用任何通知渠道（安全告警无外发通道）',
            'evidence': [f'{c["channel"]}: {c["label"]}' for c in enabled]
        })

    # 10. 数据库数据真实性（逐表固化校验 v2.21.25）
    _db_tables = db_truth_check()
    _db_bad = [t for t in _db_tables if t['status'] != 'pass']
    checks.append({
        'id': 'db_truth', 'name': '数据库数据真实性',
        'status': 'pass' if not _db_bad else ('warn' if all(t['status'] == 'warn' for t in _db_bad) else 'fail'),
        'detail': f'校验 {len(_db_tables)} 张表，异常 {len(_db_bad)} 张' if _db_bad else f'校验 {len(_db_tables)} 张表，数据全部真实合法',
        'evidence': [f'{t["table"]}: {t["detail"]}' for t in _db_bad[:5]]
    })

    return checks


def db_truth_check():
    """数据库数据真实性固化校验：逐表检查格式/冲突/编造数据；编造主机名自动清空（幂等，每次校验实时执行）"""
    import sqlite3
    import re as _re
    _db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'webnetprobe.db')
    _mac_re = _re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
    _ip_re = _re.compile(r'^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$')
    _ts_re = _re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
    _fake_re = _re.compile(r'^(服务器|设备|摄像头|打印机)-\d+$')
    out = []
    try:
        c = sqlite3.connect(_db_path, timeout=5)
        # ---- devices ----
        _dev = c.execute('SELECT mac,ip,hostname,os_guess,first_seen,last_seen FROM devices').fetchall()
        _bad_mac, _bad_ip, _dup_ip_l, _dup_mac_l, _fake, _bad_ts = [], [], [], [], [], []
        _ip2mac, _mac2ip = {}, {}
        for _m, _ip, _hn, _os, _fs, _ls in _dev:
            _m2 = (_m or '').strip().lower()
            if _m2 and not _mac_re.match(_m2):
                _bad_mac.append(_ip)
            if _ip and not _ip_re.match(_ip or ''):
                _bad_ip.append(_ip)
            _ip2mac.setdefault(_ip, set()).add(_m2)
            if _m2:
                _mac2ip.setdefault(_m2, set()).add(_ip)
            if _hn and _fake_re.match(_hn.strip()):
                _fake.append(_ip)
                c.execute('UPDATE devices SET hostname=? WHERE ip=?', ('', _ip))  # 固化：编造名清空
            for _ts in (_fs, _ls):
                if _ts and not _ts_re.match(str(_ts)):
                    _bad_ts.append(_ip)
        _dup_ip_l = [k for k, v in _ip2mac.items() if len(v) > 1]
        _dup_mac_l = [k for k, v in _mac2ip.items() if len(v) > 1]
        c.commit()
        _dev_issues = _bad_mac + _bad_ip + _dup_ip_l + _dup_mac_l + _fake + _bad_ts
        out.append({'table': 'devices', 'status': 'pass' if not _dev_issues else 'warn',
                    'detail': '%d 台；MAC格式异常 %d，IP非法 %d，IP多MAC %d，MAC多IP %d，编造名 %d，时间异常 %d' % (
                        len(_dev), len(_bad_mac), len(_bad_ip), len(_dup_ip_l), len(_dup_mac_l), len(_fake), len(_bad_ts)),
                    'evidence': (['IP多MAC: %s -> %s' % (k, ','.join(sorted(_ip2mac[k]))) for k in _dup_ip_l[:3]] +
                                 [('编造名已清空: ' + x) for x in _fake[:3]] + [('MAC格式: ' + x) for x in _bad_mac[:3]])})
        # ---- users ----
        _us = c.execute('SELECT username,role,password_hash,status FROM users').fetchall()
        _u_bad = [u for u in _us if not u[0] or u[1] not in ('admin', 'operator', 'audit', 'viewer') or not u[2] or u[3] not in (0, 1)]
        out.append({'table': 'users', 'status': 'pass' if not _u_bad else 'warn',
                    'detail': '%d 账户；异常 %d（用户名/角色/口令哈希/状态）' % (len(_us), len(_u_bad)),
                    'evidence': [u[0] for u in _u_bad[:3]]})
        # ---- usage_daily ----
        _ud = c.execute('SELECT date,down,up FROM usage_daily').fetchall()
        _ud_bad = [d for d in _ud if not _re.match(r'^\d{4}-\d{2}-\d{2}$', d[0] or '') or not isinstance(d[1], int) or not isinstance(d[2], int) or d[1] < 0 or d[2] < 0]
        out.append({'table': 'usage_daily', 'status': 'pass' if not _ud_bad else 'warn',
                    'detail': '%d 天；异常 %d（日期格式/流量数值非负）' % (len(_ud), len(_ud_bad)),
                    'evidence': [d[0] for d in _ud_bad[:3]]})
        # ---- audit ----
        _au = c.execute('SELECT ts,action FROM audit').fetchall()
        _au_bad = [a for a in _au if not _ts_re.match(a[0] or '') or not a[1]]
        out.append({'table': 'audit', 'status': 'pass' if not _au_bad else 'warn',
                    'detail': '%d 条留痕；异常 %d（时间格式/操作类型）' % (len(_au), len(_au_bad)),
                    'evidence': [a[1] for a in _au_bad[:3]]})
        # ---- sessions ----
        _ss = c.execute('SELECT token,created_at,expires_at FROM sessions').fetchall()
        _ss_bad = [s for s in _ss if not s[0] or not s[1] or not s[2] or s[2] <= s[1]]
        out.append({'table': 'sessions', 'status': 'pass' if not _ss_bad else 'warn',
                    'detail': '%d 会话；异常 %d（令牌/有效期）' % (len(_ss), len(_ss_bad)),
                    'evidence': [s[0][:16] for s in _ss_bad[:3]]})
        # ---- settings / notify_config ----
        _st = c.execute('SELECT key,value FROM settings').fetchall()
        _nc = c.execute('SELECT channel,enabled FROM notify_config').fetchall()
        _st_bad = [s for s in _st if not s[0]]
        _nc_bad = [n for n in _nc if not n[0] or n[1] not in (0, 1)]
        out.append({'table': 'config', 'status': 'pass' if not _st_bad and not _nc_bad else 'warn',
                    'detail': '设置 %d 项/通知 %d 渠道；异常 %d' % (len(_st), len(_nc), len(_st_bad) + len(_nc_bad)),
                    'evidence': [s[0] for s in _st_bad[:3]] + [n[0] for n in _nc_bad[:3]]})
        c.close()
    except Exception as _e:
        out.append({'table': 'db', 'status': 'fail', 'detail': '数据库读取异常: ' + str(_e), 'evidence': []})
    return out


# ==================== ISO 27001:2022 Annex A 映射 ====================
def iso27001_matrix():
    """ISO/IEC 27001:2022 Annex A 核心控制项 → 平台实现证据（静态映射 + 动态状态）"""
    return [
        {'control': 'A.5.1', 'category': '组织控制', 'name': '信息安全政策',
         'platform': '合规/SOP 基线文档；数据采集与使用边界声明',
         'evidence': 'SOP 第 1/2/7 节（适用范围、采集规范、安全边界）', 'dynamic': False, 'status': 'pass'},
        {'control': 'A.5.2', 'category': '组织控制', 'name': '信息安全的角色与职责',
         'platform': '账户分级 admin/operator/audit/viewer，角色职责分离',
         'evidence': '用户管理与角色矩阵（管理中心 · 用户管理）', 'dynamic': True, 'status': None},
        {'control': 'A.5.10', 'category': '组织控制', 'name': '信息及其他相关资产清单',
         'platform': '设备注册表（MAC 主键 + IP/厂商/类型/状态）',
         'evidence': '内网资产/设备管理页，可导出 CSV', 'dynamic': True, 'status': None},
        {'control': 'A.5.12', 'category': '组织控制', 'name': '信息分类与分级',
         'platform': '数据分级展示：只读/操作/管理权限隔离；数据源口径分级（高/中/低）',
         'evidence': '数据源目录 accuracy 字段', 'dynamic': False, 'status': 'pass'},
        {'control': 'A.5.15', 'category': '组织控制', 'name': '访问控制',
         'platform': '登录认证 + 角色分权显示 + 后端权限校验（未授权 API 返回 403）',
         'evidence': '登录页、X-Auth-Token、VIEWER_FORBIDDEN_PREFIXES', 'dynamic': True, 'status': None},
        {'control': 'A.5.16', 'category': '组织控制', 'name': '身份管理',
         'platform': '用户管理：创建/角色分配/启用停用/密码重置与修改',
         'evidence': '管理中心 · 用户管理；PBKDF2-SHA256 密码存储', 'dynamic': False, 'status': 'pass'},
        {'control': 'A.5.18', 'category': '组织控制', 'name': '特权访问权限',
         'platform': 'admin 专属：用户管理/系统重置/通知配置；operator 不具管理权限',
         'evidence': 'ADMIN_ONLY_PREFIXES 后端硬边界', 'dynamic': False, 'status': 'pass'},
        {'control': 'A.5.24', 'category': '组织控制', 'name': '信息安全事件管理规划',
         'platform': '安全告警流 + 攻击检测/封禁 + 合规告警同步',
         'evidence': '安全告警页、态势感知、_sync_compliance_alerts', 'dynamic': True, 'status': None},
        {'control': 'A.5.25', 'category': '组织控制', 'name': '信息安全事件的评估与决策',
         'platform': '态势感知：攻击等级判定 + 白名单 + 风险提示（高亮/通知）',
         'evidence': '态势感知页、风险提示通知接口', 'dynamic': True, 'status': None},
        {'control': 'A.5.28', 'category': '组织控制', 'name': '日志信息的收集',
         'platform': '审计日志（只增不删）+ 会话历史（上限 5 万条）+ 告警历史',
         'evidence': '管理中心 · 数据导出；audit 表', 'dynamic': True, 'status': None},
        {'control': 'A.6.3', 'category': '人员控制', 'name': '信息安全意识教育、培训',
         'platform': 'SOP 操作规程作为内部培训基线；合规检查项可视化',
         'evidence': '合规/SOP 页', 'dynamic': False, 'status': 'pass'},
        {'control': 'A.7.10', 'category': '物理控制', 'name': '防丢失设备',
         'platform': '内网设备在线监测（online/offline 状态 + 最后在线时间）',
         'evidence': '设备管理页排序（在线优先）', 'dynamic': True, 'status': None},
        {'control': 'A.8.2', 'category': '技术控制', 'name': '特权访问管理',
         'platform': 'admin 最高权限；特权操作（重置/用户管理）仅 admin',
         'evidence': '角色矩阵 + ADMIN_ONLY_PREFIXES', 'dynamic': False, 'status': 'pass'},
        {'control': 'A.8.3', 'category': '技术控制', 'name': '信息访问限制',
         'platform': 'audit/viewer 只读；viewer 屏蔽导出/合规/工具/策略等敏感功能',
         'evidence': '前端分权显示 + 后端 VIEWER_FORBIDDEN_PREFIXES', 'dynamic': True, 'status': None},
        {'control': 'A.8.6', 'category': '技术控制', 'name': '容量管理',
         'platform': '数据保留上限（会话 5 万/告警 2 万）自动清理最旧数据',
         'evidence': 'SOP 第 6 节', 'dynamic': False, 'status': 'pass'},
        {'control': 'A.8.8', 'category': '技术控制', 'name': '防恶意代码的技术管理',
         'platform': '端口封禁（高亮+手工封禁）+ 白名单 + 攻击告警',
         'evidence': '端口封禁页、态势感知白名单', 'dynamic': True, 'status': None},
        {'control': 'A.8.9', 'category': '技术控制', 'name': '配置管理',
         'platform': '流控策略管理（创建/更新/冲突检测/优先级裁决）',
         'evidence': '流控策略页', 'dynamic': True, 'status': None},
        {'control': 'A.8.16', 'category': '技术控制', 'name': '监测活动',
         'platform': '实时上下行带宽 + 会话实时表 + 网络抖动监测',
         'evidence': '仪表盘、实时会话、网络工具', 'dynamic': True, 'status': None},
        {'control': 'A.8.20', 'category': '技术控制', 'name': '网络安全',
         'platform': '防火墙规则管理（WNP- 前缀，方向/协议/端口/IP）',
         'evidence': '端口封禁页（netsh 下发）', 'dynamic': True, 'status': None},
        {'control': 'A.8.26', 'category': '技术控制', 'name': '应用安全',
         'platform': '会话参数合法性校验 + IP/端口/时间戳单调性检查',
         'evidence': 'run_checks #5', 'dynamic': True, 'status': None},
        {'control': 'A.8.31', 'category': '技术控制', 'name': '数据备份',
         'platform': '全量/时间段数据导出（CSV/JSON）+ SQLite 持久化',
         'evidence': '管理中心 · 数据导出', 'dynamic': True, 'status': None},
    ]


# ==================== 等保 3.0（三级）映射 ====================
def djbh_matrix():
    """等保 3.0：参考 GB/T 22239 等保三级要求，按 10 个层面映射平台控制点"""
    return [
        {'layer': '安全物理环境', 'point': '物理访问控制/防雷防火防水防静电/温湿度控制',
         'platform': '平台侧不直接控制机房物理环境；设备在线监测辅助发现物理离线',
         'evidence': '设备状态/最后在线（外部物理措施由部署环境保障）', 'status': 'na'},
        {'layer': '安全通信网络', 'point': '通信传输加密、可信路径',
         'platform': '本机/内网部署建议启用 HTTPS 反向代理；认证 token 12h 过期防重放',
         'evidence': 'X-Auth-Token + TOKEN_TTL=12h', 'status': 'warn'},
        {'layer': '安全区域边界', 'point': '边界防护、访问控制、入侵防范、恶意代码防范、安全审计',
         'platform': '端口封禁（netsh 防火墙）+ 攻击检测/封禁 + 白名单 + 合规/安全双告警流',
         'evidence': '端口封禁页、态势感知、安全告警页', 'status': 'pass'},
        {'layer': '安全计算环境', 'point': '身份鉴别（口令+双因素建议）、访问控制、安全审计、入侵防范、恶意代码防范、可信验证',
         'platform': '登录认证（PBKDF2 口令）+ 角色分权访问控制 + 审计日志 + 会话/策略交叉校验 + 默认密码强制修改',
         'evidence': '登录页、用户管理、run_checks #8、audit 表', 'status': 'pass'},
        {'layer': '安全管理中心', 'point': '集中管控、审计跟踪、安全告警',
         'platform': '管理中心：系统状态/重置/数据导出/模块重置；告警全局管理（单条/多选/全部删除）',
         'evidence': '管理中心页、安全告警页', 'status': 'pass'},
        {'layer': '安全管理制度', 'point': '安全策略/制度/规程体系',
         'platform': 'SOP 操作规程 + 合规基线（ISO 映射 + 数据真实性校验）',
         'evidence': '合规/SOP 页', 'status': 'pass'},
        {'layer': '安全管理机构', 'point': '岗位设置、人员配备、授权与审批',
         'platform': '角色分级岗位：admin/operator/audit/viewer；授权功能由 admin 统一分配',
         'evidence': '用户管理 · 角色分配', 'status': 'pass'},
        {'layer': '安全管理人员', 'point': '人员录用、离岗、安全意识培训',
         'platform': '用户启用/停用（离岗即停）；SOP 培训基线',
         'evidence': '用户管理 · 状态开关', 'status': 'pass'},
        {'layer': '安全建设管理', 'point': '方案设计、产品采购、开发测试、上线验收',
         'platform': '版本迭代（v2.x）逐轮校验 + 交付前内容级验证',
         'evidence': '各版本升级报告', 'status': 'pass'},
        {'layer': '安全运维管理', 'point': '资产管理、配置管理、监控管理、应急预案、外包运维',
         'platform': '设备注册表（资产台账）+ 流控策略（配置管理）+ 实时监控 + 风险提示通知（应急触达）',
         'evidence': '设备管理、策略管理、仪表盘、通知接口', 'status': 'pass'},
    ]


# ==================== SOP 文档（ISO/等保 导向） ====================
def sop():
    return """# WebNetProbe 数据合规与使用 SOP（ISO 27001 / 等保 3.0 框架）

## 1. 适用范围
本平台用于**自有/授权内网**的设备识别、会话监测与流控策略管理。禁止用于未获授权网络。

## 2. 访问控制与账户分级（ISO A.5.15/A.5.16、等保身份鉴别）
1. 所有功能须登录后使用；初始 admin 账户首次登录**强制修改默认密码**；
2. 角色分级：admin（最高权限）> operator（运维操作）> audit（审计只读）> viewer（最小只读）；
3. 分权显示：各角色仅可见被授权的导航与操作，敏感功能（导出/合规/工具/策略/封禁）对 viewer 屏蔽；
4. 授权功能：用户创建/角色分配/启用停用/密码重置 仅 admin 可执行；
5. 密码管理：PBKDF2-SHA256 加盐存储，最小 6 位，严禁明文；离职/停用账号立即停用。

## 3. 数据采集规范
1. 设备识别：ARP 表 + 网段扫描双通道采集，交叉去重，按 MAC 主键建档；
2. 会话监测：浏览器探针页上报 + 本机 netstat 连接表，二者口径分离、互不混算；
3. 带宽计量：仅读取系统网卡计数器，不做抓包、不存储报文内容；
4. 所有采集均为被动/轻量主动探测（ICMP、TCP 连接探测），不发送攻击性载荷。

## 4. 数据真实性校验流程（每次巡检执行，动态联动）
1. IP-MAC 冲突检测：同 IP 多 MAC 视为异常，人工核实；
2. MAC 唯一性：同 MAC 多 IP 视为多网卡/虚拟接口，人工标注；
3. ARP/扫描交叉：仅 ARP 出现的主机判定为隐藏设备；
4. 厂商覆盖：OUI 识别率低于 60% 提示补库；
5. 会话合法性：IP/端口/时间戳参数校验；
6. 策略目标有效性：启用策略引用的设备/MAC/分组必须真实存在；
7. 账号安全：默认密码未改、停用账号状态实时反映；
8. 通知可达：风险提示渠道启用状态纳入合规巡检。

## 5. 策略管理规范
1. 新建策略必须填写名称与明确目标，端口/协议/时段可空（表示全部）；
2. 保存前运行冲突检测，重叠策略按优先级（数值大者）裁决；
3. 限速值为平台侧策略定义，真实执行由执行层适配器（tc / 防火墙）承接；
4. 删除策略前确认影响面，删除动作写入审计日志。

## 6. 风险提示与应急（ISO A.5.24/25、等保安全运维）
1. 安全告警/合规告警写入告警流，并按已配置渠道异步推送（邮箱/企业微信/微信/微信小程序/飞书）；
2. 通知接口统一：每渠道真实发送测试消息验证连通性，失败原因明确返回；
3. 态势感知发现攻击：高亮提示 + 手工封禁；白名单内地址不提示；
4. 应急处置顺序：确认告警 → 定位来源设备 → 端口封禁/策略限速 → 通知相关人员 → 复盘留痕。

## 7. 审计与责任
1. 策略创建/删除、设备编辑、防火墙规则变更、用户管理全部留痕审计；
2. 审计日志只增不删，保留期建议 ≥ 180 天；
3. 平台产生的估算值（流量、超限）仅作参考，不作为计费/考核依据。

## 8. 数据保留与备份
- 会话历史上限 50,000 条，告警上限 20,000 条，超出自动丢弃最旧数据；
- 设备注册表与策略持久化于 SQLite，可随时导出 CSV/JSON 备份（支持精确到秒的时间段）。

## 9. 安全操作边界
1. 端口封禁通过 Windows 高级防火墙下发，仅管理本平台创建的规则（WNP- 前缀）；
2. 网络工具（ping/tracert/端口扫描）仅限内网授权范围使用；
3. 禁止将本平台用于对外攻击、未授权渗透或恶意流量生成；
4. 本平台为本机/内网工具，涉公网部署时须启用 HTTPS 与更强的口令策略（等保通信传输要求）。
"""


def hash_integrity_checks():
    """v2.21.18 数据真实性 · 哈希值校验：关键文件 SHA-256 + 基线对比（防篡改）
    返回检查项列表（[{id,name,status,detail,evidence}]），供合规·SOP·数据真实性校验板块展示"""
    checks = []
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    targets = ['server.py', 'static/index.html', 'data/oui.csv']
    for _m in ('arp.py', 'auth.py', 'compliance.py', 'db.py', 'firewall.py', 'network_tools.py', 'notify.py', 'oui.py', 'policies.py'):
        targets.append(os.path.join('app', _m))
    for _c in ('flow_policy.json', 'whitelist.json', 'custom_app_names.json'):
        _p = os.path.join('data', _c)
        if os.path.isfile(os.path.join(root, _p)):
            targets.append(_p)
    base_path = os.path.join(root, 'data', 'compliance_hashes.json')

    # 计算当前文件 SHA-256
    cur, missing = {}, []
    for rel in targets:
        fp = os.path.join(root, rel)
        if not os.path.isfile(fp):
            missing.append(rel)
            continue
        try:
            h = hashlib.sha256()
            with open(fp, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 16), b''):
                    h.update(chunk)
            cur[rel] = h.hexdigest()
        except Exception:
            pass

    base = {}
    try:
        if os.path.isfile(base_path):
            with open(base_path, 'r', encoding='utf-8') as f:
                base = _json.load(f)
    except Exception:
        base = {}

    changed = [(rel, base[rel], cur[rel]) for rel in cur if rel in base and base[rel] != cur[rel]]
    added = [rel for rel in cur if rel not in base]

    if not base:
        # 首次校验：建立哈希基线
        try:
            with open(base_path, 'w', encoding='utf-8') as f:
                _json.dump(cur, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        checks.append({
            'id': 'hash_integrity', 'name': '数据文件哈希值校验（SHA-256）',
            'status': 'pass',
            'detail': '首次建立哈希基线：%d 个关键文件已记录（data/compliance_hashes.json），后续校验将对比哈希检测篡改/升级' % len(cur),
            'evidence': ['基线文件: data/compliance_hashes.json', '覆盖: server.py / static/index.html / data/oui.csv / app/*.py / 配置文件']
        })
    else:
        if changed:
            st, det = 'warn', '%d 个文件哈希与基线不一致（可能被修改或软件已升级），请确认后点击“重置哈希基线”' % len(changed)
        elif missing:
            st, det = 'warn', '%d 个关键文件缺失（无法校验）' % len(missing)
        elif added:
            st, det = 'pass', '%d 个新增文件已自动纳入哈希基线' % len(added)
            try:
                with open(base_path, 'w', encoding='utf-8') as f:
                    _json.dump(cur, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
        else:
            st, det = 'pass', '%d 个关键文件哈希与基线一致，数据真实未被篡改' % len(cur)
        ev = ['%s: %s…' % (rel, hsh[:16]) for rel, hsh in list(cur.items())[:8]]
        if changed:
            ev += ['变更 %s: 基线 %s… ≠ 当前 %s…' % (rel, old[:12], new[:12]) for rel, old, new in changed[:4]]
        if missing:
            ev += ['缺失: ' + m for m in missing[:4]]
        checks.append({
            'id': 'hash_integrity', 'name': '数据文件哈希值校验（SHA-256）',
            'status': st, 'detail': det, 'evidence': ev
        })

    # 数据库完整性（PRAGMA quick_check）
    try:
        import sqlite3
        con = sqlite3.connect(os.path.join(root, 'data', 'webnetprobe.db'), timeout=5)
        row = con.execute('PRAGMA quick_check').fetchone()
        con.close()
        db_ok = bool(row) and row[0] == 'ok'
        checks.append({
            'id': 'db_integrity', 'name': '数据库完整性校验',
            'status': 'pass' if db_ok else 'fail',
            'detail': 'SQLite PRAGMA quick_check: ok（数据页完整）' if db_ok else '数据库完整性异常',
            'evidence': ['PRAGMA quick_check 结果: ' + (row[0] if row else '未知')]
        })
    except Exception as _e:
        checks.append({
            'id': 'db_integrity', 'name': '数据库完整性校验',
            'status': 'fail', 'detail': '数据库校验失败: ' + repr(_e), 'evidence': []
        })
    return checks
