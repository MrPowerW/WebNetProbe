# -*- coding: utf-8 -*-
"""
防火墙执行层：Windows 高级防火墙规则管理（netsh advfirewall）
仅管理本机防火墙规则，规则名统一加 WNP- 前缀，可安全回滚删除。
注意：netsh 修改防火墙需要管理员权限，未提权时返回明确错误。
"""
import re
import subprocess
from app import db

RULE_PREFIX = "WNP-"
_NAME_RE = re.compile(r'^[A-Za-z0-9_\-\u4e00-\u9fff ]{1,40}$')
_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')


def _run(args, timeout=15):
    """以参数列表方式执行命令，避免注入"""
    try:
        proc = subprocess.run(
            args, capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        out = (proc.stdout or b'').decode('gbk', errors='replace').strip()
        err = (proc.stderr or b'').decode('gbk', errors='replace').strip()
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        return -1, '', '命令执行超时'
    except Exception as e:
        return -1, '', str(e)


def _valid_ip_or_cidr(s):
    s = (s or '').strip()
    if not s:
        return True
    if not _IP_RE.match(s):
        return False
    parts = s.split('/')
    ip = parts[0]
    for seg in ip.split('.'):
        if not (0 <= int(seg) <= 255):
            return False
    if len(parts) == 2:
        if not (1 <= int(parts[1]) <= 32):
            return False
    return True


def validate_rule(direction, protocol, port, remote_ip=''):
    """校验入参，返回 (ok, msg)"""
    if direction not in ('in', 'out'):
        return False, '方向必须为 in/out'
    if protocol.upper() not in ('TCP', 'UDP'):
        return False, '协议仅支持 TCP/UDP'
    try:
        p = int(port or 0)
    except (TypeError, ValueError):
        return False, '端口必须为 0-65535 的整数'
    if not (0 <= p <= 65535):
        return False, '端口必须为 0-65535'
    if not _valid_ip_or_cidr(remote_ip):
        return False, '远程地址不合法（支持 IP 或 CIDR，如 192.168.1.100 / 172.31.87.0/24）'
    return True, ''


def create_rule(name, direction, protocol, port, remote_ip='', note=''):
    """创建入站/出站封禁规则；返回 (ok, msg, record)"""
    name = (name or '').strip()
    if not _NAME_RE.match(name):
        return False, '规则名称不合法（1-40 位，中英文/数字/-/_）', None
    ok, msg = validate_rule(direction, protocol, port, remote_ip)
    if not ok:
        return False, msg, None
    remote_ip = (remote_ip or '').strip()
    rule_name = RULE_PREFIX + name

    cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
           f'name={rule_name}', f'dir={direction}', 'action=block',
           f'protocol={protocol.upper()}']
    if int(port or 0) > 0:
        cmd.append(f'localport={int(port)}')
    if remote_ip:
        cmd.append(f'remoteip={remote_ip}')

    code, out, err = _run(cmd)
    success = code == 0 and ('Ok.' in out or '确定' in out or 'ok.' in out.lower() or err == '')
    rid = db.create_firewall_rule(
        rule_name, direction, 'block', protocol.upper(), int(port or 0),
        remote_ip, note, status='active' if success else 'failed',
        last_msg=(out or err or '')
    )
    db.audit('firewall_create',
             f"创建封禁规则「{name}」 dir={direction} proto={protocol.upper()} port={int(port or 0)} remote={remote_ip or '任意'} -> {'成功' if success else '失败'}")
    if not success:
        return False, f"执行失败（需管理员权限）：{out or err}", {'id': rid}
    return True, '规则已创建', {'id': rid}


def delete_rule(rid):
    """删除规则（仅删除 WNP- 前缀的本平台规则）"""
    rec = db.delete_firewall_rule(rid)
    if not rec:
        return False, '规则不存在'
    rule_name = rec['rule_name']
    code, out, err = _run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'])
    success = code == 0
    db.audit('firewall_delete',
             f"删除封禁规则「{rule_name}」 -> {'成功' if success else '失败'} ({out or err})")
    if not success:
        return False, f'删除失败：{out or err}'
    return True, '已删除'


def list_rules():
    """规则列表 + 实况校验（netsh show rule）"""
    rules = db.list_firewall_rules()
    for r in rules:
        # 校验规则是否真实存在于系统防火墙
        code, out, err = _run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={r["rule_name"]}'])
        if code != 0 or 'WebNetProbe' not in out and r['rule_name'] not in out:
            r['live'] = 'missing'
        else:
            r['live'] = 'active'
    return rules
