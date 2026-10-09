# -*- coding: utf-8 -*-
"""
风险提示通知接口（v2.11）：
统一 send(channel, title, content) 接口；渠道：邮箱(SMTP)、企业微信(机器人 Webhook)、
微信(通用 HTTP API)、微信小程序(通用 HTTP API)、飞书(机器人 Webhook)。
通用设计：每渠道一个适配器 send_xxx(cfg, title, content) -> (ok, detail, latency_ms)，
统一返回结构；测试 = 真实发送一条测试消息，无配置/失败返回明确原因，不假装成功。
告警联动：add_alert 时异步广播到全部已启用渠道。
"""
import json
import os
import smtplib
import socket
import ssl
import sqlite3
import threading
import time
import urllib.request
from email.mime.text import MIMEText
from email.header import Header

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'webnetprobe.db')
_lock = threading.Lock()

CHANNELS = [
    {'key': 'email',       'label': '邮箱（SMTP）'},
    {'key': 'wecom',       'label': '企业微信（机器人 Webhook）'},
    {'key': 'wechat',      'label': '微信（通用 API）'},
    {'key': 'miniprogram', 'label': '微信小程序（通用 API）'},
    {'key': 'feishu',      'label': '飞书（机器人 Webhook）'},
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS notify_config (
    channel   TEXT PRIMARY KEY,
    enabled   INTEGER DEFAULT 0,
    config    TEXT DEFAULT '{}',   -- JSON
    updated_at TEXT
);
"""

DEFAULT_CONFIG = {
    'email':       {'smtp_host': '', 'smtp_port': 465, 'use_ssl': 1, 'smtp_user': '', 'smtp_pass': '', 'mail_from': '', 'mail_to': ''},
    'wecom':       {'webhook_url': ''},
    'wechat':      {'api_url': '', 'api_token': ''},
    'miniprogram': {'api_url': '', 'api_token': ''},
    'feishu':      {'webhook_url': ''},
}


def init():
    with _lock:
        c = sqlite3.connect(DB_PATH, timeout=10)
        try:
            c.executescript(SCHEMA)
            c.commit()
        finally:
            c.close()


def _conn():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def get_config(channel):
    with _lock:
        c = _conn()
        try:
            row = c.execute("SELECT enabled,config FROM notify_config WHERE channel=?", (channel,)).fetchone()
            if not row:
                return False, dict(DEFAULT_CONFIG[channel])
            cfg = dict(DEFAULT_CONFIG[channel])
            cfg.update(json.loads(row['config'] or '{}'))
            return bool(row['enabled']), cfg
        finally:
            c.close()


def list_configs():
    out = []
    with _lock:
        c = _conn()
        try:
            rows = c.execute("SELECT channel,enabled,config,updated_at FROM notify_config").fetchall()
            have = {r['channel']: r for r in rows}
        finally:
            c.close()
    for ch in CHANNELS:
        r = have.get(ch['key'])
        if r:
            cfg = dict(DEFAULT_CONFIG[ch['key']])
            cfg.update(json.loads(r['config'] or '{}'))
            # 密钥回显时脱敏
            safe = dict(cfg)
            for k in ('smtp_pass', 'api_token'):
                if safe.get(k):
                    safe[k] = ('*' * 6) + safe[k][-2:] if len(safe[k]) > 8 else '****'
            out.append({'channel': ch['key'], 'label': ch['label'], 'enabled': bool(r['enabled']),
                        'config': safe, 'updated_at': r['updated_at']})
        else:
            out.append({'channel': ch['key'], 'label': ch['label'], 'enabled': False,
                        'config': dict(DEFAULT_CONFIG[ch['key']]), 'updated_at': None})
    return out


def save_config(channel, enabled, config):
    if channel not in DEFAULT_CONFIG:
        return {'ok': False, 'msg': '未知渠道'}
    # 已存密钥未变（脱敏值）时保留原密钥
    with _lock:
        c = _conn()
        try:
            row = c.execute("SELECT config FROM notify_config WHERE channel=?", (channel,)).fetchone()
            old = json.loads(row['config']) if row else {}
        finally:
            c.close()
    merged = dict(DEFAULT_CONFIG[channel])
    for k, v in (config or {}).items():
        if k in ('smtp_pass', 'api_token'):
            if isinstance(v, str) and v.startswith('****') and old.get(k):
                v = old[k]
        merged[k] = v
    with _lock:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO notify_config(channel,enabled,config,updated_at) VALUES(?,?,?,?) "
                "ON CONFLICT(channel) DO UPDATE SET enabled=excluded.enabled,config=excluded.config,updated_at=excluded.updated_at",
                (channel, 1 if enabled else 0, json.dumps(merged, ensure_ascii=False),
                 time.strftime('%Y-%m-%d %H:%M:%S')))
            c.commit()
        finally:
            c.close()
    return {'ok': True, 'msg': '配置已保存'}


# ---------------- 渠道适配器（统一返回 (ok, detail)） ----------------
def _send_email(cfg, title, content):
    host = (cfg.get('smtp_host') or '').strip()
    if not host:
        return False, '未配置 SMTP 服务器'
    port = int(cfg.get('smtp_port') or 465)
    user = (cfg.get('smtp_user') or '').strip()
    pwd = (cfg.get('smtp_pass') or '').strip()
    frm = (cfg.get('mail_from') or user).strip()
    to = (cfg.get('mail_to') or '').strip()
    if not to:
        return False, '未配置收件人 mail_to'
    try:
        msg = MIMEText(content, 'plain', 'utf-8')
        msg['Subject'] = Header(title, 'utf-8')
        msg['From'] = frm
        msg['To'] = to
        server = smtplib.SMTP_SSL(timeout=10) if cfg.get('use_ssl') else smtplib.SMTP(timeout=10)
        try:
            server.connect(host, port)   # 显式连接：失败信息明确（超时/拒连）
            server.ehlo()
            if not cfg.get('use_ssl'):
                server.starttls()
                server.ehlo()
            if user and pwd:
                server.login(user, pwd)
            server.sendmail(frm, [x.strip() for x in to.split(',') if x.strip()], msg.as_string())
        finally:
            try:
                server.quit()
            except Exception:
                pass
        return True, f'已发送至 {to}'
    except Exception as e:
        return False, f'SMTP 发送失败：{e}'


def _send_webhook(cfg, url_key, build_body, label):
    url = (cfg.get(url_key) or '').strip()
    if not url:
        return False, f'未配置 {label} Webhook 地址'
    if not url.lower().startswith('https://'):
        return False, 'Webhook 地址必须以 https:// 开头'
    try:
        req = urllib.request.Request(url, data=json.dumps(build_body()).encode('utf-8'),
                                     headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read(500).decode('utf-8', errors='replace')
        # 企业微信返回 {"errcode":0}；飞书返回 {"code":0}；错误时明确报出
        try:
            j = json.loads(body)
            if j.get('errcode', j.get('code', 0)) in (0, None):
                return True, f'{label} 已送达（HTTP {r.status}）'
            return False, f'{label} 平台返回错误：{j.get("errmsg") or j.get("msg") or body[:120]}'
        except Exception:
            return True, f'{label} 已送达（HTTP {r.status}，返回：{body[:80]}）'
    except Exception as e:
        return False, f'{label} 请求失败：{e}'


def _send_wecom(cfg, title, content):
    return _send_webhook(cfg, 'webhook_url',
                         lambda: {'msgtype': 'text', 'text': {'content': f'【WebNetProbe】{title}\n{content}'}},
                         '企业微信')


def _send_feishu(cfg, title, content):
    return _send_webhook(cfg, 'webhook_url',
                         lambda: {'msg_type': 'text', 'content': {'text': f'【WebNetProbe】{title}\n{content}'}},
                         '飞书')


def _send_generic(cfg, title, content, label):
    url = (cfg.get('api_url') or '').strip()
    tok = (cfg.get('api_token') or '').strip()
    if not url:
        return False, f'未配置 {label} API 地址'
    try:
        payload = {'channel': label, 'title': title, 'content': content, 'token': tok}
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'),
                                     headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read(500).decode('utf-8', errors='replace')
        return True, f'{label} 已送达（HTTP {r.status}，返回：{body[:80]}）'
    except Exception as e:
        return False, f'{label} 请求失败：{e}'


SENDERS = {
    'email':       lambda cfg, t, c: _send_email(cfg, t, c),
    'wecom':       lambda cfg, t, c: _send_wecom(cfg, t, c),
    'wechat':      lambda cfg, t, c: _send_generic(cfg, t, c, '微信'),
    'miniprogram': lambda cfg, t, c: _send_generic(cfg, t, c, '微信小程序'),
    'feishu':      lambda cfg, t, c: _send_feishu(cfg, t, c),
}


def send(channel, title, content):
    """发送单渠道；返回 {'channel','ok','detail','latency_ms'}"""
    if channel not in SENDERS:
        return {'channel': channel, 'ok': False, 'detail': '未知渠道', 'latency_ms': 0}
    enabled, cfg = get_config(channel)
    if not enabled:
        return {'channel': channel, 'ok': False, 'detail': '渠道未启用', 'latency_ms': 0}
    t0 = time.time()
    ok, detail = SENDERS[channel](cfg, title, content)
    return {'channel': channel, 'ok': ok, 'detail': detail, 'latency_ms': int((time.time() - t0) * 1000)}


def send_all(title, content):
    """广播到全部已启用渠道（异步），返回结果列表"""
    results = []
    for ch in CHANNELS:
        enabled, _ = get_config(ch['key'])
        if not enabled:
            continue
        results.append(send(ch['key'], title, content))
    return results


def send_all_async(title, content):
    """告警联动：异步广播，不阻塞主流程"""
    def _run():
        try:
            send_all(title, content)
        except Exception:
            pass
    threading.Thread(target=_run, daemon=True).start()


def test_channel(channel):
    """真实发送测试消息；返回统一结构"""
    return send(channel, 'WebNetProbe 通知测试', '这是一条测试消息：风险提示接口已连通，后续安全告警将通过本渠道推送。')
