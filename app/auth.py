# -*- coding: utf-8 -*-
"""
账户分级与访问控制（v2.11.1）：
- 角色分级：admin(超级管理员) > operator(运维操作员) > audit(审计员) > viewer(只读访客)
- 密码：PBKDF2-HMAC-SHA256 + 随机盐；强度策略（>=6位，大写/小写/数字/特殊符号 4 选 3）
- 明文查看：Fernet 对称加密存储（cryptography 库，主密钥 data/auth_master.key），仅供 admin 查看
- 会话：随机 token，有效期 12 小时，持久化到 SQLite（服务重启登录态不丢，修复异常跳登录）
- 密码时效：pwd_changed_at 记录，超过 90 天登录时返回提示
- 权限矩阵：角色 -> 可见/可操作能力（授权显示、分权显示、授权功能）
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import datetime

from app import db as _db

try:
    from cryptography.fernet import Fernet
    _HAS_FERNET = True
except Exception:
    _HAS_FERNET = False

DB_PATH = _db.get_db_path()
KEY_PATH = os.path.join(_db.DATA_DIR, 'auth_master.key')
_lock = threading.Lock()
_fernet = None

# ---------------- 角色与权限矩阵 ----------------
ROLES = {
    'admin':    {'label': '超级管理员', 'scope': '*'},
    'operator': {'label': '运维操作员', 'scope': ['read:all', 'write:devices', 'write:policies', 'write:firewall',
                                                 'write:attacks', 'write:alerts', 'write:whitelist', 'write:tools',
                                                 'write:apps', 'write:notify_test', 'write:export', 'write:history',
                                                 'view:compliance', 'view:users_ro']},
    'audit':    {'label': '审计员', 'scope': ['read:all', 'view:compliance', 'write:export', 'view:users_ro']},
    'viewer':   {'label': '只读访客', 'scope': ['read:basic']},
}

ROLE_PERM_DESC = {
    'admin':    '全部功能：用户管理(创建/角色/启停/重置/查看密码)、通知配置、系统重置、合规、读写、导出',
    'operator': '读写功能：流控/防火墙/封禁/工具/白名单/策略/告警处理 + 导出 + 合规查看（不可管理用户与通知）',
    'audit':    '只读全部数据 + 导出 + 合规查看（不可执行任何写操作）',
    'viewer':   '仅基础数据查看：仪表盘/设备/会话/告警/历史/IP工具（管理类功能全部隐藏）',
}

# viewer 不可访问的 API 前缀（后端硬边界，即使前端隐藏被绕过也拦截）
VIEWER_FORBIDDEN_PREFIXES = (
    '/api/export/', '/api/compliance/', '/api/users', '/api/notify/',
    '/api/tools/', '/api/situational', '/api/policies', '/api/firewall/',
    '/api/attacks/', '/api/whitelist/', '/api/apps/', '/api/admin/',
    '/api/scan', '/api/settings/logo',
)

# 仅 admin 可写的 API 前缀（用户管理、系统重置、通知渠道配置）
ADMIN_ONLY_PREFIXES = (
    '/api/users', '/api/admin/reset', '/api/notify/config',
)

# API 路径 -> 功能模块 映射（细粒度权限校验用）
PATH_MODULE = [
    ('/api/devices', 'devices'), ('/api/device', 'devices'), ('/api/scan', 'devices'),
    ('/api/network', 'network'),
    ('/api/hosts', 'hosts'),
    ('/api/sessions', 'sessions'), ('/api/connections', 'sessions'), ('/api/apps-analysis', 'sessions'),
    ('/api/alerts', 'alerts'),
    ('/api/history', 'history'),
    ('/api/compliance', 'compliance'),
    ('/api/export', 'export'),
    ('/api/tools', 'tools'), ('/api/jitter', 'tools'), ('/api/ping/', 'tools'),
    ('/api/situational', 'situational'),
    ('/api/ipquery', 'ipquery'), ('/api/ip/lookup', 'ipquery'), ('/api/ipcalc', 'ipcalc'),
    ('/api/firewall', 'firewall'),
    ('/api/policies', 'policies'), ('/api/flow', 'policies'),
    ('/api/whitelist', 'whitelist'),
    ('/api/attacks', 'attacks'),
    ('/api/apps', 'apps'),
    ('/api/audit', 'audit'),
    ('/api/usage', 'dashboard'), ('/api/dashboard', 'dashboard'), ('/api/stats', 'dashboard'),
    ('/api/realtime', 'dashboard'), ('/api/peak', 'dashboard'),
    ('/api/settings', 'settings'), ('/api/logo', 'settings'), ('/api/notify', 'settings'),
    ('/api/users', 'settings'),
    ('/api/admin', 'settings'),
]


def path_module(path):
    """API 路径映射到功能模块；未匹配返回 None（不校验）"""
    for p, m in PATH_MODULE:
        if path.startswith(p):
            return m
    return None


# 功能模块清单（admin 可对每个用户分发 查看/修改 权限；与前端导航对应）
MODULES = ['dashboard', 'network', 'hosts', 'devices', 'sessions', 'alerts', 'history',
           'compliance', 'settings', 'export', 'tools', 'situational', 'ipquery',
           'ipcalc', 'firewall', 'policies', 'whitelist', 'attacks', 'apps', 'audit']


def user_perm_arr(user, key):
    """读取用户权限配置（perm_view / perm_write 为 JSON 数组，空=未配置）"""
    v = (user or {}).get(key) or ''
    try:
        arr = json.loads(v) if v else []
        return arr if isinstance(arr, list) else []
    except Exception:
        return []


def module_allowed(user, module, action):
    """细粒度模块权限：admin 全通过；显式配置过的用户按配置精确生效；未配置按角色默认矩阵"""
    if not user:
        return False
    role = user.get('role', 'viewer')
    if user.get('username') == 'admin' or role == 'admin':
        return True  # v2.21.22 admin 硬编码超级管理员（即使 DB 角色异常仍全权限）
    if action == 'view' and role == 'audit' and module == 'audit':
        return True  # v2.16 审计员角色恒可查看审计日志
    key = 'perm_write' if action == 'write' else 'perm_view'
    arr = user_perm_arr(user, key)
    if arr:
        return module in arr
    # 默认矩阵（未配置时兼容现状）
    if action == 'write':
        if role == 'operator':
            return module in ('devices', 'policies', 'firewall', 'attacks', 'alerts', 'whitelist',
                              'tools', 'apps', 'export', 'history', 'situational', 'ipquery', 'ipcalc')
        if role == 'audit':
            return module in ('export',)
        return False
    if role == 'viewer':
        return module in ('dashboard', 'network', 'hosts', 'devices', 'sessions', 'alerts',
                          'history', 'ipquery', 'ipcalc', 'situational')
    if module == 'audit' and role == 'operator':
        return False  # v2.16 审计日志：运维人员需 admin 显式授权
    return True


def set_user_modules(username, perm_view=None, perm_write=None):
    """admin 分发某用户的 查看/修改 模块权限；传 None 保持原值"""
    if (username or '').strip() == 'admin':
        return {'ok': False, 'msg': '超级管理员 admin 权限全开，不可分发'}
    with _lock:
        c = _conn()
        try:
            row = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                return {'ok': False, 'msg': '用户不存在'}
            sets, args = [], []
            if perm_view is not None:
                sets.append("perm_view=?"); args.append(json.dumps(perm_view or [], ensure_ascii=False))
            if perm_write is not None:
                sets.append("perm_write=?"); args.append(json.dumps(perm_write or [], ensure_ascii=False))
            if sets:
                sets.append("updated_at=?")
                args.append(_now_str())
                args.append(username)
                c.execute("UPDATE users SET %s WHERE username=?" % ', '.join(sets), args)
                c.commit()
            return {'ok': True, 'msg': '权限已更新'}
        finally:
            c.close()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt         TEXT NOT NULL,
    pwd_cipher   TEXT DEFAULT '',
    role         TEXT NOT NULL DEFAULT 'viewer',
    display_name TEXT DEFAULT '',
    email        TEXT DEFAULT '',
    status       INTEGER DEFAULT 1,          -- 1 启用 / 0 停用
    must_change  INTEGER DEFAULT 0,          -- 1 强制下次登录改密（初始 admin）
    created_at   TEXT,
    last_login   TEXT,
    pwd_changed_at TEXT,                     -- 最近一次密码修改时间（90 天改密提示）
    perm_view    TEXT DEFAULT '',             -- JSON 数组：admin 分发可查看的模块；空=按角色默认
    perm_write   TEXT DEFAULT '',             -- JSON 数组：admin 分发可修改的模块；空=按角色默认
    fail_count   INTEGER DEFAULT 0,          -- 连续登录失败次数（5 次触发锁定）
    lock_until   REAL DEFAULT 0,             -- 锁定截止时间戳（0=未锁定）
    lock_rounds  INTEGER DEFAULT 0,          -- 锁定轮次（>=3 永久停用，仅 admin 可启用）
    updated_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at REAL,
    expires_at REAL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);
CREATE TABLE IF NOT EXISTS settings ( key TEXT PRIMARY KEY, value TEXT );
"""

TOKEN_TTL = 12 * 3600  # 兜底（登录时按会话超时配置动态计算）
SESSION_TIMEOUT_OPTIONS = (3, 5, 10, 30, 60)  # v2.14 可配置登出时间（分钟）
def get_session_timeout():
    """会话超时（分钟），默认 30；admin 可在管理中心配置"""
    try:
        with _lock:
            c = _conn()
            try:
                row = c.execute("SELECT value FROM settings WHERE key='session_timeout_minutes'").fetchone()
            finally:
                c.close()
        if row and row['value']:
            v = int(row['value'])
            if v in SESSION_TIMEOUT_OPTIONS:
                return v
    except Exception:
        pass
    return 30
def set_session_timeout(minutes):
    """admin 设置登出时间（分钟），仅允许 3/5/10/30/60"""
    try:
        minutes = int(minutes)
    except Exception:
        return {'ok': False, 'msg': '参数无效'}
    if minutes not in SESSION_TIMEOUT_OPTIONS:
        return {'ok': False, 'msg': '仅支持 3/5/10/30/60 分钟'}
    with _lock:
        c = _conn()
        try:
            c.execute("INSERT INTO settings(key,value) VALUES('session_timeout_minutes',?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(minutes),))
            c.commit()
        finally:
            c.close()
    return {'ok': True, 'msg': '会话超时已设为 %d 分钟（下次登录生效）' % minutes}
DEFAULT_ADMIN_PASSWORD = 'Admin@123456'  # 恢复出厂默认密码（v2.11.2）

# ---------------- 密码策略 ----------------
def password_policy():
    """返回策略说明（供前端展示/校验）"""
    return {
        'min_len': 6,
        'classes': ['upper', 'lower', 'digit', 'special'],
        'min_classes': 3,
        'max_age_days': 90,
        'desc': '密码至少 6 位，且包含 大写字母 / 小写字母 / 数字 / 特殊符号 四类中的至少三类；超过 90 天未修改会提示改密。',
    }

def password_strength_ok(password):
    """强度校验：>=6 位；大写/小写/数字/特殊 4 类至少 3 类"""
    if not password or len(password) < 6:
        return False, '密码至少 6 位'
    classes = 0
    if any('A' <= ch <= 'Z' for ch in password):
        classes += 1
    if any('a' <= ch <= 'z' for ch in password):
        classes += 1
    if any(ch.isdigit() for ch in password):
        classes += 1
    if any(not ch.isalnum() for ch in password):
        classes += 1
    if classes < 3:
        return False, '密码需包含 大写字母/小写字母/数字/特殊符号 四类中的至少三类'
    return True, ''

# ---------------- Fernet 明文加密 ----------------
def _load_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet
    if not _HAS_FERNET:
        return None
    try:
        if not os.path.exists(KEY_PATH):
            os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
            key = Fernet.generate_key()
            with open(KEY_PATH, 'wb') as f:
                f.write(key)
            try:
                os.chmod(KEY_PATH, 0o600)
            except Exception:
                pass
        with open(KEY_PATH, 'rb') as f:
            key = f.read().strip()
        _fernet = Fernet(key)
    except Exception:
        _fernet = None
    return _fernet

def encrypt_pwd(plain):
    f = _load_fernet()
    if f is None:
        return ''
    try:
        return f.encrypt(plain.encode('utf-8')).decode('ascii')
    except Exception:
        return ''

def decrypt_pwd(cipher):
    f = _load_fernet()
    if f is None or not cipher:
        return None
    try:
        return f.decrypt(cipher.encode('ascii')).decode('utf-8')
    except Exception:
        return None

# ---------------- 基础函数 ----------------
def _conn():
    c = sqlite3.connect(_db.get_db_path(), timeout=10)
    c.row_factory = sqlite3.Row
    return c

def _now_str():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _audit(action, detail):
    """写审计日志（登录/登出/查看/修改留痕；与 db 层同库）"""
    try:
        with _lock:
            c = _conn()
            try:
                c.execute("INSERT INTO audit (ts, action, detail) VALUES (?,?,?)", (_now_str(), action, detail))
                c.commit()
            finally:
                c.close()
    except Exception:
        pass

def init():
    """建表 + 首次启动创建初始 admin（默认密码 Admin@123456，强制下次登录修改）"""
    with _lock:
        c = _conn()
        try:
            c.executescript(SCHEMA)
            row = c.execute("SELECT COUNT(*) AS n FROM users").fetchone()
            if row['n'] == 0:
                salt = secrets.token_hex(16)
                h = _hash(DEFAULT_ADMIN_PASSWORD, salt)
                now = _now_str()
                c.execute(
                    "INSERT INTO users(username,password_hash,salt,pwd_cipher,role,display_name,status,must_change,created_at,pwd_changed_at) VALUES(?,?,?,?,?,?,1,1,?,?)",
                    ('admin', h, salt, encrypt_pwd(DEFAULT_ADMIN_PASSWORD), 'admin', '系统管理员', now, now))
                c.commit()
            # 旧表无新列时补列（兼容升级）
            cols = [r['name'] for r in c.execute("PRAGMA table_info(users)").fetchall()]
            if 'pwd_cipher' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN pwd_cipher TEXT DEFAULT ''")
            if 'pwd_changed_at' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN pwd_changed_at TEXT")
            if 'perm_view' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN perm_view TEXT DEFAULT ''")
            if 'perm_write' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN perm_write TEXT DEFAULT ''")
            if 'fail_count' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN fail_count INTEGER DEFAULT 0")
            if 'lock_until' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN lock_until REAL DEFAULT 0")
            if 'lock_rounds' not in cols:
                c.execute("ALTER TABLE users ADD COLUMN lock_rounds INTEGER DEFAULT 0")
            c.commit()
        finally:
            c.close()

def _hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 100000).hex()

def _set_password(c, uid, password):
    """写入新密码：PBKDF2 校验哈希 + Fernet 明文（admin 查看用）+ 时间戳；返回无异常即成功"""
    salt = secrets.token_hex(16)
    now = _now_str()
    c.execute(
        "UPDATE users SET password_hash=?,salt=?,pwd_cipher=?,pwd_changed_at=?,updated_at=? WHERE id=?",
        (_hash(password, salt), salt, encrypt_pwd(password), now, now, uid))

def _revoke_user_sessions(c, username):
    c.execute("DELETE FROM sessions WHERE username=?", (username,))

def verify_password(username, password, client_ip=''):
    """v2.21.14 登录校验：撞库审计 / 连续 5 次失败锁定 30 分钟 / 连续 3 轮永久停用（仅 admin 可启用）。
    返回 (status, user, extra)；status: ok/wrong/locked/disabled/nouser；extra: locked 时剩余分钟"""
    audit_events = []
    status, user, extra = 'wrong', None, None
    with _lock:
        c = _conn()
        try:
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                status = 'nouser'
                audit_events.append(('auth_login_fail', '登录失败(账户不存在/撞库尝试): %s 来源 %s' % (username, client_ip or '-')))
            elif not row['status']:
                status = 'disabled'
                audit_events.append(('auth_login_blocked', '登录被拒(账户已停用): %s 来源 %s' % (username, client_ip or '-')))
            else:
                now = time.time()
                if row['lock_until'] and row['lock_until'] > now:
                    status = 'locked'
                    extra = max(1, int((row['lock_until'] - now) / 60) + 1)
                    audit_events.append(('auth_login_blocked', '登录被拒(账户锁定中，剩余约 %d 分钟): %s 来源 %s' % (extra, username, client_ip or '-')))
                elif not hmac.compare_digest(row['password_hash'], _hash(password, row['salt'])):
                    fc = (row['fail_count'] or 0) + 1
                    rounds = row['lock_rounds'] or 0
                    if fc >= 5:
                        rounds += 1
                        perm = rounds >= 3
                        c.execute("UPDATE users SET fail_count=0, lock_until=?, lock_rounds=?, status=? WHERE id=?",
                                  (now + 1800, rounds, 0 if perm else 1, row['id']))
                        c.commit()
                        if perm:
                            status = 'disabled'
                            audit_events.append(('auth_lock_permanent', '连续 %d 次锁定，账户永久停用(需 admin 启用): %s 来源 %s' % (rounds, username, client_ip or '-')))
                        else:
                            status = 'locked'
                            extra = 30
                            audit_events.append(('auth_lock_tmp', '登录异常: 第 %d 轮连续 5 次失败，账户锁定 30 分钟: %s 来源 %s' % (rounds, username, client_ip or '-')))
                    else:
                        c.execute("UPDATE users SET fail_count=? WHERE id=?", (fc, row['id']))
                        c.commit()
                        status = 'wrong'
                        audit_events.append(('auth_login_fail', '登录失败(%d/5): %s 来源 %s' % (fc, username, client_ip or '-')))
                else:
                    c.execute("UPDATE users SET last_login=?, fail_count=0, lock_until=0, lock_rounds=0 WHERE id=?",
                              (_now_str(), row['id']))
                    c.commit()
                    status, user = 'ok', dict(row)
        finally:
            c.close()
    for ev in audit_events:
        _audit(*ev)
    return status, user, extra

# ---------------- 会话（SQLite 持久化，重启不丢） ----------------
def create_token(username):
    tok = secrets.token_hex(24)
    now = time.time()
    timeout_sec = get_session_timeout() * 60  # v2.14 先取值（锁外），避免锁内再取锁死锁
    with _lock:
        c = _conn()
        try:
            c.execute("INSERT INTO sessions(token,username,created_at,expires_at) VALUES(?,?,?,?)",
                      (tok, username, now, now + timeout_sec))
            c.commit()
        finally:
            c.close()
    return tok

def revoke_token(token):
    with _lock:
        c = _conn()
        try:
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            c.commit()
        finally:
            c.close()

def user_by_token(token):
    """返回 (user_dict, perms_list)；无效/过期返回 (None, None)。清理过期 token。"""
    now = time.time()
    with _lock:
        c = _conn()
        try:
            c.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            c.commit()
            rec = c.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
            if not rec:
                return None, None
            row = c.execute("SELECT * FROM users WHERE username=?", (rec['username'],)).fetchone()
        finally:
            c.close()
    if not row or not row['status']:
        return None, None
    return dict(row), perms_for(row['role'])

def perms_for(role):
    scope = ROLES.get(role, ROLES['viewer'])['scope']
    if scope == '*':
        return ['*']
    return list(scope)

def role_label(role):
    return ROLES.get(role, ROLES['viewer'])['label']

def can_write(user):
    """写操作：operator 及以上"""
    return user and (user['role'] in ('admin', 'operator'))

def can_admin(user):
    return user and user['role'] == 'admin'

def can_view_full(user, path):
    """GET 敏感前缀：viewer 拒绝"""
    if not user:
        return False
    if user['role'] == 'admin':
        return True
    if user['role'] == 'viewer':
        return not any(path.startswith(p) for p in VIEWER_FORBIDDEN_PREFIXES)
    return True

def pwd_age_days(user):
    """密码已使用天数（供 90 天改密提示）"""
    t = (user or {}).get('pwd_changed_at') or (user or {}).get('created_at') or ''
    try:
        d = datetime.datetime.strptime(t[:19], '%Y-%m-%d %H:%M:%S')
        return max(0, (datetime.datetime.now() - d).days)
    except Exception:
        return 0

# ---------------- 用户管理（admin） ----------------
def list_users():
    with _lock:
        c = _conn()
        try:
            rows = c.execute(
                "SELECT id,username,role,display_name,email,status,must_change,created_at,last_login,pwd_changed_at,perm_view,perm_write FROM users ORDER BY id").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d['pwd_age_days'] = pwd_age_days(d)
                pv = d.get('perm_view') or ''
                pw = d.get('perm_write') or ''
                try:
                    d['perm_view'] = json.loads(pv) if pv else []
                    d['perm_write'] = json.loads(pw) if pw else []
                except Exception:
                    d['perm_view'] = []
                    d['perm_write'] = []
                d['perm_configured'] = bool(pv or pw)
                out.append(d)
            return out
        finally:
            c.close()

def create_user(username, password, role, display_name='', email='', perm_view=None, perm_write=None):
    username = (username or '').strip()
    if not username or not password:
        return {'ok': False, 'msg': '用户名与密码必填'}
    if role not in ROLES:
        return {'ok': False, 'msg': '无效角色'}
    if username == 'admin':
        role = 'admin'  # v2.21.22 admin 用户名恒为超级管理员
    ok, msg = password_strength_ok(password)
    if not ok:
        return {'ok': False, 'msg': msg}
    with _lock:
        c = _conn()
        try:
            if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                return {'ok': False, 'msg': '用户名已存在'}
            salt = secrets.token_hex(16)
            now = _now_str()
            pv = json.dumps(perm_view or [], ensure_ascii=False) if perm_view else ''
            pw = json.dumps(perm_write or [], ensure_ascii=False) if perm_write else ''
            c.execute(
                "INSERT INTO users(username,password_hash,salt,pwd_cipher,role,display_name,email,status,must_change,created_at,pwd_changed_at,perm_view,perm_write) VALUES(?,?,?,?,?,?,?,1,1,?,?,?,?)",
                (username, _hash(password, salt), salt, encrypt_pwd(password), role, display_name, email, now, now, pv, pw))
            c.commit()
            return {'ok': True, 'msg': '用户已创建（首次登录将强制修改密码）'}
        finally:
            c.close()

def update_user(uid, role=None, display_name=None, email=None, status=None):
    with _lock:
        c = _conn()
        try:
            _row0 = c.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
            if _row0 and _row0['username'] == 'admin' and (role is not None or status is not None):
                return {'ok': False, 'msg': '超级管理员 admin 不可变更角色或停用'}  # v2.21.22
            sets, vals = [], []
            if role is not None:
                if role not in ROLES:
                    return {'ok': False, 'msg': '无效角色'}
                sets.append('role=?'); vals.append(role)
            if display_name is not None:
                sets.append('display_name=?'); vals.append(display_name)
            if email is not None:
                sets.append('email=?'); vals.append(email)
            if status is not None:
                sets.append('status=?'); vals.append(1 if status else 0)
                if status:
                    # v2.21.14 admin 启用账户：重置锁定计数（连续失败/锁定期/锁定轮次）
                    sets.append('fail_count=0')
                    sets.append('lock_until=0')
                    sets.append('lock_rounds=0')
            if not sets:
                return {'ok': False, 'msg': '无更新字段'}
            sets.append('updated_at=?'); vals.append(_now_str())
            vals.append(uid)
            c.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", vals)
            # 停用用户：会话立即失效
            if status is not None and not status:
                row = c.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
                if row:
                    _revoke_user_sessions(c, row['username'])
            c.commit()
            return {'ok': True, 'msg': '已更新'}
        finally:
            c.close()

def reset_password(username, new_password):
    """admin 重置他人密码：强度校验 + 强制下次登录改密 + 会话全部失效"""
    if not new_password:
        return {'ok': False, 'msg': '新密码必填'}
    ok, msg = password_strength_ok(new_password)
    if not ok:
        return {'ok': False, 'msg': msg}
    with _lock:
        c = _conn()
        try:
            row = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                return {'ok': False, 'msg': '用户不存在'}
            _set_password(c, row['id'], new_password)
            c.execute("UPDATE users SET must_change=1 WHERE id=?", (row['id'],))
            _revoke_user_sessions(c, username)
            c.commit()
            return {'ok': True, 'msg': '密码已重置（该用户需重新登录，且首次登录必须修改密码）'}
        finally:
            c.close()

def change_password(username, old_password, new_password, cur_token=''):
    """本人改密：强度校验 + 同步明文 + 保留当前登录（cur_token），其他会话失效"""
    ok, msg = password_strength_ok(new_password)
    if not ok:
        return {'ok': False, 'msg': msg}
    with _lock:
        c = _conn()
        try:
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                return {'ok': False, 'msg': '用户不存在'}
            if not hmac.compare_digest(row['password_hash'], _hash(old_password, row['salt'])):
                return {'ok': False, 'msg': '原密码不正确'}
            _set_password(c, row['id'], new_password)
            c.execute("UPDATE users SET must_change=0 WHERE id=?", (row['id'],))
            # 其他会话失效（当前 token 由调用方传入保留）
            c.execute("DELETE FROM sessions WHERE username=? AND token != ?", (username, cur_token or '__none__'))
            c.commit()
            return {'ok': True, 'msg': '密码已修改'}
        finally:
            c.close()

def delete_user(username):
    """删除用户（保留至少一个启用的 admin）"""
    username = (username or '').strip()
    if username == 'admin':
        return {'ok': False, 'msg': '超级管理员 admin 不可删除'}  # v2.21.22
    with _lock:
        c = _conn()
        try:
            row = c.execute("SELECT id,role FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                return {'ok': False, 'msg': '用户不存在'}
            admins = c.execute("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND status=1").fetchone()['n']
            if row['role'] == 'admin' and admins <= 1:
                return {'ok': False, 'msg': '必须保留至少一个启用的超级管理员'}
            c.execute("DELETE FROM users WHERE id=?", (row['id'],))
            _revoke_user_sessions(c, username)
            c.commit()
            return {'ok': True, 'msg': '用户已删除（该用户会话已失效）'}
        finally:
            c.close()

def view_password(username):
    """admin 查看用户密码明文（Fernet 解密）"""
    username = (username or '').strip()
    with _lock:
        c = _conn()
        try:
            row = c.execute("SELECT username,pwd_cipher FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                return {'ok': False, 'msg': '用户不存在'}
            if not row['pwd_cipher']:
                return {'ok': False, 'msg': '该账户密码以加密哈希存储（旧版本创建，未保存可逆明文），无法直接查看；请先"重置密码"，重置后即可查看明文'}
            plain = decrypt_pwd(row['pwd_cipher'])
            if plain is None:
                return {'ok': False, 'msg': '无法解密（cryptography 库不可用或密钥缺失），可改用"重置密码"'}
            return {'ok': True, 'username': row['username'], 'password': plain}
        finally:
            c.close()

def set_must_change(username, flag=1):
    with _lock:
        c = _conn()
        try:
            c.execute("UPDATE users SET must_change=? WHERE username=?", (1 if flag else 0, username))
            c.commit()
        finally:
            c.close()

def public_view(user):
    """返回给前端的安全用户视图（不含密码字段）"""
    if not user:
        return None
    return {
        'username': user['username'],
        'role': user['role'],
        'role_label': role_label(user['role']),
        'display_name': user.get('display_name') or '',
        'email': user.get('email') or '',
        'must_change': bool(user.get('must_change')),
        'pwd_age_days': pwd_age_days(user),
        'perms': perms_for(user['role']),
        'perm_view': user_perm_arr(user, 'perm_view'),
        'perm_write': user_perm_arr(user, 'perm_write'),
        'perm_configured': bool(user.get('perm_view') or user.get('perm_write')),
    }


def ensure_superadmin():
    """v2.21.22 admin 硬编码超级管理员：角色/启用/权限全量重置（幂等，服务启动时调用）"""
    with _lock:
        c = _conn()
        try:
            row = c.execute("SELECT id,role,status,perm_view,perm_write FROM users WHERE username='admin'").fetchone()
            if row:
                sets = []
                if row['role'] != 'admin':
                    sets.append("role='admin'")
                if row['status'] != 1:
                    sets.append("status=1")
                if row['perm_view']:
                    sets.append("perm_view=''")
                if row['perm_write']:
                    sets.append("perm_write=''")
                if sets:
                    c.execute("UPDATE users SET " + ','.join(sets) + " WHERE username='admin'")
                    c.commit()
                return {'ok': True, 'reset': bool(sets)}
            salt = secrets.token_hex(16)
            now = _now_str()
            c.execute(
                "INSERT INTO users(username,password_hash,salt,pwd_cipher,role,display_name,email,status,must_change,created_at,pwd_changed_at,perm_view,perm_write) VALUES(?,?,?,?,?,?,?,1,0,?,?,?,?)",
                ('admin', _hash('Admin@123456', salt), salt, encrypt_pwd('Admin@123456'), 'admin', '超级管理员', '', now, now, '', ''))
            c.commit()
            return {'ok': True, 'reset': True, 'recreated': True}
        finally:
            c.close()
