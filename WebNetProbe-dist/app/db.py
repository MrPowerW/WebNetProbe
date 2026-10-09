# -*- coding: utf-8 -*-
"""
数据层：SQLite（WAL 模式，线程安全）
表：devices 设备注册表 / policies 流控策略 / audit 审计日志 / oui 厂商库
DB 滚动（v2.11.2）：数据文件 >=1GB 或最早数据超过 1 年时，自动切换到新的 DB 文件（旧库保留归档）
"""
import os
import sqlite3
import threading
import datetime

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
DB_PATH = os.path.join(DATA_DIR, 'webnetprobe.db')
# 滚动阈值
ROLL_SIZE_BYTES = 1 * 1024 * 1024 * 1024          # >=1GB 触发滚动
ROLL_AGE_DAYS = 365                                # 最早数据超过 1 年触发滚动
ROLL_CHECK_EVERY = 300                              # 每 300 次调用检查一次（节流）
_roll_counter = 0

_conn = None
_db_lock = threading.Lock()


def get_db_path():
    """返回当前生效的 DB 文件路径（DB 滚动后指向新库）"""
    return DB_PATH


def _should_roll():
    """判断是否满足滚动条件：文件 >=1GB 或最早业务数据超过 1 年"""
    try:
        if os.path.exists(DB_PATH) and os.path.getsize(DB_PATH) >= ROLL_SIZE_BYTES:
            return True
        # 最早数据时间检查（audit / usage_daily / sessions / devices 中最老时间）
        try:
            c = sqlite3.connect(DB_PATH, timeout=3)
            c.row_factory = sqlite3.Row
            for tbl, col in (('audit', 'ts'), ('usage_daily', 'date'), ('devices', 'first_seen')):
                try:
                    r = c.execute("SELECT MIN(%s) AS m FROM %s" % (col, tbl)).fetchone()
                    v = r['m'] if r else None
                    if v:
                        try:
                            dt = datetime.datetime.strptime(v[:10], '%Y-%m-%d')
                            if (datetime.datetime.now() - dt).days >= ROLL_AGE_DAYS:
                                return True
                        except Exception:
                            pass
                except Exception:
                    pass
            c.close()
        except Exception:
            pass
    except Exception:
        pass
    return False


def _roll_db():
    """执行滚动：把 DB_PATH 切换到新的文件并初始化 schema（旧库文件保留归档）"""
    global DB_PATH
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    new_path = os.path.join(DATA_DIR, 'webnetprobe_%s.db' % ts)
    # 初始化新库（空 schema）
    c = sqlite3.connect(new_path, timeout=5)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript(SCHEMA)
    c.commit()
    c.close()
    DB_PATH = new_path
    try:
        with open(os.path.join(DATA_DIR, 'db_meta.txt'), 'w', encoding='utf-8') as f:
            f.write('current=%s\nrolled_at=%s\n' % (new_path, datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    except Exception:
        pass
    return new_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    ip         TEXT DEFAULT '',
    vendor     TEXT DEFAULT '',
    hostname   TEXT DEFAULT '',
    type       TEXT DEFAULT 'terminal',
    os_guess   TEXT DEFAULT '',
    status     TEXT DEFAULT 'offline',
    group_name TEXT DEFAULT '',
    note       TEXT DEFAULT '',
    is_bound   INTEGER DEFAULT 0,
    first_seen TEXT,
    last_seen  TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);

CREATE TABLE IF NOT EXISTS policies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    target_type   TEXT NOT NULL,           -- device|mac|ip|ip_range|group
    target_value  TEXT NOT NULL,
    ports         TEXT DEFAULT '',          -- "80,443,8000-9000"，空=全部
    protocols     TEXT DEFAULT '',          -- "TCP,UDP"，空=全部
    schedule_days TEXT DEFAULT '1,2,3,4,5,6,7',  -- 1=周一 ... 7=周日
    schedule_start TEXT DEFAULT '00:00',
    schedule_end   TEXT DEFAULT '23:59',
    down_limit    INTEGER DEFAULT 0,        -- bps，0=不限
    up_limit      INTEGER DEFAULT 0,        -- bps，0=不限
    priority      INTEGER DEFAULT 0,        -- 数值越大优先级越高
    enabled       INTEGER DEFAULT 1,
    dynamic_mode  INTEGER DEFAULT 0,        -- 动态流控开关
    created_at    TEXT,
    updated_at    TEXT
);

CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT,
    action TEXT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS oui (
    prefix TEXT PRIMARY KEY,   -- 如 286FB9（MAC 前 3 字节，无分隔符大写）
    vendor TEXT
);

CREATE TABLE IF NOT EXISTS usage_daily (
    date TEXT PRIMARY KEY,   -- YYYY-MM-DD
    down INTEGER DEFAULT 0, -- 字节
    up   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS firewall_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name   TEXT NOT NULL UNIQUE,   -- netsh 规则名（含 WNP- 前缀）
    direction   TEXT DEFAULT 'in',      -- in|out
    action      TEXT DEFAULT 'block',   -- block
    protocol    TEXT DEFAULT 'TCP',     -- TCP|UDP
    port        INTEGER DEFAULT 0,      -- 0=全部
    remote_ip   TEXT DEFAULT '',        -- 空=任意，支持 CIDR
    note        TEXT DEFAULT '',
    status      TEXT DEFAULT 'active',  -- active|failed
    last_msg    TEXT DEFAULT '',
    created_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_fw_direction ON firewall_rules(direction);
"""


def now_str():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def get_conn():
    global _conn, _roll_counter
    _roll_counter += 1
    if _roll_counter % ROLL_CHECK_EVERY == 0:
        if _should_roll():
            _roll_db()
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA busy_timeout=5000")
        _conn.executescript(SCHEMA)
        _conn.commit()
    return _conn


def query(sql, args=()):
    with _db_lock:
        cur = get_conn().execute(sql, args)
        rows = cur.fetchall()
    return [dict(r) for r in rows]


def query_one(sql, args=()):
    with _db_lock:
        cur = get_conn().execute(sql, args)
        row = cur.fetchone()
    return dict(row) if row else None


def execute(sql, args=()):
    with _db_lock:
        cur = get_conn().execute(sql, args)
        get_conn().commit()
    return cur.lastrowid


def executemany(sql, seq):
    with _db_lock:
        get_conn().executemany(sql, seq)
        get_conn().commit()


# ==================== 设备 ====================
def upsert_device(dev):
    """按 MAC 插入或更新设备；MAC 为空时跳过"""
    mac = (dev.get('mac') or '').strip().lower()
    if not mac or len(mac) < 8:
        return None
    existing = query_one("SELECT * FROM devices WHERE mac=?", (mac,))
    ts = now_str()
    if existing:
        # 保留用户设置的 type/group/note，更新动态字段
        sql = """UPDATE devices SET ip=?, hostname=?, os_guess=?, status=?, is_bound=?,
                 last_seen=?, updated_at=? WHERE mac=?"""
        execute(sql, (
            dev.get('ip', '') or existing['ip'],
            dev.get('hostname', '') or existing['hostname'],
            dev.get('os_guess', '') or existing['os_guess'],
            dev.get('status', 'online'),
            dev.get('is_bound', existing.get('is_bound', 0)),
            dev.get('last_seen', ts), ts, mac
        ))
        return mac
    execute(
        """INSERT OR IGNORE INTO devices
           (mac, ip, vendor, hostname, type, os_guess, status, group_name, note, is_bound, first_seen, last_seen, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (mac, dev.get('ip', ''), dev.get('vendor', ''), dev.get('hostname', ''),
         dev.get('type', 'terminal'), dev.get('os_guess', ''), dev.get('status', 'online'),
         dev.get('group_name', ''), dev.get('note', ''), dev.get('is_bound', 0), ts, ts, ts)
    )
    return mac


def update_device(mac, fields):
    """更新设备的可编辑字段（type/group_name/note）"""
    mac = (mac or '').strip().lower()
    if not mac:
        return False
    allowed = {'type', 'group_name', 'note'}
    sets, args = [], []
    for k, v in fields.items():
        if k in allowed:
            sets.append(f"{k}=?")
            args.append(str(v or ''))
    if not sets:
        return False
    sets.append("updated_at=?")
    args.append(now_str())
    args.append(mac)
    execute(f"UPDATE devices SET {', '.join(sets)} WHERE mac=?", args)
    return True


def list_devices():
    return query("SELECT * FROM devices ORDER BY status DESC, ip")


# ==================== 策略 ====================
def create_policy(p):
    ts = now_str()
    return execute(
        """INSERT INTO policies
           (name, target_type, target_value, ports, protocols, schedule_days,
            schedule_start, schedule_end, down_limit, up_limit, priority, enabled, dynamic_mode, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (p['name'], p['target_type'], p['target_value'], p.get('ports', ''),
         p.get('protocols', ''), p.get('schedule_days', '1,2,3,4,5,6,7'),
         p.get('schedule_start', '00:00'), p.get('schedule_end', '23:59'),
         int(p.get('down_limit', 0)), int(p.get('up_limit', 0)),
         int(p.get('priority', 0)), 1 if p.get('enabled', True) else 0,
         1 if p.get('dynamic_mode', False) else 0, ts, ts)
    )


def update_policy(pid, p):
    ts = now_str()
    fields = ['name', 'target_type', 'target_value', 'ports', 'protocols', 'schedule_days',
              'schedule_start', 'schedule_end', 'priority', 'dynamic_mode']
    sets = []
    args = []
    for k in fields:
        if k in p:
            sets.append(f"{k}=?")
            args.append(str(p[k]))
    for k, conv in (('down_limit', int), ('up_limit', int)):
        if k in p:
            sets.append(f"{k}=?")
            args.append(conv(p[k]))
    if 'enabled' in p:
        sets.append("enabled=?")
        args.append(1 if p['enabled'] else 0)
    if not sets:
        return False
    sets.append("updated_at=?")
    args.append(ts)
    args.append(pid)
    execute(f"UPDATE policies SET {', '.join(sets)} WHERE id=?", args)
    return True


def delete_policy(pid):
    execute("DELETE FROM policies WHERE id=?", (pid,))
    return True


def list_policies():
    return query("SELECT * FROM policies ORDER BY priority DESC, id")


# ==================== 防火墙规则 ====================
def create_firewall_rule(rule_name, direction, action, protocol, port, remote_ip, note='', status='active', last_msg=''):
    ts = now_str()
    return execute(
        """INSERT OR REPLACE INTO firewall_rules
           (rule_name, direction, action, protocol, port, remote_ip, note, status, last_msg, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (rule_name, direction, action, protocol, int(port or 0), remote_ip or '', note or '',
         status, last_msg[:200], ts)
    )


def list_firewall_rules():
    return query("SELECT * FROM firewall_rules ORDER BY id DESC")


def update_firewall_rule(id_, status, last_msg=''):
    execute("UPDATE firewall_rules SET status=?, last_msg=? WHERE id=?",
            (status, last_msg[:200], id_))


def delete_firewall_rule(id_):
    r = query_one("SELECT * FROM firewall_rules WHERE id=?", (id_,))
    execute("DELETE FROM firewall_rules WHERE id=?", (id_,))
    return r

# ==================== 审计 ====================
def audit(action, detail):
    return execute("INSERT INTO audit (ts, action, detail) VALUES (?,?,?)", (now_str(), action, detail))


def list_audit(limit=200):
    return query("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (min(limit, 1000),))


# ==================== 厂商库 ====================
def oui_count():
    r = query_one("SELECT COUNT(*) AS c FROM oui")
    return r['c'] if r else 0


def oui_lookup(prefix):
    r = query_one("SELECT vendor FROM oui WHERE prefix=?", (prefix.upper(),))
    return r['vendor'] if r else ''


def oui_bulk_insert(rows):
    """rows: [(prefix, vendor)]"""
    executemany("INSERT OR REPLACE INTO oui (prefix, vendor) VALUES (?,?)", rows)


# ==================== 每日累计流量 ====================
def upsert_usage(date, down, up):
    """写入/覆盖某日累计流量（字节）：内存 daily_usage 为权威，落库为持久化快照"""
    execute(
        """INSERT INTO usage_daily (date, down, up) VALUES (?,?,?)
           ON CONFLICT(date) DO UPDATE SET down=excluded.down, up=excluded.up""",
        (date, int(down), int(up))
    )


def get_usage_days(limit=400):
    """返回 {date: {down, up}}，按日期升序"""
    rows = query("SELECT date, down, up FROM usage_daily ORDER BY date DESC LIMIT ?", (max(1, min(limit, 1000)),))
    return {r['date']: {'down': int(r['down'] or 0), 'up': int(r['up'] or 0)} for r in rows}


def get_usage_day(date):
    r = query_one("SELECT down, up FROM usage_daily WHERE date=?", (date,))
    return {'down': int(r['down'] or 0), 'up': int(r['up'] or 0)} if r else {'down': 0, 'up': 0}