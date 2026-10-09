# -*- coding: utf-8 -*-
"""
WebNetProbe 管理命令行工具（v2.11.2）
用法：
  python manage.py reset                # 一键重置所有配置，恢复系统初始状态（备份旧库）
  python manage.py reset-pwd <用户名> <新密码>   # admin 重置指定用户密码（强制其下次登录改密）
  python manage.py view-pwd <用户名>     # admin 查看指定用户密码（明文，Fernet 解密）
  python manage.py status                # 查看当前 DB/版本/用户概况
"""
import io
import os
import shutil
import sqlite3
import sys
import time
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from app import auth, db

OUT = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

DEFAULT_PASSWORD = auth.DEFAULT_ADMIN_PASSWORD


def _banner(t):
    OUT.write('\n=== %s ===\n' % t)


def _backup_db():
    """备份当前 DB 到 data/backup/（带时间戳）"""
    src = db.get_db_path()
    if not os.path.exists(src):
        return None
    bk_dir = os.path.join(db.DATA_DIR, 'backup')
    os.makedirs(bk_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    dst = os.path.join(bk_dir, 'webnetprobe_%s.db' % ts)
    try:
        # 服务运行中直接复制 WAL 可能不完整；先做 SQLite 在线备份
        c = sqlite3.connect(src)
        b = sqlite3.connect(dst)
        c.backup(b)
        b.close(); c.close()
        OUT.write('已备份当前数据库 -> %s\n' % dst)
        return dst
    except Exception as e:
        OUT.write('备份失败（继续重置）: %s\n' % e)
        return None


def _restart_service():
    """重启 WebNetProbe 服务（0.0.0.0:8090），使内存态与出厂 DB 同步清零"""
    import subprocess
    try:
        out = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=15).stdout
        pids = set()
        for line in out.splitlines():
            if ':8090' in line and 'LISTENING' in line:
                parts = line.split()
                if parts:
                    pids.add(parts[-1])
        for p in pids:
            subprocess.run(['taskkill', '/F', '/PID', p], capture_output=True, text=True, timeout=10)
            OUT.write('已停止旧服务进程 PID=%s\n' % p)
        time.sleep(2)
        root = os.path.dirname(os.path.abspath(__file__))
        ps = ("Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = '\"%s\" server.py'; CurrentDirectory = '%s' }" % (sys.executable, root))
        subprocess.run(['powershell', '-Command', ps], capture_output=True, text=True, timeout=20)
        OUT.write('服务已重启（0.0.0.0:8090），内存数据已同步清零\n')
        return True
    except Exception as e:
        OUT.write('服务自动重启失败（请手动重启 server.py）: %s\n' % e)
        return False


def cmd_reset():
    """一键重置所有配置：备份 -> 清空全部业务表 -> 重建默认 admin"""
    _banner('一键重置所有配置（恢复系统初始状态）')
    _backup_db()
    path = db.get_db_path()
    c = sqlite3.connect(path, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    # 动态清空全部业务表（保留 oui 静态厂商库与 sqlite_ 系统表）
    tbls = [r['name'] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]
    for t in tbls:
        if t == 'oui':
            continue
        try:
            c.execute('DELETE FROM %s' % t)
            c.commit()
        except Exception:
            pass
    # 重建默认 admin（默认密码 Admin@123456，强制首次登录改密）
    c.execute("DELETE FROM users")
    c.execute("DELETE FROM sessions")
    c.commit()
    salt = __import__('secrets').token_hex(16)
    h = auth._hash(DEFAULT_PASSWORD, salt)
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cipher = auth.encrypt_pwd(DEFAULT_PASSWORD)
    c.execute(
        "INSERT INTO users(username,password_hash,salt,pwd_cipher,role,display_name,status,must_change,created_at,pwd_changed_at) VALUES(?,?,?,?,?,?,1,1,?,?)",
        ('admin', h, salt, cipher, 'admin', '系统管理员', now, now))
    c.commit()
    c.close()
    OUT.write('已恢复出厂状态：\n')
    OUT.write('  管理员账户: admin\n')
    OUT.write('  默认密码:   %s\n' % DEFAULT_PASSWORD)
    OUT.write('  首次登录需强制修改密码（admin 登录不弹提示，可在管理中心修改）\n')
    OUT.write('  历史数据库已保留在 data/backup/ 目录\n')
    _restart_service()


def cmd_reset_pwd(username, new_password):
    """admin 重置指定用户密码（强制下次登录改密 + 会话全部失效）"""
    _banner('重置用户密码')
    ok, msg = auth.password_strength_ok(new_password)
    if not ok:
        OUT.write('错误: %s\n' % msg)
        return 1
    r = auth.reset_password(username, new_password)
    OUT.write('%s\n' % r.get('msg', r))
    if r.get('ok'):
        auth._audit('user_reset_pwd_cli', 'CLI 重置密码: ' + username)
    return 0 if r.get('ok') else 1


def cmd_view_pwd(username):
    """admin 查看指定用户密码（明文）"""
    _banner('查看用户密码')
    c = sqlite3.connect(db.get_db_path(), timeout=10)
    c.row_factory = sqlite3.Row
    row = c.execute("SELECT username, pwd_cipher, role, status FROM users WHERE username=?", (username,)).fetchone()
    c.close()
    if not row:
        OUT.write('错误: 用户不存在\n')
        return 1
    plain = auth.decrypt_pwd(row['pwd_cipher'] or '')
    if plain:
        OUT.write('用户 [%s] 角色 [%s] 当前密码明文: %s\n' % (row['username'], row['role'], plain))
    else:
        OUT.write('用户 [%s] 无明文存储（旧版本创建），请先重置密码后再查看\n' % row['username'])
    auth._audit('user_view_pwd_cli', 'CLI 查看密码: ' + username)
    return 0


def cmd_status():
    """系统状态"""
    _banner('系统状态')
    c = sqlite3.connect(db.get_db_path(), timeout=10)
    c.row_factory = sqlite3.Row
    users = c.execute("SELECT username, role, status, must_change FROM users").fetchall()
    size = os.path.getsize(db.get_db_path()) if os.path.exists(db.get_db_path()) else 0
    for t in ('audit', 'devices', 'usage_daily'):
        try:
            n = c.execute('SELECT COUNT(*) AS n FROM %s' % t).fetchone()['n']
            OUT.write('表 %-12s: %d 条\n' % (t, n))
        except Exception:
            pass
    c.close()
    OUT.write('当前数据库: %s (%.2f MB)\n' % (db.get_db_path(), size / 1048576))
    OUT.write('用户列表:\n')
    for u in users:
        OUT.write('  %-14s 角色=%-8s 状态=%s 强制改密=%s\n' % (
            u['username'], u['role'], '启用' if u['status'] else '停用', '是' if u['must_change'] else '否'))


def main():
    args = sys.argv[1:]
    if not args:
        OUT.write(__doc__)
        return 0
    cmd = args[0]
    if cmd == 'reset':
        return cmd_reset()
    elif cmd == 'reset-pwd':
        if len(args) < 3:
            OUT.write('用法: python manage.py reset-pwd <用户名> <新密码>\n')
            return 1
        return cmd_reset_pwd(args[1], args[2])
    elif cmd == 'view-pwd':
        if len(args) < 2:
            OUT.write('用法: python manage.py view-pwd <用户名>\n')
            return 1
        return cmd_view_pwd(args[1])
    elif cmd == 'status':
        return cmd_status()
    else:
        OUT.write('未知命令: %s\n' % cmd)
        OUT.write(__doc__)
        return 1


if __name__ == '__main__':
    sys.exit(main())
