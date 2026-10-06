# -*- coding: utf-8 -*-
"""
WebNetProbe 数据库备份脚本（回滚镜像）
用法: python backup_db.py [备注]
在线安全备份（SQLite backup API，无需停服）。镜像保存到 data/backup/。
【v2.21.13】备份不自动删除，全部保留，由用户选择清理（rollback.py clean）。
"""
import io, sys, os, sqlite3, datetime
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, 'data', 'webnetprobe.db')
BK = os.path.join(BASE, 'data', 'backup')

def main():
    if not os.path.exists(DB):
        print('数据库不存在:', DB)
        return 1
    os.makedirs(BK, exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    note = sys.argv[1] if len(sys.argv) > 1 else ''
    dst = os.path.join(BK, 'webnetprobe_%s.db' % ts)
    try:
        src = sqlite3.connect(DB)
        try:
            src.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        except Exception:
            pass
        dstc = sqlite3.connect(dst)
        src.backup(dstc)          # 在线安全备份
        dstc.close(); src.close()
        size = os.path.getsize(dst)
        print('备份成功: %s (%d bytes) %s' % (os.path.basename(dst), size, note))
        print('提示: 备份全部保留不自动删除；如需清理请运行: python rollback.py clean')
    except Exception as e:
        print('备份失败:', str(e))
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
