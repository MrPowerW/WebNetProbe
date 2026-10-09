# -*- coding: utf-8 -*-
"""
WebNetProbe 数据库回滚脚本
用法:
  python rollback.py            # 列出全部备份镜像
  python rollback.py <序号>     # 回滚到指定镜像（停服->恢复->重启）
  python rollback.py latest     # 回滚到最近一次镜像
"""
import io, sys, os, glob, subprocess, shutil, datetime, time
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
BASE = os.path.dirname(os.path.abspath(__file__))
BK = os.path.join(BASE, 'data', 'backup')
DB = os.path.join(BASE, 'data', 'webnetprobe.db')

def list_backups():
    files = sorted(glob.glob(os.path.join(BK, 'webnetprobe_*.db')), reverse=True)
    return files

def stop_server():
    # 停止占用 8090 的 python 进程（server.py）
    killed = False
    try:
        out = subprocess.check_output('netstat -ano | findstr ":8090" | findstr "LISTENING"', shell=True).decode('gbk', 'ignore')
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[4].isdigit():
                pid = parts[4]
                subprocess.run(['taskkill', '/PID', pid, '/F'], capture_output=True)
                killed = True
    except Exception:
        pass
    if not killed:
        # 兜底：结束所有 python 进程（server.py 以 python 运行）
        try:
            out = subprocess.check_output('wmic process where "name=\'python.exe\'" get processid', shell=True).decode('gbk', 'ignore')
            for line in out.splitlines():
                s = line.strip()
                if s.isdigit():
                    subprocess.run(['taskkill', '/PID', s, '/F'], capture_output=True)
                    killed = True
        except Exception:
            pass
    return killed

def start_server():
    py = sys.executable
    subprocess.Popen([py, os.path.join(BASE, 'server.py')], cwd=BASE, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    print('服务已启动，等待就绪...')
    for _ in range(30):
        time.sleep(1)
        try:
            import urllib.request
            with urllib.request.urlopen('http://127.0.0.1:8090/api/version', timeout=2) as r:
                print('服务就绪:', r.read().decode('utf-8', 'ignore'))
                return True
        except Exception:
            continue
    print('警告: 服务启动后 30 秒未就绪，请检查 server.py 与端口占用')
    return False

def main():
    files = list_backups()
    if not files:
        print('没有可用备份镜像（%s 为空）' % BK)
        print('请先运行: python backup_db.py 创建镜像')
        return 1
    print('可用备份镜像（共 %d 份）:' % len(files))
    for i, f in enumerate(files):
        sz = os.path.getsize(f)
        ts = os.path.basename(f).replace('webnetprobe_', '').replace('.db', '')
        print('  [%d] %s (%d bytes)' % (i, ts, sz))

    # v2.21.13: clean 命令——用户选择删除备份（不自动删除，由用户选择）
    if len(sys.argv) >= 2 and sys.argv[1] == 'clean':
        print()
        print('选择要删除的备份（可多选，用逗号分隔，例如: 0,2，回车取消）:')
        try:
            inp = input('>>> ').strip()
        except EOFError:
            inp = ''
        if not inp:
            print('已取消，未删除任何备份。')
            return 0
        del_idx = []
        for part in inp.replace('，', ',').split(','):
            p = part.strip()
            if p.isdigit() and 0 <= int(p) < len(files):
                del_idx.append(int(p))
        if not del_idx:
            print('无效序号，未删除任何备份。')
            return 0
        for idx in sorted(set(del_idx), reverse=True):
            try:
                os.remove(files[idx])
                print('已删除: %s' % os.path.basename(files[idx]))
            except Exception as e:
                print('删除失败 %s: %s' % (os.path.basename(files[idx]), str(e)))
        print('清理完成，剩余 %d 份备份。' % len(list_backups()))
        return 0

    if len(sys.argv) < 2:
        # v2.21.13: 交互选择回滚版本（启动自检提示后由用户选择）
        print()
        print('请输入要回滚的序号（回车取消）:')
        try:
            inp = input('>>> ').strip()
        except EOFError:
            inp = ''
        if not inp:
            print('已取消回滚。')
            return 0
        arg = inp
    else:
        arg = sys.argv[1]
    if arg == 'latest':
        sel = files[0]
    else:
        try:
            idx = int(arg)
            sel = files[idx]
        except Exception:
            print('无效序号:', arg)
            return 1
    # 回滚前先备份当前（防止误操作）
    bak_cur = os.path.join(BK, 'pre_rollback_%s.db' % datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
    if os.path.exists(DB):
        shutil.copy2(DB, bak_cur)
        print('当前数据库已备份:', os.path.basename(bak_cur))
    print('停止服务...')
    stop_server()
    time.sleep(2)
    # 恢复
    for ext in ['', '-wal', '-shm']:
        p = DB + ext
        if os.path.exists(p):
            try: os.remove(p)
            except Exception: pass
    shutil.copy2(sel, DB)
    print('已恢复镜像:', os.path.basename(sel))
    print('启动服务...')
    start_server()
    print('回滚完成。请浏览器 Ctrl+F5 刷新。')
    return 0

if __name__ == '__main__':
    sys.exit(main())
