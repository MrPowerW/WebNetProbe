# -*- coding: utf-8 -*-
"""
厂商 OUI 库：加载 IEEE MA-L 官方数据（data/oui.csv）到 SQLite，
提供 MAC 前缀 -> 厂商 查询。首次运行导入，之后从数据库读取。
"""
import csv
import os
import threading

from . import db

OUI_CSV = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'oui.csv')

_cache = {}
_cache_lock = threading.Lock()


def _import_from_csv():
    """解析 IEEE oui.csv 并批量写入数据库"""
    if not os.path.exists(OUI_CSV):
        return 0
    rows = []
    with open(OUI_CSV, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        next(reader, None)  # 跳过表头
        for row in reader:
            if len(row) >= 3:
                prefix = row[1].strip().upper()
                vendor = row[2].strip()
                if prefix and vendor:
                    rows.append((prefix, vendor))
    if rows:
        # 分批写入，避免一次过大事务
        for i in range(0, len(rows), 5000):
            db.oui_bulk_insert(rows[i:i + 5000])
    return len(rows)


def load_oui(force=False):
    """加载厂商库到内存缓存；数据库为空时从 CSV 导入"""
    global _cache
    with _cache_lock:
        if _cache and not force:
            return len(_cache)
        count = db.oui_count()
        if count == 0 and not force:
            imported = _import_from_csv()
            print(f"[+] 厂商库导入完成: {imported} 条")
            count = db.oui_count()
        if count == 0:
            _cache = {}
            return 0
        # 全量读入内存（约3万条，占用很小）
        rows = db.query("SELECT prefix, vendor FROM oui")
        _cache = {r['prefix']: r['vendor'] for r in rows}
        return len(_cache)


def lookup_vendor(mac):
    """根据 MAC 地址查询厂商，未知返回空串"""
    mac = (mac or '').replace('-', '').replace(':', '').strip().upper()
    if len(mac) < 6:
        return ''
    prefix = mac[:6]
    return _cache.get(prefix, '')
